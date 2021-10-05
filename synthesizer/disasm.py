"""
Anything related to disassembling the functions extracted by Ghidra/Binary Nina
and converting them to assembly gadgets.

We support both Ghidra (as fallback) and Binary Ninja (commercial product) to
extract functions from the target binary. For Binary Ninja, we expect the
license to be present in the environment variable BNLICENSE
- if this is not the case, we automatically use Ghidra.
"""

import copy
import logging
import os
import time
from functools import partial
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from miasm.analysis.machine import Machine
from miasm.core import asmblock
from miasm.core.locationdb import LocationDB
from miasm.core.asmblock import AsmBlock, AsmBlockBad, AsmCFG
from miasm.analysis.binary import ContainerELF
from miasm.core.asmblock import disasmEngine
from miasm.expression.simplifications import expr_simp_high_to_explicit
from miasm.expression.simplifications_stateful_memory import rewrite_memory


from .config import TargetConfig
from .cache import Cache, CacheType
from .ghidra_headless import run_ghidra
from .rebase import rebase_gadget, rebase_irdst, rebase_loc_db
from .utils import Paralleliser
from .types_ import AsmGadget, RawGadget, Library, DisasSettings

logger = logging.getLogger("synthesizer.disasm")


def get_disasm_engine(binary: Path, loc_db: Optional[LocationDB] = None) -> disasmEngine:
    if loc_db is None:
        loc_db = LocationDB()
    with open(binary, "rb") as f:
        container: ContainerELF = ContainerELF.from_stream(f, loc_db)

    machine: Machine = Machine(container.arch)
    # black magic under the hood - pylint can't deal with that
    mdis: disasmEngine = machine.dis_engine(container.bin_stream, loc_db=loc_db) # pylint: disable = not-callable
    mdis.follow_call = False
    mdis.dont_dis_nulstart_bloc = True
    mdis.dontdis_retcall = False
    return mdis


def addr_to_asmcfg(binary: Path, addr: int, loc_db: LocationDB) -> Optional[AsmCFG]:
    mdis = get_disasm_engine(binary, loc_db)
    asm_cfg = AsmCFG(loc_db)
    block: 'Optional[Union[AsmBlock, AsmBlockBad]]' = mdis.dis_block(addr)
    if isinstance(block, AsmBlock) and not isinstance(block, AsmBlockBad):
        asm_cfg.add_block(mdis.dis_block(addr))
        return asm_cfg
    return None


def addr_to_asmblock(mdis: Machine, addr: int) -> Optional[AsmBlock]:
    block: 'Optional[Union[AsmBlock, AsmBlockBad]]' = mdis.dis_block(addr)
    if isinstance(block, AsmBlock) and not isinstance(block, AsmBlockBad):
        return block
    return None


### Extraction of function addresses

def get_function_addresses_from_ghidra(path: Path, workdir: Path) -> List[int]:
    # if not, run ghidra to get them
    workdir.mkdir(exist_ok=True)
    out_path = workdir / "ghidra_funcaddrsout.txt"
    script_path = Path(__file__).parent / "dump_functions.py"
    logger.info(f"Running Ghidra script {script_path}")
    run_ghidra(path, script_path, script_arguments=[out_path.as_posix()], workdir=workdir)

    func_addrs = []
    with open(out_path, "r") as f:
        for l in f:
            func_addrs += [int(l.split(": ")[1], 16)]
    return func_addrs


def get_function_addresses_from_binaryninja(path: Path) -> List[int]:
    # inline import to avoid ImportError at start of module if BinaryNinja unavailable
    from .binary_ninja import bn_get_function_starts
    return list(bn_get_function_starts(path))


def get_function_addresses(binary: Path, workdir: Path, cache_name: str = "function_addrs") -> List[int]:
    """Gets a list of function start addresses.

    This function executes a ghidra headless script.

    Args:
        path: The path to the binary file.
    Returns:
        A list of function start addresses.
    """
    logger.debug(f"Extracting function addresses from '{binary.name}'")
    # check if we already have the function addresses
    cache = Cache(binary, cache_name, cache_type=CacheType.JSON)
    func_addrs: List[int] = cache.read_from_cache() # type: ignore
    if func_addrs:
        logger.debug(f"Returning {len(func_addrs)} cached function addresses")
        return func_addrs
    start = time.time()

    try:
        if os.environ.get('BNLICENSE', None) is not None:
            func_addrs = get_function_addresses_from_binaryninja(binary)
            logger.debug(f"Used Binary Ninja to extract {len(func_addrs)} function addresses")
    except ModuleNotFoundError:
        pass

    # Binary Ninja failed, fallback to Ghidra
    if not func_addrs:
        func_addrs = get_function_addresses_from_ghidra(binary, workdir)
        logger.debug(f"Used Ghidra to extract {len(func_addrs)} function addresses")

    cache.write_to_cache(func_addrs)
    logger.info(f"Finished extraction of {len(func_addrs)} function addresses in {round(time.time() - start, 2)}s")
    return func_addrs


def get_function_gadgets(binary: Path, start_addr: int) -> Iterator[int]:
    asm_cfg = get_disasm_engine(binary).dis_multiblock(start_addr)
    for block in asm_cfg.blocks:
        # print("-", type(block), block)
        for instr in block.lines:
            # print("    -", type(instr), instr.offset, instr)
            yield instr.offset


#### Unaligned disassembly

def get_section(binary: Path, section_name: str) -> Any:
    loc_db = LocationDB()
    with open(binary, "rb") as f:
        container: ContainerELF = ContainerELF.from_stream(f, loc_db)
    return container.executable.getsectionbyname(section_name)


def get_function_gadgets_unaligned(binary: Path) -> Iterator[int]:
    code_section = get_section(binary, ".text")
    yield from range(code_section.sh.offset, code_section.sh.offset + code_section.sh.size)


def get_text_section_chunks(binary: Path, max_processes: int) -> Iterator[Tuple[int, int]]:
    print("get_text_section_chunks")
    code_section = get_section(binary, ".text")
    print(code_section)
    chunk_size, m = divmod(code_section.sh.size, max_processes)
    sizes = [chunk_size + 1] * m + [chunk_size] * (max_processes - m)
    for (i, sz) in enumerate(sizes):
        yield (sum(sizes[:i]) + code_section.sh.offset, sz)


# TODO: fix this naive approach
def get_gadgets_from_text_section_chunk(binary: Path, workdir: Path, control_flow_types: List[str], chunk: Tuple[int, int]) -> Iterator[int]:
    chunk_start, chunk_len = chunk
    for gadget_start_addr in range(chunk_start, chunk_start + chunk_len):
        yield from get_valid_gadget_from_address(binary, workdir, control_flow_types, gadget_start_addr)


### Gadget validity checks (including lifting)


def get_ira(binary: Path, loc_db: LocationDB) -> Any:
    with open(binary, "rb") as f:
        container: ContainerELF = ContainerELF.from_stream(f, loc_db)

    machine: Machine = Machine(container.arch)
    return machine.ira(loc_db)


# TODO: currently architecture dependent (ony x86 supported)
def contains_fp_ins(block: AsmBlock) -> bool:
    for instr in block.lines:
        ins_str = str(instr).lower()
        # check if we have floating point register
        if "xmm" in ins_str or "ymm" in ins_str or "zmm" in ins_str:
            return True
        if "fp" in ins_str:
            return True
        # check if we use floating point instruction
        if ins_str.startswith("f"):
            return True
    return False


def is_liftable(binary: Path, loc_db: LocationDB, block: AsmBlock) -> bool:
    ira = get_ira(binary, loc_db)
    ira_cfg = ira.new_ircfg()
    try:
        ira.add_asmblock_to_ircfg(block, ira_cfg)
    except (NotImplementedError, ValueError):
        return False
    # make flags explicit
    ira_cfg.simplify(expr_simp_high_to_explicit)
    try:
        # rewrite memory expressions
        ira_cfg.simplify(rewrite_memory, rewrite_mem=True)
    except ValueError:
        return False
    if len(ira_cfg.blocks) != 1:
        return False
    return True


# TODO: currently architecture dependent (ony x86 supported)
def is_valid_call(ins: Any) -> bool:
    ins_str = str(ins).lower()
    # memory
    if "[" in ins_str:
        return True
    # check if call target is a register
    target = ins_str.split()[1].strip()
    regs32_str = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"] + \
                 ["R%dD" % (i + 8) for i in range(8)]

    regs64_str = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
              "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
              "RIP"]
    if not target.upper() in regs64_str and not target.upper() in regs32_str:
        return False
    return True


# TODO: currently architecture dependent (ony x86 supported)
def is_valid_jmp(ins: Any) -> bool:
    ins_str = str(ins).lower()
    # memory
    if "[" in ins_str:
        return True
    # check if jmp target is a register
    target = ins_str.split()[1].strip()
    regs32_str = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"] + \
                 ["R%dD" % (i + 8) for i in range(8)]

    regs64_str = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
              "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
              "RIP"]
    if not target.upper() in regs64_str and not target.upper() in regs32_str:
        return False
    return True


# TODO: currently architecture dependent (ony x86 supported)
def last_instruction_is_valid(asm_block: AsmBlock, control_flow_types: List[str]) -> bool:
    last_ins = asm_block.lines[-1]
    last_ins_str = str(last_ins).lower()
    if "ret" in last_ins_str and "ret" in control_flow_types:
        return True
    if last_ins.is_subcall() and "call" in control_flow_types:
        return is_valid_call(last_ins)
    if "jmp" in last_ins_str and "jmp" in control_flow_types:
        return is_valid_jmp(last_ins)
    return False


def is_valid(binary: Path, asm_block: Union[AsmBlock, AsmBlockBad], loc_db: LocationDB, control_flow_types: List[str]) -> bool:
    if isinstance(asm_block, AsmBlockBad):
        return False
    # last ins must be indirect control flow
    if not last_instruction_is_valid(asm_block, control_flow_types):
        return False
    if contains_fp_ins(asm_block):
        return False
    if not is_liftable(binary, loc_db, asm_block):
        return False
    return True


def get_valid_gadget_from_address(binary: Path, workdir: Path, control_flow_types: List[str], gadget_start_addr: int) -> Iterator[int]:
    loc_db = LocationDB()
    asm_block: AsmBlock = get_disasm_engine(binary, loc_db).dis_block(gadget_start_addr)
    if is_valid(binary, asm_block, loc_db, control_flow_types):
        asm_cfg = AsmCFG(loc_db)
        asm_cfg.add_block(asm_block)
        _create_dot_file(workdir / (str(gadget_start_addr) + ".dot"), asm_cfg)
        yield gadget_start_addr


def get_gadgets_from_function(binary: Path, workdir: Path, control_flow_types: List[str], func_addr: int) -> Iterator[int]:
    for gadget_start_addr in set(get_function_gadgets(binary, func_addr)):
        yield from get_valid_gadget_from_address(binary, workdir, control_flow_types, gadget_start_addr)


def _get_gadgets_from_function_mp_wrapper(binary: Path, workdir: Path, control_flow_types: List[str], func_addr: int, results: Dict[int, Any], idx: int) -> None:
    results[idx] = list(get_gadgets_from_function(binary, workdir, control_flow_types, func_addr))


def _get_gadgets_from_text_section_chunk_mp_wrapper(binary: Path, workdir: Path, control_flow_types: List[str], chunk: Tuple[int, int], results: Dict[int, Any], idx: int) -> None:
    results[idx] = list(get_gadgets_from_text_section_chunk(binary, workdir, control_flow_types, chunk))


def gadget_tasks_from_unaligned_offsets(ds: DisasSettings) -> 'Iterator[Tuple[partial[Any], str]]':
    task_group_ctr = -1 # use unique task groups
    for chunk in get_text_section_chunks(ds.target, ds.max_processes):
        task_group_ctr += 1
        yield (partial(_get_gadgets_from_text_section_chunk_mp_wrapper, ds.target, ds.workdir, ds.control_flow_types, chunk), f"tg_{task_group_ctr}")


def gadget_tasks_from_start_addrs(start_addrs: List[int], ds: DisasSettings) -> 'Iterator[Tuple[partial[Any], str]]':
    task_group_ctr = -1 # use unique task groups
    for addr in start_addrs:
        task_group_ctr += 1
        yield (partial(_get_gadgets_from_function_mp_wrapper, ds.target, ds.workdir, ds.control_flow_types, addr), f"tg_{task_group_ctr}")


def get_gadgets_tasks(ds: DisasSettings) -> 'List[Tuple[partial[Any], str]]':
    wd = ds.workdir / "valid_asm_gadgets"
    wd.mkdir()
    task_ds = copy.deepcopy(ds)
    task_ds.workdir = wd

    tasks: 'Iterator[Tuple[partial[Any], str]]'
    if ds.disas_unaligned:
        # use all available (unaligned offsets) from text section
        tasks = gadget_tasks_from_unaligned_offsets(task_ds)
    else:
        # extract functions and use each instruction offset as potential gadget
        func_addrs = get_function_addresses(ds.target, ds.workdir)
        tasks = gadget_tasks_from_start_addrs(func_addrs, task_ds)
    return list(tasks)


def disas_gadgets(tasks: 'List[Tuple[partial[Any], str]]', ds: DisasSettings) -> List[int]:
    start_time = time.time()
    process_mgr = Paralleliser(list(tasks), ds.max_processes)
    gadgets_per_function = process_mgr.execute(ds.timeout)
    end_time = time.time()

    # flatten this; we don't care from which function a gadget originated
    gadgets: List[int] = [g for l in gadgets_per_function if not l is None for g in l]
    # deduplicate gadgets
    gadgets = list(set(gadgets))

    timeouted = (end_time - start_time) >= ds.timeout if ds.timeout is not None else False
    logger.debug(f"Disassembled {len(gadgets)} gadgets in {round((end_time - start_time), 2)}s (timeout ({ds.timeout}s) triggered: {timeouted})")
    return gadgets


def get_all_gadgets(ds: DisasSettings) -> List[int]:
    asmblock.log_asmblock.setLevel(logging.ERROR)
    cache = Cache(ds.target, ds.cache_name, cache_type=ds.cache_type)
    data: Optional[List[int]] = cache.read_from_cache()
    if data:
        logger.debug("Retuning cached valid gadgets")
        return data

    gadget_tasks = get_gadgets_tasks(ds)
    gadgets = disas_gadgets(gadget_tasks, ds)

    if gadgets:
        cache.write_to_cache(gadgets)
        logger.debug(f"Valid gadgets cached in {cache.cache_file}")
    else:
        logger.critical(f"No valid gadgets found!")
        raise RuntimeError("No valid gadgets found!")
    return gadgets


def cache_gadgets(ds: DisasSettings) -> None:
    logger.debug(f"Caching gadgets for {ds.target.name}")
    asmblock.log_asmblock.setLevel(logging.ERROR)
    cache = Cache(ds.target, ds.cache_name, cache_type=ds.cache_type)
    data: Optional[List[int]] = cache.read_from_cache()
    if data:
        logger.debug("Gadget addresses already cached")
        return

    gadget_tasks = get_gadgets_tasks(ds)
    logger.debug(f"Collected {len(gadget_tasks)} disassembly tasks")
    gadgets = disas_gadgets(gadget_tasks, ds)

    if gadgets:
        cache.write_to_cache(gadgets)
        logger.debug(f"Valid gadgets cached in {cache.cache_file}")
    else:
        logger.critical(f"No valid gadgets found!")
        raise RuntimeError("No valid gadgets found!")


def load_cached_gadgets(ds: DisasSettings) -> List[int]:
    cache = Cache(ds.target, ds.cache_name, ds.cache_type)
    data: Optional[List[int]] = cache.read_from_cache()
    if data:
        logger.debug("Loading cached gadget addresses")
        return data
    raise RuntimeError(f"No gadgets cached in {cache.cache_file}")


def merge_loc_dbs(main_loc_db: LocationDB, library_to_gadgets: Dict[Library, List[AsmGadget]]) -> None:
    """
    This merges location databases from libraries into the one of the main executable.
    Assumption is that all addresses and loc_dbs have been rebased previously. This needs a list of gadgets
    per library which are to be merged into the main loc_db (merging complete loc_dbs is overkill). Each
    library gadget must be updated to know the associated loc_key in the main loc_db
    """
    for library, library_gadgets in library_to_gadgets.items():
        for g in library_gadgets:
            lib_loc_key = library.loc_db.get_offset_location(g.addr)
            assert lib_loc_key is not None, f"Loc key for offset {g.addr:#x} is None (address must be wrong!)"
            lib_loc_key_names = library.loc_db.get_location_names(lib_loc_key)
            assert main_loc_db.get_offset_location(g.addr) is None, \
                f"Inserting {lib_loc_key} at offset {g.addr:#x} is not possible, found {main_loc_db.get_offset_location(g.addr)}"
            # add gadget at location to main_loc_db
            new_loc_key = main_loc_db.add_location(offset=g.addr)
            for name in lib_loc_key_names:
                main_loc_db.add_location_name(new_loc_key, name)
            # update asm_block's loc key and loc_db
            g.block._loc_key = new_loc_key
            g.block.loc_db = main_loc_db


def disas_and_rebase_gadget(mdis: Machine, addr: int, load_address: int) -> Optional[AsmGadget]:
    asm_block = addr_to_asmblock(mdis, addr)
    if asm_block is None:
        logger.warning(f"Failed to disassemble {addr:#x}")
        return None
    gadget = AsmGadget(addr, asm_block)
    # Step 2: (optionally) rebase gadget
    if load_address:
        # rebase gadgets in-place
        rebase_gadget(gadget, base_addr=load_address)
    return gadget


def disassemble_and_rebase_gadgets(gadget_addresses: List[RawGadget], target_config: TargetConfig) -> Tuple[List[AsmGadget], LocationDB]:
    logger.debug(f"Disassembling {len(gadget_addresses)} gadgets. This may take a while..")
    loc_db = LocationDB()
    mdis = get_disasm_engine(target_config.executable, loc_db)
    gadgets: List[AsmGadget] = []
    assert len(target_config.libraries) <= 1, f"Currently only one library is supported"
    library_to_gadgets: Dict[Library, List[AsmGadget]] = {}
    for library in target_config.libraries:
        library_to_gadgets[library] = []
        library.loc_db = LocationDB()
    for gadget in gadget_addresses:
        # TODO: currently, library addresses are specified as library load address + offset in library
        # opposed to normal gadget addresses which are given as offset into main executable
        if gadget.location != "main_exe":
            # is library -> get offset in libc from rebased address
            lib = [lib for lib in target_config.libraries if lib.name == gadget.location][0]
            lib.mdis = get_disasm_engine(lib.path, lib.loc_db)
            # logger.debug(f"{gadget.addr:#x} is in library {lib.path.name}")
            asm_gadget = disas_and_rebase_gadget(lib.mdis, gadget.addr, lib.load_address)
            if asm_gadget is None:
                logger.warning(f"Failed to disassemble {gadget.addr:#x} in library {lib.path.name}")
                if gadget in target_config.force_code_locations:
                    logger.critical(f"Forced location {gadget.addr:#x} could not be disassembled in library {lib.path.name}")
                    raise RuntimeError(f"Forced location {gadget.addr:#x} could not be disassembled in library {lib.path.name}")
            else:
                library_to_gadgets.get(lib, []).append(asm_gadget)
        else:
            # is regular gadget
            asm_gadget = disas_and_rebase_gadget(mdis, gadget.addr, target_config.load_address)
            if asm_gadget is None:
                logger.warning(f"Failed to disassemble {gadget.addr:#x}")
                if gadget in target_config.force_code_locations:
                    logger.critical(f"Forced location {gadget.addr:#x} could not be disassembled")
                    raise RuntimeError(f"Forced location {gadget.addr:#x} could not be disassembled")
            else:
                gadgets.append(asm_gadget)
    if target_config.load_address:
        loc_db = rebase_loc_db(loc_db, base_addr=target_config.load_address)
        if target_config.preconditions["IRDst"].value < target_config.load_address:
            logger.debug("Rebasing IRDst from preconditions")
            rebase_irdst(target_config.preconditions, base_addr=target_config.load_address)
        if target_config.postconditions["IRDst"].value < target_config.load_address:
            logger.debug("Rebasing IRDst from postconditions")
            rebase_irdst(target_config.postconditions, base_addr=target_config.load_address)
        logger.debug(f"Rebased gadgets onto load address {target_config.load_address:#x}")
    logger.debug(f"Disassembled {len(gadgets)} from main executable ({target_config.executable.name})")
    # we only need to merge libraries if we have any library gadgets
    if library_to_gadgets:
        assert target_config.load_address, f"We have library gadgets but main executable has no load address!"
        for library in target_config.libraries:
            library.loc_db = rebase_loc_db(library.loc_db, base_addr=library.load_address)
        # merge library loc_dbs into main loc_db
        merge_loc_dbs(loc_db, library_to_gadgets)
        for lib, lib_gadgets in library_to_gadgets.items():
            logger.debug(f"Disassembled {len(lib_gadgets)} from {lib.name}")
            gadgets.extend(lib_gadgets)
    return (gadgets, loc_db)


def _create_dot_file(path: Path, asm_cfg: AsmCFG) -> None:
    with open(path, "w") as f:
        f.write(asm_cfg.dot())
