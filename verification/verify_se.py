#!/usr/bin/python3
import logging
import shutil
import time
from argparse import ArgumentParser
from pathlib import Path
from typing import Dict, List, Optional, Union


from miasm.core.asmblock import disasmEngine
from miasm.expression.expression import ExprId, ExprMem, ExprInt
from miasm.core.locationdb import LocationDB
from miasm.analysis.machine import Machine
from miasm.ir.ir import IRCFG

from synthesizer.types_ import AsmGadget
from synthesizer.config import TargetConfig
from synthesizer.disasm import addr_to_asmblock, get_disasm_engine
from synthesizer.rebase import rebase_gadget
from miasm.ir.symbexec import SymbolicExecutionEngine


logger = logging.getLogger("se_verify")

DEBUG = False

MAX_GADGETS_IN_CHAIN = 100


def debug_print(s: str) -> None:
    if DEBUG:
        print(s)


def setup_logging(logger: logging.Logger, target_dir: Path, log_name: str) -> None:
    """Setup logger"""
    console_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(target_dir / log_name, 'w+')
    console_handler.setLevel(logging.DEBUG)
    file_handler.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    console_handler.setFormatter(logging.Formatter('%(name)-24s | %(processName)-17s - %(levelname)-8s: %(message)s'))
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)-24s | %(processName)-17s - %(levelname)-8s: %(message)s'))
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


def to_int(num: Union[int, str]) -> int:
    if isinstance(num, int):
        return num
    if num.startswith("0x"):
        return int(num, 16)
    return int(num, 10)


def stack_to_se_state(stack: List[int], stack_pointer: int, address_size: int) -> Dict[ExprMem, ExprInt]:
    init_state = {}
    # use stack values returned by solver as concrete values
    for val in stack:
        init_state.update(
            {ExprMem(ExprInt(stack_pointer, address_size), address_size) : ExprInt(val, address_size)}
            )
        stack_pointer += address_size // 8
    return init_state


def disas_and_rebase(addr: int, mdis: disasmEngine, load_address: int) -> Optional[AsmGadget]:
    debased_addr = addr - load_address
    debug_print(f"disas + rebase OF {addr:#x}")
    debug_print(f"DEBASING: new addr = {debased_addr:#x}")
    block = addr_to_asmblock(mdis, debased_addr)
    g = AsmGadget(debased_addr, block)
    if not block:
        return None
    debug_print(f"OLD GADGET {g.addr:#x}, {g.block}")
    rebase_gadget(g, load_address)
    debug_print(f"REBASED GADGET {g.addr:#x}, {g.block}")
    # rebase in loc_db
    loc_key = mdis.loc_db.get_offset_location(debased_addr)
    debug_print(f"loc_key={loc_key}")
    names = mdis.loc_db.get_location_names(loc_key)
    new_loc_key = mdis.loc_db.add_location(offset=addr)
    g.block.loc_db = mdis.loc_db
    g.block._loc_key = new_loc_key
    debug_print(f"new_loc_key={new_loc_key}")
    # TODO: maybe remove old loc_key + names + offset?
    for name in names:
        mdis.loc_db.add_location_name(new_loc_key, name)
    return g


def disas_block(addr: int, mdis: disasmEngine, load_address: int) -> Optional[AsmGadget]:
    debug_print(f"DISAS OF {addr:#x}")
    if load_address > 0x0 and addr > load_address:
        return disas_and_rebase(addr, mdis, load_address)
    block = addr_to_asmblock(mdis, addr)
    if not block:
        return None
    return AsmGadget(addr, block)


def lift_block(ira: Machine, asm_gadget: AsmGadget) -> IRCFG:
    try:
        ira_cfg = ira.new_ircfg()
        ira.add_asmblock_to_ircfg(asm_gadget.block, ira_cfg)
        return ira_cfg
    except (NotImplementedError, ValueError) as e:
        logger.error("symbolic_execution: Failed to create IR CFG - skipping block: " + str(e))
        return None


def has_syscall_instruction(gadget: AsmGadget) -> bool:
    for ins in gadget.block.lines:
        if "syscall" in str(ins).lower():
            return True
    return False


def run_symbolic_execution(stack: List[int], executable: Path, target_config: TargetConfig, func: str) -> bool:
    # 1. set preconditions + stack
    # 2. symbolically execute block
    # 3. get IRDst -> disassemble if real address
    # 4. Unless we are at destination (or reach some loop ctr), go to 2.
    # 5. verify postconditions
    loc_db = LocationDB()
    machine = Machine(target_config.arch_context.arch_str)
    mdis = get_disasm_engine(executable, loc_db)
    ira = machine.ira(loc_db)

    # init stack
    sz = target_config.arch_context.address_size
    sp = target_config.preconditions[target_config.arch_context.sp].value
    logger.debug("Setting initial stack state")
    init_state = stack_to_se_state(stack, sp, sz)
    # init preconditions
    logger.debug("Setting initial preconditions")
    for _, constr in target_config.preconditions.items():
        init_state.update({ExprId(constr.reg, constr.size) : ExprInt(constr.value, constr.size)})

    # init SE engine
    sb = SymbolicExecutionEngine(ira, state=init_state)

    addr = target_config.preconditions['IRDst'].value
    dst_addr = target_config.postconditions["IRDst"].value
    logger.debug("Running SE")
    num_gadgets_executed = 0
    gadget_cache: Dict[int, AsmGadget] = {}
    has_syscall_dst = False
    while addr != dst_addr and num_gadgets_executed < MAX_GADGETS_IN_CHAIN:
        logger.debug(f"Symbolically executing {addr:#x} (round {num_gadgets_executed})")
        # we need to de-rebase the address before diassembly
        # TODO: libraries not supported -- right now rebasing assumes main exe only
        # we cache disassembled blocks to avoid entering the same loc_key multiple times
        gadget: Optional[AsmGadget] = gadget_cache.get(addr, None)
        if not gadget:
            gadget = disas_block(addr, mdis, target_config.load_address)
            if gadget is None:
                logger.error(f"Failed to disassemble {addr:#x}")
                return False
            debug_print(gadget.block)
            gadget_cache[addr] = gadget
        if func == "execve" and has_syscall_instruction(gadget):
            logger.info(f"Found syscall in gadget. Assuming this ({gadget.addr:x}) is last gadget in chain")
            has_syscall_dst = True
        ira_cfg = lift_block(ira, gadget)
        if ira_cfg is None:
            logger.error(f"Failed to verify chain")
            return False
        debug_print("IRCFG:")
        debug_print(ira_cfg.get_block(addr))

        debug_print("\nPRE--------")
        if DEBUG:
            sb.dump()
        debug_print("--------")

        # symbolically execute lifted block
        sb.run_block_at(ira_cfg, addr)

        irdst_sym = ExprId("IRDst", sz)
        pc_sym = ExprId(target_config.arch_context.pc, sz)
        # sanity check
        if not has_syscall_dst and sb.state.symbols[irdst_sym] != sb.state.symbols[pc_sym]:
            logger.error(f"Final IRDst != final RIP ({sb.state.symbols[irdst_sym]} != {sb.state.symbols[pc_sym]})")
            logger.error(f"Failed to verify chain")
            return False
        # update addr to point to next block
        # TODO: how to extract int value from ExprId
        if not isinstance(sb.state.symbols[irdst_sym], ExprInt):
            logger.error(f"IRDst is no concrete address but {sb.state.symbols[irdst_sym]}")
            logger.error(f"Failed to verify chain")
            return False
        debug_print("POST======")
        if DEBUG:
            sb.dump()
        debug_print("============")
        addr = int(sb.state.symbols[irdst_sym])
        num_gadgets_executed += 1
        debug_print("\n\n")

    logger.debug("Reached final block. Verifying postconditions")
    # once we've reached the final block, check postconditions
    for _, constr in target_config.postconditions.items():
        expect = ExprInt(constr.value, constr.size)
        try:
            find = sb.state.symbols[ExprId(constr.reg, constr.size)]
        except KeyError:
            # this implies, the solver relies on a register constrainted to 0  initially (without explicit precondition)
            logger.error(f"Gadget failed to set {constr.reg} (but is postconditioned)")
            logger.error(f"Failed to verify chain")
            return False
        # in case of execve, second and third paramemter can be 0 or ptr to 0
        # so if we have a value != 0, we need to check whether it points to 0
        if func == "execve" and int(expect) == 0x0 and (not isinstance(find, ExprInt) or int(find) != 0):
            logger.debug("Expected 0 found value != 0. Checking if is pointer to 0")
            find_pointee = sb.mem_read(ExprMem(find, target_config.arch_context.address_size))
            if find_pointee == expect:
                continue
            else:
                logger.error(f"Postcondition {constr} does not hold - expected {expect} found {find}, which points to {find_pointee}")
        elif expect != find:
            logger.error(f"Postcondition {constr} does not hold - expected {expect} found {find}")
            logger.error(f"Failed to verify chain")
            return False
    if target_config.ptr_postconditions:
        logger.debug("Verifying pointer postconditions")
        for ptr_constr in target_config.ptr_postconditions:
            # TODO: the following assumes we always read 8 bytes of memory; in theory, the string may have arbitrary length
            # such that we either need to check it byte-wise or chunk it
            expect = ExprInt(int.from_bytes(ptr_constr.ref_bytes, byteorder='little'), ptr_constr.size * 8)
            try:
                # TODO: this should not assume the address_size in bytes of the architecture
                # but ptr_postconditions should store the REG's size as well (right now, size == number of bytes in ptr_postcondition)
                addr = sb.state.symbols[ExprId(ptr_constr.reg, sz)]
            except KeyError:
                # this implies, the solver relies on a register constrainted to 0  initially (without explicit precondition)
                logger.error(f"Gadget failed to set {ptr_constr.reg} (but is ptr-postconditioned)")
                logger.error(f"Failed to verify chain")
                return False
            try:
                # convert addr to ExprMem (size is given in bits; i.e., number of bytes in string * 8)
                find = sb.mem_read(ExprMem(addr, ptr_constr.size * 8))
            except KeyError:
                # this implies, the solver relies on a register constrainted to 0  initially (without explicit precondition)
                logger.error(f"Gadget failed to write to address described by {ptr_constr.reg} (but is postconditioned)")
                logger.error(f"Failed to verify chain")
                return False
            # assert find == expect, f"Postcondition {constr} does not hold - expected {expect} found {find}"
            if expect != find:
                if int(expect) == 0x68732F6E69622F:
                    # try common variations, such as //bin/sh and /bin//sh
                    if isinstance(find, ExprInt) and (int(find) == 0x68732F6E69622F2F or int(find) == 0x68732F2F6E69622F):
                        logger.debug(f"Checking variations //bin/sh and /bin//sh")
                        # it is //bin/sh or /bin//sh
                        # now we only need to check the trailing nullbyte
                        succ_addr = ExprInt(int(addr) + sz // 8, sz)
                        try:
                            nullbyte = sb.mem_read(ExprMem(succ_addr, sz))
                            if isinstance(nullbyte, ExprInt) and int(nullbyte) == 0x0:
                                logger.debug("Benign variation with nullbyte")
                                # benign variation that is nullterminated
                                continue
                            else:
                                logger.error(f"Pointer-Postcondition {ptr_constr.reg} does not hold - expected {expect} (or variation) @ {addr} but found {find} without nullbyte")
                                logger.error(f"Failed to verify chain")
                                return False
                        except KeyError:
                            pass
                logger.error(f"Pointer-Postcondition {ptr_constr.reg} does not hold - expected {expect} @ {addr} but found {find}")
                logger.error(f"Failed to verify chain")
                return False
    logger.info("Symbolic Execution verified chain successfully")
    return True


def stack_str_to_stack_dict(stack_str: str, stack_pointer: int, address_size: int) -> Dict[int, int]:
    stack_str = stack_str.strip()
    assert stack_str.startswith("[") and stack_str.endswith("]"), "Expected leading '[' and final ']'"
    stack_str = stack_str.lstrip("[").rstrip("]")
    stack: Dict[int, int] = {}
    vals = stack_str.split(",")
    for val in vals:
        stack[stack_pointer] += to_int(val.strip())
        stack_pointer += (address_size // 8)
    return stack


def assert_has_valid_config(path: Path, func: str) -> None:
    assert path.is_dir(), f"{path} not a directory"
    assert (path / f"config_{func}.json").is_file(), f'{path / f"config_{func}.json"} does not exist or not a file'


def assert_is_valid_function(target: str) -> None:
    assert target in ("execve", "mprotect", "mmap"), \
        f'"{target}" is not a valid target. Must be one of ("execve", "mprotect", "mmap")'


def assert_is_valid_tool(tool: str) -> None:
    assert tool in ("tool", "ropgadget", "ropper", "angrop", "ropium", "pshape"), \
        f'"{tool}" is not a valid tool. Must be one of ("tool", "ropgadget", "ropper", "angrop", "ropium", "pshape")'


def create_gdb_commands_file(file_: Path, config: Path, stack_str: str) -> None:
    with open(file_, 'w') as f:
        f.write("source gdb_script_verify_chain.py\n")
        f.write(f"verify_chain {config.as_posix()} {stack_str}\n")


def parse_gdb_output(stdout: str) -> None:
    lines = [l.strip() for l in stdout.split("\n") if l.strip()]
    info = list(filter(lambda l: l.startswith("INFO:"), lines))
    for i in info:
        logger.info(i.replace("INFO:", "GDB:"))


def simplify_path(p: Path) -> Path:
    ps = p.as_posix()
    psl = [e for e in ps.split("/") if e.strip()]
    ignore = 0
    poutl = []
    for e in psl[::-1]:
        if e == "..":
            ignore += 1
        else:
            if ignore:
                ignore -= 1
            else:
                poutl += [e]
    return Path("/" + "/".join(poutl[::-1]))


def main(config_path: Path, stackfile: Path, tool: str, target: str, func: str) -> None:
    target_config = TargetConfig(config_path)
    path = config_path.parent
    start_time = time.time()
    logger.debug(f"tool={tool}, func={func}, target={target}")
    # sanity checks
    assert path.name == target, f"Path gives target {path.name}, but stackfile is associated with {target}"
    config_path_func_name = config_path.name.rstrip(".json").split("_")[1]
    assert config_path_func_name == func, f"Config gives target {config_path_func_name}, but stackfile is associated with {func}"
    assert stackfile.is_file() and stackfile.name == "stack.txt", f"File not found or wrong name (found {stackfile.name}, expected stack.txt)"
    assert_is_valid_function(func)
    assert_is_valid_tool(tool)
    assert_has_valid_config(path, func)
    # load config
    executable = (path / target_config.executable).absolute()
    executable = simplify_path(executable)
    assert executable.is_file(), f"{executable} not a file or not found"

    with open(stackfile, 'r') as f:
        stack_str = f.read().strip()
    # stack = stack_str_to_stack_dict(stack_str, target_config.preconditions[target_config.arch_context.sp].value, target_config.arch_context.address_size)
    stack = [to_int(v.strip()) for v in stack_str.lstrip("[").rstrip("]").split(",")]
    # run SE
    # TODO: our SE currently is not adapted to do this - we need an SE working only with stack values?
    run_symbolic_execution(stack, executable, target_config, func)
   
    logger.info(f"Done in {round(time.time() - start_time, 2)}s")



if __name__ == "__main__":
    parser = ArgumentParser(description="Given a target's config and a chain, use GDB to insert the chain and verify that we indeed arrive at the desired outcome")
    parser.add_argument("path", type=Path, help="Path to target config")
    parser.add_argument("stackfile", type=Path, help="Path to stack.txt file which contains the chain to be dropped on the stack")
    parser.add_argument("tool", type=str, help="Tool name")
    parser.add_argument("target", type=str, help="Target name")
    parser.add_argument("func", type=str, help="Function name")
    args = parser.parse_args()
    logfile = "log_verify_se.log"
    setup_logging(logger, Path("."), logfile)
    main(args.path.resolve(), args.stackfile.resolve(), args.tool, args.target, args.func)
    shutil.copy(logfile, args.stackfile.parent / logfile)
