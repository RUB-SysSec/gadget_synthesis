"""
Helper functions to create human-readable output files for the synthesized 
gadget chain.
"""
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterator, List
import logging
import time

from miasm.core.locationdb import LocationDB

from smt_solvers import SMTModel
from synthesizer.arch import ArchContext
from synthesizer.config import SynthesizerConfig, TargetConfig
from synthesizer.types_ import AsmGadget, GadgetIRTy
from synthesizer.utils import min_or_some
from synthesizer.smt import round_var_name

logger = logging.getLogger('synthesizer.helper')


def create_lookup_table(gadgets: List[AsmGadget], iras: List[GadgetIRTy],
                        loc_db: LocationDB,
                        workdir: Path, dump: bool) -> Dict[int, str]:
    """Create lookup table needed to dump some statistics"""
    gadget_table = {}
    for g in gadgets:
        asmblock = g.block
        addr = loc_db.get_location_offset(asmblock.loc_key)
        for offset in asmblock.get_offsets():
            gadget_table[offset] = asmblock.to_string_from(offset)

    if dump:
        start = time.time()
        gadgets_txt = workdir / "gadgets.txt"
        with open(gadgets_txt, "w") as f:
            for addr, ira in iras:
                f.write(f"{addr}:\n")
                f.write(gadget_table.get(addr, "no asm"))
                f.write("\n---\n")
                f.write(str(ira))
                f.write("\n\n")
        logger.debug(f"{gadgets_txt.name} written in {round(time.time() - start, 2)}s")
    return gadget_table


def print_model(model: SMTModel, synthesizer_config: SynthesizerConfig,
                target_config: TargetConfig, workdir: Path) -> None:
    stack_dict: Dict[int, int] = {}
    arch_context = target_config.arch_context
    logger.info("Dumping model to stdout")
    print("Model:")
    if True:
        word_size = int((arch_context.address_size/8))
        for i in range(synthesizer_config.iterations + 1):
            for reg in arch_context.report_vars:
                val = model[round_var_name(reg, i)]
                assert isinstance(val, int)
                print(f"    {reg}_{i}: {val}")

        for var, value in model.model.items():
            if (not(var.startswith("stack_byte")) and var.startswith("stack")):
                addr = int(var[5:])
                byte_offset = addr & (word_size - 1)
                addr &= ~(word_size - 1)
                stack_dict[addr] = (stack_dict.get(addr, 0)
                                    | value << byte_offset * 8)

        # initial stack pointer value:
        sp_init = int(model[round_var_name(arch_context.sp, 0)])
        stack_words = min_or_some(synthesizer_config.max_stack_words, target_config.stack_words)
        stack = [stack_dict[sp_init + word_size*i]
                 for i
                 in range(0, stack_words)]
        print("Stack:", stack)

    model_txt = workdir / "model.txt"
    with open(model_txt, "w") as f:
        f.write(str(model))
    logger.debug(f"{model_txt.name} written")


def extract_initial_stack_assignment(model: SMTModel, address_size: int) -> Dict[int, int]:
    stack: Dict[int, int] = OrderedDict()
    word_size = int((address_size//8))
    for var, value in model.model.items():
        if var.startswith("stack"):
            addr = int(var[5:])
            byte_offset = addr & (word_size - 1)
            addr &= ~(word_size - 1)
            stack[addr] = (stack.get(addr, 0) | value << byte_offset * 8)
    return stack


def extract_gadget_chain(model: SMTModel, iterations: int) -> Iterator[int]:
    """Extract gadget chain in form of gadget addresses executed consecutively"""
    for iteration in range(iterations + 1):
        reg_name = f"IRDst_{iteration}"
        val = int(str(model[reg_name]), 10)
        yield val


def dump_stacktxt(stack: List[int], workdir: Path) -> None:
    s = "[" + ", ".join(map(lambda v: f"{v:#x}", stack)) + "]"
    with open(workdir / "stack.txt", "w") as f:
        f.write(s + "\n")


def dump_report(model: SMTModel, arch_context: ArchContext, iterations: int,
                loc_db: LocationDB, gadgets: List[AsmGadget],
                iras: List[GadgetIRTy], workdir: Path, verbose: bool) -> None:
    """Creates report.txt and stack.txt"""
    stack_dict: Dict[int, int] = {}
    # predefined stack bytes:
    stack_bytes_dict: Dict[int, int] = {}
    word_size = int((arch_context.address_size//8))
    for var, value in model.model.items():
        if var.startswith("stack_byte"):
            addr = int(var[10:])
            stack_bytes_dict[addr] = value
        elif var.startswith("stack"):
            addr = int(var[5:])
            byte_offset = addr & (word_size - 1)
            addr &= ~(word_size - 1)
            stack_dict[addr] = (stack_dict.get(addr, 0) | value << byte_offset * 8)
    stack = sorted(stack_dict.items())
    stack_bytes = sorted(stack_bytes_dict.items())

    for i, (addr, _) in enumerate(stack[:-1]):
        next_addr, _ = stack[i+1]
        assert addr + word_size == next_addr, "Stack hole"

    # create stack.txt used by many evaluation scripts
    dump_stacktxt([val for (_, val) in stack], workdir)

    gadget_table = create_lookup_table(gadgets, iras, loc_db, workdir, verbose)

    report_txt = workdir / "report.txt"
    with open(report_txt, "w") as f:
        for i in range(iterations + 1):
            f.write("=" * 10 + " ")
            if i == 0:
                f.write("Initial values")
            elif i < iterations:
                f.write(f"After round {i}")
            else:
                f.write(f"Final values (after round {iterations})")
            f.write(" " + "=" * 10 + "\n")

            if i == 0:
                for addr, value in stack:
                    f.write("stack[0x{:0{pad}X}] = 0x{:0{pad}X}\n".format(
                                addr, value, pad=2*word_size))

                for addr, value in stack_bytes:
                    f.write("stack_bytes[0x0{:{pad}X}] = 0x{:0{pad}X}"
                            " '{:c}'\n".format(value, value, value, pad=2*word_size))

            for reg in arch_context.report_vars + ["IRDst"]:
                # build name:
                reg_name = str(round_var_name(reg, i))
                # get the value in the model:
                val = int(str(model[reg_name]), 10)
                f.write(f"{reg}_{i}: {val:#x}\n")

            if i != iterations:
                f.write("=" * 50 + "\n")
                rip = model[str(round_var_name("IRDst", i))]
                f.write(f"{rip:#x}:\n")
                gadget = str(gadget_table.get(rip, "no gadget"))
                f.write(gadget + "\n")
    logger.debug(f"{report_txt.name} written")
    stack_bin = workdir / "stack.bin"
    with open(stack_bin, "wb") as stack_file:
        for _, value in stack:
            for j in range(0, 64, 8):
                stack_file.write(bytes([value >> j & 0xff]))
    logger.debug(f"{stack_bin.name} written")
