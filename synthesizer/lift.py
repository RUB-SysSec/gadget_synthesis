"""Functions to lift assembly to IR representation"""

from typing import Iterator, List, Optional, Tuple
import logging
import itertools

from miasm.analysis.machine import Machine
from miasm.analysis.ssa import SSABlock

from miasm.expression.simplifications import expr_simp_high_to_explicit
from miasm.expression.simplifications_stateful_memory import rewrite_memory
from miasm.ir.ir import IRBlock

from miasm.core.locationdb import LocationDB
from miasm.core.asmblock import AsmBlock

from .arch import ArchContext
from .types_ import AsmGadget, GadgetIRTy


logger = logging.getLogger("synthesizer.lift")


def asm_to_ira(arch_context: ArchContext, asm_block: AsmBlock, loc_db: LocationDB, offset_generator: Iterator[int], debug: bool = False) -> Optional[List[GadgetIRTy]]:
    machine = Machine(arch_context.arch_str)
    ira = machine.ira(loc_db)

    # IRA cfg
    try:
        ira_cfg = ira.new_ircfg()
        ira.add_asmblock_to_ircfg(asm_block, ira_cfg)
    except (NotImplementedError, ValueError) as e:
        logger.error("asm_to_ira: Failed to create IR CFG - skipping block: " + str(e))
        return None

    if debug:
        print("ira_cfg (%s):" % type(ira_cfg))
        print(ira_cfg.blocks)
        print("-" * 40)

    # make flags explicit
    ira_cfg.simplify(expr_simp_high_to_explicit)

    try:
        # rewrite memory expressions
        ira_cfg.simplify(rewrite_memory, rewrite_mem=True)
    except ValueError as e:
        logger.warning(f"Skipping block (bug in miasm memory rewriter: {str(e)})")
        return None

    result = []

    for loc_key, block in ira_cfg.blocks.items():
        ssa = SSABlock(ira_cfg)
        ssa.transform(loc_key)

    for loc_key, block in ira_cfg.blocks.items():
        assert isinstance(loc_key.key, int)
        offset = loc_db.get_location_offset(loc_key)
        # for IR blocks (that do not exist in Assembly), offset may be None
        # this means, there is no actual address; we use a generator to
        # associate a 'random' adress with the IRBlock
        if offset is None:
            offset = next(offset_generator)
            loc_db.set_location_offset(loc_key, offset)
        result.append((offset, block))

    for k in loc_db.loc_keys:
        if loc_db.get_location_offset(k) is None:
            logger.warning(f"loc_db has key {k} without location offset")
            loc_db.set_location_offset(k, next(offset_generator))

    return result


def lift_all_gadgets(gadgets: List[AsmGadget], loc_db: LocationDB, arch_context: ArchContext) -> List[GadgetIRTy]:
    offset_generator = itertools.count(start=100000000, step=1)
    iras_all: List[Tuple[int, Optional[List[IRBlock]]]] = [(g.addr, asm_to_ira(arch_context, g.block, loc_db, offset_generator))
                for g in gadgets]
    failed = [addr for (addr, irb) in iras_all if irb is None]
    if failed:
        logger.warning(f"Failed to lift {len(failed)} gadgets. Discarding these gadgets..")
    iras_nested = [iras for (_, iras) in iras_all if iras is not None]
    # flatten iras
    iras: List[Tuple[int, IRBlock]] = [ira for iras in iras_nested for ira in iras]
    return iras
