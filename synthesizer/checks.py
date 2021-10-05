"""
Sanity checks to avoid a scenario where a postconditioned register is not 
touched by any gadget (thus the subset cannot fulfill our constraints).
"""
import logging
from typing import List, Set
from .types_ import GadgetIRTy

logger = logging.getLogger("synthesizer.checks")


def get_dst_regs(ira_gadgets: List[GadgetIRTy]) -> Set[str]:
    regs: Set[str] = set()
    for (_, ira_block) in ira_gadgets:
        for assignblock in ira_block:
            for key in assignblock:
                if key.is_id():
                    name = key.name
                    if "." in name:
                        name = name.split(".")[0]
                    regs.add(name)
    return regs


def postcondition_regs_exist(postcondition_regs: List[str], ira_gadgets: List[GadgetIRTy]) -> bool:
    """Check if postconditioned registers are written to from at least one gadget"""
    dst_regs = get_dst_regs(ira_gadgets)
    for reg in postcondition_regs:
        if reg not in dst_regs:
            logger.warning(f"Register {reg} is never assigned a value within selected gadgets")
            return False
    return True
