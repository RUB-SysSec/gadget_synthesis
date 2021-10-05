"""
Architecture-dependent stuff such as address size or known registers. 
Current prototype is limited to x86(-64).
"""

from typing import List
import logging

from miasm.arch.x86 import regs as x86_regs

logger = logging.getLogger("synthesizer.arch")


class ArchContext(object):
    """Class which contains all architecture-dependent context"""

    def __init__(self, arch_str: str, known_vars: List[str], special_vars: List[str], selectors: List[str], address_size: int, pc: str, sp: str, report_vars: List[str]) -> None:
        self.arch_str = arch_str
        self.known_vars = ["IRDst"] + known_vars
        self.special_vars = special_vars
        self.address_size = address_size
        self.selectors = selectors
        self.pc = pc 
        self.sp = sp 
        self.report_vars = report_vars

    def reg_size(self, reg: str) -> int:
        raise NotImplementedError("Not implemented, subclass needed!")


class X86_64Context(ArchContext):
    """x86_64"""

    def __init__(self) -> None:
        known_vars = x86_regs.regs64_str + [
            x86_regs.reg_zf,
            x86_regs.reg_nf,
            x86_regs.reg_pf,
            x86_regs.reg_of,
            x86_regs.reg_cf,
            x86_regs.reg_af,
            x86_regs.reg_df
        ]
        # below are used for variable renaming (i.e. ssa)
        special_vars = x86_regs.selectr_str + \
                    x86_regs.regs_mm_str + x86_regs.regs_xmm_str + [
                    "exception_flags",
                    "interrupt_num",
                    "float_",
                    "reg_float_",
                    x86_regs.reg_tf,
                    x86_regs.reg_if,
                    x86_regs.reg_iopl,
                    x86_regs.reg_nt,
                    x86_regs.reg_rf,
                    x86_regs.reg_vm,
                    x86_regs.reg_ac,
                    x86_regs.reg_vif,
                    x86_regs.reg_vip,
                    x86_regs.reg_id
                    ]
        # variables printed in the visualization of gadget chain
        report_vars = x86_regs.regs64_str + [x86_regs.reg_cf]
        super().__init__("x86_64", known_vars, special_vars, \
                            x86_regs.selectr_str, 64, 'RIP', \
                            'RSP', report_vars)

    def reg_size(self, reg: str) -> int:
        if reg in x86_regs.regs64_str or reg == "IRDst":
            return 64
        if reg in (
                x86_regs.reg_zf,
                x86_regs.reg_nf,
                x86_regs.reg_pf,
                x86_regs.reg_of,
                x86_regs.reg_cf,
                x86_regs.reg_af,
                x86_regs.reg_df,
                x86_regs.reg_if,
                x86_regs.reg_df,
                x86_regs.reg_af,
                x86_regs.reg_iopl,
                x86_regs.reg_nt,
                x86_regs.reg_rf,
                x86_regs.reg_vm,
                x86_regs.reg_ac,
                x86_regs.reg_vif,
                x86_regs.reg_vip,
                x86_regs.reg_id):
            return 1
        if reg == "M":
            return 64
        if reg in x86_regs.regs08_str:
            return 32
        if reg in x86_regs.regs16_str:
            return 16
        if reg in x86_regs.regs32_str:
            return 32
        if reg.startswith("exception_flags"):
            return 32
        if reg.startswith("interrupt_num"):
            return 8
        if reg.startswith("XMM"):
            return 128
        if reg.startswith("MM"):
            return 64
        if reg.startswith("BND"):
            return 128
        logger.critical(f"X86_64Context failed to determine size for reg {reg}")
        raise RuntimeError(f"Could not determine size of {reg}")


class X86_32Context(ArchContext):
    """x86_32"""

    def __init__(self) -> None:
        known_vars = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"] + [
            x86_regs.reg_zf,
            x86_regs.reg_nf,
            x86_regs.reg_pf,
            x86_regs.reg_of,
            x86_regs.reg_cf,
            x86_regs.reg_af,
            x86_regs.reg_df,
        ]
        # below are used for variable renaming (i.e. ssa)
        special_vars = x86_regs.selectr_str + \
                    x86_regs.regs_mm_str + x86_regs.regs_xmm_str + [
                    "exception_flags",
                    "interrupt_num",
                    "float_",
                    "reg_float_",
                    x86_regs.reg_tf,
                    x86_regs.reg_if,
                    x86_regs.reg_iopl,
                    x86_regs.reg_nt,
                    x86_regs.reg_rf,
                    x86_regs.reg_vm,
                    x86_regs.reg_ac,
                    x86_regs.reg_vif,
                    x86_regs.reg_vip,
                    x86_regs.reg_id
                    ]
        # variables printed in the visualization of gadget chain
        report_vars =["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"] + [x86_regs.reg_cf]
        super().__init__("x86_32", known_vars, special_vars, \
                            x86_regs.selectr_str, 32, 'EIP', 'ESP', 
                            report_vars)

    def reg_size(self, reg: str) -> int:
        if reg in x86_regs.regs32_str or reg == "IRDst":
            return 32
        if reg in (
                x86_regs.reg_zf,
                x86_regs.reg_nf,
                x86_regs.reg_pf,
                x86_regs.reg_of,
                x86_regs.reg_cf,
                x86_regs.reg_af,
                x86_regs.reg_df,
                x86_regs.reg_if,
                x86_regs.reg_df,
                x86_regs.reg_af,
                x86_regs.reg_iopl,
                x86_regs.reg_nt,
                x86_regs.reg_rf,
                x86_regs.reg_vm,
                x86_regs.reg_ac,
                x86_regs.reg_vif,
                x86_regs.reg_vip,
                x86_regs.reg_id):
            return 1
        if reg == "M":
            return 32
        if reg in x86_regs.regs08_str:
            return 32
        if reg in x86_regs.regs16_str:
            return 16
        if reg in x86_regs.regs32_str:
            return 32
        if reg.startswith("exception_flags"):
            return 32
        if reg.startswith("interrupt_num"):
            return 8
        if reg.startswith("XMM"):
            return 128
        if reg.startswith("MM"):
            return 32
        if reg.startswith("BND"):
            return 128
        logger.critical(f"X86_32Context failed to determine size for reg {reg}")
        raise RuntimeError(f"Could not determine size of {reg}")
