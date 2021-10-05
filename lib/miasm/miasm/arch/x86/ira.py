#-*- coding:utf-8 -*-

from miasm.expression.expression import ExprAssign, ExprOp, ExprInt, ExprMem, ExprLoc
from miasm.expression.simplifications import expr_simp
from miasm.ir.ir import AssignBlock
from miasm.ir.analysis import ira
from miasm.arch.x86.sem import ir_x86_16, ir_x86_32, ir_x86_64
from miasm.arch.x86.regs import mRIP


class ir_a_x86_16(ir_x86_16, ira):

    def __init__(self, loc_db):
        ir_x86_16.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.AX

    def get_out_regs(self, _):
        return set([self.ret_reg, self.sp])

class ir_a_x86_32(ir_x86_32, ir_a_x86_16):

    def __init__(self, loc_db):
        ir_x86_32.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.EAX

    def sizeof_char(self):
        return 8

    def sizeof_short(self):
        return 16

    def sizeof_int(self):
        return 32

    def sizeof_long(self):
        return 32

    def sizeof_pointer(self):
        return 32


class ir_a_x86_64(ir_x86_64, ir_a_x86_16):

    def __init__(self, loc_db):
        ir_x86_64.__init__(self, loc_db)
        self.ret_reg = self.arch.regs.RAX

    #def call_effects(self, ad, instr):
    #    call_assignblk = AssignBlock(
    #        [
    #            ExprAssign(
    #                self.ret_reg,
    #                ExprOp(
    #                    'call_func_ret',
    #                    ad,
    #                    self.sp,
    #                    self.arch.regs.RCX,
    #                    self.arch.regs.RDX,
    #                    self.arch.regs.R8,
    #                    self.arch.regs.R9,
    #                )
    #            ),
    #            ExprAssign(self.sp, ExprOp('call_func_stack', ad, self.sp)),
    #        ],
    #        instr
    #    )
    #    return [call_assignblk], []

    def call_effects(self, addr, instr):
        """Custom hack to handle function calls"""
        from miasm.arch.x86.sem import call
        # call semantics
        instr_ir, [] = call(self, instr, addr)
        # fix pc relative offsets
        pc_fixed = {self.pc: ExprInt(instr.offset + instr.l, 64)}
        for i, expr in enumerate(instr_ir):
            dst, src = expr.dst, expr.src
            if dst != self.pc:
                dst = dst.replace_expr(pc_fixed)
            src = src.replace_expr(pc_fixed)
            instr_ir[i] = expr_simp(ExprAssign(dst, src))

        return [AssignBlock(instr_ir, instr)], []

    def sizeof_char(self):
        return 8

    def sizeof_short(self):
        return 16

    def sizeof_int(self):
        return 32

    def sizeof_long(self):
        return 64

    def sizeof_pointer(self):
        return 64
