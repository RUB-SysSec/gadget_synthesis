"""
Code to encode the IR gadgets, pre/post-conditions into a formula
"""
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path
import logging
import os
import shutil

from miasm.expression.expression import ExprId
from miasm.expression.smt2_helper import *
from miasm.ir.translators.smt2 import TranslatorSMT2
from miasm.ir.ir import AssignBlock, IRBlock
from miasm.core.locationdb import LocationDB

from miasm.expression.smt2_helper import array_select, array_store, bvadd, bit_vec, bit_vec_val, declare_array, declare_bv, \
    smt2_assert, smt2_eq, smt2_distinct, smt2_and, smt2_or, smt2_ite
from miasm.expression.smt2_helper import *

from .arch import ArchContext
from .utils import min_or_some
from .config import TargetConfig, SynthesizerConfig
from .types_ import GadgetIRTy


logger = logging.getLogger("synthesizer.smt")
MEM_NAME = "M"


TMP_PATH_SMT = Path("/tmp/gadget_synthesis/debug/smt_expressions/")
# TODO: DEBUG cannot be used with multithreading
DEBUG = False


def dump_file(name: str, expr: str, mode: str = "a") -> None:
    with open(TMP_PATH_SMT / name, mode) as f:
        f.write(expr + "\n")


def round_var_name(reg: str, iteration: int) -> str:
    return f"{reg}_{iteration}"


def input_var_name(reg: str, address: int, iteration: int) -> str:
    return "%s.%016x_%d.IN" % (reg, address, iteration)


def ssa_var_name(reg: str, address: int, iteration: int, ssa_id: str) -> str:
    return "%s.%016x_%d.%s" % (reg, address, iteration, ssa_id)

class SMTFormula():
    """SMT formula class, builds up the smt formula."""

    def __init__(self, arch_context: ArchContext, stack_words: int):
        # keep track of variables (mem, bitvectors, ...) by
        # bv mapping: bitvector_name -> size
        # mem directly tracked via declaration (i.e. set of smt declarations)
        self._mem: Set[str] = set()
        self._bitvectors: Dict[str, int] = dict()
        # Assertions:
        self._expr: Set[str] = set()
        self.arch_context = arch_context
        self.stack_words = stack_words

    def num_expr(self) -> int:
        """Returns amount of assertions/expressions in current formula"""
        return len(self._expr)

    def _gen_mem_var(self, name: str, addr_size: Optional[int] = None,
                     size: Optional[int] = 8) -> str:
        if addr_size is None:
            addr_size = self.arch_context.address_size
        self._mem.add(declare_array(name, bit_vec(addr_size), bit_vec(size)))
        return name

    def _gen_var(self, reg: str, name: str, size: Optional[int] = None) -> str:
        if reg.startswith(MEM_NAME) and not reg.startswith(
                                            tuple(self.arch_context.special_vars
                                                          )):
            return self._gen_mem_var(name)
        elif reg not in self._bitvectors.keys():
            if size is None:
                size = self.arch_context.reg_size(reg)
            self._bitvectors[name] = size
        return name

    def gen_round_var(self, reg: str, iteration: int) -> str:
        name = round_var_name(reg, iteration)
        return self._gen_var(reg, name)

    def gen_input_var(self, reg: str, address: int, iteration: int) -> str:
        name = input_var_name(reg, address, iteration)
        return self._gen_var(reg, name)

    def gen_output_var(self, reg: str, address: int, iteration: int) -> str:
        name = "%s.%016x_%d.OUT" % (reg, address, iteration)
        return self._gen_var(reg, name)

    def gen_irdst_var(self, iteration: int) -> str:
        name = "IRDst_%d" % iteration
        # -> not necessarily known reg... just use name as reg
        return self._gen_var(name, name, size=self.arch_context.address_size)

    def gen_stack_var(self, offset: int, size: int) -> str:
        name = f"stack{offset}"
        return self._gen_var(name, name, size=size)

    def gen_stack_byte_var(self, offset: int, size: int) -> str:
        """ TODO refactor naming """
        name = f"stack_byte{offset}"
        return self._gen_var(name, name, size=size)

    def gen_mem_var(self, name: str, addr_size: Optional[int] = None,
                    size: int = 8) -> str:
        assert name.startswith(MEM_NAME)
        return self._gen_mem_var(name, addr_size, size)

    def gen_final_out_var(self, reg: str) -> str:
        name = reg + "_OUT"
        return self._gen_var(reg, name)

    def add_var(self, reg: str, name: str, size: int) -> str:
        # adds variables to tracking (e.g. retrieved from translator)
        return self._gen_var(reg, name, size)

    def add_memory_var(self, smt_mem: str) -> None:
        self._mem.add(smt_mem)

    def add_expr(self, smt_expr: str) -> None:
        # adds an smt expr:
        if smt_expr is None:
            raise ValueError("Tried to add None expression")
        self._expr.add(smt_expr)

    def get_formula(self) -> str:
        # Get var declarations:
        ret = ""
        # ret += "(set-logic {})\n".format(logic)

        # define bit vectors
        for bv in self._bitvectors:
            size = self._bitvectors[bv]
            ret += "{}\n".format(declare_bv(bv, size))

        for mem in self._mem:
            ret += "{}\n".format(mem)

        if DEBUG:
            dump_file("definitions", ret)

        for expr in self._expr:
            if expr is None:
                logger.debug("Tried to add None expression")
                continue
            ret += "{}\n".format(expr)

        return ret


def smt2_assert_eq(a: str, b: str) -> str:
    return smt2_assert(smt2_eq(a, b)) # type: ignore


def smt2_assert_eq_bvv(a: str, val: int, size: int) -> str:
    return smt2_assert(smt2_eq(a, bit_vec_val(val, size))) # type: ignore


def smt2_eq_bvv(a: str, val: int, size: int) -> str:
    return (smt2_eq(a, bit_vec_val(val, size))) # type: ignore


def smt2_distinct_bvvs(a: str, vals: List[int], size: int) -> str:
    smt: str = (smt2_distinct(a, *[bit_vec_val(v, size) for v in vals]))
    return smt


def smt2_const_array(address_size: int, const_val: int, size: int = 8) -> str:
    # generates a constant array expression
    assert(const_val < 2**size)
    address_size = bit_vec(address_size)
    const_val = bit_vec_val(const_val, size)
    size = bit_vec(size)
    return f"((as const (Array {address_size} {size})) {const_val})"


def restrict_access(smt_formula: SMTFormula, addr: int, addr_size: int,
                    mem_areas: List[Tuple[int, int]], iteration: int,
                    block_addr: int) -> str:
    addr_expr = []

    for (lower, upper) in mem_areas:
        # addr >= lower:
        low = "(bvuge {} {})".format(addr, bit_vec_val(lower, addr_size))
        # addr < upper:
        # addr is an already defined bitvector/bitvecval
        up = "(bvult {} {})".format(addr, bit_vec_val(upper - (addr_size // 8), addr_size))
        addr_expr += [smt2_and(" ".join(x for x in [low, up]))]
    # the address needs to fall into one of the valid memory areas:
    assert(addr_expr)
    if len(addr_expr) > 1:
        restriction = smt2_or(" ".join(x for x in addr_expr))
    else:
        restriction = addr_expr[0]

    # Restrictions only need to hold for those gadgets which happen
    # to get executed
    irdst = smt_formula.gen_round_var("IRDst", iteration)
    # if IRDst in current round lands at current gadget -> restrict access
    ite = smt2_ite(smt2_eq(irdst, bit_vec_val(
            block_addr, smt_formula.arch_context.address_size)),
            restriction, "true")
    expr: str = smt2_assert(ite)
    return expr


def encode_smt(smt_formula: SMTFormula, arch_context: ArchContext,
               ira_block: IRBlock, loc_db: LocationDB,
               restrict_mem: bool = False, read_mem_areas: List[Tuple[int, int]] = [],
               write_mem_areas: List[Tuple[int, int]] = [], iteration: int = 0, block_addr: int = 0,
               add_vars: bool = False, debug: bool = False
               ) -> Optional[List[str]]:

    translator = TranslatorSMT2(
        loc_db=loc_db, stateful_mem=True, restrict_mem=restrict_mem,
        read_mem_areas=read_mem_areas, write_mem_areas=write_mem_areas,
        mem_size=arch_context.address_size)

    if debug:
        print("SMT2 expressions (%d):" % len(ira_block))

        print("----------------")
        print(type(ira_block))
        print("loc_key:", ira_block.loc_key)
        print(ira_block)
        print("----------------")

    expressions = []

    try:
        # translate all IR expressions
        for assignblock in ira_block:
            for expr in assignblock:
                expr_smt2 = translator.from_expr(
                    assignblock.dst2ExprAssign(expr))
                expressions.append(expr_smt2)
    except NotImplementedError as e:
        if debug:
            logger.warning("Ignoring block due to not implemented OP:", e)
        return None

    if add_vars:
        # add variables used in translator to the smt_formula object
        # TODO: accessing private vars of translator here
        # for size in translator._mem.mems:
        #   mem = translator._mem.mems[size]
        #   smt_formula.gen_mem_var(mem, size, 8)
        # Stateful memory only:
        for arr in translator._mem.mems:
            smt_formula.add_memory_var(arr)
        for bv in translator._bitvectors:
            size = translator._bitvectors[bv]
            if "." in bv:
                reg = bv.split(".")[0]
            else:
                reg = bv
            smt_formula.add_var(reg, bv, size)

    if translator.restrict_mem:
        # build restrictions of addresses used for memory read/writes:
        for addr in translator.read_addrs:
            if addr in arch_context.known_vars:
                # raise ValueError("Not an SSA variable")
                if DEBUG:
                    logger.warning("Encountered restriction for non-SSA var {}. "
                          "Skipping...".format(addr))
                continue
            # TODO: currently we assume: addr writable => addr readable
            read_restrictions = restrict_access(
                smt_formula, addr, translator._mem.addr_size,
                translator.read_mem_areas + translator.write_mem_areas,
                iteration, block_addr)
            assert(isinstance(read_restrictions, str))
            if read_restrictions:
                expressions.append(read_restrictions)

        for addr in translator.write_addrs:
            if addr in arch_context.known_vars:
                # raise ValueError("Not an SSA variable")
                logger.warning("Encountered restriction for {}. "
                      "Skipping...".format(addr))
                continue
            write_restrictions = restrict_access(
                smt_formula, addr, translator._mem.addr_size,
                translator.write_mem_areas, iteration, block_addr)
            assert(isinstance(write_restrictions, str))
            if write_restrictions:
                expressions.append(write_restrictions)

    return expressions


def rename_variable(arch_context: ArchContext, name: str, address: int,
                    iteration: int) -> str:
    if name == "IRDst":
        return "IRDst.%016x_%d" % (address, iteration)
    # check for ESP manually --> ES segment results in buggy behaviour
    if (name.startswith(tuple(arch_context.special_vars))
       and not name.startswith("ESP")):
        return "%s.%016x_%d" % (name, address, iteration)
    if "." in name:
        reg, ssa_id = name.split(".")
        if reg in arch_context.selectors:
            return "%s.%s.%016x_%d" % (name, ssa_id, address, iteration)
        return ssa_var_name(reg, address, iteration, ssa_id)
    return input_var_name(name, address, iteration)


def rename_variables(arch_context: ArchContext, ira_block: IRBlock,
                     address: int, iteration: int, debug: bool = False
                     ) -> IRBlock:
    if debug:
        print("start simplify")

    def simplifier(obj: Any, debug: bool = False) -> Any:
        if debug:
            print(obj)

        def visit(node: Any) -> Any:
            if debug:
                print("    ", node, type(node))
            if isinstance(node, ExprId):
                new_name = rename_variable(arch_context, node.name,
                                           address, iteration)
                if debug:
                    print("     renamed from %s to %s" % (node.name, new_name))
                return ExprId(new_name, node.size)
            if debug:
                print("     not renamed")
            return node
        return obj.visit(visit)

    _, new_ira = ira_block.simplify(simplifier)
    new_ira_ret: IRBlock = new_ira
    if debug:
        print("end simplify")
    return new_ira_ret


def phi_output(smt_formula: SMTFormula, reg: str, addresses: List[int],
               iteration: int) -> Any:
    irdst = smt_formula.gen_irdst_var(iteration)
    v1 = smt_formula.gen_round_var(reg, iteration + 1)
    expr = v1
    for address in addresses:
        v2 = smt_formula.gen_output_var(reg, address, iteration)
        expr = smt2_ite(smt2_eq(irdst, bit_vec_val(
            address, smt_formula.arch_context.address_size)), v2, expr)
    return smt2_assert_eq(v1, expr)


def phi_outputs(smt_formula: SMTFormula, addresses: List[int],
                iteration: int) -> Any:
    """Create phi output merging all register outputs of the gadgets into round variable"""
    for reg in smt_formula.arch_context.known_vars + [MEM_NAME]:
        smt_formula.add_expr(phi_output(smt_formula, reg, addresses,
                                        iteration))
        if DEBUG:
            dump_file("phi_outputs", phi_output(smt_formula, reg, addresses,
                                                iteration))


def constrain_gadget_pool(smt_formula: SMTFormula, addresses: List[int],
                   iteration: int) -> None:
    """Constrain successors (of previous round) to be one of our gadgets"""
    if len(addresses) <= 1:  # https://github.com/Boolector/boolector/issues/70
        logger.warning(f"Expected more than 1 successor - found {len(addresses)} gadget addresses")
        return
    irdst = smt_formula.gen_irdst_var(iteration)
    smt_formula.add_expr(smt2_assert(smt2_or(" ".join([
        smt2_eq_bvv(irdst, address, smt_formula.arch_context.address_size)
        for address
        in addresses]))))
    if DEBUG:
        dump_file("constrain_gadget_pool", smt2_assert(smt2_or(" ".join([
            smt2_eq_bvv(irdst, address, smt_formula.arch_context.address_size)
            for address
            in addresses
            ]))))


def input_variables(smt_formula: SMTFormula, addresses: List[int], iteration: int) -> None:
    """ Bind round variables to input variables of basic blocks """
    for reg in smt_formula.arch_context.known_vars + [MEM_NAME]:
        if reg != "IRDst":
            for address in addresses:
                var = smt_formula.gen_round_var(reg, iteration)
                input_var = smt_formula.gen_input_var(reg, address, iteration)
                smt_formula.add_expr(smt2_assert_eq(var, input_var))
                if DEBUG:
                    dump_file("input_variables",
                              smt2_assert_eq(var, input_var))


def _get_output_variables(arch_context: ArchContext, ira_block: IRBlock, debug: bool = False) -> Dict[str, str]:
    outputs = {}
    for assignblock in ira_block:
        for dst, _ in assignblock.iteritems():
            name = dst.name

            if dst.name != "IRDst":
                name, _ = dst.name.split(".", 1)

            if name in arch_context.known_vars or name == "M":
                outputs[name] = dst.name
            else:
                if debug:
                    logger.warning(f"Ignoring variable: {name}")
    return outputs


def add_output_variables(arch_context: ArchContext, ira_block: IRBlock, loc_db: LocationDB) -> IRBlock:
    outputs = _get_output_variables(arch_context, ira_block)
    irs = {}
    for reg in arch_context.known_vars + ["M"]:
        src_name = outputs.get(reg, reg + ".IN")
        src: ExprId = ExprId(src_name, arch_context.reg_size(reg))
        dst: ExprId = ExprId(reg + ".OUT", arch_context.reg_size(reg))
        irs[dst] = src
    blk: AssignBlock = AssignBlock(irs)
    assignblks = ira_block.assignblks + (blk,)
    irblock: IRBlock = IRBlock(loc_db, ira_block.loc_key, assignblks)
    return irblock


def encode_preconditions(smt_formula: SMTFormula, synthesizer_config: SynthesizerConfig, target_config: TargetConfig) -> None:
    logger.debug("Setting up preconditions")
    for reg, constr in target_config.preconditions.items():
        var = smt_formula.gen_round_var(constr.reg, 0)
        smt = smt2_assert_eq_bvv(var, constr.value, constr.size)
        smt_formula.add_expr(smt)
        if DEBUG:
            dump_file("preconditions", smt)

    stack_words = min_or_some(synthesizer_config.max_stack_words, target_config.stack_words)

    # Initial
    for reg in target_config.arch_context.known_vars:
        # check if user declared this a free variable which should not be conditioned
        if reg in target_config.free_variables:
            continue
        # check if user already defined and initial value
        if reg in target_config.preconditions.keys():
            continue
        if reg == target_config.arch_context.pc:
            # let smt solver decide initial RIP
            continue
        var = smt_formula.gen_round_var(reg, 0)
        filler_pattern = 0
        if target_config.arch_context.reg_size(reg) >= 64:
            filler_pattern = 0xaaaaaaaaaaaaaaaa
        elif target_config.arch_context.reg_size(reg) >= 32:
            filler_pattern = 0xaaaaaaaa
        smt = smt2_assert_eq_bvv(var, filler_pattern, target_config.arch_context.reg_size(reg))
        smt_formula.add_expr(smt)
        if DEBUG:
            dump_file("reg_initial_values", smt)

    # This needs to be constant:
    mem = smt_formula.gen_mem_var(MEM_NAME)

    # generate constant array to prevent solver from writing
    # at arbitrary addresses
    memory_expr = smt2_const_array(target_config.arch_context.address_size, 0, 8)
    logger.debug("Setting up stack data")
    # check if limited/multiple buffers:
    buffers = []
    if target_config.controlled_buffers:
        buffers += target_config.controlled_buffers
    else:
        word_size = target_config.arch_context.address_size // 8
        upper_bound = target_config.preconditions[target_config.arch_context.sp].value + (word_size * stack_words)
        buffers += [[target_config.preconditions[target_config.arch_context.sp].value, upper_bound]]
    for buf in buffers:
        for i in range(buf[0], buf[1]):
            stack_value = smt_formula.gen_stack_var(i, 8)
            memory_expr = array_store(
                memory_expr, bit_vec_val(i, target_config.arch_context.address_size),
                stack_value)
            if target_config.bad_bytes:
                smt = smt2_assert(smt2_distinct_bvvs(stack_value, target_config.bad_bytes, size=8))
                smt_formula.add_expr(smt)
    if target_config.bad_bytes:
        logger.debug(f"Constraining bad bytes {[f'{b:#x}' for b in target_config.bad_bytes]}")

    smt_formula.add_expr(smt2_assert_eq(memory_expr, mem))
    if DEBUG:
        dump_file("initial_memory", smt2_assert_eq(memory_expr, mem))

    # Memory is all set up -> make this the initial memory of round 0
    m_0 = smt_formula.gen_round_var(MEM_NAME, 0)
    smt_formula.add_expr(smt2_assert_eq(mem, m_0))
    if DEBUG:
        dump_file("initial_memory", smt2_assert_eq(mem, m_0))



def encode_program_rounds(smt_formula: SMTFormula, iras: List[GadgetIRTy], synthesizer_config: SynthesizerConfig, \
                          target_config: TargetConfig, loc_db: LocationDB) -> None:
    logger.debug("Encoding program")
    iras = [(address, add_output_variables(target_config.arch_context, ira, loc_db))
            for address, ira
            in iras]
    # initial check (filter blocks)... do not add variables here
    # (i.e. let default add_vars = False)
    iras = [
        (address, ira)
        for (address, ira)
        in iras
        if encode_smt(smt_formula, target_config.arch_context, ira, loc_db) is not None
        ]

    assert iras, "Expected at least one ira"

    addresses_set: Set[int] = set(map(lambda x: x[0], iras))
    addresses = list(map(lambda x:  x[0], iras))
    assert len(addresses) == len(addresses_set), f"Found some {len(addresses)} addresses, but only {len(addresses_set)} unique addresses"


    for iteration in range(synthesizer_config.iterations):
        iras_i = (
            (address, rename_variables(target_config.arch_context, ira, address, iteration))
            for address, ira
            in iras)

        # we can ignore "None" is not iterable as all blocks where filtered
        # before and None blocks removed
        smts = (
            smt
            for (address, ira) in iras_i
            for smt in encode_smt(smt_formula, target_config.arch_context, ira, loc_db,
                                  restrict_mem=synthesizer_config.restrict_mem,
                                  read_mem_areas=target_config.read_mem_areas,
                                  write_mem_areas=target_config.write_mem_areas,
                                  iteration=iteration,
                                  block_addr=address,
                                  add_vars=True))  # type: ignore
        for x in smts:
            smt_formula.add_expr(x)
            if DEBUG:
                dump_file("translator_expressions", x)

        # This determines which blocks can be executed in the current round
        logger.debug(f"Round {iteration}: Constraining available gadgets")
        constrain_gadget_pool(smt_formula, addresses, iteration)

        # This connects for each gadget the gadget's internal register inputs to the output
        # of the previous round (i.e., RAX_after_round1 == RAX_GadgetA_beginning_of_round2)
        logger.debug(f"Round {iteration}: Binding round variables to gadget input variables")
        input_variables(smt_formula, addresses, iteration)

        # This determines which of the basic block output registers set the round variables
        # I.e., RAX_after_round_2 == phi(RAX_GadgetA_after_round_2 || RAX_GadgetB_after_round_2 || ...)
        logger.debug(f"Round {iteration}: Setting up phi nodes")
        phi_outputs(smt_formula, addresses, iteration)


def encode_postconditions(smt_formula: SMTFormula, synthesizer_config: SynthesizerConfig, target_config: TargetConfig) -> None:
    logger.debug("Setting up final out vars")
    for reg in target_config.arch_context.known_vars + [MEM_NAME]:
        var_final = smt_formula.gen_final_out_var(reg)
        var_round = smt_formula.gen_round_var(reg, synthesizer_config.iterations)
        smt_formula.add_expr(smt2_assert_eq(var_final, var_round))
        if DEBUG:
            dump_file("final_out_vars", smt2_assert_eq(var_final, var_round))

    mem_final = smt_formula.gen_final_out_var(MEM_NAME)

    logger.debug("Setting up pointer postconditions")
    for ptr_constr in target_config.ptr_postconditions:
        # get the register and gen var (checks if already def):
        reg = smt_formula.gen_final_out_var(ptr_constr.reg)
        assert(target_config.arch_context.reg_size(ptr_constr.reg) == target_config.arch_context.address_size)

        for i, val in enumerate(ptr_constr.ref_bytes):
            # build index to store byte at
            index = bvadd(reg, bit_vec_val(i, target_config.arch_context.address_size))
            # read at this index
            mem_read = array_select(mem_final, index)
            # reading at this index should hold value val as specified
            # by constraint
            smt_formula.add_expr(smt2_assert_eq_bvv(mem_read, val, size=8))
            if DEBUG:
                dump_file("ptr_postconditions", smt2_assert_eq_bvv(mem_read, val,
                                                                size=8))
    logger.debug("Setting up postconditions")
    for _, constr in target_config.postconditions.items():
        var = smt_formula.gen_final_out_var(constr.reg)
        smt = smt2_assert_eq_bvv(var, constr.value, constr.size)
        if DEBUG:
            dump_file("postconditions", smt)
        smt_formula.add_expr(smt)


def build_smt_formula(iras: List[GadgetIRTy],
                      synthesizer_config: SynthesizerConfig,
                      target_config: TargetConfig,
                      loc_db: LocationDB) -> str:

    if DEBUG:
        try:
            os.makedirs(TMP_PATH_SMT)
        except FileExistsError:
            shutil.rmtree(TMP_PATH_SMT)
            os.makedirs(TMP_PATH_SMT)

    # sanity check
    for _, c in iras:
        assert isinstance(c, IRBlock)

    stack_words = min_or_some(synthesizer_config.max_stack_words, target_config.stack_words)
    # generate new formula builder object:
    formula_builder = SMTFormula(target_config.arch_context, stack_words)


    encode_preconditions(formula_builder, synthesizer_config, target_config)

    encode_program_rounds(formula_builder, iras, synthesizer_config, target_config, loc_db)
    encode_postconditions(formula_builder, synthesizer_config, target_config)

    return formula_builder.get_formula()
