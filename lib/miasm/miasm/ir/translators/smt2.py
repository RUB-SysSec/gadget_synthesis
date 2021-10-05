from builtins import map
from builtins import range
import logging

from miasm.ir.translators.translator import Translator
from miasm.expression.smt2_helper import *

log = logging.getLogger("translator_smt2")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.WARNING)

class SMT2Mem(object):
    """
    Memory abstraction for TranslatorSMT2. Memory elements are only accessed,
    never written. To give a concrete value for a given memory cell in a solver,
    add "mem32.get(address, size) == <value>" constraints to your equation.
    The endianness of memory accesses is handled accordingly to the "endianness"
    attribute.
    Note: Will have one memory space for each addressing size used.
    For example, if memory is accessed via 32 bits values and 16 bits values,
    these access will not occur in the same address space.

    Adapted from Z3Mem
    """

    def __init__(self, endianness="<", name="mem"):
        """Initializes an SMT2Mem object with a given @name and @endianness.
        @endianness: Endianness of memory representation. '<' for little endian,
            '>' for big endian.
        @name: name of memory Arrays generated. They will be named
            name+str(address size) (for example mem32, mem16...).
        """
        if endianness not in ['<', '>']:
            raise ValueError("Endianness should be '>' (big) or '<' (little)")
        self.endianness = endianness
        self.mems = {} # Address size -> SMT2 memory array
        self.name = name
        # initialise address size
        self.addr_size = 0

    def get_mem_array(self, size):
        """Returns an SMT Array used internally to represent memory for addresses
        of size @size.
        @size: integer, size in bit of addresses in the memory to get.
        Return an string with the name of the SMT array..
        """
        try:
            mem = self.mems[size]
        except KeyError:
            # Lazy instantiation
            self.mems[size] = self.name + str(size)
            mem = self.mems[size]
        return mem

    def __getitem__(self, addr):
        """One byte memory access. Different address sizes with the same value
        will result in different memory accesses.
        @addr: an SMT2 expression, the address to read.
        Return an SMT2 expression of size 8 bits representing a memory access.
        """
        size = self.addr_size
        mem = self.get_mem_array(size)
        return array_select(mem, addr)

    def get(self, addr, size, addr_size):
        """ Memory access at address @addr of size @size with
        address size @addr_size.
        @addr: an SMT2 expression, the address to read.
        @size: int, size of the read in bits.
        @addr_size: int, size of the address
        Return a SMT2 expression representing a memory access.
        """
        # set address size per read access
        self.addr_size = addr_size

        original_size = size
        if original_size % 8 != 0:
            # Size not aligned on 8bits -> read more than size and extract after
            size = ((original_size // 8) + 1) * 8
        res = self[addr]
        if self.is_little_endian():
            for i in range(1, size // 8):
                index = bvadd(addr, bit_vec_val(i, addr_size))
                res = bv_concat(self[index], res)
        else:
            for i in range(1, size // 8):
                index = bvadd(addr, bit_vec_val(i, addr_size))
                res = bv_concat(res, self[index])
        if size == original_size:
            return res
        else:
            # Size not aligned, extract right sized result
            return bv_extract(original_size-1, 0, res)

    def is_little_endian(self):
        """True if this memory is little endian."""
        return self.endianness == "<"

    def is_big_endian(self):
        """True if this memory is big endian."""
        return not self.is_little_endian()


class SMT2MemStateful(object):
    """
    Stateful memory abstraction for TranslatorSMT2. 
    The endianness of memory accesses is handled accordingly to the "endianness"
    attribute.

    Adapted from Z3MemStateful
    """

    def __init__(self, endianness="<", addr_size=64):
        """Initializes an SMT2Mem object with a given @name and @endianness.
        @endianness: Endianness of memory representation. '<' for little endian,
            '>' for big endian.
        @name: name of memory Arrays generated. They will be named
            name+str(address size) (for example mem32, mem16...).
        """
        if endianness not in ['<', '>']:
            raise ValueError("Endianness should be '>' (big) or '<' (little)")
        self.endianness = endianness
        self.mems = set()
        # initialise address size
        self.addr_size = addr_size

    def gen_mem(self, mem="M", addr_size=None):
        """
        Generates an SMT2 array that maps @self.addr_size bitvecs to 8 byte bitvecs
        @mem: name of memory as string
        @size: memory address size
        Return: SMT2 array
        """
        if not addr_size:
            size = self.addr_size   
        
        mem_array = declare_array(mem, bit_vec(size), bit_vec(8))
        if mem_array not in self.mems:
            self.mems.add(mem_array)
        return mem

    def read(self, mem, addr, size):
        """ Memory access at address @addr of total size @size with
        in current memory state @mem.
        @mem: SMT2 expressions, current memory state
        @addr: an SMT2 expression, the address to read.
        @size: int, size of the read in bits.
        Return a SMT2 expression representing a memory access.
        """

        original_size = size
        if original_size % 8 != 0:
            # Size not aligned on 8bits -> read more than size and extract after
            size = ((original_size // 8) + 1) * 8
        res = array_select(mem, addr)
        if self.is_little_endian():
            for i in range(1, size // 8):
                index = bvadd(addr, bit_vec_val(i, self.addr_size))
                res = bv_concat(array_select(mem, index), res)
        else:
            for i in range(1, size // 8):
                index = bvadd(addr, bit_vec_val(i, self.addr_size))
                res = bv_concat(res, array_select(mem, index))
        if size == original_size:
            return res
        else:
            # Size not aligned, extract right sized result
            return bv_extract(original_size-1, 0, res)

    def write(self, mem, addr, val, size):
        """ Memory write at address @addr with address size @addr_size
        of size @size with value @v of size @val_size.
        @mem: SMT2 expressions, current memory state
        @addr: an SMT2 expression, the address to read.
        @v: an SMT2 expression, value to be written (total size @size)
        @size: int, size of value @val in bit
        Return: updated SMT2 memory array
        """
        original_size = size

        if original_size % 8 != 0:
            # align size to 8 bits
            size = ((original_size / 8) + 1) * 8

        # transform into SMT2 expressions
        one_smt2 = bit_vec_val(1, self.addr_size)
        eight_smt2 = bit_vec_val(8, self.addr_size)
        size_smt2 = bit_vec_val(size, self.addr_size)

        if self.is_little_endian():
            mem = array_store(mem, addr, bv_extract(7, 0, val))
            for i in range(2, size // 8 + 1):
                # transform into SMT2 expression
                i_smt2 = bit_vec_val(i, self.addr_size)

                # index = addr + i - 1
                index = bvadd(addr, bvsub(i_smt2, one_smt2))
                mem = array_store(mem, index, bv_extract(8 * i - 1, 8 * (i - 1), val))
        else:
            mem = array_store(mem, addr, bv_extract(self.addr_size - 1, self.addr_size - 8, val))
            for i in range((size // 8) - 1, 0, -1):
                # transform into SMT2 expression
                i_smt2 = bit_vec_val(i, self.addr_size)

                # index = addr + (-i % (size / 8))
                index = bvadd(addr, bvsmod(bvneg(i_smt2), bvsdiv(size_smt2, eight_smt2)))
                mem = array_store(mem, index, bv_extract(8 * i - 1, 8 * (i - 1), val))

        return mem

    def is_little_endian(self):
        """True if this memory is little endian."""
        return self.endianness == "<"

    def is_big_endian(self):
        """True if this memory is big endian."""
        return not self.is_little_endian()


class TranslatorSMT2(Translator):
    """Translate a Miasm expression into an equivalent SMT2
    expression. Memory is abstracted via SMT2Mem or SMT2MemStateful
    The result of from_expr will be an SMT2 expression.

    If you want to interact with the memory abstraction after the translation,
    you can instantiate your own SMT2Mem that will be equivalent to the one
    used by TranslatorSMT2.

    TranslatorSMT2 provides the creation of a valid SMT2 file. For this,
    it keeps track of the translated bit vectors.

    Adapted from TranslatorZ3
    """

    # Implemented language
    __LANG__ = "smt2"

    def __init__(self, endianness="<", loc_db=None, stateful_mem=False, restrict_mem=False, write_mem_areas=[], read_mem_areas=[], mem_size=64, **kwargs):
        """Instance a SMT2 translator
        @endianness: (optional) memory endianness
        @loc_db: Location database
        @stateful_mem: Memory model to use
        @mem_size: address size used in memory model
        """
        super(TranslatorSMT2, self).__init__(**kwargs)
        # memory abstraction
        self.stateful_mem = stateful_mem
        self.restrict_mem = restrict_mem
        if self.stateful_mem:
            self._mem = SMT2MemStateful(endianness, mem_size)
            # check if read/writeable memory range has been specified:
            if self.restrict_mem:
                self.write_mem_areas = write_mem_areas
                self.read_mem_areas = read_mem_areas
        else:
            assert(not self.restrict_mem)
            self._mem = SMT2Mem(endianness)
        # map of translated bit vectors
        self._bitvectors = dict()
        # set of (ssa-) vars used as address to read in memory:
        self.read_addrs = set()
        # ... used to write in memory:
        self.write_addrs = set()
        # symbol pool
        self.loc_db = loc_db

    @staticmethod
    def parse_bv_val(bvv_expr):
        """Parse SMT2 expression of a bitvector value:
        e.g. (_ bv8 32) --> 8
        @bvv_expr: the bitvector values SMT2 expression
        Return the (int) value of the bvv expression
        """
        return int(bvv_expr.split(" ")[1][2::])

    def from_ExprInt(self, expr):
        return bit_vec_val(int(expr), expr.size)

    def from_ExprId(self, expr):
        if self.stateful_mem and isinstance(expr.name, str) and expr.name.split(".")[0] == "M":
            return self._mem.gen_mem(expr.name) 
        else:
            if str(expr) not in self._bitvectors:
                self._bitvectors[str(expr)] = expr.size
            return str(expr)

    def from_ExprLoc(self, expr):
        loc_key = expr.loc_key
        if self.loc_db is None or self.loc_db.get_location_offset(loc_key) is None:
            if str(loc_key) not in self._bitvectors:
                self._bitvectors[str(loc_key)] = expr.size
            return str(loc_key)

        offset = self.loc_db.get_location_offset(loc_key)
        return bit_vec_val(str(offset), expr.size)

    def from_ExprMem(self, expr):
        addr = self.from_expr(expr.ptr)
        # size to read from memory
        size = expr.size
        if self.stateful_mem:
            mem = self._mem.gen_mem()
            return self._mem.read(mem, addr, size)
        else:
            # size of memory address
            addr_size = expr.ptr.size
            return self._mem.get(addr, size, addr_size)

    def from_ExprSlice(self, expr):
        res = self.from_expr(expr.arg)
        res = bv_extract(expr.stop-1, expr.start, res)
        return res

    def from_ExprCompose(self, expr):
        res = None
        for arg in expr.args:
            e = bv_extract(arg.size-1, 0, self.from_expr(arg))
            if res:
                res = bv_concat(e, res)
            else:
                res = e
        return res

    def from_ExprCond(self, expr):
        cond = self.from_expr(expr.cond)
        src1 = self.from_expr(expr.src1)
        src2 = self.from_expr(expr.src2)

        # (and (distinct cond (_ bv0 <size>)) true)
        zero = bit_vec_val(0, expr.cond.size)
        distinct = smt2_distinct(cond, zero)
        distinct_and = smt2_and(distinct, "true")

        # (ite ((and (distinct cond (_ bv0 <size>)) true) src1 src2))
        return smt2_ite(distinct_and, src1, src2)

    def from_ExprOp(self, expr):
        args = list(map(self.from_expr, expr.args))
        res = args[0]

        if len(args) > 1:
            for arg in args[1:]:
                if expr.op == "+":
                    res = bvadd(res, arg)
                elif expr.op == "-":
                    res = bvsub(res, arg)
                elif expr.op == "*":
                    res = bvmul(res, arg)
                elif expr.op == "/":
                    res = bvsdiv(res, arg)
                elif expr.op == "sdiv":
                    res = bvsdiv(res, arg)
                elif expr.op == "udiv":
                    res = bvudiv(res, arg)
                elif expr.op == "%":
                    res = bvsmod(res, arg)
                elif expr.op == "smod":
                    res = bvsmod(res, arg)
                elif expr.op == "umod":
                    res = bvurem(res, arg)
                elif expr.op == "&":
                    res = bvand(res, arg)
                elif expr.op == "^":
                    res = bvxor(res, arg)
                elif expr.op == "|":
                    res = bvor(res, arg)
                elif expr.op == "<<":
                    res = bvshl(res, arg)
                elif expr.op == ">>":
                    res = bvlshr(res, arg)
                elif expr.op == "a>>":
                    res = bvashr(res, arg)
                elif expr.op == "<<<":
                    res = bv_rotate_left(res, arg, expr.size)
                elif expr.op == ">>>":
                    res = bv_rotate_right(res, arg, expr.size)
                elif expr.op == "mem_read":
                    # simplifications generated:
                    # mem_read(M, addr, size),
                    # This only exists for stateful mem
                    assert(self.stateful_mem == True)
                    mem = self._mem.gen_mem(str(args[0]))
                    addr = args[1]
                    size = self.parse_bv_val(args[2])
                    self.read_addrs.add(addr)
                    res = self._mem.read(mem, addr, size)
                    break
                elif expr.op == "mem_write":
                    # simplifications generated:
                    # M = mem_write(M, addr, val, size),
                    # This only exists for stateful mem
                    assert(self.stateful_mem == True)
                    mem = self._mem.gen_mem(str(args[0]))
                    addr = args[1]
                    val = args[2]
                    size = self.parse_bv_val(args[3])
                    self.write_addrs.add(addr)
                    res = self._mem.write(mem, addr, val, size)
                    break
                else:
                    raise NotImplementedError("Unsupported OP yet: %s" % expr.op)
        elif expr.op == 'parity':
            arg = bv_extract(7, 0, res)
            res = bit_vec_val(1, 1)
            for i in range(8):
                res = bvxor(res, bv_extract(i, i, arg))
        elif expr.op == '-':
            res = bvneg(res)
        elif expr.op == "cnttrailzeros":
            src = res
            size = expr.size
            size_smt2 = bit_vec_val(size, size)
            one_smt2 = bit_vec_val(1, size)
            zero_smt2 = bit_vec_val(0, size)
            # src & (1 << (size - 1))
            op = bvand(src, bvshl(one_smt2, bvsub(size_smt2, one_smt2)))
            # op != 0
            cond = smt2_distinct(op, zero_smt2)
            # ite(cond, size - 1, src)
            res = smt2_ite(cond, bvsub(size_smt2, one_smt2), src)
            for i in range(size - 2, -1, -1):
                # smt2 expression of i
                i_smt2 = bit_vec_val(i, size)
                # src & (1 << i)
                op = bvand(src, bvshl(one_smt2, i_smt2))
                # op != 0
                cond = smt2_distinct(op, zero_smt2)
                # ite(cond, i, res)
                res = smt2_ite(cond, i_smt2, res)
        elif expr.op == "cntleadzeros":
            src = res
            size = expr.size
            one_smt2 = bit_vec_val(1, size)
            zero_smt2 = bit_vec_val(0, size)
            # (src & 1) != 0
            cond = smt2_distinct(bvand(src, one_smt2), zero_smt2)
            # ite(cond, 0, src)
            res= smt2_ite(cond, zero_smt2, src)
            for i in range(size - 1, 0, -1):
                index = - i % size
                index_smt2 = bit_vec_val(index, size)
                # src & (1 << index)
                op = bvand(src, bvshl(one_smt2, index_smt2))
                # op != 0
                cond = smt2_distinct(op, zero_smt2)
                # ite(cond, index, res)
                value_smt2 = bit_vec_val(size - (index + 1), size)
                res = smt2_ite(cond, value_smt2, res)
        else:
            raise NotImplementedError("Unsupported OP yet: %s" % expr.op)

        return res

    def from_ExprAssign(self, expr):
        src = self.from_expr(expr.src)
        dst = self.from_expr(expr.dst)
        return smt2_assert(smt2_eq(src, dst))

    def to_smt2(self, exprs, logic="QF_ABV", model=False):
        """
        Converts a valid SMT2 file for a given list of
        SMT2 expressions.

        Memory accesses are tracked by the translator, restrictions
        however, need to be applied by the user depending on context

        :param exprs: list of SMT2 expressions
        :param logic: SMT2 logic
        :param model: model generation flag
        :return: String of the SMT2 file
        """
        ret = ""
        ret += "(set-logic {})\n".format(logic)

        # define bit vectors
        for bv in self._bitvectors:
            size = self._bitvectors[bv]
            ret += "{}\n".format(declare_bv(bv, size))

        if self.stateful_mem: 
            # stateful: the mem set already contains generated smt2 arrays:
            for arr in self._mem.mems:
                ret += "{}\n".format(arr)
        else:
            # define memory arrays
            for size in self._mem.mems:
                mem = self._mem.mems[size]
                ret += "{}\n".format(declare_array(mem, bit_vec(size), bit_vec(8)))

        # merge SMT2 expressions
        for expr in exprs:
            ret += expr + "\n"

        # define action
        ret += "(check-sat)\n"

        # enable model generation
        if model:
            ret += "(get-model)\n"

        return ret


# Register the class
Translator.register(TranslatorSMT2)
