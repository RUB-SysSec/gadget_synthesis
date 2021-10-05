"""
Configuration files to define both SGC's internal approach and the targeted binary.

There are two different configuration files.
1) TargetConfig: This configuration file describes the target binary for which
                 we want to synthesize a gadget chain.
2) SynthesizerSettings: These are the settings for SGC itself; the settings
                        set the frame for a number of possible configurations
                        for one single run of SGC. Each such config is called
                        SynthesizerConfig. This is to enable convenient evaluation.
"""
from enum import Enum
from pathlib import Path
from typing import Iterator, List, Optional, Type, Union
import logging
import json

from smt_solvers import BoolectorSolver
from smt_solvers.solver import SMTSolver
from .arch import ArchContext, X86_64Context, X86_32Context
from .types_ import Library, RawGadget
from .utils import get_library_of_addr, to_int

logger = logging.getLogger('synthesizer.config')


# TODO: this currently assumes that the pointee value fits at the memory address
# and expects the user to encode this as multiple values if the string is longer
# than can fit into 8 bytes (for x86-64)
class PtrConstraint():
    """Class used for pointer constraints.

    Example for pointer constraints:
        QWORD [RDI_OUT] = 0x41414141
        or
        QWORD [RDI_OUT] = "/bin/sh"

    """

    def __init__(self, reg: str, iteration: int, ref_value: Union[int, str],
                 size: int = 0, null_termination: bool = True):
        """Initializates pointer constraint object.

        Args:
            reg: Register holding the address (i.e. the ptr), which is to be
                accessed/dereferenced.
            iteration: Specifies at which point in the gadget chain this constraint
                applies.
            ref_value: Value referenced by the pointer.
            size: Size of pointer in bits.
            null_termination: Toggle null termination for (C) strings.
        """
        self.reg = reg
        if iteration != -1:
            raise ValueError("PtrConstraints only supported for final round")
        self.iteration = iteration
        if isinstance(ref_value, int):
            self.ref_type: Union[Type[str], Type[int]] = int
            self.size = int(size/8)
            # split referenced value into bytes:
            # TODO support for big endian
            self.ref_bytes = []
            for i in range(0, self.size):
                self.ref_bytes += [((ref_value >> (i*8)) & 0xFF)]
        elif isinstance(ref_value, str):
            self.ref_type = str
            self.size = len(ref_value)
            self.ref_bytes = [int(x) for x in ref_value.encode("utf-8")]
            if null_termination:
                self.size += 1
                self.ref_bytes += [0]
        else:
            raise ValueError("Unknown ref_value type")


class Constraint():
    """Register constraints regarding final values."""

    def __init__(self, reg: str, iteration: int, value: int, size: int):
        self.reg = reg
        self.iteration = iteration
        self.value = value
        self.size = size

    def __repr__(self) -> str:
        return f"[{self.reg}, {self.iteration}, {self.value}, {self.size}]"


class SelectionStrategy(Enum):
    """
    Strategy according to which we choose the gadget subset
    """
    Random = 0,
    Seed = 1,
    Deterministic = 2,

class SelectionLocation(Enum):
    """
    Location from which we select the gadgets
    """
    MAIN_EXE = 0,
    LIBRARIES = 1,
    MIXED = 2,

class SynthesizerSettings():
    """
    Configuration class controling all tool/evaluation settings. For binary specific
    configurtation options, use TargetConfig

    Attributes:
        block_limit: the maximum amount of blocks considered as potential
            gadgets
        initial_seed_or_offset: Initial seed (if Seed selection strategy or block offset
            (if Deterministic selection strategy) - to which +1 is added for each number
            in range(max_selection_variations + 1)
        iterations: number of "rounds" / gadgets total used for gadget chain
        solver: SMTSolver used for solving final smt formula
    """

    def __init__(self, path: Path):
        logger.debug(f"Loading SynthesizerConfig from '{path}'")
        with open(path, "r") as f:
            cf = json.load(f)

        self.block_limits = cf["block_limits"]
        self.all_iterations = cf["all_iterations"]
        self.restrict_mem = cf.get("restrict_mem", False)

        if "boolector" in cf.get("solver").lower():
            self.solver = BoolectorSolver(sat_engine="picosat")
        else:
            raise RuntimeError("Solver not specified.")

        self.all_max_stack_words = cf["all_max_stack_words"]

        self.disassemble_unaligned = cf.get("disassemble_unaligned", False)


        # max_selection_variations controls how many times we add +1 to seed or offset and spawn a new process
        self.max_selection_variations = cf.get("max_selection_variations", 0)
        selection_strategy = cf.get("selection_strategy", None)
        if selection_strategy == "seed":
            self.selection_strategy = SelectionStrategy.Seed
            self.initial_seed_or_offset = cf.get("initial_seed", 0)
        elif selection_strategy == "deterministic":
            self.selection_strategy = SelectionStrategy.Deterministic
            self.initial_seed_or_offset = cf.get("initial_block_offset", 0)
        else:
            raise NotImplementedError(f"Selection strategy {selection_strategy} not implemented")

        selection_location_str = cf.get("selection_location", None)
        if selection_location_str == "main_exe":
            self.selection_location = SelectionLocation.MAIN_EXE
        elif selection_location_str == "libraries":
            self.selection_location = SelectionLocation.LIBRARIES
        elif selection_location_str == "mixed":
            self.selection_location = SelectionLocation.MIXED
        else:
            raise NotImplementedError(f"Selection location {selection_location_str} not implemented")

        self.solver_timeout = cf["solver_timeout"]
        self.disassembly_timeout = cf["disassembly_timeout"]
        self.control_flow_types = cf.get("control_flow_types", ["ret", "call", "jmp"])


    def all_config_permutations(self, target_max_stack_words: Optional[int]) -> Iterator['SynthesizerConfig']:
        """Return all possible run configurations for the given settings"""
        all_stack_words = self.all_max_stack_words
        if target_max_stack_words:
            all_stack_words = [sw for sw in self.all_max_stack_words if sw < target_max_stack_words]
        for max_stack_words in all_stack_words:
            for iterations in self.all_iterations:
                for block_limit in self.block_limits:
                    for i in range(self.max_selection_variations + 1):
                        yield SynthesizerConfig(self.solver, self.restrict_mem,
                                        self.disassemble_unaligned, block_limit,
                                        self.selection_strategy, self.selection_location, (self.initial_seed_or_offset + i),
                                        iterations, max_stack_words,
                                        self.solver_timeout, self.disassembly_timeout)


class SynthesizerConfig(SynthesizerSettings):

    def __init__(self, solver: SMTSolver, restrict_mem: bool,  disassemble_unaligned: bool,
                 block_limit: int, selection_strategy: SelectionStrategy, selection_location: SelectionLocation, 
                 initial_seed_or_offset: int, iterations: int, max_stack_words: int, solver_timeout: int, disassembly_timeout: int):
        # initialize standard values
        self.solver = solver
        self.restrict_mem = restrict_mem
        self.disassemble_unaligned = disassemble_unaligned
        self.block_limit = block_limit
        self.selection_strategy = selection_strategy
        self.selection_location = selection_location
        self.initial_seed_or_offset = initial_seed_or_offset
        self.iterations = iterations
        self.max_stack_words = max_stack_words
        self.solver_timeout = solver_timeout
        self.disassembly_timeout = disassembly_timeout

    def __repr__(self) -> str:
        return ("iteration{:d}-blocks{:04d}-offset{:03d}-sw{:02d}".format(
                    self.iterations, self.block_limit,
                    self.initial_seed_or_offset, self.max_stack_words))


def make_absolute_path(root: Path, path: Path) -> Path:
    if path.is_absolute():
        return path
    return (root / path).absolute()


class TargetConfig(object):
    """Configuration class. Must be loaded from JSON file.

    Attributes:
        executable: Path to the target binary (required)
        load_address: Load address
        libraries: List of libraries (each having: name, path to library file, 
                    load address)
        architecture: the target's architecture, e.g. x86_64
        stack_words: number of words on stack available at most for use by 
                    gadget chain (can be overridden by binary)
        free_variables: explicitly *not* preconditioned registers (attacker-controlled)
        preconditions: initial state
        postconditions: desired state
        ptr_postconditions: indirect postconditions/pointer constraints 
                            (e.g., when we need /bin/sh)
        read_mem_areas: Which areas may be read (if restrict_mem == True)
        write_mem_areas: Which areas may be written to (if restrict_mem == True)
        force_code_locations_set: List of addresses that must be included in sampled subset;
                        For example, we automatically add the attacker's desired target to this,
                        as else the targeted state instantly is impossible to reach
        controlled_buffers: List of attacker-controlled buffers (if not using stack)
        bad_bytes: Bytes that may not occur in the gadget chain
    """

    def __init__(self, path: Path):
        logger.debug(f"Loading TargetConfig from '{path}'")
        assert path.is_file(), f"File not found or not a readable file: {path}"
        with open(path, "r") as f:
            cf = json.load(f)

        self.executable = Path(cf["executable"])
        if not self.executable.is_absolute():
            logger.debug(f"Executable is relative path: '{self.executable}' - adjusting to '{path.parent / self.executable}'")
            self.executable = path.parent / self.executable

        self.load_address = to_int(cf.get("load_address", 0))

        self.libraries = [Library(lib[0], make_absolute_path(root=path.parent, path=Path(lib[1])), to_int(lib[2])) for lib in cf.get("libraries", [])]
        if self.libraries:
            assert self.load_address != 0, f"Load address must be set when using libraries (is {self.load_address:#x} but using {len(self.libraries)} libraries)"


        arch = cf["arch"]
        if arch == "x86_64":
            self.arch_context: ArchContext = X86_64Context()
        elif arch == "x86_32":
            self.arch_context = X86_32Context()
        else:
            raise ValueError("Unknown architecture {}.".format(arch))

        self.stack_words = cf.get("stack_words", None)

        # parse constraints:
        # free_variables describe explicitly *not* preconditioned registers (no default value is enforced by us)
        # These should be used for attacker controlled registers, where we can set any value
        self.free_variables = cf.get("free_variables", [])
        for c in cf.get("preconditions", []) + cf.get("postconditions", []):
            assert len(c) == 3, f"{c} expected to have three fields (name, val, size) but found {len(c)}"
            assert isinstance(c[0], str), f"First field must be name, found: {c[0]} w/ type {type(c[0])}"
            assert c[0] not in self.free_variables, f"Variable is declared a free variable and preconditioned at the same time"
            assert isinstance(to_int(c[1]), int), f"Second field must be value (\"0x..\" or int), found: {c[1]} w/ type {type(c[1])}"
            assert isinstance(c[2], int), f"Third field must be size (int), found: {c[2]} w/ type {type(c[2])}"
        self.preconditions = {c[0] : Constraint(reg=c[0], iteration=0, value=to_int(c[1]), size=c[2]) for c in cf.get("preconditions", [])}
        assert self.preconditions.get("IRDst", None), "Initial IRDst is a required precondition"
        assert self.preconditions.get(self.arch_context.sp, None), f"Initial {self.arch_context.sp} is a required precondition"
        self.postconditions = {c[0] : Constraint(reg=c[0], iteration=-1, value=to_int(c[1]), size=c[2]) for c in cf.get("postconditions", [])}
        assert self.postconditions.get("IRDst", None), "Final IRDst is a required postcondition"

        # parse force_code_locations:
        force_code_locations_set = set([to_int(addr) for addr in cf.get("force_code_locations", [])])
        # Add initial IRDst to ensure they will be preserved as gadget
        force_code_locations_set.add(self.preconditions["IRDst"].value)
        # add forced code locations
        force_code_locations: List[RawGadget] = []
        for addr in force_code_locations_set:
            lib = get_library_of_addr(addr, self.libraries)
            if lib is None: # main executable
                force_code_locations += [RawGadget(addr, "main_exe")]
            else:
                # this was a lib address -> subtract base 
                force_code_locations += [RawGadget(addr - lib.load_address, lib.name)]
        self.force_code_locations = force_code_locations


        # parse pointer constraints:
        self.ptr_postconditions = []
        ptr_postconditions = cf.get("ptr_postconditions", [])
        for c in ptr_postconditions:
            # for convenience, we allow specification of strings,
            #  e.g., /bin/sh, which we want to point to
            if type(c[1]) == str:
                if c[1].startswith("0x"):
                    # hex string:
                    c[1] = int(c[1], 16)
                    size = c[2]
                else:
                    size = len(c[1])
            self.ptr_postconditions += [PtrConstraint(c[0], -1, c[1], size)]

        # parse memory areas:
        self.read_mem_areas = []
        for [lower, upper] in cf.get("read_mem_areas", []):
            self.read_mem_areas += [(to_int(lower), to_int(upper))]

        self.write_mem_areas = []
        for (lower, upper) in cf.get("write_mem_areas", []):
            self.write_mem_areas += [(to_int(lower), to_int(upper))]

        # check if we are dealing with limited buffers:
        self.controlled_buffers = []
        controlled_buffers = cf.get("controlled_buffers", [])
        if controlled_buffers:
            for buf in controlled_buffers:
                assert len(buf) == 2, "Controlled buffer contained"
                self.controlled_buffers.append([to_int(buf[0]), to_int(buf[1])])

        self.bad_bytes = [to_int(b) for b in cf.get("badbytes", [])]

        if self.bad_bytes:
            logger.debug(f"Using bad bytes: {[hex(b) for b in self.bad_bytes]}")

        logger.debug(f"Using {len(self.free_variables)} free variables, {len(self.preconditions.keys())} preconditions, {len(self.postconditions.keys())} postconditions, and {len(self.ptr_postconditions)} ptr_postconditions")
