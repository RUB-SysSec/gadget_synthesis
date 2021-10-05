import logging
from typing import Dict, List

from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprMem, ExprInt

from .types_ import AsmGadget
from .config import TargetConfig

logger = logging.getLogger("synthesizer.verification")


def stack_values_to_se_state(initial_stack_assignment: Dict[int, int], target_config: TargetConfig) -> Dict[ExprMem, ExprInt]:
    init_state = {}
    # use stack values returned by solver as concrete values
    sp_offset = 0
    sz = target_config.arch_context.address_size
    for addr in initial_stack_assignment.keys():
        init_state.update(
            {ExprMem(ExprInt(addr, sz), sz) : ExprInt(initial_stack_assignment[addr], sz)}
            )
        sp_offset += sz // 8
    return init_state


def symbolically_execute_chain(blocks: List[AsmGadget], intial_stack_assignment: Dict[int, int], chain: List[int], \
                                target_config: TargetConfig, loc_db: LocationDB) -> bool:
    logger.info("Using symbolic execution to verify gadget chain..")
    machine = Machine(target_config.arch_context.arch_str)
    ira = machine.ira(loc_db)

    init_state = stack_values_to_se_state(intial_stack_assignment, target_config)
    for _, constr in target_config.preconditions.items():
        init_state.update({ExprId(constr.reg, constr.size) : ExprInt(constr.value, constr.size)})

    # init SE engine
    sb = SymbolicExecutionEngine(ira, state=init_state)

    assert len(blocks) == len(chain), f"Expected len(blocks) == len(chain) but found {len(blocks)} != {len(chain)}"
    # execute all but last block symbolically
    # last block == gadget we want to reach
    for (i, gadget) in enumerate(blocks[:-1]):
        try:
            ira_cfg = ira.new_ircfg()
            ira.add_asmblock_to_ircfg(gadget.block, ira_cfg)
        except (NotImplementedError, ValueError) as e:
            logger.error("symbolic_execution: Failed to create IR CFG - skipping block: " + str(e))
            raise RuntimeError("Symbolic Execution: Failed to lift assembly block to IR")

        # symbolically execute lifted block
        sb.run_block_at(ira_cfg, gadget.addr)

        # after executing the block, check whether we jump to next gadget as intended by model
        for (var, val) in sb.modified(mems=False):
            if var == "IRDst":
                if not val == chain[i+1]:
                    logger.error(f"SE: Iteration {i} - expected IRDst to be {chain[i]} but got {val}")
                    return False
                # assert val == chain[i+1], f"Iteration {i}: expected IRDst to be {chain[i]} but got {val}"
        # DEBUG
        # print("==="*10)
        # print(f"Round {i}")
        # print(ira_cfg.get_block(gadget.addr))
        # sb.dump()

    final_irdst_constr = target_config.postconditions["IRDst"]
    irdst_sym = ExprId(final_irdst_constr.reg, final_irdst_constr.size)
    pc_sym = ExprId(target_config.arch_context.pc, target_config.arch_context.address_size)
    if sb.state.symbols[irdst_sym] != sb.state.symbols[pc_sym]:
        logger.error(f"SE: Final IRDst != final RIP")
        return False
    for _, constr in target_config.postconditions.items():
        expect = ExprInt(constr.value, constr.size)
        try:
            find = sb.state.symbols[ExprId(constr.reg, constr.size)]
        except KeyError:
            # this implies, the solver relies on a register constrainted to 0 initially (without explicit precondition)
            logger.error(f"SE: Solver is relying on {constr.reg} being {constr.value}, however, does not enforce this through gadget chain (implicit precondition)")
            return False
        if expect != find:
            logger.error(f"SE: Postcondition {constr} does not hold - expected {expect} found {find}")
            return False
    for ptr_constr in target_config.ptr_postconditions:
        # TODO: the following assumes we always read 8 bytes of memory; in theory, the string may have arbitrary length
        # such that we either need to check it byte-wise or chunk it
        expect = ExprInt(int.from_bytes(ptr_constr.ref_bytes, byteorder='little'), ptr_constr.size * 8)
        try:
            # TODO: this should not assume the address_size in bytes of the architecture
            # but ptr_postconditions should store the REG's size as well (right now, size == number of bytes in ptr_postcondition)
            addr = sb.state.symbols[ExprId(ptr_constr.reg, target_config.arch_context.address_size)]
        except KeyError:
            # this implies, the solver relies on a register constrainted to 0 initially (without explicit precondition)
            logger.error(f"SE: Chain failed to set {ptr_constr.reg} (but is ptr-postconditioned)")
            return False
        try:
            # convert addr to ExprMem (size is given in bits; i.e., number of bytes in string * 8)
            find = sb.mem_read(ExprMem(addr, ptr_constr.size * 8))
        except KeyError:
            # this implies, the solver relies on a register constrainted to 0  initially (without explicit precondition)
            logger.error(f"SE: Chain failed to write to address described by {ptr_constr.reg} (but is postconditioned)")
            return False
        if expect != find:
            logger.error(f"SE: Ptr-Postcondition {ptr_constr} does not hold - expected {expect} @ {addr} but found {find}")
            return False
    # sb.dump()
    logger.info("Symbolic execution found the chain to be correct")
    return True


def verify_gadget_chain(asm_gadgets: List[AsmGadget], chain: List[int], initial_stack_assignment: Dict[int, int], \
                        target_config: TargetConfig, loc_db: LocationDB) -> bool:
    blocks: List[AsmGadget] = []
    # for each address in the chain, we lookup the respective AsmBlock in the gadget pool
    # we skip this for the last element of the chain as it may not be within the gadget pool
    # because it is never actually executed (but our destination)
    for addr in chain[:-1]:
        for gadget in asm_gadgets:
            if addr == gadget.addr:
                blocks.append(gadget)
                break
    # in a second step, add the final IRDst - as it is not executed, we can just add its address
    # and an empty block (SE also doesn't evaluate it - we're done when we reach it with all
    # conditions fulfilled)
    blocks.append(AsmGadget(target_config.postconditions["IRDst"].value, None))
    assert len(chain) == len(blocks), f"Chain has len {len(chain)}, but we have found {len(blocks)} blocks (should be equal)"

    return symbolically_execute_chain(blocks, initial_stack_assignment, chain, target_config, loc_db)
