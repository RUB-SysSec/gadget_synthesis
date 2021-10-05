"""
Code to sample a subset of gadgets
"""
from typing import List
import logging
import random

from .config import SelectionStrategy, SynthesizerConfig, TargetConfig
from .types_ import RawGadget


logger = logging.getLogger('synthesizer.selection')


def choose_blocks(gadgets_init: List[RawGadget], random_block_offset: int,
                  block_limit: int) -> List[RawGadget]:
    """Deterministically shuffles input by selecting every n-th element
       modulo the size.
       n should not share any divisors with the length of the input
    """
    logger.debug("Selecting blocks deterministically (every n-th input module number of gadgets)")
    def resort(xs: List[RawGadget], n: int) -> List[RawGadget]:
        def gcd(x: int, y: int) -> int:
            if y == 0:
                return x
            else:
                return gcd(y, x % y)
        assert gcd(len(xs), n) == 1
        res = [xs[i * n % len(xs)] for i in range(len(xs))]
        assert sorted(xs) == sorted(res)
        return res
    offset = random_block_offset * block_limit
    return resort(gadgets_init, 101)[offset:][:block_limit]


def choose_blocks_random(gadgets_init: List[RawGadget], seed: int, block_limit: int) -> List[RawGadget]:
    random.seed(seed)
    return random.sample(gadgets_init, k=block_limit)


def choose_gadgets(gadgets_init: List[RawGadget], synthesizer_config: SynthesizerConfig,
                target_config: TargetConfig) -> List[RawGadget]:
    """Selects a specific number of gadgets and adds forced code locations.

       Returns: A list of gadgets.
    """
    if synthesizer_config.block_limit is not None and synthesizer_config.block_limit < len(gadgets_init):
        block_limit = synthesizer_config.block_limit - len(target_config.force_code_locations)
        if synthesizer_config.selection_strategy == SelectionStrategy.Seed:
            gadgets_selection = choose_blocks_random(gadgets_init, synthesizer_config.initial_seed_or_offset, block_limit)
        elif synthesizer_config.selection_strategy == SelectionStrategy.Deterministic:
            gadgets_selection = choose_blocks(gadgets_init, synthesizer_config.initial_seed_or_offset, block_limit)
        else:
            raise NotImplementedError(f"Selection stategy {synthesizer_config.selection_strategy.name} not implemented")
    else:
        logger.warning(f"Too few gadgets. Found {len(gadgets_init)} gadgets but block limit is {synthesizer_config.block_limit}")
        gadgets_selection = gadgets_init

    # ensure forced code locations are actually contained within selected gadgets
    gadgets = list(set(gadgets_selection + target_config.force_code_locations))
    logger.info(f"Selecting {len(gadgets)} from {len(gadgets_init)} available gadgets " \
                f"({len(target_config.force_code_locations)} fixed)")
    return gadgets
