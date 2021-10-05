#!/usr/bin/python3

import argparse
import copy
import json
import logging
import os
import sys
import time
from functools import partial
from multiprocessing import Pool
from synthesizer.cache import CacheType
import multiprocessing_logging; multiprocessing_logging.install_mp_handler()
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from miasm.core.locationdb import LocationDB

from smt_solvers import SMTResult, SMTModel, SMTSolver
from synthesizer.arch import ArchContext
from synthesizer.config import SelectionLocation, SelectionStrategy, SynthesizerConfig, SynthesizerSettings, TargetConfig
from synthesizer.checks import postcondition_regs_exist
from synthesizer.disasm import cache_gadgets, get_function_addresses, load_cached_gadgets, disassemble_and_rebase_gadgets
from synthesizer.lift import lift_all_gadgets
from synthesizer.smt import build_smt_formula
from synthesizer.types_ import GadgetIRTy, AsmGadget, DisasSettings, RawGadget
from synthesizer.utils import min_or_some
from synthesizer.verification import verify_gadget_chain
from synthesizer.helper import dump_report, extract_gadget_chain, extract_initial_stack_assignment
from synthesizer.selection import choose_gadgets


TMP_PATH = Path("/tmp/gadget_synthesis/")

logger = logging.getLogger('synthesizer')


def setup_logging(target_dir: Path) -> None:
    """Setup logger"""
    console_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(target_dir / 'synthesizer.log', 'w+')
    console_handler.setLevel(logging.INFO)
    file_handler.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    console_handler.setFormatter(logging.Formatter('%(name)-24s | %(processName)-17s - %(levelname)-8s: %(message)s'))
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)-24s | %(processName)-17s - %(levelname)-8s: %(message)s'))
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


def cache_all_library_gadgets(target_config: TargetConfig, disas_settings: DisasSettings) -> None:
    for library in target_config.libraries:
        lib_disas_settings = copy.deepcopy(disas_settings)
        lib_disas_settings.target_name = library.name
        lib_disas_settings.target = library.path
        lib_disas_settings.cache_name = f"{library.name}_gadgets"
        lib_disas_settings.workdir = disas_settings.workdir.parent / library.name
        lib_disas_settings.workdir.mkdir(exist_ok=True)
        library.disas_settings = lib_disas_settings
        get_function_addresses(library.path, disas_settings.workdir, cache_name=f"{library.name}_func_addrs")
        cache_gadgets(lib_disas_settings)


def lift_asm_gadgets(arch_context: ArchContext, gadgets: List[AsmGadget], loc_db: LocationDB, stats: Dict[str, Any]) \
        -> List[GadgetIRTy]:
    """Lift to IRA"""
    start = time.time()
    iras: List[GadgetIRTy] = lift_all_gadgets(gadgets, loc_db, arch_context)
    logger.info(f"Lifted {len(gadgets)} ASM gadgets to {len(iras)} IRa gadgets in {round(time.time() - start, 2)}s")
    if len(iras) < len(gadgets):
        logger.warning(f"Lifting failed in {len(gadgets) - len(iras)} cases")
    stats["num_ir_gadgets"] = len(iras)
    return iras


def encode_ir_gadgets(iras: List[GadgetIRTy],
                      synthesizer_config: SynthesizerConfig,
                      target_config: TargetConfig, loc_db: LocationDB,
                      stats: Dict[str, Any]) -> str:

    logger.debug("Encoding IR gadgets as SMT formula")
    start = time.time()

    formula = build_smt_formula(iras, synthesizer_config, target_config, loc_db=loc_db)

    stats["time_encoding"] = time.time() - start
    logger.info(f"Encoded {len(iras)} IR gadgets as SMT formula"
                f" ({len(formula.splitlines())} assertions)"
                f" in {round(time.time() - start, 2)}s")
    return formula


def run_solver(solver: SMTSolver, formula: str, workdir: Path, timeout: int,
               stats: Dict[str, Any]) -> Tuple[SMTResult, SMTModel]:
    """Run SMT solver and return model (if any)"""
    logger.info(f"Running solver {solver}")
    start = time.time()

    solver_result, output = solver.check(formula, workdir, timeout)

    stats["time_solver"] = time.time() - start
    stats["result"] = solver_result.name
    logger.info(f"Solver returned {solver_result.name} in {round(stats['time_solver'], 2)}s")

    model: Optional[SMTModel] = None
    if solver_result == SMTResult.SAT:
        start = time.time()
        model = solver.parse_model(output)
        logger.info(f"Model was parsed in {round(time.time() - start, 2)}s")

    return solver_result, model


def load_and_select_gadgets(synthesizer_config: SynthesizerConfig, target_config: TargetConfig, disas_settings: DisasSettings, stats: Dict[str, Any]) -> List[RawGadget]:
    gadget_addrs: List[RawGadget] = []
    if synthesizer_config.selection_location == SelectionLocation.MAIN_EXE or \
        synthesizer_config.selection_location == SelectionLocation.MIXED:
        main_exe_addrs: List[int] = load_cached_gadgets(disas_settings)

        gadget_addrs = [RawGadget(addr, "main_exe") for addr in main_exe_addrs]
    if synthesizer_config.selection_location == SelectionLocation.LIBRARIES or \
        synthesizer_config.selection_location == SelectionLocation.MIXED:
        for library in target_config.libraries:
            assert library.disas_settings is not None, f"{library} has no disassembly settings set!"
            lib_addrs = load_cached_gadgets(library.disas_settings)
            gadget_addrs += [RawGadget(addr, library.name) for addr in lib_addrs]

    assert len(gadget_addrs) > 0, f"Failed to load any gadget addresses; Mode was {synthesizer_config.selection_location.name}"
    stats["num_all_gadget_addresses"] = len(gadget_addrs)
    # get N gadgets
    selected_gadget_addresses: List[RawGadget] = choose_gadgets(gadget_addrs, synthesizer_config, target_config)
    stats["num_selected_gadget_addresses"] = len(selected_gadget_addresses)
    return selected_gadget_addresses


def run_config(synthesizer_config: SynthesizerConfig, target_config: TargetConfig,
               disas_settings: DisasSettings, workdirs: Path, verbose: bool
               ) -> Dict[str, Any]:

    workdir = workdirs / str(synthesizer_config)
    workdir.mkdir()
    logger.debug(f"Workdir is {workdir.as_posix()}")
    if synthesizer_config.selection_strategy == SelectionStrategy.Seed:
        logger.debug(f"Seed is {synthesizer_config.initial_seed_or_offset}")
    elif synthesizer_config.selection_strategy == SelectionStrategy.Deterministic:
        logger.debug(f"Offset is {synthesizer_config.initial_seed_or_offset}")
    else:
        raise NotImplementedError(f"Selection stategy {synthesizer_config.selection_strategy.name} not implemented")

    stats: Dict[str, Union[str, int, float, List[str]]] = {}
    stats["settings_iterations"] = synthesizer_config.iterations
    stats["settings_block_limit"] = synthesizer_config.block_limit
    stats["settings_selection_strategy"] = synthesizer_config.selection_strategy.name
    stats["settings_initial_seed_or_offset"] = synthesizer_config.initial_seed_or_offset
    stats["settings_disassemble_unaligned"] = synthesizer_config.disassemble_unaligned
    stats["settings_stack_words"] = min_or_some(synthesizer_config.max_stack_words, target_config.stack_words)
    stats["preconditions"] = [str(c) for c in target_config.preconditions.values()]
    stats["postconditions"] = [str(c) for c in target_config.postconditions.values()]

    selected_gadget_addresses: List[RawGadget] = load_and_select_gadgets(synthesizer_config, target_config, disas_settings, stats)

    start = time.time()
    gadgets, loc_db = disassemble_and_rebase_gadgets(selected_gadget_addresses, target_config)
    stats["num_asm_gadgets"] = len(gadgets)
    if len(gadgets) < len(selected_gadget_addresses):
        logger.warning(f"Failed to disassemble {len(gadgets) - len(selected_gadget_addresses)} gadgets")
    logger.info(f"Disassembled ASM block for {len(gadgets)} gadgets in {round(time.time() - start, 2)}s")

    if verbose:
        start = time.time()
        gadgets_txt = workdir / "asm_gadgets.txt"
        with open(gadgets_txt, "w") as f:
            for g in gadgets:
                f.write("%s:\n" % hex(g.addr))
                f.write(str(g.block))
                f.write("\n" + "=" * 40 + "\n")
        logger.debug(f"{gadgets_txt.name} written in {round(time.time() - start, 2)}s")

    # lift to IR
    iras: List[GadgetIRTy] = lift_asm_gadgets(target_config.arch_context, gadgets, loc_db, stats)

    # check if the postconditions can be fulfilled given our selected gadgets
    # it may be impossible when a certain register is never used as destination,
    # thus there is no way to control it
    if not postcondition_regs_exist(list(target_config.postconditions.keys()), iras):
        logger.error("At least one postcondition cannot be fulfilled by selected gadgets. Not running SMT solver!")
        stats["result"] = "UNSOLVABLE"
        stats_json = workdir / "result.json"
        with open(stats_json, "w") as f:
            json.dump(stats, f, indent=2)
        logger.debug(f"{stats_json.name} written")
        return stats

    # get solver and add constraints
    smt2_formula = encode_ir_gadgets(iras, synthesizer_config, target_config, loc_db, stats)

    # add prefix and postfix
    smt2_formula = "(set-logic QF_ABV)\n" + smt2_formula + "(check-sat)\n(get-model)\n"

    start = time.time()
    formula_file = workdir / "formula-smt2.txt"
    with open(formula_file, "w") as f:
        f.write(smt2_formula)
    logger.debug(f"{formula_file.name} written in {round(time.time() - start, 2)}s")

    # run SMT Solver
    solver_result, model = run_solver(synthesizer_config.solver, smt2_formula, workdir, synthesizer_config.solver_timeout, stats)

    if solver_result == SMTResult.SAT:
        # print_model(model, synthesizer_config, target_config, workdir)
        # Create report.txt and stack.txt
        dump_report(model, target_config.arch_context, synthesizer_config.iterations, loc_db,
                    gadgets, iras, workdir, verbose)

        # verify results
        stack = extract_initial_stack_assignment(model, target_config.arch_context.address_size)
        chain = list(extract_gadget_chain(model, synthesizer_config.iterations))

        is_correct = verify_gadget_chain(gadgets, chain, stack, target_config, loc_db)
        stats["verification"] = is_correct
        if not is_correct:
            logger.error("Verification found chain to be incorrect")

    stats_json = workdir / "result.json"
    with open(stats_json, "w") as f:
        json.dump(stats, f, indent=2)
    logger.debug(f"{stats_json.name} written")

    return stats


def prepare_caches(target: Path, workdir: Path, target_config: TargetConfig, disas_settings: DisasSettings) -> None:
        logger.debug(f"Preparing {target.name}")

        # in a first step, ensure Ghidra results are cached -- currently this is not thread-safe
        # and there is no point in running Ghidra more than once
        extractor_wd = workdir / "gadget_extractor"
        extractor_wd.mkdir()
        logger.debug(f"Ensure function addresses are cached for {target.name}")
        _ = get_function_addresses(target_config.executable, extractor_wd)

        # extract all gadgets for the target and make sure they are cached
        logger.debug(f"Ensure valid gadgets are cached for {target.name}")
        cache_gadgets(disas_settings)

        if target_config.libraries:
            logger.debug("Ensure necessary libraries are cached")
            cache_all_library_gadgets(target_config, disas_settings)


def run_config_mp_wrapper(target: Path, target_config: TargetConfig, disas_settings: DisasSettings, workdirs: Path,
                         verbose: bool, synthesizer_config: SynthesizerConfig) -> Dict[str, Any]:
    logger.info(f"Running config: {target.name} - {synthesizer_config}")
    return run_config(synthesizer_config, target_config, disas_settings, workdirs, verbose)


def mp_wrapper(tup: 'Tuple[partial[Dict[str, Any]], SynthesizerConfig]') -> Dict[str, Any]:
    """
    Each function has a specific partial to be used for all its configs. We unpack this
    tuple and call partial_of_target(one_target_config) here.
    """
    return tup[0](tup[1])


def main(targets: List[Path], config_name: str, out_dir: Path, max_processes: int, verbose: bool) -> None:
    settings = SynthesizerSettings(Path("synthesizer_config_default.json"))
    results: List[Dict[str, Any]] = []
    tasks: List[Tuple[partial[Dict[str, Any]], SynthesizerConfig]] = []
    for target in targets:
        workdir = out_dir / target.name
        workdir.mkdir()
        logger.debug(f"Using configuration at {(target / config_name).as_posix()}")
        target_config = TargetConfig(target / config_name)
        disas_settings = DisasSettings(
            target_name=target_config.executable.name,
            target=target_config.executable,
            workdir=workdir,
            disas_unaligned=settings.disassemble_unaligned,
            control_flow_types=settings.control_flow_types,
            max_processes=max_processes,
            timeout=settings.disassembly_timeout,
            cache_name="gadgets",
            cache_type=CacheType.JSON
        )
        logger.debug(f"Disassembly settings used: {str(disas_settings)}")
        # ensure functions and gadgets are cached (also for libraries if need be)
        prepare_caches(target, workdir, target_config, disas_settings)

        all_possible_configs = list(settings.all_config_permutations(target_config.stack_words))
        partial_run_config = partial(run_config_mp_wrapper, target, target_config, disas_settings, workdir, verbose)
        for conf in all_possible_configs:
            tasks.append((partial_run_config, conf))
        logger.info(f"Colleted {len(all_possible_configs)} configurations for {target.name}")

    logger.debug(f"Collected {len(tasks)} configruations in total")
    with Pool(max_processes) as pool:
        results = pool.map(mp_wrapper, tasks)
    logger.debug(f"Received {len(results)} results")


def main_single_threaded(targets: List[Path], config_name: str, out_dir: Path, verbose: bool) -> None:
    settings = SynthesizerSettings(Path("synthesizer_config_default.json"))
    # if we run singlethreaded, we can optimize the process by extracting the gadgets only once
    for target in targets:
        start = time.time()
        logger.info(f"Processing {target.name}")
        workdir = out_dir / target.name
        workdir.mkdir()

        results: List[Dict[str, Any]] = []
        logger.debug(f"Using configuration at {(target / config_name).as_posix()}")
        target_config = TargetConfig(target / config_name)

        disas_settings = DisasSettings(
            target_name=target_config.executable.name,
            target=target_config.executable,
            workdir=workdir,
            disas_unaligned=settings.disassemble_unaligned,
            control_flow_types=settings.control_flow_types,
            max_processes=1,
            timeout=settings.disassembly_timeout,
            cache_name="gadgets",
            cache_type=CacheType.JSON
            )
        logger.debug(f"Disassembly settings used: {str(disas_settings)}")

        # ensure functions and gadgets are cached (also for libraries if needed)
        prepare_caches(target, workdir, target_config, disas_settings)

        all_configs = list(settings.all_config_permutations(target_config.stack_words))
        logger.debug(f"Found {len(all_configs)} configurations")

        results = []
        for conf in all_configs:
            logger.info(f"Running config: {target.name} - {conf}")
            results.append(run_config(conf, target_config, disas_settings, workdir, verbose))
        logger.info(f"Processed {target.name} in {round(time.time() - start, 2)}s")


if __name__ == "__main__":
    cpu_count = os.cpu_count()
    if cpu_count is None:
        cpu_count = 1
    parser = argparse.ArgumentParser(description="Synthesize a gadget chain")
    parser.add_argument("targets", nargs='+', type=Path, help="Path to target directory; must contain config.json")
    parser.add_argument("-c", "--config", dest="config_name", type=str, default="config.json", help="Name of config. Default: config.json")
    parser.add_argument("-o", "--out", dest="out_dir", metavar="out", type=Path,
                        default=TMP_PATH, help="Define path of results directory")
    parser.add_argument("-v", "--verbose", action="store_true",
                        default=False, help="Increase output verbosity")
    parser.add_argument("-j", "--threads", nargs='?', const=os.cpu_count(), default=1,
                        type=int, dest="max_processes", help="number of processes to use")
    parser.add_argument("--all", action="store_true", default=False,
                        help="Find recursively all config.json files in given target dirs")
    args = parser.parse_args()
    if args.out_dir.exists():
        print(f"{args.out_dir} exists - aborting..")
        sys.exit(1)
    args.max_processes = args.max_processes if args.max_processes > 0 else os.cpu_count()
    args.out_dir.mkdir(parents=True)
    setup_logging(args.out_dir)
    # TODO: this hardcodes the targets directory location
    starttime = time.time()
    logger.info("Starting synthesizer")
    logger.debug(f"Using up to {args.max_processes} processes")
    if args.all:
        new_targets = []
        for t in args.targets:
            new_targets.extend([tt.parent for tt in t.glob(f"**/{args.config_name}")])
        args.targets = new_targets
    if args.max_processes == 1:
        main_single_threaded([t.absolute() for t in args.targets], args.config_name, args.out_dir, args.verbose)
    else:
        main([t.absolute() for t in args.targets], args.config_name, args.out_dir, args.max_processes, args.verbose)
    logger.info(f"Done in {round(time.time() - starttime, 2)}s")
