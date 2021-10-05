#!/usr/bin/python3

import argparse
import copy
import logging
import os
import sys
import time
import multiprocessing_logging; multiprocessing_logging.install_mp_handler()
from pathlib import Path
from typing import List

from synthesizer.config import SynthesizerSettings, TargetConfig
from synthesizer.cache import CacheType
from synthesizer.disasm import cache_gadgets, get_function_addresses
from synthesizer.types_ import DisasSettings

TMP_PATH = Path("/tmp/gadget_synthesis_initial_disassembly/")

logger = logging.getLogger('synthesizer')


def setup_logging(target_dir: Path) -> None:
    """Setup logger"""
    console_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(target_dir / 'synthesizer_initial_disassembly.log', 'w+')
    console_handler.setLevel(logging.DEBUG)
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
        lib_disas_settings.workdir.mkdir()
        library.disas_settings = lib_disas_settings
        get_function_addresses(library.path, disas_settings.workdir, cache_name=f"{library.name}_func_addrs")
        cache_gadgets(lib_disas_settings)


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


def main(targets: List[Path], config_name: str, out_dir: Path, max_processes: int) -> None:
    settings = SynthesizerSettings(Path("synthesizer_config_default.json"))
    # if we run singlethreaded, we can optimize the process by extracting the gadgets only once
    for target in targets:
        start = time.time()
        logger.info(f"Processing {target.name}")
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

        # ensure functions and gadgets are cached (also for libraries if needed)
        prepare_caches(target, workdir, target_config, disas_settings)

        all_configs = list(settings.all_config_permutations(target_config.stack_words))
        logger.debug(f"Found {len(all_configs)} configurations")

        logger.info(f"Processed {target.name} in {round(time.time() - start, 2)}s")


if __name__ == "__main__":
    cpu_count = os.cpu_count()
    if cpu_count is None:
        cpu_count = 1
    parser = argparse.ArgumentParser(description="Extract function addresses, disassemble all gadgets and filter valid ones - results are cached such that run.py may use them")
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
    starttime = time.time()
    logger.info("Starting initial extraction and disassembly")
    logger.debug(f"Using up to {args.max_processes} processes")
    if args.all:
        new_targets = []
        for t in args.targets:
            new_targets.extend([tt.parent for tt in t.glob(f"**/{args.config_name}")])
        args.targets = new_targets
    main([t.absolute() for t in args.targets], args.config_name, args.out_dir, args.max_processes)
    logger.info(f"Done in {round(time.time() - starttime, 2)}s")
