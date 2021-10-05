#!/usr/bin/python3
import json
import logging
import os
import shutil
import subprocess
import time
from argparse import ArgumentParser
from pathlib import Path
from typing import Any, Dict, Union

logger = logging.getLogger("gdb_verify")


def setup_logging(logger: logging.Logger, target_dir: Path, log_name: str) -> None:
    """Setup logger"""
    console_handler = logging.StreamHandler()
    file_handler = logging.FileHandler(target_dir / log_name, 'w+')
    console_handler.setLevel(logging.DEBUG)
    file_handler.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    console_handler.setFormatter(logging.Formatter('%(name)-24s | %(processName)-17s - %(levelname)-8s: %(message)s'))
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)-24s | %(processName)-17s - %(levelname)-8s: %(message)s'))
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


def to_int(num: Union[int, str]) -> int:
    if isinstance(num, int):
        return num
    if num.startswith("0x"):
        return int(num, 16)
    return int(num, 10)


def load_config(path: Path) -> Dict[str, Any]:
    with open(path, 'r') as f:
        content: Dict[str, Any] = json.load(f)
    return content


def assert_has_valid_config(path: Path, func: str) -> None:
    assert path.is_dir(), f"{path} not a directory"
    assert (path / f"config_{func}.json").is_file(), f'{path / f"config_{func}.json"} does not exist or not a file'


def assert_is_valid_function(target: str) -> None:
    assert target in ("execve", "mprotect", "mmap"), \
        f'"{target}" is not a valid target. Must be one of ("execve", "mprotect", "mmap")'


def assert_is_valid_tool(tool: str) -> None:
    assert tool in ("tool", "ropgadget", "ropper", "angrop", "ropium", "pshape"), \
        f'"{tool}" is not a valid tool. Must be one of ("tool", "ropgadget", "ropper", "angrop", "ropium", "pshape")'


def create_gdb_commands_file(file_: Path, config: Path, stack_str: str, func: str) -> None:
    libs_dir = config.parent / "libs"
    with open(file_, 'w') as f:
        if libs_dir.is_dir():
            f.write(f"set environment LD_LIBRARY_PATH={simplify_path(libs_dir.absolute()).as_posix()}\n")
        f.write("source gdb_script_verify_chain.py\n")
        f.write(f"verify_chain {config.as_posix()} {func} {stack_str}\n")


def parse_gdb_output(stdout: str) -> None:
    lines = [l.strip() for l in stdout.split("\n") if l.strip()]
    interesting_msgs = list(filter(lambda l: \
        l.startswith("INFO:") or \
        l.startswith("ERROR:") or \
        l.startswith("WARNING:"), lines))
    for msg in interesting_msgs:
        logger.info(msg.replace("INFO:", "GDB:").replace("ERROR:", "GDB:").replace("WARNING:", "GDB:"))


def simplify_path(p: Path) -> Path:
    ps = p.as_posix()
    psl = [e for e in ps.split("/") if e.strip()]
    ignore = 0
    poutl = []
    for e in psl[::-1]:
        if e == "..":
            ignore += 1
        else:
            if ignore:
                ignore -= 1
            else:
                poutl += [e]
    return Path("/" + "/".join(poutl[::-1]))


def main(config_path: Path, stackfile: Path, tool: str, target: str, func: str) -> None:
    path = config_path.parent
    start_time = time.time()
    logger.debug(f"tool={tool}, func={func}, target={target}")
    # sanity checks
    assert path.name == target, f"Path gives target {path.name}, but stackfile is associated with {target}"
    config_path_func_name = config_path.name.rstrip(".json").split("_")[1]
    assert config_path_func_name == func, f"Config gives target {config_path_func_name}, but stackfile is associated with {func}"
    assert stackfile.is_file() and stackfile.name == "stack.txt", f"File not found or wrong name (found {stackfile.name}, expected stack.txt)"
    assert_is_valid_function(func)
    assert_is_valid_tool(tool)
    assert_has_valid_config(path, func)
    # load config
    config = load_config(config_path)
    executable = (path / config['executable']).absolute()
    assert executable.is_file(), f"{executable} not a file or not found"

    with open(stackfile, 'r') as f:
        stack_str = f.read().strip()
    gdb_commands_file = stackfile.parent / f"commands_{tool}_{target}_{func}"
    logger.debug(f"Creating gdb commands file '{gdb_commands_file.as_posix()}'")
    create_gdb_commands_file(gdb_commands_file, config_path, stack_str, func)

    # if necessary, set LD_LIBRARIES
    libs_dir = config_path.parent / "libs"
    env = dict(os.environ)
    if libs_dir.is_dir():
        logger.debug(f"Setting LD_LIBRARY_PATH={simplify_path(libs_dir.absolute()).as_posix()}")
        env["LD_LIBRARY_PATH"] = simplify_path(libs_dir.absolute()).as_posix()
    cmd = ["gdb", "-batch", "-x", gdb_commands_file.as_posix()]
    logger.debug(f"Running GDB: {' '.join(cmd)}")
    try:
        p = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        logger.debug("GDB completed")
        stdout = p.stdout.decode()
    except subprocess.CalledProcessError as e:
        logger.error(f"GDB error: {str(e)}")
        stdout = e.stdout.decode()
        print("GDB output:")
        print(stdout)

    with open(stackfile.parent / "gdb.log", 'w') as f:
        f.write(stdout)
    logger.debug("Parsing output")
    parse_gdb_output(stdout)
    logger.info(f"Done in {round(time.time() - start_time, 2)}s")


if __name__ == "__main__":
    parser = ArgumentParser(description="Given a target's config and a chain, use GDB to insert the chain and verify that we indeed arrive at the desired outcome")
    parser.add_argument("path", type=Path, help="Path to target config")
    parser.add_argument("stackfile", type=Path, help="Path to stack.txt file which contains the chain to be dropped on the stack")
    parser.add_argument("tool", type=str, help="Tool name")
    parser.add_argument("target", type=str, help="Target name")
    parser.add_argument("func", type=str, help="Function name")
    args = parser.parse_args()
    logfile = "log_verify_gdb.log"
    setup_logging(logger, Path("."), logfile)
    main(args.path.resolve(), args.stackfile.resolve(), args.tool, args.target, args.func)
    shutil.copy(logfile, args.stackfile.parent / logfile)
