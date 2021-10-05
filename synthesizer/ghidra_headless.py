from pathlib import Path
from typing import List, Optional
from subprocess import CalledProcessError, PIPE, TimeoutExpired, run
import shutil
import sys
import tempfile


def get_ghidra_path() -> Path:
    """
    Returns Ghidra path
    :return: Path
    """
    p = shutil.which("ghidra-analyzeHeadless")
    if p is None:
        raise RuntimeError("Failed to find ghidra-analyzeHeadless binary. Install Ghidra or verify its on PATH")
    return Path(p)


def ghidra_exists() -> bool:
    """
    Checks if Ghidra executable exists
    """
    return get_ghidra_path().is_file()


def run_ghidra(input_file: Path, script_path: Path, script_arguments: List[str], workdir: Optional[Path] = None) -> None:
    """
    Builds Ghidra command and runs exporter script
    :param input_file: Path, path to binary file
    :param script_path: Path, path to script file
    :param script_arguments: List[string], script arguments
    :param workdir: Optional[Path], path where Ghidra stdout/stderr are to be stored
    """
    # check if ghidra exists
    assert ghidra_exists(), "Ghidra not installed"

    # init temp dir
    tmp_dir = tempfile.TemporaryDirectory()

    # init
    project_path = Path(tmp_dir.name)

    project_name = "ghidra_project"
    cmd: List[str] = [get_ghidra_path().as_posix(),
                        project_path.as_posix(), project_name,
                        "-import", input_file.absolute().as_posix(),
                        "-postscript", script_path.as_posix(),
                     ] + script_arguments

    try:
        p = run(cmd, check=True, stdout=PIPE, stderr=PIPE)
        if workdir is not None:
            with open(workdir / "ghidra_stdout.txt", 'w') as f:
                f.write(p.stdout.decode())
            with open(workdir / "ghidra_stderr.txt", 'w') as f:
                f.write(p.stderr.decode())
    except CalledProcessError as e:
        print(e)
        sys.exit(1)
    except TimeoutExpired as e:
        print(e)
        sys.exit(1)

    # cleanup temp dir
    tmp_dir.cleanup()
