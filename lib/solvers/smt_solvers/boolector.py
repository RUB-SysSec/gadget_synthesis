"""Wrapper classes and functions to run Boolector"""

from pathlib import Path
from typing import Dict, Optional, Tuple, Union

import shutil
import subprocess

from .solver import SMTSolver
from .model import SMTResult, SMTModel 
from .smt2lib import DefaultDict, parse_smt2lib_model


class BoolectorModel(SMTModel):
    def __init__(self, model: Dict[str, Union[int, DefaultDict]]):
        self.model = model

    def __str__(self) -> str:
        result = ""
        for name, value in self.model.items():
            if isinstance(value, int):
                result += "%s: %x\n" % (name, value)
            elif isinstance(value, DefaultDict):
                for address, v in sorted(value.items()):
                    result += "%s[%s]: 0x%x\n" % (name, hex(address), v)
            else:
                raise NotImplementedError(f"Value is neither int nor tuple: {value}")
        return result




class BoolectorSolver(SMTSolver):
    
    sat_engines = ["lingeling", "cadical", "cms", "picosat"]

    def __init__(self, path: Optional[Path] = None, sat_engine: str = "picosat"):
        if path is None:
            which = shutil.which("boolector")
            if which is not None:
                path = Path(which)
            else:
                path = Path("/usr/bin/boolector")
        super().__init__("Boolector")
        assert sat_engine in self.sat_engines, f"Unknown Boolector SAT Engine: {sat_engine} (supported: {self.sat_engines}"
        self.sat_engine = sat_engine
        self.path = path
    
    def parse_model(self, model_str: str) -> BoolectorModel:
        return BoolectorModel(parse_smt2lib_model(model_str))
    
    def check(self, smt2_formula: str, save_dir: Optional[Path] = None, timeout: int = 3600) \
            -> Tuple[SMTResult, str]:

        input_bytes = bytes(smt2_formula, "ascii")

        try:
            result = subprocess.run(
                [
                    self.path,
                    "--model-gen",
                    "--sat-engine", self.sat_engine,
                    "--exit-codes", "0",
                    #"--loglevel", "99",
                    #"--verbosity", "3",
                ],
                input=input_bytes,
                capture_output=True,
                check=False,
                timeout=timeout)
        except subprocess.TimeoutExpired:
            return (SMTResult.UNKNOWN, f"TimeoutExpired: {timeout}s")

        if result.stderr:
            if save_dir is not None:
                with open(save_dir / "boolector-stderr.txt", "w") as f:
                    f.write(result.stdout.decode())
            return (SMTResult.UNKNOWN, result.stderr.decode())

        stdout = result.stdout.decode()
        if save_dir is not None:
            with open(save_dir / "boolector-stdout.txt", "w") as f:
                f.write(stdout)

        if "ALARM TRIGGERED" in stdout or "CAUGHT SIGNAL" in stdout:
            return (SMTResult.UNKNOWN, stdout)

        if result.returncode != 0:
            return (SMTResult.UNKNOWN, f"Bad returncode: {result.returncode}")

        sat_str, output = stdout.split("\n", 1)
        if sat_str == "sat":
            return (SMTResult.SAT, output)
        elif sat_str == "unsat":
            return (SMTResult.UNSAT, output)
        
        raise NotImplementedError(f"Unreachable: Neither SAT, UNSAT nor ALARM triggered: {output}")

    def __repr__(self) -> str:
        return self.path.as_posix()
