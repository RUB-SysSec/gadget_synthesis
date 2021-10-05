"""Classes and functions to handle SMT solver and their models"""

from pathlib import Path
from typing import Optional, Tuple

from .model import SMTResult, SMTModel

class SMTSolver(object):

    def __init__(self, name: str) -> None:
        self.name = name
    
    def check(self, smt2_formula: str, save_output_to: Optional[Path], timeout: int) -> Tuple[SMTResult, str]:
        raise NotImplementedError("needs subclass")
    
    def parse_model(self, model_str: str) -> SMTModel:
        raise NotImplementedError("needs subclass")
