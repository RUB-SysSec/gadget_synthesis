"""Wrapper for result returned by SMT solver"""

from enum import Enum
from typing import Any


class SMTResult(Enum):
    SAT = 0,
    UNSAT = 1,
    UNKNOWN = 2

class SMTModel(object):
    def __init__(self, model: Any) -> None:
        self.model = model

    def __str__(self) -> str:
        return str(self.model)

    def __getitem__(self, key: Any) -> Any:
        return self.model[key]

    def get(self, key: Any, default_value: Any) -> Any:
        return self.model.get(key, default_value)
