from dataclasses import dataclass
from functools import total_ordering
from pathlib import Path
from typing import List, Optional, Tuple
from miasm.analysis.machine import Machine

from miasm.core.asmblock import AsmBlock
from miasm.core.locationdb import LocationDB
from miasm.ir.ir import IRBlock

from .cache import CacheType


# Tuple: Address -> IR
GadgetIRTy = Tuple[int, IRBlock]


@dataclass
class AsmGadget(object):
    """
    Gadget in Miasm Asm representation
    """
    addr: int
    block: AsmBlock


@dataclass
class IrGadget(object):
    """
    Gadget in Miasm IR
    """
    addr: int
    block: IRBlock


@dataclass
class DisasSettings(object):
    """
    Settings to control the disassembly of gadgets
    """
    target_name: str
    target: Path
    workdir: Path
    disas_unaligned: bool
    control_flow_types: List[str]
    max_processes: int
    timeout: Optional[int]
    cache_name: str
    cache_type: CacheType = CacheType.JSON

    def __repr__(self) -> str:
        return f"target_name={self.target_name}, " \
               f"target={self.target}, " \
               f"workdir={self.workdir}, " \
               f"disas_unaligned={self.disas_unaligned}, " \
               f"control_flow_types={self.control_flow_types}, " \
               f"max_processes={self.max_processes}, " \
               f"timeout={self.timeout}, " \
               f"cache_name={self.cache_name}, " \
               f"cache_type={self.cache_type.name}"


@dataclass
class Library(object):
    """
    Dynamically linked library
    """
    name: str
    path: Path
    load_address: int
    loc_db: LocationDB = LocationDB()
    mdis: Optional[Machine] = None
    disas_settings: Optional[DisasSettings] = None

    def __hash__(self) -> int:
        return hash((self.path.name, self.load_address))


@total_ordering
@dataclass
class RawGadget(object):
    """
    A RawGadget is the address of a gadget (and its location, whether it is
    located in the main executable or some library)
    """
    addr: int
    location: str

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RawGadget):
            return self.addr == other.addr
        if isinstance(other, int):
            return self.addr == other
        raise RuntimeError(f"Unexpected type in __eq__: LHS is RawGadget, RHS is {type(other)}")

    def __lt__(self, other: 'RawGadget') -> bool:
        if isinstance(other, int):
            return self.addr < other
        if isinstance(other, RawGadget):
            return self.addr < other.addr
        raise RuntimeError(f"Unexpected type in __lt__: LHS is RawGadget, RHS is {type(other)}")

    def __hash__(self) -> int:
        return hash(str(self.addr) + self.location)
