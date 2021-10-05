"""
Functions to rebase Gadgets in the loc_db (Miasm per default extracts gadgets
as offset, not accounting for the load_address). To work with libraries,
we need to rebase all gadgets to their actual address.
"""
from typing import Dict, List
import copy

from miasm.core.locationdb import LocationDB

from .config import Constraint
from .types_ import AsmGadget

def rebase_addresses(addresses: List[int], base_addr: int) -> List[int]:
    rebased_addresses: List[int] = list(map(lambda gadget: base_addr + gadget, addresses))
    return rebased_addresses


# NOTE: this assumes all locations are position-independent
def rebase_loc_db(loc_db: LocationDB, base_addr: int) -> LocationDB:
    if base_addr == 0:
        return copy.deepcopy(loc_db)
    rebased_loc_db = LocationDB()
    for loc_key in loc_db.loc_keys:
        names = loc_db.get_location_names(loc_key)
        offset = loc_db.get_location_offset(loc_key)
        rebased_offset = base_addr + offset
        new_loc_key = rebased_loc_db.add_location(offset=rebased_offset)
        for name in names:
            rebased_loc_db.add_location_name(new_loc_key, name)
    return rebased_loc_db


def rebase_gadget(gadget: AsmGadget, base_addr: int) -> None:
    if base_addr == 0:
        return
    gadget.addr += base_addr
    for i in gadget.block.lines:
        i.offset += base_addr


def rebase_irdst(conditions: Dict[str, Constraint], base_addr: int) -> None:
    if conditions.get("IRDst", 0):
        conditions["IRDst"].value += base_addr
