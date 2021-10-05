#!/usr/bin/python
from pathlib import Path
from typing import Iterator, Optional
import time
import os

from binaryninja import BinaryViewType, SymbolType, core_set_license

# faster method for large binaries (such as browsers)
def bn_load_or_create_db_optimized(path: Path, timeout: Optional[int]) -> BinaryViewType:
    # check if we analyzed the binary before; If so, return cached DB
    cached_db = path.parent / ".cache" / (path.name + ".bndb")
    if cached_db.is_file():
        return BinaryViewType.get_view_of_file(cached_db)
    # else run initial auto-analysis and cache results
    options = {
        'analysis.mode': 'basic',
        'analysis.limits.maxFunctionAnalysisTime': 2000,
    }
    bv = BinaryViewType.get_view_of_file_with_options(path.as_posix(), options=options, update_analysis=False)
    if timeout:
        bv.update_analysis()
        time.sleep(timeout)
        bv.abort_analysis()
    else:
        bv.update_analysis_and_wait()
    bv.create_database(cached_db)
    return bv


def bn_load_or_create_db(path: Path) -> BinaryViewType:
    # check if we analyzed the binary before; If so, return cached DB
    cached_db = path.parent / ".cache" / (path.name + ".bndb")
    if cached_db.is_file():
        return BinaryViewType.get_view_of_file(cached_db)
    # else run initial auto-analysis and cache results
    bv = BinaryViewType.get_view_of_file(path)
    bv.create_database(cached_db)
    return bv


def bn_get_function_starts(path: Path, timeout: Optional[int] = 300) -> Iterator[int]:
    core_set_license(os.environ['BNLICENSE'])
    if "chromium" in path.name:
        bv = bn_load_or_create_db_optimized(path, timeout)
    else:
        bv = bn_load_or_create_db(path)

    for f in bv.functions:
        # ignore thunks
        if f.symbol.type == SymbolType.ImportedFunctionSymbol:
            continue
        yield f.start
