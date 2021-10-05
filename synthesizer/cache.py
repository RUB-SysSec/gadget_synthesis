"""
Simple "cache" to avoid extracting function / gadget addresses more than once.
"""
from enum import Enum
from typing import Any, Dict, Optional
from pathlib import Path
import os
import logging

import hashlib
import msgpack
import json
import pickle

logger = logging.getLogger("synthesizer.cache")

class CacheType(Enum):
    MSGPACK = 0,
    JSON = 1,
    PICKLE = 2

class Cache(object):
    """
    We store a few things in a file (to "cache" them), notably
    a) functions initially discovered by Ghidra/Binary Ninja,
    b) gadget addresses disassembled
    """
    cache_dir_name = ".cache"
    cache_metadata_name = ".metadata"

    def __init__(self, target_file: Path, cache_name: str, cache_type: CacheType = CacheType.MSGPACK):
        path = target_file.parent
        self.path = path
        assert isinstance(cache_type, CacheType), "cache_type must be instance of CacheType" 
        self.cache_type = cache_type
        self.cache_dir = path / self.cache_dir_name
        self.cache_file = path / self.cache_dir_name / (cache_name + "." + cache_type.name.lower())
        self.cache_metadata = self.cache_dir / self.cache_metadata_name
        self.cache_target_name = target_file.name
        logger.debug(f"Cache intialized ({self.cache_file.name})")

        self.cache_dir.mkdir(exist_ok=True, parents=False)
        if not self.cache_metadata.exists():
            with open(self.cache_metadata, 'w') as f:
                f.write("\n")
        logger.debug(f"Metadata is at {self.cache_metadata}")

    def cache_exists(self) -> bool:
        return self.cache_file.is_file()
    
    def read_from_cache(self) -> Optional[Any]:
        if not self.cache_exists():
            logger.debug(f"{self.cache_file.name}: Read failed; cache does not exist")
            return None
        if os.environ.get("SYNTHESIZER_IGNORE_CACHE", "0") == "1":
            logger.debug(f"{self.cache_file.name}: Ignoring cache read as SYNTHESIZER_IGNORE_CACHE=1 is set")
            return None
        # check if target hash is still relevant
        cur_hash = self._get_cur_hash()
        if cur_hash is None:
            logger.debug(f"{self.cache_file.name}: File not cached")
            return None
        actual_hash = self._hash_target()
        if cur_hash != actual_hash:
            logger.debug(f"{self.cache_file.name}: Hash mismatch; Data is valid for {cur_hash} but binary's hash is {actual_hash} (SHA-256)")
            return None
        if self.cache_type == CacheType.MSGPACK:
            with open(self.cache_file, "rb") as msgpack_file:
                byte_data = msgpack_file.read()
                data = msgpack.unpackb(byte_data)
        elif self.cache_type == CacheType.JSON:
            with open(self.cache_file, 'r') as json_file:
                data = json.load(json_file)
        elif self.cache_type == CacheType.PICKLE:
            with open(self.cache_file , 'rb') as pickle_file:
                data = pickle.load(pickle_file)
        else:
            raise NotImplementedError(f"Cache file type '{self.cache_type.name}' read not implemented")
        return self._postprocess_data(data)
    
    def write_to_cache(self, data: Any) -> None:
        new_hash = self._hash_target()
        if self.cache_exists() and not os.environ.get("SYNTHESIZER_IGNORE_CACHE", "0") == "1":
            # Check if hash matches -- if so, no need to store again
            cur_hash = self._get_cur_hash()
            if cur_hash is not None and new_hash == cur_hash:
                logger.debug(f"{self.cache_file.name}: data already cached")
                return None
        data = self._preprocess_data(data)
        if self.cache_type == CacheType.MSGPACK:
            with open(self.cache_file, 'wb') as msgpack_file:
                packed_data = msgpack.packb(data)
                msgpack_file.write(packed_data)
        elif self.cache_type == CacheType.JSON:
            with open(self.cache_file, 'w') as json_file:
                json.dump(data, json_file)
        elif self.cache_type == CacheType.PICKLE:
            with open(self.cache_file, 'wb') as pickle_file:
                pickle.dump(data, pickle_file)
        else:
            raise NotImplementedError(f"Cache file type '{self.cache_type.name}' write not implemented")
        self._set_cur_hash(new_hash)
        logger.debug(f"{self.cache_file.name}: Data stored in cache (associated with {self.cache_target_name}:{new_hash})")
    
    def _preprocess_data(self, data: Any) -> Any:
        return data
    
    def _postprocess_data(self, data: Any) -> Any:
        return data

    def _hash_target(self) -> str:
        m = hashlib.sha256()
        # 64kb chunks
        BUF_SIZE = 65536
        with open(self.path / self.cache_target_name, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                m.update(data)
        return m.hexdigest()
    
    def _read_metadata(self) -> Dict[str, str]:
        metadata = {}
        with open(self.cache_metadata, 'r') as f:
            content = [l.strip() for l in f.readlines() if l.strip()]
        for l in content:
            parts = l.split(":", 1)
            metadata[parts[0]] = parts[1]
        return metadata
    
    def _write_metadata(self, metadata: Dict[str, str]) -> None:
        with open(self.cache_metadata, 'w') as f:
            for (k, v) in metadata.items():
                f.write(f"{k}:{v}\n")

    def _get_cur_hash(self) -> Optional[str]:
        return self._read_metadata().get(self.cache_file.name + "_" + self.cache_target_name, None)

    def _set_cur_hash(self, hash_: str) -> None:
        md = self._read_metadata()
        md[self.cache_file.name + "_" + self.cache_target_name] = hash_
        self._write_metadata(md)
