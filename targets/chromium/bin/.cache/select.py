import json
import random
from pathlib import Path

TIME = 23033.12
EXPECTED_NUM_FUNCS = 364263

with open("all_function_addrs.json", 'r') as f:
    f_addrs = json.load(f)

print(f"Found {len(f_addrs)} addresses")

assert len(f_addrs) == EXPECTED_NUM_FUNCS


hours = TIME / 3600.0

funcs_per_hour = int(round(len(f_addrs) / hours, 0))

print(f"~{funcs_per_hour} functions per hour")


f_addrs_1h = random.sample(f_addrs, k=funcs_per_hour)

print(f"Sampled {len(f_addrs_1h)} functions")

out_file = Path("function_addrs.json")

assert not out_file.exists(), "{out_file.as_posix()} already exists!"
with open(out_file, 'w') as f:
    json.dump(f_addrs_1h, f)

