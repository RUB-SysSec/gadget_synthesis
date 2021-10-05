from argparse import ArgumentParser
from pathlib import Path
from typing import List


def contains_badbytes(badbytes_strs: List[str], stack: List[str]) -> bool:
    for b in badbytes_strs:
        for s in stack:
            for i in range(0, len(s), 2):
                if b == s[i:i+2]:
                    print(f"{s} contains {b} (slice @ {i}:{i+2} {s[i:i+2]})")
                    return True
    return False

def main(stackfile: Path, badbytes: List[int]) -> None:
    assert stackfile.is_file() and stackfile.name == "stack.txt", f"File not found or wrong name (found {stackfile.name}, expected stack.txt)"
    with open(stackfile, 'r') as f:
        stack_str = f.read().strip()
    # stack = stack_str_to_stack_dict(stack_str, target_config.preconditions[target_config.arch_context.sp].value, target_config.arch_context.address_size)
    
    stack = [f"{int(v.strip(), 0):016x}" for v in stack_str.lstrip("[").rstrip("]").split(",")]
    badbytes_strs = [f"{b:02x}" for b in badbytes]
    
    if contains_badbytes(badbytes_strs, stack):
        print(f"ERROR: Chain contains badbytes")
    else:
        print(f"Chain successfully verified (no badbytes)")


if __name__ == "__main__":
    parser = ArgumentParser(description="Check if gadget chain contains badbytes")
    parser.add_argument("stackfile", type=Path, help="Path to stack.txt file which contains the chain to be dropped on the stack")
    parser.add_argument("badbytes", nargs="+", default=[], help="Bad bytes")
    args = parser.parse_args()
    main(args.stackfile, [int(b, 0) for b in args.badbytes])
