#!/usr/bin/python3
"""
GDB analysis script to verify whether a gadget chain is viable. Makes the verify_chain command available within GDB. 
The command expects a path to a TargetConfig file and a list of elements that should be placed on the stack
List format:     [0x123, 0x235324, 0x40000, 0xdeadbeef, ...]
Will be placed @ [  RSP,    RSP+8,  RSP+16,     RSP+24, ...]

Must be executed from inside of GDB! We recommend to create a gdb command file (e.g., 'gdb_commands'). Example:
``
source gdb_script_verify_chain.py
verify_chain ../targets/openssl/config_mprotect.json [0x00005555555D75BE, 0xFFFFFFFF000356A4, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFBFF, 0xFFFFFFFF00000040, 0xFFFFFFFFFFFFFFFF, 0x00005555555D81E0, 0x00007FFFF7B60D00, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF0000007B, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF]
```
and then run gdb -x gdb_commands
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import gdb

# Configuration options
# Trace execution of gadgets using 'stepi' rather than 'continue'. This populates the log with each executed
# gadget of the rop chain, helping to debug where a chain crashes for example
# Default: True
TRACE = True
# We need some 'ret' instruction from which we can switch to the chain (by inserting it on the stack, such that it is
# executed upon 'ret'). We either may use the first 'ret' found during program execution or start from the preconditioned
# IRDst. If this is set to False and LONG_CHAIN is still required, your chain will not work in practice.
# Default: False
USE_FIRST_RET = False
# The chain is extraordinarily long (and the available stack too small at the first return).
# If set, the stack pointer is set to a smaller value allowing for a larger chains (but possibly
# making the chain non-applicable in real programs - especially if USE_FIRST_RET is not set). Use with caution
# Default: False
LONG_CHAIN = False
# Initially, the program must be run and we must stop at some point, preferably the 'main' (which is done via GEF's
# 'entry' command). If GEF is unavailable, setting this to false will use 'starti' rather than 'entry'.
# Default: True
USE_ENTRY = True
# Our chain walking usually runs until the desired function (address) is reached; however, in the case of EXECVE, some syscall
# is called (not necessarily the one we use in the config). This requires the TRACE option to be set to TRUE
WALK_CHAIN_UNTIL_SYSCALL = TRACE and False
# When constructing a syscall, e.g., execve(&"/bin/sh", x, y), some tools set the parameters to argv and envp to 0, others
# however, provide a pointer to a 0 (as is intended). This flag allows the latter behavior (and if 0 is expected by our
# postconditions, checks whether a pointer to 0 is provided). Should be only applied to execve scenario
ALLOW_PTR_TO_ZERO = WALK_CHAIN_UNTIL_SYSCALL and True
# End configuration options


# this flag is used to communicate when the program segfaults
PROCESS_EXITED = False


def check_aslr() -> bool:
    with open("/proc/sys/kernel/randomize_va_space", 'r') as f:
        aslr = f.read().strip()
    if aslr != "0":
        print(f"ERROR: ASLR ENABLED (randomize_va_space={aslr}). To disable, run echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")
        return False
    return True


def load_config(path: Path) -> Dict[str, Any]:
    with open(path, 'r') as f:
        content: Dict[str, Any] = json.load(f)
    return content


def to_int(num: Union[int, str, gdb.Value]) -> int:
    if isinstance(num, int):
        return num
    if isinstance(num, gdb.Value):
        if str(num.type) == "int64_t":
            return int(num)
        res = to_int(str(num))
        return res
    if num.startswith("0x"):
        return int(num, 16)
    return int(num, 10)


def rebase(val: int, load_addr: int) -> int:
    if val >= load_addr:
        return val
    return val + load_addr


def parse_stack(stack_str: str) -> List[int]:
    stack_str = stack_str.strip()
    assert stack_str.startswith("[") and stack_str.endswith("]"), "Expected leading '[' and final ']'"
    stack_str = stack_str.lstrip("[").rstrip("]")
    stack: List[int] = []
    vals = stack_str.split(",")
    for val in vals:
        stack.append(to_int(val.strip()))
    return stack


def exec(cmd: str) -> None:
    print(cmd)
    gdb.execute(cmd)


def exec_silent(cmd: str) -> str:
    returned_string: str = gdb.execute(cmd, to_string=True)
    return returned_string


def get_reg_val(reg: str, address_size: int) -> int:
    reg_val = gdb.parse_and_eval(f"${reg}")
    if " " in str(reg_val):
        reg_val = str(reg_val).split(" ", 1)[0]
    res = to_int(reg_val)
    if res < 0:
        res = (res + 2**address_size) % 2**address_size
    return res


def get_pc() -> int:
    pc = gdb.parse_and_eval(f"$pc")
    if " " in str(pc):
        pc = str(pc).split(" ", 1)[0]
    return to_int(pc)


def step_until_asm(mnemonic: str, silent: bool = False) -> None:
    arch = gdb.selected_frame().architecture()
    while not PROCESS_EXITED:
        pc = get_pc()
        disasm = arch.disassemble(pc)[0]
        if mnemonic in disasm["asm"]:
            ds = disasm
            break
        if silent:
            exec_silent("stepi")
        else:
            exec("stepi")
    if not PROCESS_EXITED:
        print(f"DEBUG: Reached '{ds['asm'].strip()}' @ {ds['addr']:#x}")
    return


def step_until_address(address: int, silent: bool = False) -> None:
    pc = get_pc()
    while pc != address and not PROCESS_EXITED:
        if silent:
            exec_silent("stepi")
        else:
            exec("stepi")
        pc = get_pc()


def pivot_stack(offset: int, address_size: int) -> None:
    # adjust stack pointer by offset
    # offset may be negative to increase stack size (used by LONG_CHAIN)
    print(f"DEBUG: Pivoting stack by {offset}")
    rsp = get_reg_val("rsp", address_size)
    cmd = f"set $rsp = {rsp-4096*8:#x}"
    exec(cmd)


def get_address_size(arch_str: str) -> int:
    if arch_str == "x86_64":
        return 64
    elif arch_str == "x86_32":
        return 32
    else:
        raise NotImplementedError(f"Architecture '{arch_str}' not implemented")


def examine_memory(address: int, address_size: int) -> Optional[int]:
    if address_size == 64:
        unit_size = 'g'
    else:
        unit_size = 'w'
    # display one element in hexadecimal notation (4 or 8 bytes)
    cmd = f"x/1x{unit_size} {address}"
    try:
        line = exec_silent(cmd)
    except Exception as e:
        print(f"ERROR: Cannot access memory at {address:#x}")
        print(f"DEBUG: Exception was: {str(e)}")
        return None
    return to_int(line.split(":", 1)[1].strip())


def exit_handler(event: 'gdb.Event') -> None:
    global PROCESS_EXITED
    if hasattr(event, 'inferior'):
        print(f"DEBUG: inferior={event.inferior}")
    if hasattr(event, 'exit_code'):
        print(f"WARNING: Process exited with code {event.exit_code}")
    else: # if exit was forced by 'quit', no exit code exists
        print(f"INFO: Process exited")
    PROCESS_EXITED = True


def signal_handler(event: gdb.Event) -> None:
    global PROCESS_EXITED
    if (isinstance (event, gdb.SignalEvent)):
        print(f"WARNING: Process received signal {event.stop_signal}")
        PROCESS_EXITED = True


def set_preconditions(preconditions: Dict[str, int], address_size: int) -> None:
    print("DEBUG: Setting preconditions..")
    for reg in preconditions.keys():
        if reg == "IRDst":
            continue
        # set all preconditions
        reg_str = reg.lower()
        reg_val = preconditions[reg]
        # print(f"{reg_str} <- {reg_val:#x}")
        # reg_cur_val = get_reg_val(reg_str))
        # print(f"reg_str={reg_cur_val}")
        cmd = f"set ${reg_str} = {reg_val:#x}"
        exec(cmd)
        reg_cur_val = get_reg_val(reg_str, address_size)
        assert reg_cur_val == reg_val, f"Failed to set precondition value ({reg_str} is {reg_cur_val:#x} but should be {reg_val:#x})"
        # reg_cur_val = gdb.selected_frame().read_register(reg_str)


def place_chain_on_stack(chain: List[int], address_size: int) -> None:
    # In case your chain is longer than available stack space allows,
    # set LONG_CHAIN to allocate another 4096 elements
    if LONG_CHAIN:
        pivot_stack(-(4096 * (address_size // 8)), address_size)

    print("DEBUG: Preparing stack")
    rsp = get_reg_val("rsp", address_size)
    offset = 0
    for val in chain:
        # print(hex(val))
        cmd = f"set *((long *) {rsp+offset:#x}) = {val:#018x}"
        offset += 8
        exec(cmd)
    assert offset / 8 == len(chain), f"Allocated {offset / 8} elements on stack but user specified {len(chain)} elements"


def walk_chain(target_address: int) -> None:
    print("DEBUG: Setting breakpoint on final IRDst")
    _ = gdb.Breakpoint(f"*{target_address:#x}")
    if TRACE:
        # single step until destination, such that each
        # step is visible in log
        if WALK_CHAIN_UNTIL_SYSCALL:
            step_until_asm("syscall", silent=False)
        else:
            step_until_address(target_address, silent=False)
    else:
        exec("continue")


def check_postconditions(postconditions: Dict[str, int], address_size: int) -> bool:
    print("DEBUG: Checking postconditions")
    postconditions_correct = True
    for reg in postconditions.keys():
        if reg == "IRDst":
            continue
        reg_str = reg.lower()
        reg_cur_val = get_reg_val(reg_str, address_size)
        # convert negative numbers to two's complement
        if reg_cur_val < 0:
            reg_cur_val = (reg_cur_val + 2**address_size) % 2**address_size
        reg_val = postconditions[reg]
        if ALLOW_PTR_TO_ZERO and reg_val == 0 and reg_cur_val != 0:
            pointee = examine_memory(reg_cur_val, address_size)
            if pointee != 0:
                print(f"WARNING: Postcondition violated: {reg_str} = {reg_cur_val:#x} -> {pointee:#x} but should be {reg_val:#x}")
        elif reg_cur_val != reg_val:
            print(f"WARNING: Postcondition violated: {reg_str} = {reg_cur_val:#x} but should be {reg_val:#x}")
            postconditions_correct = False
    return postconditions_correct


def check_ptr_postconditions(ptr_postconditions: Dict[str, str], address_size: int) -> bool:
    print("DEBUG: Checking pointer postconditions")
    postconditions_correct = True
    for reg in ptr_postconditions.keys():
        if reg == "IRDst":
            continue
        reg_str = reg.lower()
        found_address = get_reg_val(reg_str, address_size)
        # convert negative numbers to two's complement
        if found_address < 0:
            found_address = (found_address + 2**address_size) % 2**address_size

        found_value = examine_memory(found_address, address_size)
        expected_value_str = ptr_postconditions[reg]
        if expected_value_str.startswith("0x"):
            expected_value: int = int(expected_value_str, 16)
        else:
            expected_value = int.from_bytes(expected_value_str.encode(), byteorder='little', signed=False)
        if found_value != expected_value:
            # capture a few common cases
            if expected_value == 0x68732f6e69622f:     # /bin/sh\0
                if found_value == 0x68732f2f6e69622f or found_value == 0x68732f6e69622f2f:  # /bin//sh or //bin/sh
                    # fine, but we need to check for nullbyte
                    found_terminator = examine_memory(found_address + address_size // 8, address_size)
                    if found_terminator == 0:
                        continue
            print(f"WARNING: Ptr Postcondition violated for [{reg_str}]: [{found_address:#x}] = {found_value:#x} but should be {expected_value:#x}")
            postconditions_correct = False
        # TODO: check nullbyte at addr + address_size // 8 + 1 == 0x00
    return postconditions_correct


class VerifyCommand(gdb.Command): # type: ignore
    def __init__(self) -> None:
        # This registers our class as "verify_chain"
        super(VerifyCommand, self).__init__("verify_chain", gdb.COMMAND_DATA)

    def invoke(self, arg: str, from_tty: bool) -> None:
        # When we call "simple_command" from gdb, this is the method
        # that will be called.
        if not check_aslr():
            return
        # register signal handler to check if we segmentation fault
        gdb.events.stop.connect(signal_handler)
        # register handler to see if program exists before reaching some condition
        gdb.events.exited.connect(exit_handler)
        start_time = time.time()
        print(f"DEBUG: Configuration: TRACE={TRACE}, USE_FIRST_RET={USE_FIRST_RET}, LONG_CHAIN={LONG_CHAIN}, USE_ENTRY={USE_ENTRY}")
        print(f"DEBUG: arg='{arg}'", type(arg))
        print(f"DEBUG: from_tty={from_tty}")
        args = arg.split(" ", 2)
        print(f"DEBUG: args={args}")
        if len(args) < 3:
            print("ERROR: Usage: verify_chain PATH_TO_CONFIG TARGET STACK_VALUES_LIST")
            return
        
        config_path = Path(args[0])
        assert config_path.is_file(), f"No config file found at {config_path}"
        config = load_config(config_path)
        func = args[1]
        assert func in ("mprotect", "mmap", "execve"), f"Unexpected function {func}"
        # TODO: hacky fixes to allow special treatment of execve
        if TRACE and func == "execve":
            global WALK_CHAIN_UNTIL_SYSCALL
            global ALLOW_PTR_TO_ZERO
            WALK_CHAIN_UNTIL_SYSCALL = True
            ALLOW_PTR_TO_ZERO = True
            print(f"DEBUG: func == 'execve' - Setting WALK_CHAIN_UNTIL_SYSCALL = True")
        # print("config=", config)
        stack = parse_stack(args[2])
        print(f"DEBUG: stack={[f'{v:#x}' for v in stack]}")

        # load file
        executable = (config_path.parent / config['executable']).as_posix()
        print(f"DEBUG: Loading file '{executable}'")
        gdb.execute(f"file {executable}")

        # Run program initially
        if USE_ENTRY:
            exec("entry")
        else:
            exec("starti")

        address_size = get_address_size(config['arch'])
        preconditions = {e[0] : to_int(e[1]) for e in config['preconditions']}
        postconditions = {e[0] : to_int(e[1]) for e in config['postconditions']}
        ptr_postconditions = {e[0] : e[1] for e in config.get('ptr_postconditions', [])}
        print(f"DEBUG: preconditions={preconditions}")
        print(f"DEBUG: postconditions={postconditions}")
        print(f"DEBUG: ptr_postconditions={ptr_postconditions}")
        print(f"DEBUG: address_size={address_size}")

        if USE_FIRST_RET:
            print("DEBUG: Stepping until next 'ret'")
            step_until_asm('ret', silent=True)
        else:
            # 1. Set breakpoints
            init = rebase(preconditions['IRDst'], to_int(config['load_address']))
            print(f"DEBUG: break *{init:#x}")
            _ = gdb.Breakpoint(f"*{init:#x}")
            # print(b_init.location)
            print("DEBUG: Running until initial IRDst..")
            exec('continue')

            # Alternatively: jump directly to our location
            # exec(f"jump *{init:#x}")

        # Ensure user's preconditions are set
        set_preconditions(preconditions, address_size)

        # Place the chain on the stack
        place_chain_on_stack(stack, address_size)

        # Execute each gadget until we crash or reach our destination
        dst_addr = rebase(postconditions['IRDst'], to_int(config['load_address']))
        walk_chain(dst_addr)

        # Verify whether our postconditions hold
        postconditions_correct = check_postconditions(postconditions, address_size)

        ptr_postconditions_correct = check_ptr_postconditions(ptr_postconditions, address_size)

        if PROCESS_EXITED or not postconditions_correct or not ptr_postconditions_correct:
            print("INFO: Failed to verify chain")
        else:
            print("INFO: Successfully verified chain")
        print(f"INFO: Done in {round(time.time() - start_time, 2)}s")
        print(f"INFO: Consumed {len(stack)} elements ({len(stack) * 8} bytes) on stack")


# This registers our class to the gdb runtime at "source" time.
VerifyCommand()
