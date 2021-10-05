# Targets

The targets included here have been used during our evaluation. For your convenience, we have included cached function addresses and gadget addresses (in `$target/.cache`).

## Adding new targets
SGC should work on any target supported by a disassembler of your choice and Miasm (depending on the architecture, you may need to add another architecture stub -- currently only x86 and x86-64 are supported).

That said, the essential part to building a gadget chain is a JSON configuration file. This file is parsed and represented by TargetConfig. The following fields are interesting:

```
{
    "executable": "./httpd",                   # Path to executable file
    "arch": "x86_64",                          # architecture
    "load_address" : "0x555555554000",         # load address (only relevant if libraries are used)
    "libraries": [                             # a list of libraries from which gadgets should be used
                    ["libc", "../libraries/libc-2.31.so", "0x7ffff7a67000"] # "Name", "Path to file", "load_address"
    ],
    "preconditions": [                    # list of initial constraints: format ["name", "value", size]
                      ["IRDst", "0x6edaa", 64],
                      ["RAX", "0x0", 64],
                      ["RCX", "0x0", 64],
                      ["RDX", "0x2", 64],
                      ["RBX", "0x5555557451b0", 64],
                      ["RSP", "0x7fffffffe348", 64],
                      ["RBP", "0x7fffffffe3b0", 64],
                      ["RSI", "0x78", 64],
                      ["RDI", "0x7ffff70e2118", 64],
                      ["R8", "0x7ffff70e20a0", 64],
                      ["R9", "0x0", 64],
                      ["R10", "0x1", 64],
                      ["R11", "0x246", 64],
                      ["R12", "0x5555555857a0", 64],
                      ["R13", "0x7fffffffe5b0", 64],
                      ["R14", "0x0", 64],
                      ["R15", "0x0", 64]
                    ],
    "postconditions": [                      # list of final constraints: format ["name", "value", size]
                      ["IRDst", "0x5555555f6e65", 64],
                      ["RAX",  "0x3b", 64],
                      ["RSI",  "0x0", 64],
                      ["RDX",  "0x0", 64]
                  ],
    "ptr_postconditions": [                  # list of final, indirect constraints: format ["name", "memory values", size]
                    ["RDI", "/bin/sh", 64]
                ],
    "read_mem_areas": [["0x400000", "0x4a8000"]],              # ranges from which the solver may read memory
    "write_mem_areas": [["0x7ffffffde000", "0x7ffffffff000"]]  # ranges in which the solver may write memory
  }
```

It is not strictly necessary to set all register values in the preconditions. If not explicitly mentioned in "free_variables", we will assign a random filler value. If a chain is synthesized that depends on this random value, symbolic execution will refute the gadget chain.
