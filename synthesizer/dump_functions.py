# example script to dump function starts
from ghidra.app.util.opinion import ElfLoader

def fix_image_base():
    """
    Relocates the image base if it differs from the original binary
    """
    # check if ELF
    if  currentProgram.getExecutableFormat() == ElfLoader.ELF_NAME:
        # get image base from ELF file
        original_image_base = ElfLoader.getElfOriginalImageBase(currentProgram)
        # check if Ghidra chose a different image base
        if currentProgram.getImageBase() != original_image_base:
            # set to original image base
            currentProgram.setImageBase(toAddr(original_image_base), True)


#  check arguments
args = getScriptArgs()
if len(args) != 1:
    print("[*] Parameters: <output file>")
    exit(-1)


# parse arguments
output_file = args[0]

fix_image_base()

# get function iterator
fm = currentProgram.getFunctionManager()
functions = fm.getFunctions(True)

# walk over all functions
content = ""
for f in functions:
    # ignore import trampolines
    if f.isThunk():
        continue
    content += "{}: 0x{:x}\n".format(f.name, f.getEntryPoint().getOffset())

# write output
with open(output_file, "w") as f:
    f.write(content)
