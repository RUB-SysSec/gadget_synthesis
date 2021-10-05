#!/bin/bash

# This will initially in the container:
# * install all python requirements
# * install Miasm, SMT solvers, and the gadget chain synthesizer as (editable) packages
# * build Boolector and install it to $HOME/.local/bin
# This may happen in the background and take up to 60s before boolector is available

cd "$HOME"/synthesis/gadget_synthesis && \
python3 -m pip install --user -r requirements.txt && \
python3 -m pip install --user -e . && \
cd lib/solvers && \
./install_solvers.sh boolector

exec /bin/cat
