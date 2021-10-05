#!/bin/bash

# Install various SMT solvers as backend for gadget synthesis

set -eu
set -o pipefail

usage="Usage: $(basename "$0") [-h] [all|boolector] -- build specified SMT solvers

where:
    -h        show this help text"


function get_prefix {
    set +u # VIRTUAL_ENV can be unbound
    if [ -v "${VIRTUAL_ENV}" ] && [ -z "${VIRTUAL_ENV}" ]; then
        echo "[*] Found virtual env at: $VIRTUAL_ENV"
        prefix="$VIRTUAL_ENV/"
    else
        prefix="${HOME}/.local/"
    fi
    set -u
    echo "[*] Prefix is $prefix"
}


function install_all {
    install_boolector
}


function install_boolector {
    echo "[*] Installing Boolector"
    pushd ./boolector/ > /dev/null

    # Picosat    
    ./contrib/setup-picosat.sh

    # # Minisat
    # ./contrib/setup-minisat.sh

    # # Cadical
    # ./contrib/setup-cadical.sh

    ## Download and build BTOR2Tools
    ./contrib/setup-btor2tools.sh

    ./configure.sh --only-picosat --prefix "$prefix"

    pushd build > /dev/null
    make -j install

    popd > /dev/null
    popd > /dev/null
}


BOOLECTOR=0
ALL=0

PARAMS=""
while (( "$#" )); do
    case "$1" in
        all)
            ALL=1
            shift
            ;;
        boolector)
            BOOLECTOR=1
            shift
            ;;
        -h|--help)
            echo "$usage"
            exit 0
            ;;
        --) # end argument parsing
            shift
            break
            ;;
        -*) # unsupported flags
            echo "$usage"
            echo ""
            echo "Error: Unsupported flag $1" >&2
            exit 1
            ;;
        *) # preserve positional arguments
            PARAMS="$PARAMS $1"
            shift
            ;;
    esac
done
# set positional arguments in their proper place
eval set -- "$PARAMS"

get_prefix
if [[ $BOOLECTOR == 1 ]]; then
    install_boolector
elif [[ $ALL == 1 ]]; then
    install_all
else
    echo "Failed to specifiy install target!"
    echo "$usage"
    exit 1
fi
echo "Done"
