# SMT solvers for gadget synthesis

Wrapper around various SMT solvers, which can be used for gadget synthesis. This
repository is inteded for use by our gadget synthesis tool.

## Build
Make sure to initialize the (desired/all) submodules:
```
git init
git submodule update --init --recursive --rebase
```
Install the (desired) SMT solver(s) using the `install_solvers.sh` script:
```
# install all available solvers
./install_solvers.sh all

# install Boolector
./install_solvers.sh boolector
```
