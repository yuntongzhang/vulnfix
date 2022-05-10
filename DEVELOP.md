# Develop

This file lists main source files for VulnFix and its directory structure.

|-- lib                    # Contains source file to build into libpatch.so, which is used for snapshot handling.
|   |-- Makefile           # build libpatch.so
|   |-- addr_map.c         # parses the running program's address map.
|   |-- addr_map.h
|   |-- afl-rt.c           # for e9afl
|   |-- afl_mark.c         # extension for e9afl, to record whether certain source locations are touched during execution
|   |-- dwarf_eval.c       # dwarf evaluator
|   |-- dwarf_eval.h
|   |-- e9AFLPlugin.cpp    # for e9afl
|   |-- e9afl.cpp          # for e9afl
|   |-- ghost.c            # ghost variable handling, based on ASAN shadow map
|   |-- ghost.h
|   |-- patch.c            # main entry points for libpatch.so
|   |-- patch.h
|   |-- patch_hook.c       # for dynamic loading libpatch.so with e9patch
|   |-- variables.c        # representation of variables in snapshot
|   `-- variables.h
|-- src                    # Main source files in python
|   |-- backend.py         # interfacing with daikon and cvc5 backend
|   |-- ce_refiner.py      # counter-example refiner based on current patch invariant
|   |-- ce_single_var.py   # counter-example refiner for invidividual patch invariant and variable
|   |-- concfuzz.py        # concfuzz procedure
|   |-- logger.py          # for logging
|   |-- main.py            # entry point of VulnFix, and config parsing
|   |-- patch_gen.py       # patch_gen module to generate patch from patch invariant
|   |-- snapshot.py        # snapshot handling
|   |-- snapshot_pool.py   # stores all seen snapshots
|   |-- subroutines.py     # interfacing with tools such as AFL, and also running of the buggy program
|   |-- utils.py
|   `-- values.py          # pre-defined and runtime-set values
|-- thirdparty             # Contains thirdparty submodules
|   |-- AFL
|   |-- cvc5
|   |-- daikon
|   `-- e9patch
|-- daikon-config          # config file for daikon
|-- Dockerfile
|-- build.sh               # all-in-one build script for VulnFix
|-- driver.py              # driver for running VulnLoc benchmark
`-- meta-data.json         # describes VulnLoc benchmark subjects
|-- DEVELOP.md             # this file
|-- INSTALL.md             # installation instructions
|-- MANUAL.md              # options and config file fields for VulnFix
|-- README.md
