# Develop

> This file contains information that helps in developing or extending VulnFix.

## Directory organization

Main source files for VulnFix and its directory structure:

```
|-- doc                    # Contains documentation.
|   |-- AE.md              # information for artifact evaluation.
|   |-- DEVELOP.md         # information for developing and extending the tool.
|   |-- INSTALL.md         # instructions for using the tool in docker/manually install the tool.
|   `-- MANUAL.md          # more detailed information on using the tool.
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
|-- meta-data.json         # describes VulnLoc benchmark subjects
`-- README.md
```

## Runtime-Generated Files

Apart from the result, VulnFix stores various runtime-generated files in the runtime directory
(The runtime directory is specified in the `config` file for each run,
e.g. `data/libtiff/bugzilla-2633/runtime`). These runtime-generated files may be helpful in debugging.

The runtime directory can contain the following files:

- `vulnfix.result`: The final result from VulnFix.
- `vulnfix.patch`: An example patch generated from patch invariant, if `patch_gen` module is invoked.
- `vulnfix.log.info`, `vulnfix.log.debug`: log files.
- `bin`: The original binary (or patched binary if `patch_gen` was invoked).
- `bin.afl`: Instrumented binary for AFL.
- `bin.snapshot`: Instrumented binary for snapshot logging.
- `bin.mutate`: Instrumented binary for snapshot mutation.
- `snapshot.out*`: Intermediate snapshot files.
- `afl-*`: Various AFL directories.
- `pass.dtrace`, `fail.dtrace`, `pass.inv`, `daikon.decls`: Input files generated for daikon.
- `input.sl`: Input file generated for cvc5.


## Variables in snapshot

Apart from regularly looking variables, the variables `_GSize_*` and `_GDiff_*` in the patch
invariants are the ghost variables, representing `size(ptr)` and `ptr-base(ptr)` respectively
(there are more details about ghost variables in the paper).

### Patch generation with ghost variables

To convert ghost variables in patch invariant to concrete program constructs when generating a patch,
the current implementation relies on memory allocators that gives the information about buffer size
and buffer base. In principle, any such allocator would work. For convenience, we use the ASAN
allocator, which is already used for detecting the bug. During patch generation, ghost variables
are replaced with calls to `generic_buffer_size` and `generic_buffer_base`, which are implemented
to obtain these information from the ASAN allocator (their implementation can be found in
`lib/ghost.c`).

Other techniques, such as additionally storing the allocation size and base in the program,
would also be possible.
