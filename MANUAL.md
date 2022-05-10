# Manual

_This file contains information about using VulnFix._

## Main program

The entry for VulnFix is in `src/main.py`, which should be invoked by `python3.8 src/main.py`.
This main script requires a compulsory argument, which is the path to a config file including
the information of the bug being fixed (see next section). It also optionally supports the following
arguments:

- `--budget`: Total timeout for the tool in mins. Default is 30.
- `--backend`: Either "daikon" (default) or "cvc5".
- `--concfuzz`: Use ConcFuzz instead of AFL+snapshot fuzzing.
- `--aflfuzz`: Use AFL instead of AFL+snapshot fuzzing.
- `--reset-bench`: Reset a (previously fixed) benchmark program to its original vulnerable state.
- `--unreduced`: Do not attempt to reduce the number of variables in snapshot.
- `--no-early-term`: Do not attempt to terminate early if does not see useful new states.


## Config file

The config file requires the following compulsory fields:

- `binary`: Absolute path to the buggy binary.
- `cmd`: Command to trigger the target bug. `<exploit>` should be used a placeholder for the input.
- `exploit`: Exploit input used.
- `fix-location`: Source location to do invariant inference.
- `crash-location`: Source location where the bug happens.
- `runtime-dir`: Absolute path to store the runtime generated files. For cvc5, aflfuzz, and concfuzz,
this value will be prefixed with addtional string.
- `source-dir`: Absolute path for the source directory of the program.
- `fix-file-path`: Relative path to the file for which patch should be applied.
- `fix-line`: A number in fix file, specifying source line to apply patch.
- `build-cmd`: Command to rebuild the program for patch validation.

Additionally, some optional fields are supported:

- `input-from-stdin`: the program should take input from stdin instead of file.
- `afl-skip-deterministic`: Explicitly set whether AFL should skip deterministic stage. If not specified,
VulnFix automatically determines this.
- `use-raw-size`: Use raw size (in bytes) instead of #(element) for ghost size variable.
