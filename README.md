# VulnFix Artifact Evaluation

Public github repo for reference: https://github.com/yuntongzhang/vulnfix.

The .md files and `result-expected` folder are only included in github and Zenodo, not in the docker image.

The (OPTIONAL) sections are not needed for running the experiments; they are for information only.

## Running with container

The VulnFix tool, its dependencies, and most of experiment subjects have already been built and
packaged inside a docker container. To start, execute the following command to download the image
and run the container:

```
docker pull yuntongzhang/vulnfix:issta22
docker run -it --memory=30g --name vulnfix-issta22 yuntongzhang/vulnfix:issta22
```

The `--memory=30g` option is used to limit the memory usage of the container. This is because some
thirdparty tools (e.g. cvc5) can potentially use a lot of memory. To avoid using up all the memory
on the machine, this option is recommended. Please set a reasonable limit based on the machine used.
(`30g` was used in our experiments.)

The `docker run` command should land in the container at the directory `/home/yuntong/vulnfix`.
If not otherwise specified, all the commands and paths listed in this document are from this directory.

### Hardware and environment

Although a docker image is provided, here are the host environment we used for reference (although other
settings may work as well):

- Host OS: ubuntu 20
- Host memory: 64GB
  - cvc5 can use a lot of memory when it runs for a long time. So it
  would be better to use a machine with at least 30GB memory.
  - If such machine is not available, one can try running only the bugs which shows "Correct" in
  Table 2 for cvc5 backend, in which cvc5 terminates faster and likely uses less memory (though not guranteed).
- Host CPU: 40-core Intel Xeon
  - However, VulnFix is implemented with sequential algorithms, so requirement on CPU cores are not that strict.
  - To run some of the experiments in parallel (see "Recommended workflow"), a few cores will be needed.
- Host disk space:
  - There needs to be enough space for the container.
  - In addtion, the experiments can generate more files. In our testing run of all the experiments,
  an additional 8GB is taken up by the runtime-generated files.



## Getting started

In this section, we show how to run VulnFix to produce a patch invariant (and a corresponding patch)
for an example.


### Turn off ASLR on Host

Before running VulnFix, please temporarily turn off ASLR on the **host** machine of the container
with the following command (for linux hosts):

```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Although VulnFix does not infer patch invariant over pointer values most of the time, they can be
included in snapshots. If ASLR is on, two same snapshots with only pointer values differences due to
randomization will be classified as two different snapshots, resulting in redundancy. ASLR needs to
be turned off on the host machine instead of the container, to make sure it works.


### CVE demo

The example vulnerability used here is CVE-2019-9077 from binutils, and its relevant information
are in `demo/cve_2019_9077`. This directory contains the following files:

- `config`: A configuration file used by VulnFix.
- `dev.patch`: The developer patch for this vulnerability.
- `exploit`: An exploit input to trigger the vulnerability.
- `README.txt`: Some additional information such as where the exploit was downloaded from.
- `setup.sh`: Script to download and build the vulnerable version of the program.


#### Building

First, download and build the vulnerable program (may take a few minutes):

```
cd demo/cve_2019_9077
./setup.sh
```

If the build is successful, there will be a `readelf` binary in the current directory, and running
`./readelf -a ./exploit` should result in a santizer error report.

#### Running

After building the program, we are ready to invoke VulnFix with the following command:

```
cd /home/yuntong/vulnfix
python3.8 src/main.py demo/cve_2019_9077/config
```

The entry point of VulnFix is in the python script `src/main.py`. VulnFix requires one compulsory
argument, which is the config file for the target vulnerability.

After running the command above, AFL should be started after a short period of time for parsing config
and setting up runtime directory. At this point, if AFL aborts and complains about some OS-level
configuration (such as cpu scaling governor), please fix them on the host machine according to the
instructions and re-run the command above. This can happen a few times if there are multiple things
to fix for AFL, especially if AFL has not been run on the machine before.

If AFL starts successfully, the VulnFix process has staretd. Firstly, AFL will be run for 10 mins
(default), followed by the snapshot fuzzing stage. The total timeout is 30 minutes, but the demo
should finish before the timeout.

#### Interpreting log and result

During the run, information about the stages are printed on
console. The notable ones are the patch invariants printed for each round. "Initial patch invariants"
shows the patch invariants obtained after input-level fuzzing (AFL), and "Refinement round X finished.
Current patch invariants ..." shows the intermediate patch invariants during snapshot fuzzing.
The final result of VulnFix is printed in "Final patch invariants", which is the list of
patch invariants after snapshot fuzzing. In each of these printed lines, `n` in `#(n)` is the number
of patch invariants currently. The "Final patch invariants" line printed shows that
VulnFix completes normally and is functioning.

For this example, VulnFix successfully generates a single invariant `sect->sh_size >= 8`, which is semantically
equivalent to the condition used in developer patch. On top of the patch invariants output by VulnFix,
we have also implemented a `patch_gen` module to demonstrate some kinds of patchs that can be
generated from the patch invariants. For the demo example, a patch will be generated at the path
`/home/yuntong/vulnfix/demo/cve_2019_9077/runtime/vulnfix.patch`.

#### (OPTIONAL) Information about runtime directory

Apart from the result, VulnFix stores various runtime-generated files in the runtime directory, which
is `/home/yuntong/vulnfix/demo/cve_2019_9077/runtime/` for this example (the runtime directory is
specified in the config file). This directory can contain the following intermediate files:

- `vulnfix.result`: The final result from VulnFix.
- `vulnfix.patch`: An example patch generated from patch invariant, if `patch_gen` module is invoked.
- `vulnfix.log.info`, `vulnfix.log.debug`: log files.
- `readelf`: The original binary (or patched binary if `patch_gen` was invoked).
- `readelf.afl`: Instrumented binary for AFL.
- `readelf.snapshot`: Instrumented binary for snapshot logging.
- `readelf.mutate`: Instrumented binary for snapshot mutation.
- `snapshot.out*`: Intermediate snapshot files.
- `afl-*`: Various AFL directories.
- `pass.dtrace`, `fail.dtrace`, `pass.inv`, `daikon.decls`: Input files generated for daikon.
- `input.sl`: Input file generated for cvc5.



## Detailed description

In this section, we describe how to validate the results in Table 2 and Table 3. Since some of the
experiments can be run in parallel to save time, we also recommend a workflow of running the
experiments in Section _Recommended workflow_.

### Preparation

Before running any of the experiments, the bugs (vulnerability programs) need to be built. To save
time, we have already built most of the bugs in the docker image. However, the `zziplib` build
generates files dependent on the host kernel version, so they are not built yet. As a first step,
please build the zziplib bugs with the following command:

```
python3.8 driver.py --setup --bug 28 --bug 29 --bug 30
```

Now all the buggy programs are built.

### Table 2

The main claims supported by Table 2 are:

1. With a 30-minute timeout, VulnFix generated more patches than CPR and SenX.
2. VulnFix can work with different backends (daikon and cvc5). They are able to generate
similar number of patches, although with different timeout used (30 minutes vs. 3 hours).

#### VulnFix with daikon backend

Firstly, we describe how to reproduce the results for the column "VulnFix-Daikon backend". In total,
there are 30 subjects, and the `driver.py` script can be used to run all of them at once, one-by-one,
by using the following command:

```
python3.8 driver.py --daikon-exp
```

This command should be sufficient to run all bugs for this column. From our testing run,
this command takes around 8 hours to finish. The result of this command is a result summary file at
`result/result-vulnfix-daikon`. We will describe how to use this file later on.

(_OPTIONAL_) The script `driver.py` runs all bugs in the benchmark. In addition, this script can be used to run individual bugs as well. This can be
done with the option `--bug X`, where X is the `id` field in `meta-data.json` (e.g.
`python3.8 driver.py --daikon-exp --bug 12` to run cve_2017_15232). Be aware that each time some
experiment is invoked throught this script (like `--daikon-exp`), the result summary file will be
overwritten. Please backup them especially if they are obtained after a long experiment.

#### VulnFix with cvc5 backend

Similarly, to run all experiments for the column "VulnFix-cvc5 backend", using the following command:

```
python3.8 driver.py --cvc-exp
```

Since the timeout for cvc5 backend is 3 hours, this command takes more time (around 18 hours) to
finish. The result is written to the file `result/result-vulnfix-cvc`.

#### (OPTIONAL) CPR

Since CPR is an external tool, we did not provide a replication package for it. However, interested
readers can refer to our experiment results and logs from the repo:
https://github.com/yuntongzhang/cpr-experiments. The CPR tool is also publically available at:
https://github.com/rshariffdeen/cpr.

#### (OPTIONAL) SenX

SenX is another external tool but is closed source. We have obtained a copy of SenX from its authors
and performed the experiments. Interested readers can refer to the repo https://github.com/yuntongzhang/senx-experiments
for our experiment materials on SenX. This repo includes scripts to build experimental subjects,
running SenX, and the obtained results for each bug.


### Table 3

The main claims supported by Table 3 is:
1. Compared to input-level fuzzing (AFL and ConcFuzz), VulnFix with snapshot fuzzing can generate
more precise patch invariants.

In Table 3, the "VulnFix" column is the same as the "VulnFix-Daikon backend" column in Table 2. The
"VulnFixC" column shows the result of running ConcFuzz for 30 minutes, followed by one invariant
inference step with Daikon. The "VulnFixA" column shows the result of running AFL for 30 minutes,
followed by one invariant inference step with Daikon. Besides, the #Inv column lists the number of
patch invariants in the end.

#### VulnFixC (ConcFuzz)

Again, all bugs can be invoked with the driver script:

```
python3.8 driver.py --concfuzz-exp
```

Although the timeout of running ConcFuzz is 30 minutes, the actual time required can be longer.
This is because a lot of inputs can be generated by fuzzing, and each of them needs to be processed
to take snapshots. The time for processing inputs to log snapshots are not included in the 30 minutes,
since we can't "predict" how long the input processing is going to take beforehand and allocate
part of the 30 minutes to it. In contrast, "VulnFix" column (or "VulnFix-Daikon backend" in Table 2) has a strict timeout of 30
minutes including the time for processing the inputs. We note that this actually gives advantage to
VulnFixC (and VulnFixA), which strengthens the claim for Table 3.

From our testing run, this command takes around 16 hours to finish. The result is written to
`result/result-concfuzz-daikon`.

#### VulnFixA (AFL)

All bugs can be invoked with the command:

```
python3.8 driver.py --aflfuzz-exp
```

Similar to "VulnFixC", this command also takes longer even though each fuzzing run is given timeout
of 30 minutes.

From our testing run, this command takes around 22 hours. The result is written to file
`result/result-aflfuzz-daikon`.


### Using result summary files to check for correctness

After obtaining the result summary files from the 4 experiments, they are used to check correctness
of the patch invariant produced. Here, we use the following criteria for "correct":

1. There is only one patch invariant in the result, and
2. The patch invariant is correct, which means either one of the following is true:
   1. It is semantically equivalent to the patch invariant extracted from developer patch, or
   2. Although not semantically equivalent, it can be used to generate a patch that fixes the target bug.

Criteria 1 is easy to check by reading the result summary file, in which the number of final patch
invariants and the patch invariants themselves are printed.

For Criteria 2, we need to extract a patch invariant relevant to the bug (which separates the benign and vulnerable
behaviors of the program) from the developer patch, and also decide on whether a generated patch
invariant can be used to fix the bug. For convenience, we provide a file which contains a few correct
patch invariants that are manually generated from the developer patch, as a list of acceptable answers.

This file is `result-expected/acceptable-invs`. To check whether a patch invariant `I` satisfies Criteria 2,
one can check whether `I` is one of the listed answers in `result-expected/acceptable-invs`. If `I`
is the only patch invariant produce (Criteria 1) and is one of the listed answers (Criteria 2), it
is considered correct and corresponds to a "tick" in Table 2 and 3; otherwise, it will be a "cross". Furthermore, each listed answer
is annotated with either `{equiv}` (Criteria 2.1) or `{correct}` (Criteria 2.2). If `I` is the same as an
`{equiv}` answer, it corresponds to `Correct(equivalent)` in Table 2; if `I` is the same as a `{correct}`
answer, it corresponds to `Correct(not equivalent)` in Table 2.

We did not automate the process of comparing `I` against the acceptable answers, since daikon and cvc5
outputs patch invariants in different formats, and it can be difficult to include all the formats in
acceptable answers. Please compare the semantics of the patch invariant manually, despite that
they may be in slightly different formats.

**Note**: The correctness criteria used here is stronger than "the patch makes all failing inputs in
a test suite pass". In our senario, there is a test suite generated by the input-level fuzzing stage.
Since the patch invariant is inferred over snapshots from inputs in the test suite, by construction,
this patch invariant separates benign and vulnerable behaviors, and will make all failing inputs pass.
Here, we use a stronger criteria that the patch invariant should additionally be "sensible" according
to the program semantics (i.e. the patch invariant is not over arbitrary variables that are not relevant
to the bug). In this way, those patch invariants that are terribly overfitting to the test suite
(though maybe pass all failing inputs) are not classifed as correct.

In the `result-expected` directory, there are also result summary files from our previous testing
runs, for reference.

(_OPTIONAL_) Just for information, the variables `_GSize_*` and `_GDiff_*` in the patch invariants are the
ghost variables, representing `size(ptr)` and `ptr-base(ptr)` respectively (there are more details about ghost variables in the paper).

### Recommended workflow

In this section, we recommend a workflow to run some experiments in parallel to save time. In total,
there are four commands to run all the experiments:

1. `python3.8 driver.py --daikon-exp`
2. `python3.8 driver.py --cvc-exp`
3. `python3.8 driver.py --aflfuzz-exp`
4. `python3.8 driver.py --concfuzz-exp`

Since the `patch_gen` module is just for demonstrating how patches can be generated from patch
invariants (and not for correctness), it is only enabled for `--daikon-exp`. As `patch_gen`
involves changing the source file for the subject and rebuilding the program for validation,
`--daikon-exp` should **not** be run together with any other experiment. In order to reset the program
sources to its original vulnerable states after running `--daikon-exp`, one can use the command
`python3.8 driver.py --reset` to reset all bugs. This should be run after `--daikon-exp` if another
experiment is to be run afterwards. To reset an individual bug X instead of all of them, run
`python3.8 driver.py --reset --bug X`.

To avoid the complication above, a recommend workflow is as follows:

1. Open 3 terminals into the container, with `docker exec -it vulnfix-issta22 bash`.
2. Run command 2,3,4 in each of the 3 terminals to start 3 of the experiments together. It will take
around 22 hours for all 3 of them to finish.
3. After 2,3,4 finish, run command 1 in one of the terminal to start `--daikon-exp`.

When one experiment finishes, its respective result file will be generated. One can now use the
result file to check against `result-expected/acceptable-invs` and reproduce results to Table 2 and 3.



### Additional remarks

#### Randomness in experiments

Since VulnFix uses fuzzing, there are some randomness in the process. The randomness may cause the
results to be slightly different, but the overall claims from Table 2 and 3 should still hold.

In particular, here are some of results that could be affected by randomness:

1. The "#Inv" column in Table 3 can be easily affected by randomness. However, this number is only
for information, and the "result" column that indicates correctness is where the claim is drawn from.
2. Due to randomness in input-level fuzzing, different inputs can be generated, which may cause
VulnFix to unexpectedly fail to produce correct patch invariants in rare occasions. In this case,
please try and re-run the individual bug, which should work for most cases.
Please remember to back up result files and reset that bug before re-running it.

(_OPTIONAL_) One reason for point 2 to happen is because the current implementation uses ASAN as
test oracle, which is not perfect. For a buffer overflow, if an malicious input manages to "skip"
the redzone by ASAN and access some other valid buffer (but not the intended one), ASAN does not flag
it as error. As such, although being rare, if such an input is generated, its snapshot can be
wrongly classified, causing VulnFix to fail. Re-running VulnFix can likely avoid such issue.


#### (OPTIONAL) Patch generation with ghost variables

To convert ghost variables in patch invariant to concrete program constructs when generating a patch,
the current implementation relies on memory allocators that gives the information about buffer size
and buffer base. In principle, any such allocator would work. For convenience, we use the ASAN
allocator, which is already used for detecting the bug. During patch generation, ghost variables
are replaced with calls to `generic_buffer_size` and `generic_buffer_base`, which are implemented
to obtain these information from the ASAN allocator.

Other techniques, such as additionally storing the allocation size and base in the program, would also be possible.
