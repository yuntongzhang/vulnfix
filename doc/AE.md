# VulnFix Artifact Evaluation

> This file contains steps on replicating results in the ISSTA22 paper.

Public github repo for reference: https://github.com/yuntongzhang/vulnfix.

The .md files and `result-expected` folder are only included in github and Zenodo, not in the docker image.

This document contains the following main sections:

- [Preparation](#preparation): all setup steps required before running the experiments.
- [Getting started](#getting-started): instructions of running VulnFix on one CVE. This would
likely take less than 20 minutes.
- [Detailed description](#detailed-description): instructions of running all experiments, as well
as how to interpret the result file to reproduce Table 2 and 3 in the paper.
- [Additional information](#additional-information): not required for replication of the result.
Additional information for interested readers.

All steps are tested on a Linux host machine.

## Preparation

This section contains all the preparation steps required before using VulnFix in the
[Getting started](#getting-started) and [Detailed description](#detailed-description) sections.

### Download and run docker container

The VulnFix tool, its dependencies, and most of experiment subjects have already been built and
packaged inside a docker container. To start, execute the following command to download the image
and run the container:

```
docker pull yuntongzhang/vulnfix:issta22
docker run -it --memory=30g --name vulnfix-issta22 yuntongzhang/vulnfix:issta22
```
> The `--memory=30g` option is used to limit the memory usage of the container. This is because some
> thirdparty tools (e.g. cvc5) can potentially use a lot of memory. To avoid using up all the memory
> on the machine, this option is recommended. Please set a reasonable limit based on the machine used.
> (`30g` was used in our experiments.)

The `docker run` command should land in the container at the directory `/home/yuntong/vulnfix`.
If not otherwise specified, all the commands and paths listed in this document are from this directory.


### Setting OS configurations

Some of VulnFix's dependencies (e.g. AFL) requires certain OS configurations to be set to improve
performance. Besides, VulnFix also requires turning off ASLR to have stable values for pointer
variables. Please perform the following on the **host** machine:

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | sudo tee cpu*/cpufreq/scaling_governor

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

### Building the remaining CVEs

Most of the CVEs in the benchmark have already been built inside the container, and are ready for
running. However, one exception are the `zziplib` CVEs, since the `zziplib` build generates files
dependent on the host kernel version, they are not built yet. Please use the following command
to build the remaing 3 CVEs (this should take a few minutes):

```bash
python3.8 driver.py --setup --bug 28 --bug 29 --bug 30
```

Now all the CVEs should have been built.



## Getting started

In this section, we show how to run VulnFix to produce a patch invariant (and a corresponding patch)
for one CVE in the benchmark.

First, go to the project root:

```bash
cd /home/yuntong/vulnfix
```

Next, invoke VulnFix on one of the CVEs in the benchmark, with the following command:

```bash
python3.8 src/main.py data/libxml2/cve_2012_5134/config
```

AFL should be started after a shorting period of time of parsing the config file and setting up the
runtime directory. The snapshot fuzzing stage will follow. The total time taken for this command
is roughly 12-15 minutes, and the final few lines printed on screen should be something like this:

```
2022-05-24 05:40:33 --- Final patch invariants - #(1) : ['len >= 1'] ---

2022-05-24 05:40:33 Generating patch from the patch invariant `len >= 1` ...
2022-05-24 05:40:41 Patch generation successful! Please find the patch at: /home/yuntong/vulnfix/data/libxml2/cve_2012_5134/runtime/vulnfix.patch.
```

This indicates a successful run of VulnFix, with a single patch invariant `len >= 1` produced in the
end. A patch file is also generated based on this invariant, at the location:
`/home/yuntong/vulnfix/data/libxml2/cve_2012_5134/runtime/vulnfix.patch`.

Since this CVE is going to be run again in other experiments, execute the following commands to
reset the program to vulnerable stage (it is now patched after running VulnFix). This will take a
few seconds.

```bash
python3.8 src/main.py --reset-bench data/libxml2/cve_2012_5134/config
```



## Detailed description

In this section, we first describe a workflow (i.e. a few commands to run) to execute the
VulnFix experiments used for Table 2 and 3 in the paper
(Section [Recommended workflow](#recommended-workflow) and
[Running subset of the CVEs](#running-subset-of-the-cves)).
Then there will be a subsection describing
what each of these commands do (for information) (Section
[Description for each command](#description-for-each-command)). The last subsection describes how to interpret
the results from these commands (Section [Interpreting results](#interpreting-results)).

Readers can execute the commands in either [Recommended workflow](#recommended-workflow) or
[Running subset of the CVEs](#running-subset-of-the-cves) first, and then refer to
[Interpreting results](#interpreting-results) to check the generated result files from executing the commands.

### Recommended workflow

There are total four commands to run:

1. `python3.8 driver.py --daikon-exp`  (takes ~8 hours)
2. `python3.8 driver.py --cvc-exp`  (takes ~18 hours)
3. `python3.8 driver.py --aflfuzz-exp`  (takes ~22 hours)
4. `python3.8 driver.py --concfuzz-exp`  (takes ~16 hours)

A recommended workflow is:

1. Open 3 terminals into the container, with `docker exec -it vulnfix-issta22 bash`.
2. Run command 2,3,4 in each of the 3 terminals to start 3 of the experiments together. It will take
around 22 hours for all 3 of them to finish.
3. After 2,3,4 finish, run command 1 in one of the terminal to start `--daikon-exp`.

When one command finishes, its result file will be generated. The corresponding result file for each
of the commands will be at the following locations:

1. `result/result-vulnfix-daikon`
2. `result/result-vulnfix-cvc`
3. `result/result-aflfuzz-daikon`
4. `result/result-concfuzz-daikon`

We have previously performed a run with all four commands, and the generated result files are in
the directory `result-expected` (instead of `result`), for reference.

### Running subset of the CVEs

The four commands above run all the 30 CVEs for each experiment.
To save time, it is also possible to only run a subset of the benchmark. This takes the same steps
as the recommended workflow, except that additional arguments are passed to each command.

For example, if we want to run Command 1 on gnubug_25023 and cve_2016_5321, first go to file
`meta-data.json` and find their corresponding ids to be 6 and 16. Then, the following can be used
to run Command 1 only on these two CVEs (instead of all 30 of them):

```bash
python3.8 driver.py --daikon-exp --bug 6 --bug 16
```
In general, `--bug X` can be appended to each of the four commands to run the experiment on bug with
id `X`, where the mapping from id to CVE is stored in `meta-data.json`.

Note that each invokation of `python3.8 driver.py --daikon-exp` destroy the previous result file for this command
(similar for other commands). In any case that you want to run each command multiple times, please
back up the result file if they are intended to be used later.


### Description for each command

In this subsection, we describe what results in Table 2 and 3 are based on the four commands above.

#### Command 1

Command 1 runs all 30 CVEs with VulnFix (daikon backend), and corresponds to the column
"VulnFix-Daikon backend" in Table 2.

In this setup, a patch will also be generated from the patch invariant, to demonstrate how patch
generation can be done. Since a patch needs to be applied to the program for validation, this command
changes the CVE source code, which means the commands run after it will be affected. That is why
the recommended workflow puts this command at last. However, in any case that you want to run other
commands afterwards, you can execute the following command to reset all CVEs to their vulnerable
stage, and run any of the four commands without issue:

```bash
python3.8 driver.py --reset
```

#### Command 2

Command 2 runs all 30 CVEs with VulnFix (cvc5 backend), and corresponds to the column
"VulnFix-cvc5 backend" in Table 2.

#### Command 3

Command 3 runs all 30 CVEs with only AFL fuzzing and invariant inference (no snapshot fuzzing), which
corresponds to "VulnFixA" column in Table 3.

#### Command 4

Command 4 runs all 30 CVEs with only ConcFuzz and invariant inference (no snapshot fuzzing), which
corresponds to "VulnFixC" column in Table 3.


### Interpreting results

In this subsection, we first describe the main claims supported by Table 2 and 3, and then
describe how to use the four result files to check for patch correctness.

#### Table 2 main claim

There are two main claims supported by Table 2:

1. With a 30-minute timeout, VulnFix generated more patches than CPR and SenX.
2. VulnFix can work with different backends (daikon and cvc5). They are able to generate
similar number of patches, although with different timeout used (30 minutes vs. 3 hours).

Claim 1 is supported by Command 1. Command 1 runs VulnFix (daikon backend) with 30-minute timeout
for each CVE, and VulnFix generates around 19 correct patch invariants out of 30 CVEs. The CPR
experiment steps and results are in the repo https://github.com/yuntongzhang/cpr-experiments.
The SenX experiment steps and results are in the repo https://github.com/yuntongzhang/senx-experiments.

Claim 2 is supported by both Command 1 and Command 2. Both VulnFix (daikon backend) and VulnFix
(cvc5 backend) produces around 19 correct patch invariants out of 30 CVEs.

#### Table 3 main claim

The main claim supported by Table 3 is:

1. Compared to input-level fuzzing (AFL and ConcFuzz), VulnFix with snapshot fuzzing can generate
more precise patch invariants.

This claim is supported by Command 1, 3, 4. Command 1 shows that VulnFix (with snapshot fuzzing)
produces around 19 correct patch invariants. Command 3 and 4 show that with only input-level
fuzzing (AFL and ConcFuzz respectively for the two commands), less correct patch invariants could
be produced.

#### Using result summary files to check correctness for one CVE

In order to examine whether these claims are supported by the results, the four result files need to
be checked to determine how many correct invariants (out of 30 CVEs) are produced by each
experiment/command. Here we describe how to check for correctness of one CVE in one result file.

For convenience, we provide a file that contains a list of acceptable patch invariants manually
generated from the developer patch of each CVE. This "answer file" is
`result-expected/acceptable-invs`. For one CVE, each line in the answer file is a correct patch
invariant, marked with either `{equiv}` or `{correct}`. `{equiv}` means that this invariant is
equivalent to the one used in developer patch, which corresponds to `Correct (equivalnent)` in
the paper; `{correct}` means that this invariant is not equivalent to the one in developer patch,
but still correctly fixes the bug, which corresponds to `Correct (not equivalent)` in the paper.

Now, for a patch invariant produced by VulnFix to be considered as correct, it has to satisfy (1)
it is the single final invariant from VulnFix; (2) it is one of the answers in the
"answer file". For example, suppose result file for Command 1 (`result/result-vulnfix-daikon`) contains the following for CVE number 16:

```
=================== (16) libtiff cve_2016_5321 ===================
SUCCESS (Exactly one patch invariant in the end) (Its correctness is not checked yet)

Patch Invariants:
1
['s <= 7']
```
This indicates that `s <= 7` is the single final patch invariant. Now, for CVE 16, the answer file
contains the following:

```
=================== (16) libtiff cve_2016_5321 ===================

s < MAX_SAMPLES                      {equiv}
s < 8                                {equiv: MAX_SAMPLES == 8}
s <= 7                               {equiv}
```

Since `s <= 7` is one of the listed answers, and its the only patch invariant, result for CVE 16 is
`Correct (equivalent)` for Command 1.

Consider another example for CVE 19 result for Command 3:

```
=================== (19) libtiff cve_2017_7595 ===================
FAIL (More than one or no patch invariants in the end)

Patch Invariants:
3
['sp->v_sampling >= 1', 'sp->v_sampling >= td->td_fillorder', 'sp->v_sampling >= sp->ycbcrsampling_fetched']
```
and the section in answer file for CVE 19 is:

```
=================== (19) libtiff cve_2017_7595 ===================

sp->v_sampling != 0                  {equiv}
sp->v_sampling >= 1                  {equiv}
```

Although `sp->v_sampling >= 1` is one of the final patch invariants from Command 3, the result for
CVE 19 with Command 3 is **not** correct, since there are more than one final patch invariant in
the end. This means that the patches are _overfitting_.

Consider another example of CVE 15 result for Command 2:

```
=================== (15) libtiff bugzilla_2633 ===================
SUCCESS (Exactly one patch invariant in the end) (Its correctness is not checked yet)

Patch Invariants:
1
['4 <= samplesperpixel']
```
and the section in answer file is:

```
=================== (15) libtiff bugzilla_2633 ===================

es > 0                               {equiv}
samplesperpixel > nc                 {equiv}
```

There is a single final patch invariant, but it is not in the list of answers. Therefore, the result
here is **not** correct.

#### Check correctness for one column

After knowing how to check correctness for one CVE, please use the following steps to reproduce
results for one column:

1. Open the result file for that column, and also the answer file.
2. For each CVE, check whether the produced patch invariant is correct, with the criteria described above.

___

This is the end of the replication steps. Below are some additional information if readers are interested.

___




## Additional information

This section contains some additional information.

### Hardware and environment used in our setup

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


### Contents of CVE directory

Files in each CVE directory (e.g. `data/libtiff/bugzilla-2633`) and what they are:

- `config`: A configuration file used by VulnFix.
- `dev.patch`: The developer patch for this vulnerability.
- `exploit`: An exploit input to trigger the vulnerability.
- `README.txt`: Some additional information such as where the exploit was downloaded from.
- `setup.sh`: Script to download and build the vulnerable version of the program.


### Randomness in experiments

Since VulnFix uses fuzzing, there are some randomness in the process. The randomness may cause the
results to be slightly different, but the overall claims from Table 2 and 3 should still hold.

In particular, here are some of results that could be affected by randomness:

1. The "#Inv" column in Table 3 can be easily affected by randomness. However, this number is only
for information, and the "result" column that indicates correctness is where the claim is drawn from.
2. Due to randomness in input-level fuzzing, different inputs can be generated, which may cause
VulnFix to unexpectedly fail to produce correct patch invariants in rare occasions. In this case,
please try and re-run the individual bug, which should work for most cases.
Please remember to back up result files and reset that bug before re-running it.

One reason for point 2 to happen is because the current implementation uses ASAN as
test oracle, which is not perfect. For a buffer overflow, if an malicious input manages to "skip"
the redzone by ASAN and access some other valid buffer (but not the intended one), ASAN does not flag
it as error. As such, although being rare, if such an input is generated, its snapshot can be
wrongly classified, causing VulnFix to fail. Re-running VulnFix can likely avoid such issue.
