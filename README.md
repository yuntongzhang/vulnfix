# VulnFix

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![docker pull](https://img.shields.io/docker/pulls/yuntongzhang/vulnfix)](https://hub.docker.com/repository/docker/yuntongzhang/vulnfix)
![docker build](https://github.com/yuntongzhang/vulnfix/actions/workflows/docker-image.yml/badge.svg)


VulnFix - An automated program repair technique for fixing security vulnerabilities via inductive
inference.

VulnFix targets security vulnerabilities in C/C++ programs, such as buffer overflows, integer
overflows, and NULL dereferences. It works by first exploring the states at the patch location
with a combination of input-level fuzzing and state-level mutations, and then generalizing
a _patch invariant_ from the observed states.
A patch invariant is a formula that evaluates to true for the benign states and false for
the vulnerable states, which can be used to generate a patch later on.

## Getting started

Firstly, certain OS configurations are required to be set for VulnFix and its dependencies (e.g. AFL).
To set these, run:

```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | sudo tee cpu*/cpufreq/scaling_governor

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

The VulnFix tool and its dependencies are available in docker container. (Please refer to
[doc/INSTALL.md](doc/INSTALL.md) for instructions on building it from source.)
To start:

```bash
docker pull yuntongzhang/vulnfix:issta22
docker run -it --memory=30g --name vulnfix-issta22 yuntongzhang/vulnfix:issta22
```

Once inside the container, navigate to the VulnFix directory and invoke it on CVE-2012-5134:

```bash
cd /home/yuntong/vulnfix
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


## Documentation

More details can be found in the documentation in the `doc` folder. [MANUAL.md](doc/MANUAL.md)
describes how to use VulnFix in more detail; [DEVELOP.md](doc/DEVELOP.md) contains useful
information for hacking and extending VulnFix.


## Bugs

VulnFix should be considered alpha-quality software. Bugs can be reported
[here](https://github.com/yuntongzhang/vulnfix/issues).
