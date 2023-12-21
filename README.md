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

_New changes has been added to VulnFix since the ISSTA22 publication. To get the version during
ISSTA22 period and steps for using that version, please refer to [ISSTA22.md](doc/ISSTA22.md)._

> TODO: Add getting started instruction for the new tool version.

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
docker pull yuntongzhang/vulnfix:latest-manual
docker run -it --memory=30g --name vulnfix yuntongzhang/vulnfix:latest-manual
```

Once inside the container, invoke it on one example (e.g. CVE-2012-5134) with:

```bash
# clone and build the target project
cd /home/yuntong/vulnfix/data/libxml2/cve_2012_5134
./setup.sh
# run vulnfix to repair
cd /home/yuntong/vulnfix
vulnfix data/libxml2/cve_2012_5134/config
```

After VulnFix finishes, the results (generated invariants and patches) can be found in
`/home/yuntong/vulnfix/data/libxml2/cve_2012_5134/runtime/result/`.

## Documentation

More details can be found in the documentation in the `doc` folder. [MANUAL.md](doc/MANUAL.md)
describes how to use VulnFix in more detail; [DEVELOP.md](doc/DEVELOP.md) contains useful
information for hacking and extending VulnFix.


## Bugs

VulnFix should be considered alpha-quality software. Bugs can be reported
[here](https://github.com/yuntongzhang/vulnfix/issues).
