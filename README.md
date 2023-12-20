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

## Documentation

More details can be found in the documentation in the `doc` folder. [MANUAL.md](doc/MANUAL.md)
describes how to use VulnFix in more detail; [DEVELOP.md](doc/DEVELOP.md) contains useful
information for hacking and extending VulnFix.


## Bugs

VulnFix should be considered alpha-quality software. Bugs can be reported
[here](https://github.com/yuntongzhang/vulnfix/issues).
