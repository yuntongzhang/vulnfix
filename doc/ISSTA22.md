# Getting started steps (for the version during ISSTA 22)

_This is the instruction for running VulnFix on one example. The full steps for ISSTA22 artifact
evaluation is at [doc/AE.md](doc/AE.md)

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
