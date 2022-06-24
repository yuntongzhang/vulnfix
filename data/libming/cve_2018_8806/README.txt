Patch:
https://github.com/libming/libming/commit/3a000c7b6fe978dd9925266bb6847709e06dbaa3

PoC:
https://github.com/libming/libming/issues/128
https://github.com/ProbeFuzzer/poc/blob/master/libming/libming_0-4-8_swftophp_heap-use-after-free_bmpdecompileArithmeticOp.swf

Command:
> cd /root/source/util
> ./swftophp /root/exploit

Note:
Not applicable to VulnFix since developer patch introduced new variable `poolcounter`.
