Patch:
https://github.com/gdraheim/zziplib/commit/64e745f8a3604ba1c444febed86b5e142ce03dd7

PoC:
https://blogs.gentoo.org/ago/2017/02/09/zziplib-heap-based-buffer-overflow-in-__zzip_get64-fetch-c/
https://github.com/asarubbo/poc/blob/master/00151-zziplib-heapoverflow-__zzip_get64

Command:
> cd /root/source/Linux_5.0.0-37-generic_x86_64.d/bins
> ./unzzipcat-mem /root/exploit

The benign input `test.zip` is from source code test suite.
