Patch:
https://github.com/vadz/libtiff/commit/9657bbe3cdce4aaa90e07d50c1c70ae52da0ba6a

PoC:
https://blogs.gentoo.org/ago/2017/01/01/libtiff-multiple-heap-based-buffer-overflow/
https://github.com/asarubbo/poc/blob/master/00102-libtiff-heapoverflow-_TIFFmemcpy

Command:
> cd /root/source/tools
> ./tiffcrop -i /root/exploit foo

Note:
Not applicable to VulnFix since developer patch is assignment statement.
