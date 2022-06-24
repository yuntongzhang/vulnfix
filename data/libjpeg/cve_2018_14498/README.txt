Patch:
https://github.com/libjpeg-turbo/libjpeg-turbo/commit/9c78a04df4e44ef6487eee99c4258397f4fdca55

PoC:
https://github.com/libjpeg-turbo/libjpeg-turbo/issues/258

Command:
> cd /root/source
> ./cjpeg -outfile vulnfix /root/exploit

Note:
Not applicable to VulnFix since the developer patch introduced a new variable `source->cmap_length`.
