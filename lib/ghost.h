#ifndef GHOST_H
#define GHOST_H

int generic_buffer_size(void *raw_addr);
int adjust_redzone_size(void* raw_addr, long adjustment);
void *generic_buffer_base(void *raw_addr);

#endif
