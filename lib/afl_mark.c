#include "stdlib.c"

#define MARKER_BASE   ((uint8_t *)0x1FF000)


/* SHM setup. */
static void __afl_setup_marker(void)
{
    const char *id_str = getenv("__AFL_MARKER_SHM_ID");
    intptr_t afl_marker_ptr = 0x0;
    uint32_t shm_id = 0;
    
    if (id_str != NULL)
    {
        shm_id = (uint32_t)atoi(id_str);
        afl_marker_ptr = (intptr_t)shmat(shm_id, MARKER_BASE, 0);
    }
    else
    {
        /**
         * If there is no id_str then we are running the programming normally
         * and not with afl-fuzz. Create a dummy area so the program does not
         * crash.
         **/
        afl_marker_ptr = (intptr_t)mmap(MARKER_BASE, 4096, 
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }

    /* Whooooops. */
    if (afl_marker_ptr != (intptr_t)MARKER_BASE)
    {
        fprintf(stderr, "fail to map AFL marker are (shm_id=%s): %s", id_str,
            strerror(errno));
        abort();
    }

    // for each exeuction of the patched binary, clear marker content
    memset(MARKER_BASE, 0, 1);
}


/**
 * Set first bit of marker.
 * call entry_fix@afl_mark
 **/
void entry_fix(void)
{
    *MARKER_BASE |= (1 << 7);
}


/**
 * Set second bit of marker.
 * call entry_crash@afl_mark
 **/
void entry_crash(void)
{
    *MARKER_BASE |= (1 << 6);
}


/**
 * Set both bits of marker.
 * call entry_combine@afl_mark
 **/
void entry_combine(void)
{
    *MARKER_BASE |= ((1 << 7) | (1 << 6));
}


void init(int argc, char **argv, char **envp)
{
    environ = envp;
    __afl_setup_marker();
}
