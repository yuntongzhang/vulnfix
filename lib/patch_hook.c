
#define LIBDL
#include "stdlib.c"

void *external_snapshot = NULL;
void *external_mutate = NULL;
void *external_post_mutate = NULL;

void entry(const void *base, const void *addr, void *state)
{
    dlcall(external_snapshot, base, addr, state);
}

void entry2(intptr_t k, intptr_t add_cert, const char *ins, const void *base, const void *addr, void *state)
{
    dlcall(external_mutate, k, add_cert, ins, base, addr, state);
}

void entry3()
{
    dlcall(external_post_mutate);
}

void init(int argc, char **argv, char **envp, void *dynamic)
{
    if (dlinit(dynamic) != 0)
    {
        fprintf(stderr, "dlinit() failed: %s\n", strerror(errno));
        abort();
    }

    void *handle = dlopen("/home/yuntong/vulnfix/lib/libpatch.so", RTLD_NOW);
    if (handle == NULL)
    {
        fprintf(stderr,
            "dlopen(\"/home/yuntong/vulnfix/lib/libpatch.so\") failed\n");
        abort();
    }

    external_snapshot = dlsym(handle, "snapshot");
    if (external_snapshot == NULL)
    {
        fprintf(stderr, "dlsym(\"snapshot\") failed\n");
        abort();
    }

    external_mutate = dlsym(handle, "mutate");
    if (external_mutate == NULL)
    {
        fprintf(stderr, "dlsym(\"mutate\") failed\n");
        abort();
    }

    external_post_mutate =dlsym(handle, "post_mutate");
    if (external_post_mutate == NULL)
    {
        fprintf(stderr, "dlsym(\"post_mutate\") failed\n");
        abort();
    }
}
