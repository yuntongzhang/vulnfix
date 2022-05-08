#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include "patch.h"
#include "addr_map.h"
#include "ghost.h"

/* Whether output debug log */
static bool log = false;
/* Dwarf debug and cfi for the program */
static Dwarf *debug = NULL;
static Dwarf_CFI *cfi = NULL;
/* The runtime addr of the instruction being instrumented. */
static const void *target_addr = NULL;
/* Value k for kth execution of this instrumentation. */
static int execution_counter = 0;


struct __func_die_search_param {
	Dwarf_Addr	addr;
	Dwarf_Die	*die;
};


/**
 * @brief Callback function for walking through subprogram DIEs.
 */
static int __dwarf_func_search_cb(Dwarf_Die *fn_die, void *arg)
{
    struct __func_die_search_param *param = arg;
    /*
	 * Since a declaration entry doesn't has given pc, this always returns
	 * function definition entry.
	 */
	if (dwarf_tag(fn_die) == DW_TAG_subprogram &&
	    dwarf_haspc(fn_die, param->addr)) {
		memcpy(param->die, fn_die, sizeof(Dwarf_Die));
		return DWARF_CB_ABORT;
	}
	return DWARF_CB_OK;
}


static __attribute__((__constructor__(3333))) void dwarf_init(void)
{
    if (getenv("PATCH_DEBUG") != NULL)
        log = true;

    const char *filename = "/proc/self/exe";
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "error: failed to open \"%s\" for reading: %s\n",
            filename, strerror(errno));
        fprintf(stderr, "       (did you forget to compile with -g?)\n");
        abort();
    }

    debug = dwarf_begin(fd, DWARF_C_READ);
    if (debug == NULL)
    {
        fprintf(stderr, "error: failed to read DWARF debug information for "
            "\"%s\": %s\n", filename, dwarf_errmsg(dwarf_errno()));
        abort();
    }

    cfi = dwarf_getcfi_elf(dwarf_getelf(debug));
    if (cfi == NULL)
    {
        fprintf(stderr, "error: failed to get the DWARF CFI information: %s\n",
            dwarf_errmsg(dwarf_errno()));
        abort();
    }
}


/**
 * @brief Initialization rountine to prepare for the real variable loc parsing.
 * @return 0 on success; -1 on failure.
 */
static int dwarf_var_parsing_init(const void *base, const void *addr, STATE *state)
{
    // Initialize global states
    binary_base_addr = base;
    target_addr = addr;
    saved_state = state;

    // Get frame information
    Dwarf_Frame *frame;
    if (dwarf_cfi_addrframe(cfi, (Dwarf_Addr)addr, &frame) != 0) {
        if (log)
            fprintf(stderr, "warning: failed to get DWARF frame information "
                "for address %p: %s\n", addr, dwarf_errmsg(dwarf_errno()));
        return -1;
    }

    // Store CFA expression
    if (dwarf_frame_cfa(frame, &cfa_expr, &cfa_expr_size) != 0) {
        if (log)
            fprintf(stderr, "warning: failed to get Canonical Frame Address "
                " (CFA) DWARF expression: %s\n", dwarf_errmsg(dwarf_errno()));
        return -1;
    }

    // Scan all compilation units to find subprogram that contains `addr`,
    // And evaluate value for DW_AT_frame_base
    Dwarf_Off offset = 0, last_offset = 0;
    size_t hdr_size;
    while (dwarf_nextcu(debug, offset, &offset, &hdr_size, 0, 0, 0) == 0) {
        Dwarf_Die cudie_obj, *cudie;
        if ((cudie = dwarf_offdie(debug, last_offset + hdr_size, &cudie_obj)) == NULL) {
            last_offset = offset;
            continue;
        }
        last_offset = offset;
        // walk through subprograms (funcs) in this CU and get our current func
        Dwarf_Die func_die;
        struct __func_die_search_param param;
        param.addr = (Dwarf_Addr) addr;
        param.die = &func_die;
        if (dwarf_getfuncs(cudie, __dwarf_func_search_cb, &param, 0) == 0)
            continue;
        // found the func, now retrieve and evaluate DW_AT_frame_base
        Dwarf_Attribute attr_obj, *attr;
        attr = dwarf_attr(&func_die, DW_AT_frame_base, &attr_obj);
        Dwarf_Op *fb_loc = NULL;
        size_t fb_loc_size;
        if (dwarf_getlocation_addr(attr, (Dwarf_Addr)addr, &fb_loc, &fb_loc_size, 1) != 1) {
            if (log) fprintf(stderr, "warning: failed to decode DW_AT_frame_base.");
            return -1;
        }
        frame_base_addr = *(void **)dwarf_evaluate(fb_loc, fb_loc_size);
    }

    if (frame_base_addr == NULL) {
        if (log) fprintf(stderr, "warning: failed to eval DW_AT_frame_base.\n");
        return -1;
    }

    return 0;
}


static VAR *dwarf_get_variables(const void *base, const void *addr, STATE *state)
{
    if (dwarf_var_parsing_init(base, addr, state) != 0)
        return NULL;

    VAR *vars = NULL;

    // Scan all compilation units for the `addr':
    Dwarf_Off offset = 0, last_offset = 0;
    size_t hdr_size;
    while (dwarf_nextcu(debug, offset, &offset, &hdr_size, 0, 0, 0) == 0) {
        Dwarf_Attribute attr_obj, *attr;
        Dwarf_Die cudie_obj, *cudie;
        if ((cudie = dwarf_offdie(debug, last_offset + hdr_size, &cudie_obj)) == NULL) {
            last_offset = offset;
            continue;
        }
        last_offset = offset;

        // look into each scope
        Dwarf_Die *scopes = NULL;
        int n = dwarf_getscopes(cudie, (Dwarf_Addr)addr, &scopes);
        if (n <= 0) continue;

        // Scan all scopes for parameters and variables:
        for (int i = 0; i < n; i++) {
            Dwarf_Die *scope = scopes + i, child_obj;
            Dwarf_Die *child = &child_obj;
            if (!dwarf_haschildren(scope) || dwarf_child(scope, child) != 0)
                continue;
            do {
                switch (dwarf_tag(child)) {
                    case DW_TAG_variable:
                    case DW_TAG_formal_parameter:
                        break;
                    default:
                        continue;
                }
                /* filter out variables that are definitely irrelevant */
                // Skip const vars - const vars won't be mutated
                Dwarf_Die type_obj, *type;
                attr = dwarf_attr(child, DW_AT_type, &attr_obj);
                type = dwarf_formref_die(attr, &type_obj);
                dwarf_peel_type(type, &type_obj);
                type = &type_obj;
                if (dwarf_tag(type) == DW_TAG_const_type)
                    continue;
                if (dwarf_tag(type) == DW_TAG_array_type
                    || dwarf_tag(type) == DW_TAG_pointer_type) {
                    // for const array/ptr, need to examine one more type layer
                    attr = dwarf_attr(type, DW_AT_type, &attr_obj);
                    type = dwarf_formref_die(attr, &type_obj);
                    dwarf_peel_type(type, &type_obj);
                    type = &type_obj;
                    if (dwarf_tag(type) == DW_TAG_const_type)
                        continue;
                    if (dwarf_tag(type) == DW_TAG_array_type
                        || dwarf_tag(type) == DW_TAG_pointer_type) {
                        // TODO: improve coding
                        // yet another layer
                        attr = dwarf_attr(type, DW_AT_type, &attr_obj);
                        type = dwarf_formref_die(attr, &type_obj);
                        dwarf_peel_type(type, &type_obj);
                        type = &type_obj;
                        if (dwarf_tag(type) == DW_TAG_const_type)
                            continue;
                    }
                }
                /* filtering done; proceed to get this variable */
                vars = dwarf_get_variable("", child, vars);
            }
            while (dwarf_siblingof(child, child) == 0);
        }
    }

	return vars;
}


// must be supported when calling this function
static VAR *real_add_var(char *name, TYPE t, void *addr, VAR *vars)
{
    VAR *entry = (VAR *)malloc(sizeof(VAR));
    assert(entry != NULL);
    entry->name = name;
    assert(entry->name != NULL);
    entry->type = t;
    entry->ptr  = addr;
    entry->next = vars;
    entry->elem_size = -1; // indicates invalid
    entry->parent = NULL;
    vars = entry;
    if (log) {
        fprintf(stderr, "\33[32m");
        dwarf_print_type(stderr, t);
        fprintf(stderr, "\33[0m %s (addr: \33[31m%p", entry->name, entry->ptr);
        fprintf(stderr, "\33[0m)\n");
    }
    return vars;
}

static VAR *add_new_var_to_list(char *name, TYPE t, void* addr, VAR *vars)
{
    // fprintf(stderr, "add_new_var_to_list with %s\n", name);
    bool skip = false;
    if (t == TYPE_UNION) {
        if (log)
            fprintf(stderr, "warning: leaving out union type var (%s) for now\n", name);
        skip = true;
    } else if (t == TYPE_UNKNOWN) {
        if (log)
            fprintf(stderr, "warning: leaving out unknown type var (%s) for now\n", name);
        skip = true;
    } else if (!is_addr_writable(addr)) {
        if (log)
            fprintf(stderr, "warning: leaving out var (%s) [not writable]\n", name);
        skip = true;
    }

    if (!skip) {
        return real_add_var(name, t, addr, vars);
    } else {
        free(name);
        return vars;
    }
}


static VAR *add_new_ghost_size_to_list(char *name, int elem_size, VAR *parent,
    void *addr, VAR *vars)
{
    // no sanitiy check needed. Ghost vars are added by us, so always supported.
    vars = real_add_var(name, TYPE_UINT32, addr, vars);
    // post action: add ghost var specific fields
    vars->elem_size = elem_size;
    vars->parent = parent;
    return vars;
}


static VAR *add_new_ghost_base_to_list(char *name, VAR *parent, void *addr, VAR *vars)
{
    // no sanity check needed. Ghost vars are added by us, so always supported.
    vars = real_add_var(name, TYPE_PTR, addr, vars);
    // post action: add ghost var specific fields
    vars->parent = parent;
    return vars;
}


/**
 * Base name should be the form "name->" or "name.", depending on whether
 * this function is called from ptr or not
 **/
static VAR *dwarf_get_vars_in_struct(char *base_name, void *base_addr, Dwarf_Die *structure,
   VAR *vars)
{
    Dwarf_Die child_obj, *child = &child_obj;
    if (dwarf_child(structure, child) != 0)
    {
        if (log)
            fprintf(stderr, "warning: failed to get child die for (%s)\n",
                dwarf_diename(structure));
        free(base_name);
        return vars;
    }
    do
    {
        if (dwarf_tag(child) != DW_TAG_member)
            continue;
        Dwarf_Attribute attr_obj, *attr;
        void *child_addr;
        if (dwarf_hasattr(child, DW_AT_data_member_location))
        {
            attr = dwarf_attr(child, DW_AT_data_member_location, &attr_obj);
            Dwarf_Word offset;
            if (dwarf_formudata(attr, &offset) == 0) // integer offset
            {
                child_addr = (char *)base_addr + (unsigned)offset;
            }
            else // attr is location description
            {
                Dwarf_Op *loc = NULL;
                size_t loc_size;
                dwarf_getlocation(attr, &loc, &loc_size);
                // TODO: not correct yet! need to push the base of struct first!
                child_addr = (void *)dwarf_evaluate(loc, loc_size);
            }
        }
        else // DW_AT_data_bit_offset
        {
            attr = dwarf_attr(child, DW_AT_data_bit_offset, &attr_obj);
            Dwarf_Word offset_bits;
            dwarf_formudata(attr, &offset_bits);
            // TODO: have a better way of handling this.
            child_addr = (char *)base_addr + (unsigned)offset_bits / 8;
        }
        // prepare for child name
        size_t new_len = strlen(base_name) + strlen(dwarf_diename(child)) + 1;
        char *new_name = (char *)malloc(new_len);
        snprintf(new_name, new_len, "%s%s", base_name, dwarf_diename(child));
        // check type of this member
        Dwarf_Die type_obj, *type;
        attr = dwarf_attr(child, DW_AT_type, &attr_obj);
        type = dwarf_formref_die(attr, &type_obj);
        dwarf_peel_type(type, &type_obj);
        TYPE t = dwarf_decode_type_die(type);

        if (t == TYPE_STRUCT) // depth-first-search on inner struct
        {
            new_len++;
            new_name = (char *)realloc(new_name, new_len);
            snprintf(new_name, new_len, "%s%s.", base_name, dwarf_diename(child));
            vars = dwarf_get_vars_in_struct(new_name, child_addr, type, vars);
        }
        else if (t == TYPE_PTR)
        {
            // sanity checks before continue with a ptr field
            if (!is_addr_accessable(child_addr))
            {
                vars = add_new_var_to_list(new_name, t, child_addr, vars);
                continue;
            }
            // also make sure ptr_val is not NULL since it's going to be derefed
            void *ptr_val = *(void **)child_addr;
            if (!is_addr_accessable(ptr_val)) {
                vars = add_new_var_to_list(new_name, t, child_addr, vars);
                continue;
            }

            // make another allocation for name, since the original one
            // is going to be used for a variable
            char *new_name_dup = strdup(new_name);

            // add the original pointer field to var list
            vars = add_new_var_to_list(new_name, t, child_addr, vars);
            // count how many ">" are there in the base name
            int arrow_count = 0;
            for (int i = 0; i < strlen(base_name); ++i)
            {
                if (*(base_name + i) == '>')
                    arrow_count++;
            }
            // use this heuristic to decide whether to continue unpack ptr field
            // we don't always unpack a ptr field to avoid too many variables,
            // and also to avoid unpacking linked list node
            if (arrow_count <= 2)
            {
                if (arrow_count == 2) // only add ghost
                {
                    vars = dwarf_get_vars_from_ptr(new_name_dup, ptr_val,
                        type, vars, true);
                }
                else // add ghost + derefed vars from this pointer field
                {
                    vars = dwarf_get_vars_from_ptr(new_name_dup, ptr_val,
                        type, vars, false);
                }
            } else {
                free(new_name_dup);
            }
        }
        else if (t == TYPE_ARRAY)
        {
            vars = dwarf_get_ghost_from_array(new_name, child_addr, type, vars);
        }
        else // we reach a base type which is directly addable to list
        {
            // fprintf(stderr, "going to add %s in struct as new var\n", new_name);
            vars = add_new_var_to_list(new_name, t, child_addr, vars);
        }
    }
    while (dwarf_siblingof(child, child) == 0);

    free(base_name);
    return vars;
}


/**
 * Recursively dereference pointer to obtain more variables.
 * For top-level pointer, `ptr_name` should only contain the name string
 *      (no extra * for this layer). (So that we are not confused when producing next-level names.)
 * `ptr_val`: content of this pointer.
 * `type_die`: the type die associated with the pointer.
 **/
static VAR *dwarf_get_vars_from_ptr(char *ptr_name, void *ptr_val, Dwarf_Die *type_die,
    VAR *vars, bool only_ghost)
{
    assert(dwarf_tag(type_die) == DW_TAG_pointer_type);
    TYPE t; // the decoded type of the pointed to type
    // type die should have a next layer type die that describe the real type
    Dwarf_Attribute attr_obj, *attr;
    Dwarf_Die new_type_obj, *new_type;
    attr = dwarf_attr(type_die, DW_AT_type, &attr_obj);
    if (attr == NULL)
        return vars;
    new_type = dwarf_formref_die(attr, &new_type_obj);
    // this next layer type die can be `typedef`, which requires peeling
    dwarf_peel_type(new_type, &new_type_obj);
    new_type = &new_type_obj;

    /**
     * A hacky check to avoid further segfault when this function is dealing
     * with void*
     **/
    build_address_map(); // somehow new VMAs has been created
    if (!is_addr_readable(new_type->abbrev)) {
        free(ptr_name);
        return vars;
    }

    /**
     * For each ptr, attempt to get ghost variables for it
     **/
    if (!is_addr_writable(ptr_val))
        goto pointer_normal;
    if (!dwarf_hasattr(new_type, DW_AT_byte_size))
        goto pointer_normal;
    int elem_size = dwarf_bytesize(new_type); // size in bytes of the pointed type
    if (elem_size <= 0)
        goto pointer_normal;
    // NOTE: here we hold the assumption that the parent ptr var was added
    // immediately before this one
    VAR *parent_var = vars;
    // (1) ghost variable for buffer size
    int buffer_size = generic_buffer_size(ptr_val);
    // TODO: check for elem_size in python
    // if (buffer_size != -1 && elem_size < 16)
    if (buffer_size != -1)
    {
        unsigned int *size_holder = (unsigned int *)malloc(sizeof(unsigned int));
        *size_holder = buffer_size;
        // *size_holder = *size_holder / elem_size;
        char *gsize_name = (char *)malloc(strlen(ptr_name) + 9);
        snprintf(gsize_name, strlen(ptr_name) + 8, "_GSize_%s", ptr_name);
        vars = add_new_ghost_size_to_list(gsize_name, elem_size, parent_var,
            size_holder, vars);
    }
    // (2) ghost variable for buffer base
    void *buffer_base = generic_buffer_base(ptr_val);
    if (buffer_base != NULL)
    {
        void **base_holder = (void **)malloc(sizeof(void *));
        *base_holder = buffer_base;
        char *gbase_name = (char *)malloc(strlen(ptr_name) + 9);
        snprintf(gbase_name, strlen(ptr_name) + 8, "_GBase_%s", ptr_name);
        vars = add_new_ghost_base_to_list(gbase_name, parent_var, base_holder, vars);
    }

    if (only_ghost)
    {
        free(ptr_name);
        return vars;
    }

pointer_normal:
    // this new type die can be ptr/struct/simple type
    t = dwarf_decode_type_die(new_type);
    size_t new_len = strlen(ptr_name) + 2;
    char *new_name = (char *)malloc(new_len);
    snprintf(new_name, new_len, "*%s", ptr_name);
    switch (t)
    {
        case TYPE_PTR:
        {
            // (1) add this next-level ptr to variable list
            vars = add_new_var_to_list(new_name, t, ptr_val, vars);
            // (2) deref this pointer and process the derefed variable
            if (!is_addr_writable(ptr_val))
                return vars;
            void *new_ptr_val = *(void **)ptr_val;
            return dwarf_get_vars_from_ptr(new_name, new_ptr_val, new_type, vars, false);
        }
        case TYPE_STRUCT:
            // fprintf(stderr, "going to examine var %s as struct\n", ptr_name);
            new_len++;
            new_name = (char *)realloc(new_name, new_len);
            snprintf(new_name, new_len, "%s->", ptr_name);
            return dwarf_get_vars_in_struct(new_name, ptr_val, new_type, vars);
        case TYPE_ARRAY:
            free(new_name);
            return dwarf_get_ghost_from_array(ptr_name, ptr_val, new_type, vars);
        default:
            return add_new_var_to_list(new_name, t, ptr_val, vars);
    }
}


static VAR *dwarf_get_ghost_from_array(char *base_name, void *addr,
    Dwarf_Die *type_die, VAR *vars)
{
    if (!is_addr_writable(addr))
        goto exit;
    // first add the actual array variable
    char *array_name = strdup(base_name);
    vars = add_new_var_to_list(array_name, TYPE_ARRAY, addr, vars);
    // read asan shadow memory for size in bytes
    int buffer_size = generic_buffer_size(addr);
    if (buffer_size == -1)
        goto exit;
    unsigned int *size_addr = (unsigned int *)malloc(sizeof(unsigned int));
    *size_addr = buffer_size;
    // read dwarf to get element size
    Dwarf_Attribute attr_obj, *attr;
    Dwarf_Die type_obj, *type;
    attr = dwarf_attr(type_die, DW_AT_type, &attr_obj);
    type = dwarf_formref_die(attr, &type_obj);
    dwarf_peel_type(type, &type_obj);
    type = &type_obj; // this is the type of array element
    int elem_size = dwarf_bytesize(type);
    // assert(elem_size != 0);
    // TODO: check elem_size in python
    // if (elem_size <= 0 || elem_size >= 16)
    if (elem_size <= 0)
        goto exit;
    // *size_addr = *size_addr / elem_size;
    char *ghost_name = (char *)malloc(strlen(base_name) + 9);
    snprintf(ghost_name, strlen(base_name) + 8, "_GSize_%s", base_name);
    free(base_name);

    return add_new_ghost_size_to_list(ghost_name, elem_size, vars, size_addr, vars);
exit:
    free(base_name);
    return vars;
}

static VAR *dwarf_get_variable(char *base_name, Dwarf_Die *var, VAR *vars)
{
    if (dwarf_diename(var) == NULL) // No name?
        return vars;

    // fprintf(stderr, "get_variable on the var %s\n", dwarf_diename(var));
    // get location of this var
    Dwarf_Attribute attr_obj;
    Dwarf_Attribute *attr = dwarf_attr(var, DW_AT_location, &attr_obj);
    if (attr == NULL)
        return vars;
    Dwarf_Op *loc = NULL;
    size_t loc_size;
    if (dwarf_getlocation_addr(attr, (Dwarf_Addr)target_addr, &loc, &loc_size, 1) != 1)
    {
        if (log)
            fprintf(stderr, "warning: failed to decode DW_AT_location for "
                "(%s): %s\n",
                dwarf_diename(var), dwarf_errmsg(dwarf_errno()));
        return vars;
    }
    void *var_addr = (void *)dwarf_evaluate(loc, loc_size);

    // get type of this var
    Dwarf_Die type_obj, *type;
    attr = dwarf_attr(var, DW_AT_type, &attr_obj);
    if (attr == NULL)
    {
        if (log)
            fprintf(stderr, "warning: missing DW_AT_type for (%s)\n",
                dwarf_diename(var));
        return vars;
    }
    type = dwarf_formref_die(attr, &type_obj);
    dwarf_peel_type(type, &type_obj);
    type = &type_obj;
    TYPE t = dwarf_decode_type_die(type);
    // prepare for name
    size_t new_len = strlen(base_name) + strlen(dwarf_diename(var)) + 1;
    char *new_base = (char *)malloc(new_len);
    snprintf(new_base, new_len, "%s%s", base_name, dwarf_diename(var));
    if (t == TYPE_PTR)
    {
        // fprintf(stderr, "get_variable on the ptr var %s\n", dwarf_diename(var));
        // (1) add this pointer to variable list
        vars = add_new_var_to_list(new_base, t, var_addr, vars);
        // (2) retrieve deref variables from this pointer
        char *new_base_dup = strdup(new_base);
        return dwarf_get_vars_from_ptr(new_base_dup, *(void **)var_addr,
            type, vars, false);
    }
    if (t == TYPE_STRUCT)
    {
        new_len++;
        new_base = (char *)realloc(new_base, new_len);
        snprintf(new_base, new_len, "%s%s.", base_name, dwarf_diename(var));
        return dwarf_get_vars_in_struct(new_base, var_addr, type, vars);
    }
    if (t == TYPE_ARRAY)
    {
        return dwarf_get_ghost_from_array(new_base, var_addr, type, vars);
    }
    if (t == TYPE_UNKNOWN)
    {
        if (log) fprintf(stderr, "warning: unknown type for (%s)\n", new_base);
        return vars;
    }

    return add_new_var_to_list(new_base, t, var_addr, vars);
}


/**
 * Mutate a single var according to a "var=val" instruction.
 **/
void mutate_var(char *instruction, VAR *vars)
{
    /** Parse mutation instruction **/
    char *val_str = instruction;
    int var_len = 0;
    while (*val_str != '\0')
    {
        if (*val_str == '=')
        {
            val_str++;
            break;
        }
        val_str++;
        var_len++;
    }
    char *var = instruction;
    *(var + var_len) = '\0';
    char *to_search = (char *)malloc(var_len + 1);
    if (strstr(var, "_GDiff_")) {
        // search for the underlying ptr if asked to mutate GDiff
        strcpy(to_search, var + 7);
    } else {
        strcpy(to_search, var);
    }

    /** Find out which var this instruction wants to mutate **/
    VAR *to_mutate = vars;
    while (to_mutate != NULL)
    {
        if (!strcmp(to_mutate->name, to_search))
            break;
        to_mutate = to_mutate->next;
    }
    if (to_mutate == NULL)
        return;

    /** Case (1): asked to mutate _GDiff_, so `to_mutate` is the underlying pointer **/
    if (strstr(var, "_GDiff_"))
    {
        int64_t gdiff_value = strtoll(val_str, NULL, 0);
        void *orig_ptr_val; // value of ptr for _GDiff_ptr
        if (to_mutate->type == TYPE_PTR) {
            orig_ptr_val = *(void **)to_mutate->ptr;
        } else { // TYPE_ARRAY
            orig_ptr_val = to_mutate->ptr;
        }
        // value of _GBase_ptr for ptr and _GDiff_ptr
        void *base_ptr_val = generic_buffer_base(orig_ptr_val);
        // get mutated value
        void *new_ptr_val = base_ptr_val + gdiff_value;
        // write the new val to complete mutation
        if (to_mutate->type == TYPE_PTR) {
            *(void **)to_mutate->ptr = new_ptr_val;
        } else { // TYPE_ARRAY
            to_mutate->ptr = new_ptr_val;
        }
    }
    /** Case (2): var to mutate is buffer size **/
    else if (strstr(to_mutate->name, "_GSize_"))
    {
        long new_size = (long)strtoll(val_str, NULL, 0);
        long old_size = *(uint32_t *)to_mutate->ptr;
        // new size and old size are raw size values in bytes
        long adjustment = new_size - old_size;
        VAR *underlying_var = to_mutate->parent;
        int mutated_size;
        if (underlying_var->type == TYPE_PTR) {
            mutated_size = adjust_redzone_size(*(void **)underlying_var->ptr, adjustment);
        } else {// TYPE_ARRAY, ->ptr is the actual address of array
            mutated_size = adjust_redzone_size(underlying_var->ptr, adjustment);
        }

        if (mutated_size != -1) { // mutation success
            // update ghost var value + initialize for in-place extension
            *(uint32_t *)to_mutate->ptr = mutated_size;
            // memcpy(to_mutate->ptr, (uint32_t *)&mutated_size, size(to_mutate->type));
            long actual_size_change = mutated_size - old_size;
            if (actual_size_change > 0) { // in-place extension
                void *buffer_start, *buffer_end;
                if (underlying_var->type == TYPE_PTR) {
                    buffer_start = generic_buffer_base(*(void **)underlying_var->ptr);
                } else { // TYPE_ARRAY
                    buffer_start = generic_buffer_base(underlying_var->ptr);
                }
                buffer_end = buffer_start + old_size;
                // zero-initialization of the extended space
                memset(buffer_end, 0x0, actual_size_change);
            }
        } else { // mutation fail
            if (log) fprintf(stderr, "warning: _GSize_ mutation failed.\n");
        }
    }
    /** Case (3): var to mutate is pointer **/
    else if (to_mutate->type == TYPE_PTR)
    {
        if (strstr(val_str, "malloc"))
        {
            val_str += 6;
            int malloc_size = atoi(val_str);
            // newly allocated object is zero-initialized
            void *new_val = calloc(malloc_size, 1);
            *(void **)to_mutate->ptr = new_val;
        }
        else // just ptr=val
        {
            void *new_val = (void *)strtoll(val_str, NULL, 0);
            *(void **)to_mutate->ptr = new_val;
        }
    }
    /** Case (4): var to mutate is an integer value **/
    else
    {
        long long val_num = strtoll(val_str, NULL, 0);
        switch (to_mutate->type)
        {
            case TYPE_INT8:
            {
                int8_t real_val = (int8_t)val_num;
                *(int8_t *)to_mutate->ptr = real_val;
                // memcpy(to_mutate->ptr, &real_val, size(to_mutate->type));
                break;
            }
            case TYPE_CHAR:
            case TYPE_BOOL:
            case TYPE_UINT8:
            {
                uint8_t real_val = (uint8_t)val_num;
                *(uint8_t *)to_mutate->ptr = real_val;
                // memcpy(to_mutate->ptr, &real_val, size(to_mutate->type));
                break;
            }
            case TYPE_INT16:
            {
                int16_t real_val = (int16_t)val_num;
                *(int16_t *)to_mutate->ptr = real_val;
                // memcpy(to_mutate->ptr, &real_val, size(to_mutate->type));
                break;
            }
            case TYPE_UINT16:
            {
                uint16_t real_val = (uint16_t)val_num;
                *(uint16_t *)to_mutate->ptr = real_val;
                // memcpy(to_mutate->ptr, &real_val, size(to_mutate->type));
                break;
            }
            case TYPE_INTEGER:
            case TYPE_INT32:
            {
                int32_t real_val = (int32_t)val_num;
                *(int32_t *)to_mutate->ptr = real_val;
                // memcpy(to_mutate->ptr, &real_val, size(to_mutate->type));
                break;
            }
            case TYPE_UINT32:
            {
                uint32_t real_val = (uint32_t)val_num;
                *(uint32_t *)to_mutate->ptr = real_val;
                // memcpy(to_mutate->ptr, &real_val, size(to_mutate->type));
                break;
            }
            case TYPE_INT64:
            {
                int64_t real_val = (int64_t)val_num;
                *(int64_t *)to_mutate->ptr = real_val;
                // memcpy(to_mutate->ptr, &real_val, size(to_mutate->type));
                break;
            }
            case TYPE_UINT64:
            {
                uint64_t real_val = (uint64_t)val_num;
                *(uint64_t *)to_mutate->ptr = real_val;
                // memcpy(to_mutate->ptr, &real_val, size(to_mutate->type));
                break;
            }
            default:
                fprintf(stderr, "Unsupported type during mutation.\n");
        }
    }
}

static void clean_up_vars(VAR *vars)
{
    VAR *prev = NULL;
    while (vars != NULL)
    {
        prev = vars;
        vars = vars->next;
        free((void *)prev->name);
        free(prev);
    }
}


static void print_snapshot_to_file(char *fname, VAR *vars)
{
    FILE *out;
    if (execution_counter == 1)
        out = fopen(fname, "w");
    else
        out = fopen(fname, "a");
    VAR *tmp = vars;
    while (tmp != NULL)
    {
        my_print_var(out, tmp, log);
        tmp = tmp->next;
    }
    // delimeter between snapshots
    fprintf(out, "---\n");
    fclose(out);
}

static void certify_snapshot_file(char *fname)
{
    FILE *out;
    if (execution_counter == 1) {
        out = fopen(fname, "a");
        fprintf(out, "snapshotfileisvalid\n");
        fclose(out);
    }
}


/****************************************************************************/
/* ENTRY POINT FROM E9TOOL INSTRUMENTATION                                  */
/****************************************************************************/

void snapshot(const void *base, const void *addr, STATE *state)
{
    if (log)
        printf("\naddr = \33[33m%p\33[0m:\n", addr);

    execution_counter++;
    build_address_map();

    VAR *vars = dwarf_get_variables(base, addr, state);

    print_snapshot_to_file("snapshot.out", vars);
    certify_snapshot_file("snapshot.out");

    /* Clean up. */
    clean_up_vars(vars);
    clean_up_address_map();

    if (log)
        fprintf(stderr, "~~~~ Congrats! Snapshot instrumentation ended! ~~~~\n");
}


/**
 *  k: which snapshot to mutate
 *  ins: instructions on how to mutate
 *      format: "varA=10 varB=100"
 */
void mutate(intptr_t k, intptr_t add_cert, const char *ins, const void *base, const void *addr, STATE *state)
{
    if (log)
        printf("\naddr = \33[33m%p\33[0m:\n", addr);

    execution_counter++;
    build_address_map();

    VAR *vars = dwarf_get_variables(base, addr, state);

    /**
     * If this `mutate` function is executed more than once, only perform actual
     * mutation on the kth execution, and only take snapshot for other executions.
     * This is to handle loop control variable. If we are mutating a loop
     * control variable, there is chance that the mutation makes program stuck
     * inside that loop.
     **/
    if (execution_counter == k)
    {
        // parse instruction list and mutate
        char *ins_list = strdup(ins);
        char *pair = strtok(ins_list, " ");
        char *var, *val;
        while (pair != NULL)
        {
            mutate_var(pair, vars);
            pair = strtok(NULL, " ");
        }
        // aliasing can be possbile: two ptrs can be aliasing - mutating _GSize_
        // for one will not change the other, if we don't retrieve snapshot again
        vars = dwarf_get_variables(base, addr, state);
    }

    // print snapshot after mutation
    print_snapshot_to_file("snapshot.out", vars);
    if (add_cert) certify_snapshot_file("snapshot.out");

    // clean up
    clean_up_vars(vars);
    clean_up_address_map();

    if (log)
        fprintf(stderr, "~~~~ Congrats! Mutation instrumentation ended! ~~~~\n");
}


/**
 * To be instrumented at the bug location after `mutate` is executed at fix loc.
 * This is to distinguish whether the mutation still cause the program to reach
 * the original bug location.
 **/
void post_mutate()
{
    certify_snapshot_file("snapshot.out");
}
