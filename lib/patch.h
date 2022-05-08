#include <stdio.h>

#include <dwarf.h>
#include <elfutils/libdw.h>

#include "dwarf_eval.h"
#include "variables.h"


static VAR *dwarf_get_variables(const void *base, const void *addr, STATE *state);

static VAR *dwarf_get_variable(char *base_name, Dwarf_Die *var, VAR *vars);

static VAR *dwarf_get_vars_from_ptr(char *ptr_name, void *ptr_val, Dwarf_Die *type_die,
    VAR *vars, bool only_ghost);

static VAR *dwarf_get_vars_in_struct(char *base_name, void *base_addr, Dwarf_Die *structure,
    VAR *vars);

static VAR *dwarf_get_ghost_from_array(char *base_name, void *addr,
    Dwarf_Die *type_die, VAR *vars);


static VAR *real_add_var(char *name, TYPE t, void *addr, VAR *vars);
static VAR *add_new_var_to_list(char *name, TYPE t, void* addr, VAR *vars);
static VAR *add_new_ghost_size_to_list(char *name, int elem_size, VAR *parent,
    void *addr, VAR *vars);
static VAR *add_new_ghost_base_to_list(char *name, VAR *parent, void *addr, VAR *vars);
