#include <stdio.h>

#include <dwarf.h>
#include <elfutils/libdw.h>

typedef __int128 int128_t;

typedef enum
{
  TYPE_INTEGER,
  TYPE_BOOL,
  TYPE_CHAR,
  TYPE_INT8,
  TYPE_UINT8,
  TYPE_INT16,
  TYPE_UINT16,
  TYPE_INT32,
  TYPE_UINT32,
  TYPE_INT64,
  TYPE_UINT64,
  TYPE_PTR,
  TYPE_STRUCT,
  TYPE_UNION,
  TYPE_ARRAY,
  TYPE_UNKNOWN = -1,
  TYPE_ERROR = -2
} TYPE;

struct var_s
{
  TYPE type;
  const char *name;
  void *ptr;
  struct var_s *next;
  int elem_size; /** only for ghost varibles **/  /** -1 indicates invalid **/
  struct var_s *parent; /** only for ghost varibles **/
};
typedef struct var_s VAR;


size_t size(TYPE t);
void dwarf_print_type(FILE *stream, TYPE t);
TYPE dwarf_decode_type_die(Dwarf_Die *type);
void my_print_var(FILE *stream, VAR *var, bool log);
