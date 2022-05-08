#include <stdio.h>

#include <dwarf.h>
#include <elfutils/libdw.h>

#include "variables.h"

size_t size(TYPE t)
{
  switch (t)
  {
    case TYPE_BOOL: case TYPE_CHAR: case TYPE_INT8: case TYPE_UINT8:
      return sizeof(int8_t);
    case TYPE_INT16: case TYPE_UINT16:
      return sizeof(int16_t);
    case TYPE_INT32: case TYPE_UINT32:
      return sizeof(int32_t);
    case TYPE_INT64: case TYPE_UINT64:
      return sizeof(int64_t);
    case TYPE_PTR:
      return sizeof(void *);
    default:
      fprintf(stderr, "error: unsized type\n");
      return 0;
  }
}


void dwarf_print_type(FILE *stream, TYPE t)
{
  switch (t)
  {
    case TYPE_UNKNOWN:
      fprintf(stream, "???   ");
      return;
    case TYPE_PTR: //TODO:should not ever happen
      fprintf(stream, "ptr   ");
      // dwarf_print_type(stream, t.deref_type);
      return;
    case TYPE_UNION:
      fprintf(stream, "union ");
      return;
    case TYPE_ARRAY:
      fprintf(stream, "arr   ");
      return;
    case TYPE_BOOL:
      fprintf(stream, "bool  ");
      return;
    case TYPE_CHAR:
      fprintf(stream, "char  ");
      return;
    case TYPE_INT8:
      fprintf(stream, "int8  ");
      return;
    case TYPE_UINT8:
      fprintf(stream, "uint8 ");
      return;
    case TYPE_INT16:
      fprintf(stream, "int16 ");
      return;
    case TYPE_UINT16:
      fprintf(stream, "uint16");
      return;
    case TYPE_INT32:
      fprintf(stream, "int32 ");
      return;
    case TYPE_UINT32:
      fprintf(stream, "uint32");
      return;
    case TYPE_INT64:
      fprintf(stream, "int64 ");
      return;
    case TYPE_UINT64:
      fprintf(stream, "uint64");
      return;
    default:
      fprintf(stream, "???   ");
  }
}


/**
 * Translate a type die into own type here
 **/
TYPE dwarf_decode_type_die(Dwarf_Die *type)
{
  switch (dwarf_tag(type))
  {
    case DW_TAG_pointer_type:
      return TYPE_PTR;
    case DW_TAG_base_type:
    {
      Dwarf_Attribute attr_obj, *attr;
      attr = dwarf_attr(type, DW_AT_byte_size, &attr_obj);
      Dwarf_Word size = 0;
      dwarf_formudata(attr, &size);
      attr = dwarf_attr(type, DW_AT_encoding, &attr_obj);
      Dwarf_Word encoding = 0;
      dwarf_formudata(attr, &encoding);
      switch (encoding)
      {
        case DW_ATE_signed:
          switch (size)
          {
            case sizeof(int8_t):
              return TYPE_INT8;
            case sizeof(int16_t):
              return TYPE_INT16;
            case sizeof(int32_t):
              return TYPE_INT32;
            case sizeof(int64_t):
              return TYPE_INT64;
            default:
              return TYPE_UNKNOWN;
          }
        case DW_ATE_unsigned:
          switch (size)
          {
            case sizeof(uint8_t):
              return TYPE_UINT8;
            case sizeof(uint16_t):
              return TYPE_UINT16;
            case sizeof(uint32_t):
              return TYPE_UINT32;
            case sizeof(uint64_t):
              return TYPE_UINT64;
            default:
              return TYPE_UNKNOWN;
          }
        case DW_ATE_signed_char:
          if (size == sizeof(char))
            return TYPE_CHAR;
          else
            return TYPE_UNKNOWN;
        case DW_ATE_unsigned_char:
          if (size == sizeof(unsigned char))
            return TYPE_UINT8;
          else
            return TYPE_UNKNOWN;
        case DW_ATE_boolean:
          return TYPE_BOOL;
        default:
          return TYPE_UNKNOWN;
      }
    }
    case DW_TAG_typedef:
    {
      // go one layer deeper to get another type die
      Dwarf_Attribute attr_obj, *attr;
      Dwarf_Die new_type_obj, *new_type;
      attr = dwarf_attr(type, DW_AT_type, &attr_obj);
      if (!attr)
      {
        // some DW_TAG_typedef does not have DW_AT_TYPE
        // attribute, which is super strange
        return TYPE_UNKNOWN;
      }
      new_type = dwarf_formref_die(attr, &new_type_obj);
      return dwarf_decode_type_die(new_type);
    }
    case DW_TAG_structure_type:
      return TYPE_STRUCT;
    case DW_TAG_union_type:
      return TYPE_UNION;
    case DW_TAG_array_type:
      return TYPE_ARRAY;
    default:
      return TYPE_UNKNOWN;
  }
}


void my_print_var(FILE *stream, VAR *var, bool log)
{
  if (log)
    fprintf(stderr, "my_print_var with %s at %p\n", var->name, var->ptr);
  if (var->type == TYPE_ARRAY)
  {
    // array var is added to list, but not printed to snapshot file
    if (log)
      fprintf(stderr, "Skipping array varialbe %s when printing to snapshot",
        var->name);
    return;
  }

  // print the actual var
  dwarf_print_type(stream, var->type);
  fprintf(stream, "   %-40s ", var->name);
  switch (var->type)
  {
    case TYPE_PTR:
      fprintf(stream, "%-30p ", *(void **)var->ptr);
      break;
    // TODO: better parsing and add more types to differtiate char/signed char/unsigned char
    case TYPE_INT8:
      fprintf(stream, "%-30d ", *(int8_t *)var->ptr);
      break;
    case TYPE_CHAR:
    case TYPE_UINT8:
      fprintf(stream, "%-30u ", *(uint8_t *)var->ptr);
      break;
    case TYPE_INT16:
      fprintf(stream, "%-30d ", *(int16_t *)var->ptr);
      break;
    case TYPE_UINT16:
      fprintf(stream, "%-30u ", *(uint16_t *)var->ptr);
      break;
    case TYPE_INTEGER:
    case TYPE_INT32:
    case TYPE_BOOL:
      fprintf(stream, "%-30d ", *(int32_t *)var->ptr);
      break;
    case TYPE_UINT32:
      fprintf(stream, "%-30u ", *(uint32_t *)var->ptr);
      break;
    case TYPE_INT64:
      fprintf(stream, "%-30ld ", *(int64_t *)var->ptr);
      break;
    case TYPE_UINT64:
    default:
      fprintf(stream, "%-30lu ", *(uint64_t *)var->ptr);
  }
  fprintf(stream, "%-30p ", var->ptr);
  fprintf(stream, "%-5d\n", var->elem_size);
}
