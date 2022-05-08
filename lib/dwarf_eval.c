#include "dwarf_eval.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* A container for calculated CFA. */
static void *cfa_holder;
/* Calculated value for DW_AT_frame_base. */
void *frame_base_addr = NULL;
/* The runtime base address of the current binary */
const void *binary_base_addr = NULL;
/* The saved register context at the instrumentation point. */
const STATE *saved_state = NULL;
/* Unevaluated expression for CFA. */
Dwarf_Op *cfa_expr = NULL;
size_t cfa_expr_size = 0;


/*
 * Push a value onto the stack.
 */
static void dwarf_push_int(dwarf_stack_t stack, intptr_t val)
{
  assert(stack->pos < sizeof(stack->data) / sizeof(stack->data[0]));
  stack->data[stack->pos++] = (uintptr_t)val;
}
static void dwarf_push_uint(dwarf_stack_t stack, uintptr_t val)
{
  assert(stack->pos < sizeof(stack->data) / sizeof(stack->data[0]));
  stack->data[stack->pos++] = val;
}
static void dwarf_push_addr(dwarf_stack_t stack, uint8_t *val)
{
  assert(stack->pos < sizeof(stack->data) / sizeof(stack->data[0]));
  stack->data[stack->pos++] = (uintptr_t)val;
}

/*
 * Pop a value from the stack.
 */
static intptr_t dwarf_pop_int(dwarf_stack_t stack)
{
  assert(stack->pos > 0);
  stack->pos--;
  return (intptr_t)stack->data[stack->pos];
}
static uintptr_t dwarf_pop_uint(dwarf_stack_t stack)
{
  assert(stack->pos > 0);
  stack->pos--;
  return stack->data[stack->pos];
}
static uint8_t *dwarf_pop_addr(dwarf_stack_t stack)
{
  assert(stack->pos > 0);
  stack->pos--;
  return (uint8_t *)stack->data[stack->pos];
}

/*
 * Pick a value from the stack.
 */
static uintptr_t dwarf_pick_uint(dwarf_stack_t stack, size_t idx)
{
  assert(idx < stack->pos);
  return stack->data[stack->pos - idx];
}

/*
 * Load an integer from a register.
 */
static const void *dwarf_load_reg(const STATE *state, size_t reg)
{
  switch (reg)
  {
    case 0:  return &state->rax;
    case 1:  return &state->rdx;
    case 2:  return &state->rcx;
    case 3:  return &state->rbx;
    case 4:  return &state->rsi;
    case 5:  return &state->rdi;
    case 6:  return &state->rbp;
    case 7:  return &state->rsp;
    case 8:  return &state->r8;
    case 9:  return &state->r9;
    case 10: return &state->r10;
    case 11: return &state->r11;
    case 12: return &state->r12;
    case 13: return &state->r13;
    case 14: return &state->r14;
    case 15: return &state->r15;
    case 16: return &state->rip;
    default:
      fprintf(stderr, "error: unsupported register (%zu)\n", reg);
      abort();
  }
}
static uintptr_t dwarf_load_value(const STATE *state, size_t reg)
{
  return *(uintptr_t *)dwarf_load_reg(state, reg);
}
static intptr_t dwarf_load_int(const STATE *state, size_t reg)
{
  return (intptr_t)dwarf_load_value(state, reg);
}
static uintptr_t dwarf_load_uint(const STATE *state, size_t reg)
{
  return dwarf_load_value(state, reg);
}
static uint8_t *dwarf_load_addr(const STATE *state, size_t reg)
{
  return (uint8_t *)dwarf_load_value(state, reg);
}


uintptr_t dwarf_evaluate(Dwarf_Op *expr, size_t expr_size)
{
  struct dwarf_stack_s stack_object;
  dwarf_stack_t stack = &stack_object;
  stack->pos = 0;

  uint8_t *a0, *a1;
  uintptr_t u0, u1, u2;
  intptr_t  s0, s1;

  const Dwarf_Op *start = expr;
  const Dwarf_Op *end   = expr + expr_size;

  while (expr < end)
  {
    Dwarf_Op *op = expr++;
    switch (op->atom)
    {
      case DW_OP_addr:
        dwarf_push_addr(stack, (uint8_t *)((intptr_t)binary_base_addr + op->number));
        break;
      case DW_OP_reg0: case DW_OP_reg1: case DW_OP_reg2:
      case DW_OP_reg3: case DW_OP_reg4: case DW_OP_reg5:
      case DW_OP_reg6: case DW_OP_reg7: case DW_OP_reg8:
      case DW_OP_reg9: case DW_OP_reg10: case DW_OP_reg11:
      case DW_OP_reg12: case DW_OP_reg13: case DW_OP_reg14:
      case DW_OP_reg15: case DW_OP_reg16: case DW_OP_reg17:
      case DW_OP_reg18: case DW_OP_reg19: case DW_OP_reg20:
      case DW_OP_reg21: case DW_OP_reg22: case DW_OP_reg23:
      case DW_OP_reg24: case DW_OP_reg25: case DW_OP_reg26:
      case DW_OP_reg27: case DW_OP_reg28: case DW_OP_reg29:
      case DW_OP_reg30: case DW_OP_reg31:
        a0 = (uint8_t *)dwarf_load_reg(saved_state, op->atom - DW_OP_reg0);
        dwarf_push_addr(stack, a0);
        break;
      case DW_OP_breg0: case DW_OP_breg1: case DW_OP_breg2:
      case DW_OP_breg3: case DW_OP_breg4: case DW_OP_breg5:
      case DW_OP_breg6: case DW_OP_breg7: case DW_OP_breg8:
      case DW_OP_breg9: case DW_OP_breg10: case DW_OP_breg11:
      case DW_OP_breg12: case DW_OP_breg13: case DW_OP_breg14:
      case DW_OP_breg15: case DW_OP_breg16: case DW_OP_breg17:
      case DW_OP_breg18: case DW_OP_breg19: case DW_OP_breg20:
      case DW_OP_breg21: case DW_OP_breg22: case DW_OP_breg23:
      case DW_OP_breg24: case DW_OP_breg25: case DW_OP_breg26:
      case DW_OP_breg27: case DW_OP_breg28: case DW_OP_breg29:
      case DW_OP_breg30: case DW_OP_breg31:
        a0 = dwarf_load_addr(saved_state, op->atom - DW_OP_breg0);
        s0 = (intptr_t)op->number;
        dwarf_push_addr(stack, a0 + s0);
        break;
      case DW_OP_bregx:
        u0 = (uintptr_t)op->number;
        a0 = dwarf_load_addr(saved_state, u0);
        s0 = (intptr_t)op->number2;
        dwarf_push_addr(stack, a0 + s0);
        break;
      case DW_OP_fbreg:
        // frame_base_addr is the addr specified by DW_AT_frame_base
        s0 = (intptr_t)op->number;
        dwarf_push_addr(stack, frame_base_addr + s0);
        break;
      case DW_OP_call_frame_cfa:
        // special case. since everything else is returning a location containing
        // the actual information, we create a location to hold this information.
        // here, the cfa is the information, not location.
        cfa_holder = (void *)dwarf_evaluate(cfa_expr, cfa_expr_size);
        return (uintptr_t) &cfa_holder;
      case DW_OP_plus_uconst:
        u0 = dwarf_pop_uint(stack);
        u1 = (uintptr_t)op->number;
        dwarf_push_uint(stack, u0 + u1);
        break;
      case DW_OP_deref:
        a0 = dwarf_pop_addr(stack);
        memcpy(&u0, a0, sizeof(u0));
        dwarf_push_uint(stack, u0);
        break;
      case DW_OP_deref_size:
        a0 = dwarf_pop_addr(stack);
        u0 = (uintptr_t)op->number;
        switch (u0)
        {
          case sizeof(int8_t): case sizeof(int16_t):
          case sizeof(int32_t): case sizeof(int64_t):
            memcpy(&u0, a0, u0);
            break;
          default:
            assert(0);
        }
        dwarf_push_uint(stack, u0);
        break;
      case DW_OP_lit0: case DW_OP_lit1: case DW_OP_lit2:
      case DW_OP_lit3: case DW_OP_lit4: case DW_OP_lit5:
      case DW_OP_lit6: case DW_OP_lit7: case DW_OP_lit8:
      case DW_OP_lit9: case DW_OP_lit10: case DW_OP_lit11:
      case DW_OP_lit12: case DW_OP_lit13: case DW_OP_lit14:
      case DW_OP_lit15: case DW_OP_lit16: case DW_OP_lit17:
      case DW_OP_lit18: case DW_OP_lit19: case DW_OP_lit20:
      case DW_OP_lit21: case DW_OP_lit22: case DW_OP_lit23:
      case DW_OP_lit24: case DW_OP_lit25: case DW_OP_lit26:
      case DW_OP_lit27: case DW_OP_lit28: case DW_OP_lit29:
      case DW_OP_lit30: case DW_OP_lit31:
        dwarf_push_uint(stack, op->atom - DW_OP_lit0);
        break;
      case DW_OP_const1u:
        u0 = (uintptr_t)op->number;
        dwarf_push_uint(stack, u0);
        break;
      case DW_OP_const2u:
        u0 = (uintptr_t)op->number;
        dwarf_push_uint(stack, u0);
        break;
      case DW_OP_const4u:
        u0 = (uintptr_t)op->number;
        dwarf_push_uint(stack, u0);
        break;
      case DW_OP_const8u:
        u0 = (uintptr_t)op->number;
        dwarf_push_uint(stack, u0);
        break;
      case DW_OP_constu:
        u0 = (uintptr_t)op->number;
        dwarf_push_uint(stack, u0);
        break;
      case DW_OP_const1s:
        s0 = (intptr_t)op->number;
        dwarf_push_int(stack, s0);
        break;
      case DW_OP_const2s:
        s0 = (intptr_t)op->number;
        dwarf_push_int(stack, s0);
        break;
      case DW_OP_const4s:
        s0 = (intptr_t)op->number;
        dwarf_push_int(stack, s0);
        break;
      case DW_OP_const8s:
        s0 = (intptr_t)op->number;
        dwarf_push_int(stack, s0);
        break;
      case DW_OP_consts:
        s0 = (intptr_t)op->number;
        dwarf_push_int(stack, s0);
        break;
      case DW_OP_dup:
        u0 = dwarf_pop_uint(stack);
        dwarf_push_uint(stack, u0);
        dwarf_push_uint(stack, u0);
        break;
      case DW_OP_drop:
        (void)dwarf_pop_uint(stack);
        break;
      case DW_OP_over:
        u0 = dwarf_pick_uint(stack, 1);
        dwarf_push_uint(stack, u0);
        break;
      case DW_OP_pick:
        u0 = (uintptr_t)op->number;
        u0 = dwarf_pick_uint(stack, u0);
        dwarf_push_uint(stack, u0);
        break;
      case DW_OP_swap:
        u0 = dwarf_pop_uint(stack);
        u1 = dwarf_pop_uint(stack);
        dwarf_push_uint(stack, u0);
        dwarf_push_uint(stack, u1);
        break;
      case DW_OP_rot:
        u0 = dwarf_pop_uint(stack);
        u1 = dwarf_pop_uint(stack);
        u2 = dwarf_pop_uint(stack);
        dwarf_push_uint(stack, u1);
        dwarf_push_uint(stack, u0);
        dwarf_push_uint(stack, u2);
        break;
      case DW_OP_abs:
        s0 = dwarf_pop_int(stack);
        s0 = (s0 < 0? -s0: s0);
        dwarf_push_int(stack, s0);
        break;
      case DW_OP_div:
        s0 = dwarf_pop_int(stack);
        assert(s0 != 0);
        s1 = dwarf_pop_int(stack);
        dwarf_push_int(stack, s1 / s0);
        break;
      case DW_OP_mod:
        s0 = dwarf_pop_int(stack);
        assert(s0 != 0);
        s1 = dwarf_pop_int(stack);
        dwarf_push_int(stack, s1 % s0);
        break;
#define DWARF_BINARY_OP(name, op, s)                                        \
        DW_OP_##name:                                               \
        s##0 = dwarf_pop_int(stack);                                \
        s##1 = dwarf_pop_int(stack);                                \
        dwarf_push_uint(stack, (uintptr_t)(s##1 op s##0));          \
        break
#define DWARF_UNARY_OP(name, op, s)                                         \
        DW_OP_##name:                                               \
        s##0 = dwarf_pop_int(stack);                                \
        dwarf_push_uint(stack, (uintptr_t)(op s##0));               \
        break
      case DWARF_BINARY_OP(shl, <<, u);
      case DWARF_BINARY_OP(shr, >>, u);
      case DWARF_BINARY_OP(shra, >>, s);
      case DWARF_BINARY_OP(and, &, u);
      case DWARF_BINARY_OP(or, |, u);
      case DWARF_BINARY_OP(xor, ^, u);
      case DWARF_UNARY_OP(not, ~, u);
      case DWARF_UNARY_OP(neg, -, s);
      case DWARF_BINARY_OP(plus, +, s);
      case DWARF_BINARY_OP(minus, -, s);
      case DWARF_BINARY_OP(mul, *, s);
      case DWARF_BINARY_OP(lt, <, s);
      case DWARF_BINARY_OP(le, <=, s);
      case DWARF_BINARY_OP(gt, >, s);
      case DWARF_BINARY_OP(ge, >=, s);
      case DWARF_BINARY_OP(eq, ==, s);
      case DWARF_BINARY_OP(ne, !=, s);
#if 0
      case DW_OP_skip:
        s0 = (intptr_t)op->number;
        expr += s0;
        break;
      case DW_OP_bra:
        s0 = dwarf_read_int16(&expr);
        u0 = dwarf_pop_uint(stack);
        if (u0 != 0)
          expr += s0;
        break;
#endif
      case DW_OP_nop:
        break;
      case DW_OP_implicit_value:
        u0 = (uintptr_t)op->number2;
        assert(expr == end);
        return u0;
      case DW_OP_stack_value:
        u0 = dwarf_pop_uint(stack);
        assert(expr == end);
        return u0;
      default:
        fprintf(stderr, "error: unknown op code (0x%.2X)\n", op->atom);
        assert(0);
    }
  }

  u0 = dwarf_pop_uint(stack);
  return u0;
}
