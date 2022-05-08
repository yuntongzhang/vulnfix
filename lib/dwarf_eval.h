#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <dwarf.h>
#include <elfutils/libdw.h>

/****************************************************************************/
/* E9TOOL STATE STRUCTURE                                                   */
/****************************************************************************/

typedef struct
{
  union
  {
    uint16_t rflags;
    uint64_t __padding;
  };
  union
  {
    int64_t r15;
    int32_t r15d;
    int16_t r15w;
    int8_t r15b;
  };
  union
  {
    int64_t r14;
    int32_t r14d;
    int16_t r14w;
    int8_t r14b;
  };
  union
  {
    int64_t r13;
    int32_t r13d;
    int16_t r13w;
    int8_t r13b;
  };
  union
  {
    int64_t r12;
    int32_t r12d;
    int16_t r12w;
    int8_t r12b;
  };
  union
  {
    int64_t r11;
    int32_t r11d;
    int16_t r11w;
    int8_t r11b;
  };
  union
  {
    int64_t r10;
    int32_t r10d;
    int16_t r10w;
    int8_t r10b;
  };
  union
  {
    int64_t r9;
    int32_t r9d;
    int16_t r9w;
    int8_t r9b;
  };
  union
  {
    int64_t r8;
    int32_t r8d;
    int16_t r8w;
    int8_t r8b;
  };
  union
  {
    int64_t rdi;
    int32_t edi;
    int16_t di;
    int8_t dil;
  };
  union
  {
    int64_t rsi;
    int32_t esi;
    int16_t si;
    int8_t sil;
  };
  union
  {
    int64_t rbp;
    int32_t ebp;
    int16_t bp;
    int8_t bpl;
  };
  union
  {
    int64_t rbx;
    int32_t ebx;
    int16_t bx;
    struct
    {
      int8_t bl;
      int8_t bh;
    };
  };
  union
  {
    int64_t rdx;
    int32_t edx;
    int16_t dx;
    struct
    {
      int8_t dl;
      int8_t dh;
    };
  };
  union
  {
    int64_t rcx;
    int32_t ecx;
    int16_t cx;
    struct
    {
      int8_t cl;
      int8_t ch;
    };
  };
  union
  {
    int64_t rax;
    int32_t eax;
    int16_t ax;
    struct
    {
      int8_t al;
      int8_t ah;
    };
  };
  union
  {
    int64_t rsp;
    int32_t esp;
    int16_t sp;
    int16_t spl;
  };
  const union
  {
    int64_t rip;
    int32_t eip;
    int16_t ip;
  };
} STATE;


/****************************************************************************/
/* DWARF EVALUATOR:                                                          */
/****************************************************************************/

struct dwarf_stack_s
{
  uintptr_t data[20];
  size_t pos;
};
typedef struct dwarf_stack_s *dwarf_stack_t;

uintptr_t dwarf_evaluate(Dwarf_Op *expr, size_t expr_size);

/* The addr after evaluating expression from DW_AT_frame_base. */
extern void *frame_base_addr;
/* The runtime base address of the current binary. */
extern const void *binary_base_addr;
/* The saved register context at the instrumentation point. */
extern const STATE *saved_state;
/* Unevaluated expression for CFA. */
extern Dwarf_Op *cfa_expr;
extern size_t cfa_expr_size;
