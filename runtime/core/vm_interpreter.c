/*
 * vm_interpreter.c - kagura VM interpreter runtime
 *
 * This file is compiled into the target application.  The VMObfuscationPass
 * replaces selected functions with a call to kagura_vm_execute(), passing
 * the function's bytecode and arguments.
 *
 * The interpreter is intentionally kept simple so it is hard to reverse
 * without understanding the specific bytecode encoding used per-build.
 * The bytecode itself is additionally encrypted by the LLVM pass.
 */

#include "../internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Opcode definitions (must match VM.h) ─────────────────────────────────── */

#define OP_PUSH_IMM8   0x00
#define OP_PUSH_IMM16  0x01
#define OP_PUSH_IMM32  0x02
#define OP_PUSH_IMM64  0x03
#define OP_PUSH_REG    0x04
#define OP_POP_REG     0x05
#define OP_DUP         0x06
#define OP_SWAP        0x07
#define OP_ADD         0x10
#define OP_SUB         0x11
#define OP_MUL         0x12
#define OP_UDIV        0x13
#define OP_SDIV        0x14
#define OP_UREM        0x15
#define OP_SREM        0x16
#define OP_AND         0x20
#define OP_OR          0x21
#define OP_XOR         0x22
#define OP_NOT         0x23
#define OP_SHL         0x24
#define OP_LSHR        0x25
#define OP_ASHR        0x26
#define OP_ICMP_EQ     0x30
#define OP_ICMP_NE     0x31
#define OP_ICMP_ULT    0x32
#define OP_ICMP_ULE    0x33
#define OP_ICMP_UGT    0x34
#define OP_ICMP_UGE    0x35
#define OP_ICMP_SLT    0x36
#define OP_ICMP_SLE    0x37
#define OP_ICMP_SGT    0x38
#define OP_ICMP_SGE    0x39
#define OP_JMP         0x40
#define OP_JZ          0x41
#define OP_JNZ         0x42
#define OP_CALL        0x43
#define OP_RET         0x44
#define OP_RET_VOID    0x45
#define OP_LOAD8       0x50
#define OP_LOAD16      0x51
#define OP_LOAD32      0x52
#define OP_LOAD64      0x53
#define OP_STORE8      0x54
#define OP_STORE16     0x55
#define OP_STORE32     0x56
#define OP_STORE64     0x57
#define OP_ZEXT        0x60
#define OP_SEXT        0x61
#define OP_TRUNC       0x62
#define OP_LOAD_ARG    0x70
#define OP_NOP         0xFF

#define VM_STACK_SIZE  256
#define VM_NUM_REGS    16

/* ── VM frame ─────────────────────────────────────────────────────────────── */

typedef struct {
    uint64_t regs[VM_NUM_REGS];
    uint64_t stack[VM_STACK_SIZE];
    int32_t  sp;   /* stack pointer: index of top element (-1 = empty) */
    uint32_t pc;
    const uint8_t *bc;
    uint32_t bc_size;
    /* Arguments passed in from the trampoline */
    uint64_t *args;
    uint32_t  nargs;
} VMFrame;

/* ── Stack helpers ────────────────────────────────────────────────────────── */

static inline void vm_push(VMFrame *f, uint64_t v) {
    if (__builtin_expect(f->sp + 1 >= VM_STACK_SIZE, 0)) abort();
    f->stack[++f->sp] = v;
}

static inline uint64_t vm_pop(VMFrame *f) {
    if (__builtin_expect(f->sp < 0, 0)) abort();
    return f->stack[f->sp--];
}

static inline uint64_t vm_peek(VMFrame *f) {
    if (__builtin_expect(f->sp < 0, 0)) abort();
    return f->stack[f->sp];
}

/* ── Bytecode readers ─────────────────────────────────────────────────────── */

static inline uint8_t  bc_u8 (VMFrame *f) { return f->bc[f->pc++]; }
static inline uint16_t bc_u16(VMFrame *f) {
    uint16_t v;
    memcpy(&v, f->bc + f->pc, 2); f->pc += 2; return v;
}
static inline uint32_t bc_u32(VMFrame *f) {
    uint32_t v;
    memcpy(&v, f->bc + f->pc, 4); f->pc += 4; return v;
}
static inline uint64_t bc_u64(VMFrame *f) {
    uint64_t v;
    memcpy(&v, f->bc + f->pc, 8); f->pc += 8; return v;
}

/* ── Main interpreter loop ────────────────────────────────────────────────── */

uint64_t kagura_vm_execute(const uint8_t *bytecode, uint32_t bc_size,
                            uint64_t *args, uint32_t nargs) {
    VMFrame f;
    memset(&f, 0, sizeof(f));
    f.sp      = -1;
    f.pc      = 0;
    f.bc      = bytecode;
    f.bc_size = bc_size;
    f.args    = args;
    f.nargs   = nargs;

    while (f.pc < f.bc_size) {
        uint8_t op = bc_u8(&f);
        switch (op) {

        /* ── Stack ─────────────────────────────── */
        case OP_PUSH_IMM8:  vm_push(&f, bc_u8 (&f)); break;
        case OP_PUSH_IMM16: vm_push(&f, bc_u16(&f)); break;
        case OP_PUSH_IMM32: vm_push(&f, bc_u32(&f)); break;
        case OP_PUSH_IMM64: vm_push(&f, bc_u64(&f)); break;
        case OP_PUSH_REG: {
            uint8_t r = bc_u8(&f);
            vm_push(&f, f.regs[r & 0xF]);
            break;
        }
        case OP_POP_REG: {
            uint8_t r = bc_u8(&f);
            f.regs[r & 0xF] = vm_pop(&f);
            break;
        }
        case OP_DUP:  vm_push(&f, vm_peek(&f)); break;
        case OP_SWAP: {
            uint64_t a = vm_pop(&f), b = vm_pop(&f);
            vm_push(&f, a); vm_push(&f, b);
            break;
        }

        /* ── Arithmetic ────────────────────────── */
        case OP_ADD: { uint64_t b=vm_pop(&f), a=vm_pop(&f); vm_push(&f, a+b); break; }
        case OP_SUB: { uint64_t b=vm_pop(&f), a=vm_pop(&f); vm_push(&f, a-b); break; }
        case OP_MUL: { uint64_t b=vm_pop(&f), a=vm_pop(&f); vm_push(&f, a*b); break; }
        case OP_UDIV:{ uint64_t b=vm_pop(&f), a=vm_pop(&f); vm_push(&f, b?a/b:0); break; }
        case OP_SDIV:{ int64_t  b=(int64_t)vm_pop(&f), a=(int64_t)vm_pop(&f);
                       vm_push(&f, (uint64_t)(b?a/b:0)); break; }
        case OP_UREM:{ uint64_t b=vm_pop(&f), a=vm_pop(&f); vm_push(&f, b?a%b:0); break; }
        case OP_SREM:{ int64_t  b=(int64_t)vm_pop(&f), a=(int64_t)vm_pop(&f);
                       vm_push(&f, (uint64_t)(b?a%b:0)); break; }

        /* ── Bitwise ───────────────────────────── */
        case OP_AND: { uint64_t b=vm_pop(&f), a=vm_pop(&f); vm_push(&f, a&b); break; }
        case OP_OR:  { uint64_t b=vm_pop(&f), a=vm_pop(&f); vm_push(&f, a|b); break; }
        case OP_XOR: { uint64_t b=vm_pop(&f), a=vm_pop(&f); vm_push(&f, a^b); break; }
        case OP_NOT: { vm_push(&f, ~vm_pop(&f)); break; }
        case OP_SHL: { uint64_t b=vm_pop(&f), a=vm_pop(&f); vm_push(&f, a<<(b&63)); break; }
        case OP_LSHR:{ uint64_t b=vm_pop(&f), a=vm_pop(&f); vm_push(&f, a>>(b&63)); break; }
        case OP_ASHR:{ uint64_t b=vm_pop(&f); int64_t a=(int64_t)vm_pop(&f);
                       vm_push(&f, (uint64_t)(a>>(b&63))); break; }

        /* ── Comparison ────────────────────────── */
        case OP_ICMP_EQ: { uint64_t b=vm_pop(&f),a=vm_pop(&f); vm_push(&f,a==b); break; }
        case OP_ICMP_NE: { uint64_t b=vm_pop(&f),a=vm_pop(&f); vm_push(&f,a!=b); break; }
        case OP_ICMP_ULT:{ uint64_t b=vm_pop(&f),a=vm_pop(&f); vm_push(&f,a< b); break; }
        case OP_ICMP_ULE:{ uint64_t b=vm_pop(&f),a=vm_pop(&f); vm_push(&f,a<=b); break; }
        case OP_ICMP_UGT:{ uint64_t b=vm_pop(&f),a=vm_pop(&f); vm_push(&f,a> b); break; }
        case OP_ICMP_UGE:{ uint64_t b=vm_pop(&f),a=vm_pop(&f); vm_push(&f,a>=b); break; }
        case OP_ICMP_SLT:{ int64_t b=(int64_t)vm_pop(&f),a=(int64_t)vm_pop(&f); vm_push(&f,a< b); break; }
        case OP_ICMP_SLE:{ int64_t b=(int64_t)vm_pop(&f),a=(int64_t)vm_pop(&f); vm_push(&f,a<=b); break; }
        case OP_ICMP_SGT:{ int64_t b=(int64_t)vm_pop(&f),a=(int64_t)vm_pop(&f); vm_push(&f,a> b); break; }
        case OP_ICMP_SGE:{ int64_t b=(int64_t)vm_pop(&f),a=(int64_t)vm_pop(&f); vm_push(&f,a>=b); break; }

        /* ── Control flow ──────────────────────── */
        case OP_JMP: {
            uint32_t off = bc_u32(&f);
            f.pc = off;
            break;
        }
        case OP_JZ: {
            uint32_t off = bc_u32(&f);
            if (vm_pop(&f) == 0) f.pc = off;
            break;
        }
        case OP_JNZ: {
            uint32_t off = bc_u32(&f);
            if (vm_pop(&f) != 0) f.pc = off;
            break;
        }
        case OP_RET:      return vm_pop(&f);
        case OP_RET_VOID: return 0;

        /* ── Memory ────────────────────────────── */
        case OP_LOAD8:  { uint8_t  *p=(uint8_t *)vm_pop(&f);  vm_push(&f,*p); break; }
        case OP_LOAD16: { uint16_t *p=(uint16_t*)vm_pop(&f);  vm_push(&f,*p); break; }
        case OP_LOAD32: { uint32_t *p=(uint32_t*)vm_pop(&f);  vm_push(&f,*p); break; }
        case OP_LOAD64: { uint64_t *p=(uint64_t*)vm_pop(&f);  vm_push(&f,*p); break; }
        case OP_STORE8: { uint8_t  v=(uint8_t)vm_pop(&f);
                          uint8_t  *p=(uint8_t*)vm_pop(&f);   *p=v; break; }
        case OP_STORE16:{ uint16_t v=(uint16_t)vm_pop(&f);
                          uint16_t *p=(uint16_t*)vm_pop(&f);  *p=v; break; }
        case OP_STORE32:{ uint32_t v=(uint32_t)vm_pop(&f);
                          uint32_t *p=(uint32_t*)vm_pop(&f);  *p=v; break; }
        case OP_STORE64:{ uint64_t v=vm_pop(&f);
                          uint64_t *p=(uint64_t*)vm_pop(&f);  *p=v; break; }

        /* ── Type conversions ──────────────────── */
        case OP_ZEXT:  /* already 64-bit on stack */ break;
        case OP_SEXT: {
            uint8_t from_bits = bc_u8(&f);
            int64_t v = (int64_t)vm_pop(&f);
            uint64_t mask = (from_bits < 64) ? ((1ULL << from_bits) - 1) : ~0ULL;
            uint64_t sign = (from_bits < 64) ? (1ULL << (from_bits - 1)) : 0;
            v &= (int64_t)mask;
            if ((uint64_t)v & sign) v |= (int64_t)~mask;
            vm_push(&f, (uint64_t)v);
            break;
        }
        case OP_TRUNC: {
            uint8_t to_bits = bc_u8(&f);
            uint64_t mask = (to_bits < 64) ? ((1ULL << to_bits) - 1) : ~0ULL;
            vm_push(&f, vm_pop(&f) & mask);
            break;
        }

        /* ── Arguments ─────────────────────────── */
        case OP_LOAD_ARG: {
            uint8_t idx = bc_u8(&f);
            vm_push(&f, (idx < f.nargs) ? f.args[idx] : 0);
            break;
        }

        case OP_NOP: break;
        default:     abort(); /* unknown opcode */
        }
    }
    return 0;
}
