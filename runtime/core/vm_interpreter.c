/*
 * vm_interpreter.c - kagura VM interpreter runtime
 *
 * This file is compiled into the target application.  The VMObfuscationPass
 * replaces selected functions with a call to kagura_vm_execute(), passing the
 * function's encrypted bytecode, its arguments, a relocation pool and the
 * decryption key.
 *
 * The bytecode contract lives in include/kagura/VMOpcodes.def, which this file
 * includes directly and which the pass reads through include/kagura/VM.h.  Read
 * it before touching anything here: the one-byte width operands and the
 * "canonical unsigned form" value representation are shared with the pass, and
 * the two sides silently computing different things is exactly the class of bug
 * this file used to have.  The opcode numbers themselves used to be a hand-kept
 * second copy; they are not any more.
 *
 * The blob is never decrypted in memory.  Each byte is XOR-decrypted as it is
 * fetched with key[offset % 8], which keeps the global read-only, makes
 * repeated calls idempotent, and makes the interpreter re-entrant.
 */

#include "../internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Opcodes and frame limits ──────────────────────────────────────────────
 *
 * From the same table the pass emits against.  An enum rather than #defines so
 * a debugger can name the opcode it is stopped on. */

enum vm_opcode {
#define KAGURA_VM_OP(Name, Value) Name = Value,
#include "kagura/VMOpcodes.def"
};

#define KAGURA_VM_LIMIT(CppName, CName, Value) CName = Value,
enum vm_limit {
#include "kagura/VMOpcodes.def"
};

/* ── VM frame ─────────────────────────────────────────────────────────────── */

#if defined(_MSC_VER)
#  define VM_ALIGN16 __declspec(align(16))
#else
#  define VM_ALIGN16 __attribute__((aligned(16)))
#endif

/* One frame is a few KB, so a virtualised function that recurses deeply uses
 * far more stack than its native form would. */
typedef struct {
    uint64_t regs[VM_NUM_REGS];
    uint64_t stack[VM_STACK_SIZE];
    /* Backs the virtualised function's allocas.  16-byte aligned because the
     * pass hands these addresses to allocas that ask for up to that much (and
     * refuses to virtualise anything needing more). */
    VM_ALIGN16 uint8_t frame[VM_FRAME_SIZE];
    int32_t  sp;   /* index of the top element, -1 when empty */
    uint32_t pc;
    const uint8_t  *bc;
    uint32_t        bc_size;
    const uint64_t *args;
    uint32_t        nargs;
    const uint64_t *pool;
    uint32_t        npool;
    uint64_t        key;
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

/* ── Bytecode readers (decrypt on fetch) ──────────────────────────────────── */

static inline uint8_t bc_u8(VMFrame *f) {
    uint32_t p = f->pc;
    if (__builtin_expect(p >= f->bc_size, 0)) abort();
    f->pc = p + 1;
    return (uint8_t)(f->bc[p] ^ (uint8_t)(f->key >> (8u * (p & 7u))));
}

static inline uint16_t bc_u16(VMFrame *f) {
    uint16_t lo = bc_u8(f);
    return (uint16_t)(lo | ((uint16_t)bc_u8(f) << 8));
}

static inline uint32_t bc_u32(VMFrame *f) {
    uint32_t lo = bc_u16(f);
    return lo | ((uint32_t)bc_u16(f) << 16);
}

static inline uint64_t bc_u64(VMFrame *f) {
    uint64_t lo = bc_u32(f);
    return lo | ((uint64_t)bc_u32(f) << 32);
}

/* ── Width helpers ────────────────────────────────────────────────────────── */

/* All widths come from the bytecode, which the pass only ever emits in 1..64.
 * Clamping rather than trusting keeps a corrupted blob from shifting by >= 64. */
static inline unsigned vm_width(VMFrame *f) {
    unsigned w = bc_u8(f);
    if (__builtin_expect(w == 0 || w > 64, 0)) abort();
    return w;
}

static inline uint64_t vm_mask(unsigned w) {
    return (w >= 64) ? ~(uint64_t)0 : (((uint64_t)1 << w) - 1u);
}

/* Canonicalise: keep the low w bits, clear the rest. */
static inline uint64_t vm_zext(uint64_t v, unsigned w) {
    return v & vm_mask(w);
}

/* Interpret the low w bits of v as a signed value. */
static inline int64_t vm_sext(uint64_t v, unsigned w) {
    uint64_t m = vm_mask(w);
    v &= m;
    if (v & ((uint64_t)1 << (w - 1u))) v |= ~m;
    return (int64_t)v;
}

/* LLVM says a shift amount >= the width is poison, so any answer is legal; we
 * reproduce what the hardware does for the power-of-two widths that actually
 * occur and stay in range for the rest. */
static inline unsigned vm_shamt(uint64_t b, unsigned w) {
    if ((w & (w - 1u)) == 0u) return (unsigned)(b & (uint64_t)(w - 1u));
    return (unsigned)(b % (uint64_t)w);
}

/* ── Native call thunks ───────────────────────────────────────────────────── */

/*
 * Every argument and the return value are passed as a full 64-bit register, so
 * one prototype per arity covers any callee whose parameters and result are
 * integers or pointers.  Narrower callees read the low half of each register
 * and leave the upper half of the result register unspecified, which is why the
 * caller masks the result to the callee's return width.
 *
 * Variadic callees are *not* callable this way and the pass refuses to
 * virtualise a function that calls one.
 */
typedef uint64_t (*vm_fn0)(void);
typedef uint64_t (*vm_fn1)(uint64_t);
typedef uint64_t (*vm_fn2)(uint64_t, uint64_t);
typedef uint64_t (*vm_fn3)(uint64_t, uint64_t, uint64_t);
typedef uint64_t (*vm_fn4)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*vm_fn5)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
typedef uint64_t (*vm_fn6)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                           uint64_t);
typedef uint64_t (*vm_fn7)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                           uint64_t, uint64_t);
typedef uint64_t (*vm_fn8)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                           uint64_t, uint64_t, uint64_t);

static uint64_t vm_call(uint64_t callee, const uint64_t *a, unsigned n) {
    uintptr_t p = (uintptr_t)callee;
    if (__builtin_expect(p == 0, 0)) abort();
    switch (n) {
    case 0: return ((vm_fn0)p)();
    case 1: return ((vm_fn1)p)(a[0]);
    case 2: return ((vm_fn2)p)(a[0], a[1]);
    case 3: return ((vm_fn3)p)(a[0], a[1], a[2]);
    case 4: return ((vm_fn4)p)(a[0], a[1], a[2], a[3]);
    case 5: return ((vm_fn5)p)(a[0], a[1], a[2], a[3], a[4]);
    case 6: return ((vm_fn6)p)(a[0], a[1], a[2], a[3], a[4], a[5]);
    case 7: return ((vm_fn7)p)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
    case 8: return ((vm_fn8)p)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    default: abort();
    }
}

/* ── Main interpreter loop ────────────────────────────────────────────────── */

uint64_t kagura_vm_execute(const uint8_t *bytecode, uint32_t bc_size,
                           const uint64_t *args, uint32_t nargs,
                           const uint64_t *pool, uint32_t npool,
                           uint64_t key) {
    VMFrame f;
    memset(&f, 0, sizeof(f));
    f.sp      = -1;
    f.pc      = 0;
    f.bc      = bytecode;
    f.bc_size = bc_size;
    f.args    = args;
    f.nargs   = nargs;
    f.pool    = pool;
    f.npool   = npool;
    f.key     = key;

    while (f.pc < f.bc_size) {
        uint8_t op = bc_u8(&f);
        switch (op) {

        /* ── Stack ─────────────────────────────── */
        case OP_PUSH_IMM8:  vm_push(&f, bc_u8 (&f)); break;
        case OP_PUSH_IMM16: vm_push(&f, bc_u16(&f)); break;
        case OP_PUSH_IMM32: vm_push(&f, bc_u32(&f)); break;
        case OP_PUSH_IMM64: vm_push(&f, bc_u64(&f)); break;
        case OP_PUSH_REG:   vm_push(&f, f.regs[bc_u8(&f)]); break;
        case OP_POP_REG: {
            uint8_t r = bc_u8(&f);
            f.regs[r] = vm_pop(&f);
            break;
        }
        case OP_DUP:  vm_push(&f, vm_peek(&f)); break;
        case OP_SWAP: {
            uint64_t a = vm_pop(&f), b = vm_pop(&f);
            vm_push(&f, a); vm_push(&f, b);
            break;
        }
        case OP_PUSH_POOL: {
            uint16_t i = bc_u16(&f);
            if (__builtin_expect(i >= f.npool, 0)) abort();
            vm_push(&f, f.pool[i]);
            break;
        }
        case OP_PUSH_FRAME: {
            uint16_t off = bc_u16(&f);
            if (__builtin_expect(off >= VM_FRAME_SIZE, 0)) abort();
            vm_push(&f, (uint64_t)(uintptr_t)(f.frame + off));
            break;
        }
        case OP_SELECT: {
            uint64_t fv = vm_pop(&f), tv = vm_pop(&f), c = vm_pop(&f);
            vm_push(&f, c ? tv : fv);
            break;
        }
        case OP_DROP: (void)vm_pop(&f); break;

        /* ── Arithmetic ────────────────────────── */
        case OP_ADD: { unsigned w=vm_width(&f); uint64_t b=vm_pop(&f),a=vm_pop(&f);
                       vm_push(&f, vm_zext(a + b, w)); break; }
        case OP_SUB: { unsigned w=vm_width(&f); uint64_t b=vm_pop(&f),a=vm_pop(&f);
                       vm_push(&f, vm_zext(a - b, w)); break; }
        case OP_MUL: { unsigned w=vm_width(&f); uint64_t b=vm_pop(&f),a=vm_pop(&f);
                       vm_push(&f, vm_zext(a * b, w)); break; }
        case OP_UDIV:{ unsigned w=vm_width(&f); uint64_t b=vm_pop(&f),a=vm_pop(&f);
                       vm_push(&f, b ? vm_zext(a / b, w) : 0); break; }
        case OP_UREM:{ unsigned w=vm_width(&f); uint64_t b=vm_pop(&f),a=vm_pop(&f);
                       vm_push(&f, b ? vm_zext(a % b, w) : 0); break; }
        /* Division is UB for a zero divisor and for INT_MIN / -1; returning
         * something deterministic beats raising SIGFPE inside the VM. */
        case OP_SDIV:{ unsigned w=vm_width(&f);
                       int64_t b=vm_sext(vm_pop(&f), w), a=vm_sext(vm_pop(&f), w);
                       uint64_t r = (b == 0) ? 0
                                  : (b == -1) ? (uint64_t)(0 - (uint64_t)a)
                                  : (uint64_t)(a / b);
                       vm_push(&f, vm_zext(r, w)); break; }
        case OP_SREM:{ unsigned w=vm_width(&f);
                       int64_t b=vm_sext(vm_pop(&f), w), a=vm_sext(vm_pop(&f), w);
                       uint64_t r = (b == 0 || b == -1) ? 0 : (uint64_t)(a % b);
                       vm_push(&f, vm_zext(r, w)); break; }

        /* ── Bitwise ───────────────────────────── */
        case OP_AND: { unsigned w=vm_width(&f); uint64_t b=vm_pop(&f),a=vm_pop(&f);
                       vm_push(&f, vm_zext(a & b, w)); break; }
        case OP_OR:  { unsigned w=vm_width(&f); uint64_t b=vm_pop(&f),a=vm_pop(&f);
                       vm_push(&f, vm_zext(a | b, w)); break; }
        case OP_XOR: { unsigned w=vm_width(&f); uint64_t b=vm_pop(&f),a=vm_pop(&f);
                       vm_push(&f, vm_zext(a ^ b, w)); break; }
        case OP_NOT: { unsigned w=vm_width(&f);
                       vm_push(&f, vm_zext(~vm_pop(&f), w)); break; }
        case OP_SHL: { unsigned w=vm_width(&f); uint64_t b=vm_pop(&f),a=vm_pop(&f);
                       vm_push(&f, vm_zext(a << vm_shamt(b, w), w)); break; }
        case OP_LSHR:{ unsigned w=vm_width(&f); uint64_t b=vm_pop(&f),a=vm_pop(&f);
                       vm_push(&f, vm_zext(vm_zext(a, w) >> vm_shamt(b, w), w));
                       break; }
        case OP_ASHR:{ unsigned w=vm_width(&f); uint64_t b=vm_pop(&f);
                       int64_t a=vm_sext(vm_pop(&f), w);
                       vm_push(&f, vm_zext((uint64_t)(a >> vm_shamt(b, w)), w));
                       break; }

        /* ── Comparison ────────────────────────── */
        case OP_ICMP_EQ: { unsigned w=vm_width(&f);
                           uint64_t b=vm_zext(vm_pop(&f),w),a=vm_zext(vm_pop(&f),w);
                           vm_push(&f, a == b); break; }
        case OP_ICMP_NE: { unsigned w=vm_width(&f);
                           uint64_t b=vm_zext(vm_pop(&f),w),a=vm_zext(vm_pop(&f),w);
                           vm_push(&f, a != b); break; }
        case OP_ICMP_ULT:{ unsigned w=vm_width(&f);
                           uint64_t b=vm_zext(vm_pop(&f),w),a=vm_zext(vm_pop(&f),w);
                           vm_push(&f, a <  b); break; }
        case OP_ICMP_ULE:{ unsigned w=vm_width(&f);
                           uint64_t b=vm_zext(vm_pop(&f),w),a=vm_zext(vm_pop(&f),w);
                           vm_push(&f, a <= b); break; }
        case OP_ICMP_UGT:{ unsigned w=vm_width(&f);
                           uint64_t b=vm_zext(vm_pop(&f),w),a=vm_zext(vm_pop(&f),w);
                           vm_push(&f, a >  b); break; }
        case OP_ICMP_UGE:{ unsigned w=vm_width(&f);
                           uint64_t b=vm_zext(vm_pop(&f),w),a=vm_zext(vm_pop(&f),w);
                           vm_push(&f, a >= b); break; }
        case OP_ICMP_SLT:{ unsigned w=vm_width(&f);
                           int64_t b=vm_sext(vm_pop(&f),w),a=vm_sext(vm_pop(&f),w);
                           vm_push(&f, a <  b); break; }
        case OP_ICMP_SLE:{ unsigned w=vm_width(&f);
                           int64_t b=vm_sext(vm_pop(&f),w),a=vm_sext(vm_pop(&f),w);
                           vm_push(&f, a <= b); break; }
        case OP_ICMP_SGT:{ unsigned w=vm_width(&f);
                           int64_t b=vm_sext(vm_pop(&f),w),a=vm_sext(vm_pop(&f),w);
                           vm_push(&f, a >  b); break; }
        case OP_ICMP_SGE:{ unsigned w=vm_width(&f);
                           int64_t b=vm_sext(vm_pop(&f),w),a=vm_sext(vm_pop(&f),w);
                           vm_push(&f, a >= b); break; }

        /* ── Control flow ──────────────────────── */
        case OP_JMP: { uint32_t t = bc_u32(&f); f.pc = t; break; }
        case OP_JZ:  { uint32_t t = bc_u32(&f); if (vm_pop(&f) == 0) f.pc = t; break; }
        case OP_JNZ: { uint32_t t = bc_u32(&f); if (vm_pop(&f) != 0) f.pc = t; break; }
        case OP_CALL: {
            unsigned n    = bc_u8(&f);
            unsigned retw = bc_u8(&f);
            uint64_t a[VM_MAX_CALL_ARGS];
            if (__builtin_expect(n > VM_MAX_CALL_ARGS || retw > 64, 0)) abort();
            for (unsigned i = n; i-- > 0;) a[i] = vm_pop(&f);
            uint64_t r = vm_call(vm_pop(&f), a, n);
            if (retw) vm_push(&f, vm_zext(r, retw));
            break;
        }
        case OP_RET:      return vm_pop(&f);
        case OP_RET_VOID: return 0;

        /* ── Memory ────────────────────────────── */
        case OP_LOAD8:  { uint8_t  v; memcpy(&v,(const void*)(uintptr_t)vm_pop(&f),1);
                          vm_push(&f, v); break; }
        case OP_LOAD16: { uint16_t v; memcpy(&v,(const void*)(uintptr_t)vm_pop(&f),2);
                          vm_push(&f, v); break; }
        case OP_LOAD32: { uint32_t v; memcpy(&v,(const void*)(uintptr_t)vm_pop(&f),4);
                          vm_push(&f, v); break; }
        case OP_LOAD64: { uint64_t v; memcpy(&v,(const void*)(uintptr_t)vm_pop(&f),8);
                          vm_push(&f, v); break; }
        case OP_STORE8: { uint8_t  v=(uint8_t )vm_pop(&f);
                          memcpy((void*)(uintptr_t)vm_pop(&f), &v, 1); break; }
        case OP_STORE16:{ uint16_t v=(uint16_t)vm_pop(&f);
                          memcpy((void*)(uintptr_t)vm_pop(&f), &v, 2); break; }
        case OP_STORE32:{ uint32_t v=(uint32_t)vm_pop(&f);
                          memcpy((void*)(uintptr_t)vm_pop(&f), &v, 4); break; }
        case OP_STORE64:{ uint64_t v=          vm_pop(&f);
                          memcpy((void*)(uintptr_t)vm_pop(&f), &v, 8); break; }

        /* ── Type conversions ──────────────────── */
        case OP_ZEXT: /* canonical form is already zero-extended */ break;
        case OP_SEXT: { unsigned w = vm_width(&f);
                        vm_push(&f, (uint64_t)vm_sext(vm_pop(&f), w)); break; }
        case OP_TRUNC:{ unsigned w = vm_width(&f);
                        vm_push(&f, vm_zext(vm_pop(&f), w)); break; }

        /* ── Arguments ─────────────────────────── */
        case OP_LOAD_ARG: {
            uint8_t idx = bc_u8(&f);
            vm_push(&f, (idx < f.nargs) ? f.args[idx] : 0);
            break;
        }

        case OP_NOP: break;
        /* Unreachable for bytecode this build emitted; a mismatch here means
         * the pass and the interpreter have drifted apart, and continuing would
         * silently compute garbage (or spin forever on a jump-only loop). */
        default: abort();
        }
    }
    /* Falling off the end means the pass emitted a block without a terminator. */
    abort();
}
