#pragma once
//===-- VM.h - Virtual Machine obfuscation definitions --------------------===//
//
// Defines the bytecode instruction set that kagura's VM obfuscation pass emits
// and that runtime/core/vm_interpreter.c executes.  The two files are a single
// contract: every constant here has a mirrored #define there and they must be
// changed together.
//
// Architecture overview:
//
//   Source IR function --> [VMObfuscationPass] --> encrypted bytecode blob
//                                                + relocation pool
//                                                + trampoline calling
//                                                  kagura_vm_execute()
//
// The VM is a stack machine over 64-bit slots with kNumRegs virtual registers,
// a value stack, and a per-call frame arena that backs the function's
// `alloca`s.  It is *not* a register machine and it has no spill mechanism: a
// function needing more registers or more frame bytes than the limits below is
// simply not virtualised.
//
// ── Value representation (the part that used to be unspecified) ─────────────
//
// Every VM slot holds 64 bits.  An LLVM value of type iN is held in *canonical
// unsigned form*: the low N bits carry the value and bits N..63 are zero.  A
// pointer is held as its full 64-bit address.
//
// Canonical form is why the arithmetic and comparison opcodes each carry a
// one-byte operand width:
//
//   - add/sub/mul/shl/and/or/xor/udiv/urem/lshr compute in 64 bits and mask
//     the result back down to the width, which reproduces iN wrapping.
//   - sdiv/srem/ashr and the signed icmp predicates sign-extend their operands
//     from the width first, because canonical form has thrown the sign bit's
//     position away.
//   - zext is therefore a no-op, sext needs the *source* width, and trunc
//     needs the *destination* width.
//
// ── Instruction encoding ───────────────────────────────────────────────────
//
//   [8-bit opcode][operands, little-endian]
//
// The whole stream is XOR-encrypted with a per-function 64-bit key applied
// byte-wise as key[offset % 8]; the interpreter decrypts each byte as it is
// fetched, so the blob is never decrypted in memory and stays read-only.
//
//===----------------------------------------------------------------------===//

#include <cstdint>

namespace kagura {
namespace vm {

// ── Opcode definitions ──────────────────────────────────────────────────────

enum Opcode : uint8_t {
  // Stack operations
  OP_PUSH_IMM8   = 0x00, // u8  imm            : push zero-extended immediate
  OP_PUSH_IMM16  = 0x01, // u16 imm
  OP_PUSH_IMM32  = 0x02, // u32 imm
  OP_PUSH_IMM64  = 0x03, // u64 imm
  OP_PUSH_REG    = 0x04, // u8  reg            : push virtual register
  OP_POP_REG     = 0x05, // u8  reg            : pop into virtual register
  OP_DUP         = 0x06,
  OP_SWAP        = 0x07,
  OP_PUSH_POOL   = 0x08, // u16 index          : push pool[index]
  OP_PUSH_FRAME  = 0x09, // u16 offset         : push &frame_arena[offset]
  OP_SELECT      = 0x0A, //                    : pop f, pop t, pop c; push c?t:f
  OP_DROP        = 0x0B,

  // Arithmetic — each takes a u8 result width in bits (1..64).
  // Pops b then a, pushes the width-masked result of `a op b`.
  OP_ADD         = 0x10,
  OP_SUB         = 0x11,
  OP_MUL         = 0x12,
  OP_UDIV        = 0x13,
  OP_SDIV        = 0x14,
  OP_UREM        = 0x15,
  OP_SREM        = 0x16,

  // Bitwise — also width-tagged.
  OP_AND         = 0x20,
  OP_OR          = 0x21,
  OP_XOR         = 0x22,
  OP_NOT         = 0x23, // pop 1, push 1
  OP_SHL         = 0x24,
  OP_LSHR        = 0x25,
  OP_ASHR        = 0x26,

  // Comparison — u8 operand width; pushes 0 or 1.
  OP_ICMP_EQ     = 0x30,
  OP_ICMP_NE     = 0x31,
  OP_ICMP_ULT    = 0x32,
  OP_ICMP_ULE    = 0x33,
  OP_ICMP_UGT    = 0x34,
  OP_ICMP_UGE    = 0x35,
  OP_ICMP_SLT    = 0x36,
  OP_ICMP_SLE    = 0x37,
  OP_ICMP_SGT    = 0x38,
  OP_ICMP_SGE    = 0x39,

  // Control flow
  OP_JMP         = 0x40, // u32 target         : unconditional
  OP_JZ          = 0x41, // u32 target         : pop; jump if zero
  OP_JNZ         = 0x42, // u32 target         : pop; jump if non-zero
  OP_CALL        = 0x43, // u8 nargs, u8 retw  : pop args (last on top), pop
                         //                      callee address, call natively;
                         //                      retw == 0 means void (nothing
                         //                      is pushed), else the result is
                         //                      masked to retw bits.
  OP_RET         = 0x44, // pop and return
  OP_RET_VOID    = 0x45, // return 0

  // Memory — the pointer is the deeper stack slot, the value the shallower one.
  OP_LOAD8       = 0x50, // pop ptr, push zero-extended i8
  OP_LOAD16      = 0x51,
  OP_LOAD32      = 0x52,
  OP_LOAD64      = 0x53,
  OP_STORE8      = 0x54, // pop val, pop ptr, store
  OP_STORE16     = 0x55,
  OP_STORE32     = 0x56,
  OP_STORE64     = 0x57,

  // Type conversions
  OP_ZEXT        = 0x60, // no operand: canonical form is already zero-extended
  OP_SEXT        = 0x61, // u8 source width
  OP_TRUNC       = 0x62, // u8 destination width

  // Argument passing
  OP_LOAD_ARG    = 0x70, // u8 index           : push args[index]
  OP_NOP         = 0xFF,
};

// ── Limits (mirrored in runtime/core/vm_interpreter.c) ──────────────────────

/// Virtual registers per frame.  Register operands are one byte, so this may
/// not exceed 256.
static constexpr unsigned kNumRegs = 256;

/// Value stack depth.  Expression trees are lowered one operand at a time and
/// the deepest transient use is one slot per PHI node in a successor block, so
/// this is generous.
static constexpr unsigned kStackSize = 128;

/// Bytes of per-call scratch memory backing the function's `alloca`s.
/// Addresses handed out by OP_PUSH_FRAME point into it.  The arena is 16-byte
/// aligned, so an alloca demanding more alignment than that is not virtualised.
///
/// Together with the register and stack arrays this makes one VM frame a few
/// kilobytes: a virtualised recursive function is far hungrier for native stack
/// than its original, which bounds how deep it can safely go.
static constexpr unsigned kFrameSize = 1024;

/// Maximum arguments in an OP_CALL.  The interpreter dispatches through a
/// fixed set of prototypes, one per arity.
static constexpr unsigned kMaxCallArgs = 8;

/// Maximum bytecode size per function; the size is passed to the interpreter
/// as a uint32_t.
static constexpr uint64_t kMaxBCSize = 0xFFFFFFFFull;

/// Maximum entries in the per-function relocation pool (OP_PUSH_POOL takes a
/// 16-bit index).
static constexpr unsigned kMaxPoolSize = 0xFFFFu;

} // namespace vm
} // namespace kagura
