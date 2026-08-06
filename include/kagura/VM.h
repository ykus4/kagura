#pragma once
//===-- VM.h - Virtual Machine obfuscation definitions --------------------===//
//
// The C++ view of the bytecode instruction set that kagura's VM obfuscation
// pass emits and that runtime/core/vm_interpreter.c executes.
//
// The numbers themselves, and the per-opcode operand documentation, live in
// kagura/VMOpcodes.def, which the C interpreter includes too. This header used
// to spell them out and so did the interpreter, with a comment in each telling
// the reader to remember the other.
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

// ── Opcodes and frame limits ────────────────────────────────────────────────
//
// From kagura/VMOpcodes.def, which documents each opcode's operands and is the
// same file the C interpreter reads its numbers out of.

enum Opcode : uint8_t {
#define KAGURA_VM_OP(Name, Value) Name = Value,
#include "kagura/VMOpcodes.def"
};

#define KAGURA_VM_LIMIT(CppName, CName, Value)                                 \
  static constexpr unsigned CppName = Value;
#include "kagura/VMOpcodes.def"

// ── Encoding limits ─────────────────────────────────────────────────────────
//
// These bound what the *pass* may emit and have no counterpart in the
// interpreter, so they are not part of the shared table.

/// Maximum bytecode size per function; the size is passed to the interpreter
/// as a uint32_t.
static constexpr uint64_t kMaxBCSize = 0xFFFFFFFFull;

/// Maximum entries in the per-function relocation pool (OP_PUSH_POOL takes a
/// 16-bit index).
static constexpr unsigned kMaxPoolSize = 0xFFFFu;

} // namespace vm
} // namespace kagura
