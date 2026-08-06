//===-- Passes/Data.h - Data and instruction-level obfuscation passes -----===//
//
// Passes that transform values rather than control flow: constants, string
// literals, globals and in-memory variables. Sources in lib/Transforms/Data/.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

namespace kagura {

/// Replaces arithmetic/bitwise ops with equivalent mixed-boolean expressions.
struct SubstitutionPass : public llvm::PassInfoMixin<SubstitutionPass> {
  uint32_t Iterations = 1;

  SubstitutionPass() = default;
  explicit SubstitutionPass(uint32_t Iter) : Iterations(Iter) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Duplicates shared SSA expressions so decompilers cannot re-fold a CSE.
struct CSEBreakPass : public llvm::PassInfoMixin<CSEBreakPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Replaces integer constants with equivalent MBA expressions.
/// e.g. 42  =>  ((x | ~x) & 42) + (x & ~x)  (always evaluates to 42)
struct ConstantObfuscationPass
    : public llvm::PassInfoMixin<ConstantObfuscationPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Encrypts string literals at compile time; injects runtime decryption stubs.
struct StringEncryptionPass
    : public llvm::PassInfoMixin<StringEncryptionPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Encrypts string literals with AES-128-CTR at compile time.
/// Stronger than XOR-based StringEncryptionPass; requires kagura_runtime.
struct StringEncryptionAESPass
    : public llvm::PassInfoMixin<StringEncryptionAESPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Splits long string literals into multiple smaller globals; recombines them
/// at runtime on first access. Defeats contiguous-blob assumptions (no
/// single offset holds the secret) and `strings -n <large>` cutoffs.
struct StringSplitPass : public llvm::PassInfoMixin<StringSplitPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Encrypts wide-character string literals (wchar_t / char16_t / char32_t)
/// and ObjC/CoreFoundation CFString backing buffers using XOR with a
/// per-string random 8-byte key.  Wide strings use lazy-decrypt guards;
/// CFString buffers are decrypted once in a module constructor (priority 0).
struct WideStringEncryptionPass
    : public llvm::PassInfoMixin<WideStringEncryptionPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Encrypts non-string integer globals at compile time; patches every load
/// site with an inline XOR to decrypt. Scalar and array-of-integer globals.
struct GlobalEncryptionPass
    : public llvm::PassInfoMixin<GlobalEncryptionPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// XOR-encrypts alloca'd pointer variables to defeat memory dump
/// analysis by obscuring raw pointer addresses in game object fields.
struct PointerEncryptionPass : public llvm::PassInfoMixin<PointerEncryptionPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// XOR-encrypts local (alloca'd) integer variables at every store site
/// and decrypts at every load site, protecting in-memory values from memory
/// dump and debugger inspection.
struct MemoryValueObfuscationPass
    : public llvm::PassInfoMixin<MemoryValueObfuscationPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Transforms eligible switch statements into XOR-encrypted lookup
/// tables.  Contiguous constant-return switches with N <= 64 cases and 8-bit
/// output values are replaced with a bounds-checked table load + XOR decrypt.
struct EncryptedLookupTablePass
    : public llvm::PassInfoMixin<EncryptedLookupTablePass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

} // namespace kagura
