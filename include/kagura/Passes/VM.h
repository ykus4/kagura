//===-- Passes/VM.h - Function virtualization pass -------------------------===//
//
// Sources in lib/Transforms/VM/. The bytecode contract itself lives in
// kagura/VM.h, which the C interpreter in runtime/core/vm_interpreter.c shares.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

namespace kagura {

/// Virtualizes function bodies into a custom stack-based VM bytecode.
/// The original IR is replaced by an XOR-encrypted bytecode blob and a
/// trampoline that dispatches via kagura_vm_execute(), which decrypts each
/// byte as it fetches it.  See include/kagura/VM.h for the bytecode contract
/// and the set of IR shapes that can be lowered; anything else is left alone.
struct VMObfuscationPass : public llvm::PassInfoMixin<VMObfuscationPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

} // namespace kagura
