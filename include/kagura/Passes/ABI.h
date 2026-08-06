//===-- Passes/ABI.h - C++ ABI protection passes ---------------------------===//
//
// Passes that operate on C++ ABI artefacts — the RTTI name strings and vtables
// the Itanium and MSVC ABIs emit — rather than on a function's own code.
// Sources in lib/Transforms/ABI/.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

namespace kagura {

/// Obfuscates C++ RTTI typeinfo name strings (_ZTS) using XOR
/// encryption with a per-string key, and records vtable metadata for
/// runtime integrity checking via kagura_vtable_check().
struct VTableProtectionPass
    : public llvm::PassInfoMixin<VTableProtectionPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

} // namespace kagura
