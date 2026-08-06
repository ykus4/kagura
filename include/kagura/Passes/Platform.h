//===-- Passes/Platform.h - Language-runtime specific passes ---------------===//
//
// Passes that only mean anything on a particular language runtime: the
// Objective-C metadata sections, the JNI registration protocol. Sources in
// lib/Transforms/Platform/.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

namespace kagura {

/// Obfuscates Objective-C selector names and class names in IR metadata.
struct ObjCObfuscationPass : public llvm::PassInfoMixin<ObjCObfuscationPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Converts static JNI functions (Java_*) to dynamic RegisterNatives calls.
struct JNIObfuscationPass : public llvm::PassInfoMixin<JNIObfuscationPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

} // namespace kagura
