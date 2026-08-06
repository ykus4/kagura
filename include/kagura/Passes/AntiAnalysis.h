//===-- Passes/AntiAnalysis.h - Anti-debug / anti-tamper passes ------------===//
//
// Passes that make the binary hostile to a live analyst rather than harder to
// read: runtime detection, integrity checks, decoys and symbol hiding. Sources
// in lib/Transforms/AntiAnalysis/.
//
// Every pass here emits calls into kagura_runtime, so a target that enables one
// must link it.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

namespace kagura {

/// Injects anti-debug / anti-Frida checks (ptrace, port 27042, maps scan).
struct AntiDebugPass : public llvm::PassInfoMixin<AntiDebugPass> {
  bool AntiFramework = true; // check for Frida/Substrate
  bool AntiPtrace    = true;

  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Injects compile-time FNV-1a integrity hashes and runtime verification calls.
/// Also inserts kagura_self_check() at main() for jailbreak/root detection.
struct AntiTamperPass : public llvm::PassInfoMixin<AntiTamperPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Injects compile-time opcode checksums and runtime verification
/// calls into a random subset of basic blocks to detect binary patching.
struct BasicBlockChecksumPass
    : public llvm::PassInfoMixin<BasicBlockChecksumPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Injects decoy global variables containing fake secrets and
/// stub functions with plausible security-sounding names to mislead attackers.
struct HoneyValuePass : public llvm::PassInfoMixin<HoneyValuePass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Routes calls to external functions through a runtime-resolved thunk table,
/// defeating static import table analysis (IDA external call resolution).
struct CallIndirectionPass : public llvm::PassInfoMixin<CallIndirectionPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Inserts software pointer authentication for function pointers stored in
/// module-level globals, simulating ARM64e PAC on platforms without hardware
/// support via XOR-tagging with a runtime-derived key.
struct PointerAuthPass : public llvm::PassInfoMixin<PointerAuthPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Sets non-public functions and globals to hidden visibility, removing them
/// from the dynamic symbol table and preventing name-based dlsym() hooking.
struct SymbolVisibilityPass
    : public llvm::PassInfoMixin<SymbolVisibilityPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Injects a call to kagura_telemetry_event(uint32_t id) at the entry
/// of instrumented functions to collect behavioral signals for cheat detection.
struct TelemetryPass : public llvm::PassInfoMixin<TelemetryPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

} // namespace kagura
