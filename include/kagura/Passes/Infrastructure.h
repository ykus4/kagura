//===-- Passes/Infrastructure.h - Policy, metrics and reporting passes -----===//
//
// Passes that do not obfuscate anything themselves: they decide what the other
// passes should do, or report on what they did. Sources in
// lib/Transforms/Infrastructure/.
//
// These are the passes Plugin.cpp injects by hand rather than from the registry
// table, because each has a bespoke trigger or a fixed position relative to the
// obfuscation passes.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

namespace kagura {

/// Reads a JSON policy file and applies per-module protection
/// settings, including profile presets (FAST / BALANCED / STRONG) and
/// per-pass enable/disable overrides.  Run BEFORE other passes.
///
/// Note the actual work happens in loadConfigFileIfSpecified(), called while
/// the pipeline is built. This pass exists so `opt -passes=kagura-config`
/// stays a valid pipeline name.
struct ConfigLoaderPass : public llvm::PassInfoMixin<ConfigLoaderPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Analyzes each function's IR characteristics (cyclomatic complexity,
/// instruction count, alloca types, string refs) and annotates functions with
/// the appropriate kagura pass set. Run BEFORE other obfuscation passes.
/// Respects existing per-function annotations and globally-disabled passes.
struct AutoSelectPass : public llvm::PassInfoMixin<AutoSelectPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Controls DWARF / debug-info metadata on functions touched by kagura.
///
/// Mode is read from -kagura-dwarf:
///   "keep"       — no-op (default); debug info is preserved unchanged.
///   "strip"      — remove all DILocation / debug metadata from every
///                  function that was processed by at least one kagura pass.
///                  Prevents decompilers from correlating obfuscated code back
///                  to source lines.
///   "obfuscate"  — remap all debug locations to synthetic line numbers so
///                  that decompilers show plausible but wrong source positions.
///
/// This pass is automatically appended after all obfuscation passes when
/// -kagura-dwarf=strip or -kagura-dwarf=obfuscate is specified.
struct DWARFControlPass : public llvm::PassInfoMixin<DWARFControlPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Emits a JSON symbol map recording original and obfuscated names.
/// Run AFTER all obfuscation passes.
struct SymbolMapPass : public llvm::PassInfoMixin<SymbolMapPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Emits a JSON audit log recording all obfuscated functions and
/// which passes were applied.  Run AFTER all obfuscation passes.
struct AuditLogPass : public llvm::PassInfoMixin<AuditLogPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

/// Collects and prints obfuscation metrics per function:
///   - basic block count delta
///   - instruction count delta
///   - cyclomatic complexity before/after
/// Run this pass BEFORE and AFTER obfuscation passes to compare.
struct ObfuscationMetricsPass
    : public llvm::PassInfoMixin<ObfuscationMetricsPass> {
  bool IsBefore; // true = snapshot before, false = report after

  explicit ObfuscationMetricsPass(bool Before = false) : IsBefore(Before) {}

  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return true; } // always run even without opts
};

} // namespace kagura
