//===-- Plugin.cpp - Kagura LLVM pass plugin registration -----------------===//
//
// Registers all Kagura passes with LLVM's New Pass Manager.
// Load via: clang -fpass-plugin=libKaguraObfuscator.dylib
//
// The pass list itself lives in PassRegistry.def — every pass added to that
// table is automatically wired into:
//   1. The named-pass parsing callback (so `opt -passes=kagura-foo` works)
//   2. The OptimizerLast auto-pipeline (so `-fpass-plugin=...` alone applies
//      every opt::* flag the user enabled)
//
// Adding a new pass is a one-line edit in PassRegistry.def — no double
// registration here.
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes.h"

#include "llvm/Config/llvm-config.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif

using namespace llvm;
using namespace kagura;

//===----------------------------------------------------------------------===//
// Plugin entry point
//===----------------------------------------------------------------------===//

llvm::PassPluginLibraryInfo getKaguraPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "KaguraObfuscator", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // ---- Named-pass parsing: function-level passes ----
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) -> bool {
#define KAGURA_FN_PASS(Flag, Cli, Desc, Ctor)                                  \
                  if (Name == Cli) {                                           \
                    FPM.addPass(Ctor);                                         \
                    return true;                                               \
                  }
#include "PassRegistry.def"
                  // `kagura-anti-debug` is module-level but historically also
                  // accepted in the function-pass position as a no-op for
                  // callers using `function(...)` wrappers.
                  if (Name == "kagura-anti-debug")
                    return true;
                  return false;
                });

            // ---- Named-pass parsing: module-level passes ----
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) -> bool {
#define KAGURA_MOD_PASS(Flag, Cli, Desc, Ctor)                                 \
                  if (Name == Cli) {                                           \
                    MPM.addPass(Ctor);                                         \
                    return true;                                               \
                  }
#include "PassRegistry.def"
                  // Infrastructure passes outside the auto-pipeline table —
                  // these have ordering or conditional quirks and are injected
                  // explicitly in the OptimizerLast block below, but are still
                  // parseable by name from the shared registry table.
#define KAGURA_INFRA_PASS(Cli, Ctor)                                           \
                  if (Name == Cli) {                                           \
                    MPM.addPass(Ctor);                                         \
                    return true;                                               \
                  }
#include "PassRegistry.def"
                  return false;
                });

            // Inject at the END of the optimizer pipeline so that LLVM's own
            // passes (instcombine, simplifycfg, etc.) don't undo or crash on
            // our obfuscated IR.
            PB.registerOptimizerLastEPCallback(
#if LLVM_VERSION_MAJOR >= 20
                [](ModulePassManager &MPM, OptimizationLevel OL,
                   ThinOrFullLTOPhase Phase) {
#else
                [](ModulePassManager &MPM, OptimizationLevel OL) {
#endif
                  // --- Load JSON config / apply profile preset ---
                  //
                  // This has to happen HERE, not as a pass. Everything below
                  // reads opt::* to decide what to add to the pipeline, and a
                  // pass added to MPM does not run until the pipeline is
                  // already fixed. Adding ConfigLoaderPass here instead — as
                  // this code used to — meant the JSON policy file could never
                  // influence pass selection, so -kagura-config was silently a
                  // no-op for the -fpass-plugin entry point documented in the
                  // README.
                  loadConfigFileIfSpecified();

                  // --- LTO / ThinLTO pipeline gating ---
                  // During link-time optimisation the IR is often an
                  // incomplete cross-module view. Passes that inject new
                  // globals or rely on single-module semantics (AntiTamper,
                  // JNI, ObjC) can produce invalid IR in this context. Skip
                  // them unless the user explicitly opts in with
                  // -kagura-lto-safe.
#if LLVM_VERSION_MAJOR >= 20
                  bool IsLTOPhase =
                      Phase == ThinOrFullLTOPhase::ThinLTOPreLink ||
                      Phase == ThinOrFullLTOPhase::ThinLTOPostLink ||
                      Phase == ThinOrFullLTOPhase::FullLTOPreLink ||
                      Phase == ThinOrFullLTOPhase::FullLTOPostLink;
                  if (IsLTOPhase && !opt::LTOSafe)
                    return;
#endif

                  // --- O0 lightweight protection ---
                  if (OL == OptimizationLevel::O0) {
                    // At -O0 we only enable the passes that are explicitly
                    // requested AND that the user has opted into via
                    // -kagura-o0-protect. Heavy structural passes (FLA, BCF,
                    // VM) are skipped because they substantially increase
                    // compilation time and binary size even at -O0.
                    if (!opt::O0Protect)
                      return;
                    // Lightweight subset at O0: string encryption and
                    // anti-debug only. Bounded, predictable overhead.
                    if (opt::STR)
                      MPM.addPass(StringEncryptionPass());
                    if (opt::STRAES)
                      MPM.addPass(StringEncryptionAESPass());
                    if (opt::WSTR)
                      MPM.addPass(WideStringEncryptionPass());
                    if (opt::AntiDebug)
                      MPM.addPass(AntiDebugPass());
                    if (opt::DWARFMode != "keep")
                      MPM.addPass(DWARFControlPass());
                    return;
                  }
                  // Snapshot BEFORE obfuscation
                  if (opt::Metrics)
                    MPM.addPass(ObfuscationMetricsPass(/*Before=*/true));

                  // --- Module-level passes (table-driven) ---
#define KAGURA_MOD_PASS(Flag, Cli, Desc, Ctor)                                 \
                  if (opt::Flag)                                               \
                    MPM.addPass(Ctor);
#include "PassRegistry.def"

                  // --- Function-level passes (table-driven) ---
                  FunctionPassManager FPM;
                  bool HasFunctionPass = false;
#define KAGURA_FN_PASS(Flag, Cli, Desc, Ctor)                                  \
                  if (opt::Flag) {                                             \
                    FPM.addPass(Ctor);                                         \
                    HasFunctionPass = true;                                    \
                  }
#include "PassRegistry.def"
                  if (HasFunctionPass)
                    MPM.addPass(createModuleToFunctionPassAdaptor(
                        std::move(FPM)));

                  // Snapshot AFTER obfuscation → print report
                  if (opt::Metrics)
                    MPM.addPass(ObfuscationMetricsPass(/*Before=*/false));

                  // --- DWARF / debug-info control ---
                  // Run after all obfuscation so synthetic debug locations
                  // introduced by the passes above are also handled.
                  if (opt::DWARFMode != "keep")
                    MPM.addPass(DWARFControlPass());

                  // --- Symbol map output ---
                  // Run last so all obfuscated names are already in place.
                  if (opt::SymMap)
                    MPM.addPass(SymbolMapPass());

                  // --- RTTI / vtable protection ---
                  if (opt::VTP)
                    MPM.addPass(VTableProtectionPass());

                  // --- Audit log ---
                  // Run after everything else so all markObfuscated() calls
                  // are already recorded.
                  if (opt::AuditLog)
                    MPM.addPass(AuditLogPass());
                });
          }};
}

// Required export for -fpass-plugin loading
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getKaguraPluginInfo();
}
