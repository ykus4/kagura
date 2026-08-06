//===-- DWARFControl.cpp - DWARF / debug-info handling after obfuscation --===//
//
// Controls how DWARF debug metadata is treated after kagura passes run.
//
// Three modes (controlled by -kagura-dwarf):
//
//   "keep" (default)
//     No-op.  All debug info is left exactly as the front-end produced it.
//     Use this when you still want debuggable builds (e.g. internal QA).
//
//   "strip"
//     Remove all debug metadata from every function in the module.
//     DILocation attachments on instructions are cleared; the top-level
//     compile-unit and subprogram metadata nodes are erased.  This prevents
//     decompilers (IDA, Ghidra, Binary Ninja) from correlating obfuscated
//     machine code back to source file / line information.
//     Equivalent to compiling with -g0 but applied selectively at IR level
//     so that non-obfuscated build artefacts (e.g. third-party static libs
//     linked in before kagura runs) are unaffected.
//
//   "obfuscate"
//     Remap every DILocation to a synthetic source coordinate:
//       file = "<kagura>"  (a single fabricated source file)
//       line = hash(original_line ^ seed) % 60000  (plausible range)
//       column = 0
//     The function DISubprogram is updated to reference the fake file.
//     Decompilers still see valid DWARF (avoiding parse errors) but will
//     report incorrect source positions, misdirecting analysts.
//
// Pass key:   "kagura-dwarf-control"
// CLI flag:   -kagura-dwarf=<mode>
//
// This pass is registered as a pipeline-parsing pass ("kagura-dwarf-control")
// and is automatically appended after all other kagura passes when the mode
// is not "keep".  It is a no-op in "keep" mode so it is always safe to insert.
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/Infrastructure.h"

#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace kagura {

// ---------------------------------------------------------------------------
// "strip" mode helpers
// ---------------------------------------------------------------------------

/// Remove all debug-info attachments from every instruction in F.
static void stripFunctionDebugInfo(Function &F) {
  for (Instruction &I : instructions(F))
    I.setDebugLoc(DebugLoc());
}

/// Drop all compile-unit / subprogram named metadata so that linkers and
/// debuggers see no DWARF at all.
static void stripModuleDebugInfo(Module &M) {
  // Clear per-instruction debug locations.
  for (Function &F : M)
    stripFunctionDebugInfo(F);

  // Erase the module-level debug metadata lists.
  if (NamedMDNode *CUs = M.getNamedMetadata("llvm.dbg.cu"))
    CUs->eraseFromParent();

  // Drop all llvm.dbg.* intrinsic calls (declare, value, assign, label).
  SmallVector<Instruction *, 64> ToErase;
  for (Function &F : M)
    for (Instruction &I : instructions(F))
      if (isa<DbgInfoIntrinsic>(&I))
        ToErase.push_back(&I);
  for (Instruction *I : ToErase)
    I->eraseFromParent();
}

// ---------------------------------------------------------------------------
// "obfuscate" mode helpers
// ---------------------------------------------------------------------------

/// Return (or create) a synthetic DIFile node named "<kagura>" in builder B.
static DIFile *getOrCreateKaguraFile(DIBuilder &Builder) {
  // The filename and directory are arbitrary; we use something that looks
  // like a system path to blend in with real DWARF entries.
  return Builder.createFile("<kagura>", "/var/empty");
}

/// Remap the debug location of every instruction in F to synthetic coordinates.
static void obfuscateFunctionDebugInfo(Function &F, DIFile *FakeFile,
                                       uint64_t Seed) {
  DISubprogram *SP = F.getSubprogram();
  if (!SP)
    return;

  for (Instruction &I : instructions(F)) {
    const DebugLoc &DL = I.getDebugLoc();
    if (!DL)
      continue;

    // Derive a stable synthetic line from the original line and seed.
    // The modulo keeps it in a plausible range (1..59999).
    uint32_t OrigLine = DL.getLine();
    uint32_t FakeLine = static_cast<uint32_t>(
        ((static_cast<uint64_t>(OrigLine) * 0x9e3779b97f4a7c15ULL) ^ Seed) %
            59999) +
        1;

    // Build a new DILocation with the fake coordinates but preserving the
    // inlining scope chain so DWARF remains structurally valid.
    DILocation *NewLoc =
        DILocation::get(F.getContext(), FakeLine, /*Column=*/0,
                        DL.getScope(), DL.getInlinedAt());
    I.setDebugLoc(DebugLoc(NewLoc));
  }
}

/// Update the DISubprogram attached to F to reference the synthetic file so
/// that source-level views in decompilers show the fabricated name.
static void obfuscateSubprogram(Function &F, DIFile *FakeFile,
                                 DIBuilder &Builder) {
  DISubprogram *SP = F.getSubprogram();
  if (!SP)
    return;
  // We cannot mutate existing DISubprogram nodes in LLVM (they are immutable
  // uniqued metadata).  Instead we use DIBuilder to replace the subprogram
  // with an identical copy that references the fake file.  Because we are
  // only renaming the file reference and the function name is kept, the
  // resulting DWARF is still parseable.
  DISubprogram *NewSP = Builder.createFunction(
      FakeFile,             // scope  → fake file
      SP->getName(),        // keep original function name
      SP->getLinkageName(), // keep mangled name
      FakeFile,             // file   → fake file
      SP->getLine(),
      SP->getType(),
      SP->getScopeLine(),
      SP->getFlags(),
      SP->getSPFlags());
  F.setSubprogram(NewSP);
}

// ---------------------------------------------------------------------------
// Pass entry point
// ---------------------------------------------------------------------------

PreservedAnalyses DWARFControlPass::run(Module &M,
                                         ModuleAnalysisManager & /*MAM*/) {
  StringRef Mode = opt::DWARFMode;

  if (Mode == "keep" || Mode.empty())
    return PreservedAnalyses::all();

  if (Mode == "strip") {
    stripModuleDebugInfo(M);
    // Stripping debug info does not affect the correctness of generated code.
    return PreservedAnalyses::all();
  }

  if (Mode == "obfuscate") {
    DIBuilder Builder(M, /*AllowUnresolved=*/false);
    DIFile *FakeFile = getOrCreateKaguraFile(Builder);
    uint64_t Seed = static_cast<uint64_t>(opt::Seed);

    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      obfuscateFunctionDebugInfo(F, FakeFile, Seed);
      obfuscateSubprogram(F, FakeFile, Builder);
    }

    Builder.finalize();
    return PreservedAnalyses::all();
  }

  // Unknown mode — warn and do nothing.
  errs() << "[kagura] Warning: unknown -kagura-dwarf mode '" << Mode
         << "'. Valid values: keep, strip, obfuscate.\n";
  return PreservedAnalyses::all();
}

} // namespace kagura
