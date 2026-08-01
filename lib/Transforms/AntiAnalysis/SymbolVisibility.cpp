//===-- SymbolVisibility.cpp - Hide internal symbols ----------------------===//
//
// Reduces the exported symbol surface of a module by setting non-public
// functions and globals to hidden visibility.  On ELF targets this causes the
// linker to omit these symbols from the dynamic symbol table; on Mach-O it
// prevents the dynamic linker from exporting them.
//
// The result is a smaller symbol table, which:
//   - Removes obvious names from `nm` / `readelf --syms` output.
//   - Prevents dlsym()-based hooking by name.
//   - Enables the linker to inline and dead-strip more aggressively.
//
// Algorithm
// ---------
// For each Function and GlobalVariable in the module:
//   - Skip declarations (they name symbols defined elsewhere).
//   - Skip anything already non-default-visibility, and kagura's own runtime
//     symbols.
//   - Skip anything listed in the user-supplied keep list (the public API).
//   - Skip local (internal / private) linkage.  Those symbols are already
//     absent from the dynamic symbol table, so hidden visibility buys nothing,
//     and LLVM asserts "local linkage requires default visibility" if you try.
//   - Everything left is an exported definition: change it to Hidden.
//
// CLI flags
// ---------
//   -kagura-sv            Enable symbol visibility hardening
//   -kagura-sv-keep=<sym> Comma-separated list of symbols to keep visible
//                         (may be specified multiple times)
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"

#include <set>
#include <string>

using namespace llvm;

static cl::list<std::string> SVKeepSymbols(
    "kagura-sv-keep",
    cl::desc("[Kagura] Symbols to keep visible (comma-separated or repeated)"),
    cl::CommaSeparated);

namespace kagura {

static bool shouldHide(const GlobalValue &GV,
                       const std::set<std::string> &Allowlist) {
  // Never touch declarations — they refer to external symbols.
  if (GV.isDeclaration())
    return false;
  // Already hidden / protected — nothing to do.
  if (GV.getVisibility() != GlobalValue::DefaultVisibility)
    return false;
  // Keep explicitly listed public symbols visible.
  if (Allowlist.count(std::string(GV.getName())))
    return false;
  // Keep kagura runtime symbols visible (they're referenced by the runtime lib)
  if (GV.getName().starts_with("kagura_"))
    return false;
  // Local linkage (internal / private) is already invisible outside the
  // translation unit — it never reaches the dynamic symbol table, so there is
  // nothing for hidden visibility to add.  More importantly LLVM forbids the
  // combination outright: GlobalValue::setVisibility() asserts
  //   "local linkage requires default visibility"
  // and an assertions-enabled build crashes here rather than emitting IR.
  if (GV.hasLocalLinkage())
    return false;
  // What is left is a definition with external (or linkonce/weak) linkage that
  // is not on the keep list: exactly the symbols that would otherwise be
  // exported and dlsym()-able.  Hide those.
  return true;
}

PreservedAnalyses SymbolVisibilityPass::run(Module &M,
                                            ModuleAnalysisManager &) {
  if (!kagura::opt::SV)
    return PreservedAnalyses::all();

  // Build the allowlist from the CLI option
  std::set<std::string> Allowlist(SVKeepSymbols.begin(), SVKeepSymbols.end());

  bool Changed = false;

  for (Function &F : M) {
    if (shouldHide(F, Allowlist)) {
      F.setVisibility(GlobalValue::HiddenVisibility);
      Changed = true;
    }
  }

  for (GlobalVariable &GV : M.globals()) {
    if (shouldHide(GV, Allowlist)) {
      GV.setVisibility(GlobalValue::HiddenVisibility);
      Changed = true;
    }
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
