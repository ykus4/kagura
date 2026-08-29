//===-- SymbolMap.cpp - Pre/post obfuscation symbol name mapping ----------===//
//
// 4.6.5: Emits a JSON symbol map recording the original and post-obfuscation
// names of every function and global variable touched by kagura passes.
//
// The map is written to the path given by -kagura-symmap-out (default:
// kagura_symbols.json in the current directory).  It is appended if the file
// already exists (one map entry per TU), making it suitable for parallel
// compilation.
//
// Format:
//   {
//     "module": "<source file>",
//     "symbols": [
//       { "original": "foo", "obfuscated": "kagura_dec_12345678",
//         "kind": "function" },
//       ...
//     ]
//   }
//
// Usage:
//   The pass is run AFTER all obfuscation passes so that the obfuscated names
//   are already in place.  It scans all functions/globals for a "kagura_"
//   prefix (or a name that differs from the source name stored in debug info)
//   and records the mapping.
//
// Pass key:   "kagura-symmap"
// CLI flag:   -kagura-symmap
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/Infrastructure.h"
#include "kagura/Utils.h"

#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;

namespace kagura {

// ---- Helpers ---------------------------------------------------------------

/// Returns the source-level name for a function by consulting DISubprogram.
static std::string getOriginalFunctionName(const Function &F) {
  if (auto *SP = F.getSubprogram())
    return SP->getName().str();
  return F.getName().str();
}

// isKaguraSymbol() used to live here as its own two-prefix test, which is
// how it drifted from the one in Utils.cpp. kagura::isKaguraSymbol is the
// single definition; the local copy reported __kg_* and kagura.* symbols to
// the user as if they were their own.

// ---- Pass entry point -------------------------------------------------------

PreservedAnalyses SymbolMapPass::run(Module &M, ModuleAnalysisManager &) {
  if (!kagura::opt::SymMap)
    return PreservedAnalyses::all();

  json::Array Symbols;

  // Functions
  for (const Function &F : M) {
    if (F.isDeclaration())
      continue;
    std::string Current  = F.getName().str();
    std::string Original = getOriginalFunctionName(F);

    // Record if the name was changed by an obfuscation pass (kagura prefix,
    // or the debug name differs from the current IR name).
    bool NameChanged = isKaguraSymbol(Current) || (Original != Current);
    if (!NameChanged)
      continue;

    json::Object Entry;
    Entry["original"]    = Original;
    Entry["obfuscated"]  = Current;
    Entry["kind"]        = "function";
    Symbols.push_back(std::move(Entry));
  }

  // Globals (primarily encrypted string / key globals injected by kagura)
  for (const GlobalVariable &GV : M.globals()) {
    if (!isKaguraSymbol(GV.getName()))
      continue;
    // Skip well-known internal housekeeping globals
    StringRef Name = GV.getName();
    if (Name.starts_with("kagura_flag_") ||
        Name.starts_with("kagura_key_")  ||
        Name.starts_with("kagura_wkey_") ||
        Name.starts_with("kagura_aeskey_") ||
        Name.starts_with("kagura_honey_ctor"))
      continue;

    json::Object Entry;
    Entry["original"]    = "(injected)";
    Entry["obfuscated"]  = Name.str();
    Entry["kind"]        = "global";
    Symbols.push_back(std::move(Entry));
  }

  if (Symbols.empty())
    return PreservedAnalyses::all();

  // Build the JSON object for this module.
  json::Object ModuleEntry;
  ModuleEntry["module"]  = M.getSourceFileName();
  ModuleEntry["symbols"] = std::move(Symbols);

  // Append to the output file.
  std::string OutPath = kagura::opt::SymMapOut;
  if (OutPath.empty())
    OutPath = "kagura_symbols.json";

  std::error_code EC;
  raw_fd_ostream Out(OutPath, EC,
                     sys::fs::OF_Append | sys::fs::OF_Text);
  if (EC) {
    errs() << "[kagura] SymbolMap: cannot open " << OutPath
           << ": " << EC.message() << "\n";
    return PreservedAnalyses::all();
  }

  Out << json::Value(std::move(ModuleEntry)) << "\n";
  return PreservedAnalyses::all(); // read-only analysis
}

} // namespace kagura
