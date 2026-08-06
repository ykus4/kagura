//===-- AuditLog.cpp - Obfuscation audit log emission --------------------===//
//
// 4.6.10: Emits a JSON audit log that records what was protected and how.
//
// The log is appended (one JSON object per compilation unit) to the output
// file specified by -kagura-audit-out (default: kagura_audit.json).
//
// Each record contains:
//   "module"   : source file name (from !llvm.ident or module name)
//   "timestamp": seconds since epoch
//   "build_id" : value of -kagura-build-id if set
//   "functions": array of { "name": "...", "passes": ["fla","bcf",...] }
//
// A function is included in the log if it has the kagura_obfuscated metadata
// node attached, which each obfuscation pass is expected to set via
//   kagura::markObfuscated(F, "passname");
//
// Pass key:   "kagura-audit"
// CLI flags:  -kagura-audit  -kagura-audit-out=<path>
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/Infrastructure.h"
#include "kagura/Utils.h"

#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include <chrono>
#include <system_error>

using namespace llvm;

namespace kagura {

// ---- Metadata helpers -------------------------------------------------------

/// Attach a kagura_obfuscated metadata node to F recording the pass name.
/// Multiple calls accumulate pass names in a single MDTuple.
void markObfuscated(Function &F, StringRef PassName) {
  LLVMContext &Ctx = F.getContext();
  MDNode *Existing = F.getMetadata("kagura_obfuscated");
  SmallVector<Metadata *, 8> Ops;
  if (Existing)
    for (const MDOperand &Op : Existing->operands())
      Ops.push_back(Op.get());
  Ops.push_back(MDString::get(Ctx, PassName));
  F.setMetadata("kagura_obfuscated", MDNode::get(Ctx, Ops));
}

/// Returns all pass names recorded on F via markObfuscated().
static SmallVector<std::string, 8> getObfuscatedPasses(const Function &F) {
  SmallVector<std::string, 8> Passes;
  MDNode *MD = F.getMetadata("kagura_obfuscated");
  if (!MD)
    return Passes;
  for (const MDOperand &Op : MD->operands())
    if (auto *MDS = dyn_cast<MDString>(Op.get()))
      Passes.push_back(MDS->getString().str());
  return Passes;
}

// ---- Pass ------------------------------------------------------------------

PreservedAnalyses AuditLogPass::run(Module &M, ModuleAnalysisManager &) {
  if (!opt::AuditLog)
    return PreservedAnalyses::all();

  // Collect functions that were obfuscated
  json::Array FunctionsArr;
  for (const Function &F : M) {
    auto Passes = getObfuscatedPasses(F);
    if (Passes.empty())
      continue;
    json::Array PassesArr;
    for (const std::string &P : Passes)
      PassesArr.push_back(P);
    FunctionsArr.push_back(json::Object{
        {"name", F.getName().str()},
        {"passes", std::move(PassesArr)},
    });
  }

  if (FunctionsArr.empty())
    return PreservedAnalyses::all();

  // Build record
  auto Now = std::chrono::system_clock::now().time_since_epoch();
  int64_t Timestamp =
      std::chrono::duration_cast<std::chrono::seconds>(Now).count();

  std::string ModuleName = M.getName().str();
  if (ModuleName.empty())
    ModuleName = "<unknown>";

  json::Object Record{
      {"module",     ModuleName},
      {"timestamp",  Timestamp},
      {"build_id",   opt::BuildID.empty() ? "" : opt::BuildID.getValue()},
      {"functions",  std::move(FunctionsArr)},
  };

  // Append to output file
  std::string OutPath = opt::AuditLogOut.empty()
                            ? "kagura_audit.json"
                            : opt::AuditLogOut.getValue();

  std::error_code EC;
  raw_fd_ostream OS(OutPath, EC, sys::fs::OF_Append | sys::fs::OF_Text);
  if (!EC) {
    OS << json::Value(std::move(Record)) << "\n";
  }

  return PreservedAnalyses::all();
}

} // namespace kagura
