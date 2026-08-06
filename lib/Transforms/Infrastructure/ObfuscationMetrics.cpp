//===-- ObfuscationMetrics.cpp - Obfuscation strength metrics -------------===//
//
// Collects per-function metrics before and after obfuscation and prints a
// summary report to stderr.
//
// Metrics reported per function:
//   BB count     - number of basic blocks (CFG nodes)
//   Inst count   - total instruction count (code size proxy)
//   Cyclomatic   - McCabe cyclomatic complexity: edges - nodes + 2
//   Edge count   - number of CFG edges
//
// Usage:
//   Pass -kagura-metrics to enable.  Two snapshots are taken automatically:
//   one before and one after the obfuscation pipeline.  The report is printed
//   when the module is finalized.
//
// Example output:
//   [kagura metrics] function: compute
//     BB:     3  →  12   (+300%)
//     Instr:  18 →  67   (+272%)
//     Cyclo:  3  →  9    (+200%)
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes/Infrastructure.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <map>
#include <string>

using namespace llvm;

namespace kagura {

struct FuncMetrics {
  unsigned BBs   = 0;
  unsigned Insts = 0;
  unsigned Edges = 0;

  unsigned cyclomatic() const {
    // M = E - N + 2  (single connected component)
    return (Edges >= BBs) ? Edges - BBs + 2 : 1;
  }
};

// Global snapshot storage (module-scoped, reset per module)
static std::map<std::string, FuncMetrics> BeforeSnapshot;
static std::map<std::string, FuncMetrics> AfterSnapshot;

static FuncMetrics collectMetrics(const Function &F) {
  FuncMetrics M;
  for (const auto &BB : F) {
    ++M.BBs;
    for (const auto &I : BB)
      ++M.Insts;
    M.Edges += BB.getTerminator()->getNumSuccessors();
  }
  return M;
}

static void printReport() {
  errs() << "\n╔══════════════════════════════════════════════════════╗\n";
  errs() << "║         kagura obfuscation metrics report            ║\n";
  errs() << "╚══════════════════════════════════════════════════════╝\n";

  for (auto &[Name, Before] : BeforeSnapshot) {
    auto It = AfterSnapshot.find(Name);
    if (It == AfterSnapshot.end())
      continue;
    const FuncMetrics &After = It->second;

    auto pct = [](unsigned before, unsigned after) -> std::string {
      if (before == 0) return "N/A";
      long long delta = (long long)(((double)((long long)after - (long long)before) / before) * 100);
      return (delta >= 0 ? "+" : "") + std::to_string(delta) + "%";
    };

    errs() << "\n  function: " << Name << "\n";
    errs() << "    BB count  : " << Before.BBs   << " → " << After.BBs
           << "  (" << pct(Before.BBs, After.BBs) << ")\n";
    errs() << "    Instr cnt : " << Before.Insts  << " → " << After.Insts
           << "  (" << pct(Before.Insts, After.Insts) << ")\n";
    errs() << "    Cyclomatic: " << Before.cyclomatic()
           << " → " << After.cyclomatic()
           << "  (" << pct(Before.cyclomatic(), After.cyclomatic()) << ")\n";
  }
  errs() << "\n";
}

PreservedAnalyses ObfuscationMetricsPass::run(Module &M,
                                               ModuleAnalysisManager &) {
  if (IsBefore) {
    BeforeSnapshot.clear();
    AfterSnapshot.clear();
    for (auto &F : M)
      if (!F.isDeclaration())
        BeforeSnapshot[F.getName().str()] = collectMetrics(F);
  } else {
    for (auto &F : M)
      if (!F.isDeclaration())
        AfterSnapshot[F.getName().str()] = collectMetrics(F);
    printReport();
  }
  return PreservedAnalyses::all();
}

} // namespace kagura
