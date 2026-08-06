//===-- AutoSelect.cpp - Risk-based obfuscation pass auto-selection --------===//
//
// 4.8.1: Analyzes each function's IR characteristics and automatically enables
// the most cost-effective set of kagura passes based on estimated attack surface
// and obfuscation complexity budget.
//
// Selection algorithm:
//   For each function F in the module:
//     1. Compute a risk score from static features:
//          - Cyclomatic complexity  (high → more CFG obfuscation)
//          - Instruction count      (large → avoid VM; use lighter passes)
//          - Presence of string globals referenced from F
//          - Presence of alloca'd integers / pointers (MVO / PE candidates)
//          - External call count    (many externs → CallIndirection candidate)
//     2. Map the score to a protection tier:
//          LOW    (score <  10) → STR + BBR
//          MEDIUM (score < 30)  → STR + BCF + BBR + BBS + MVO
//          HIGH   (score >= 30) → STR + FLA + BCF + BBR + BBS + MVO + PE + SUB
//     3. Apply the tier by setting the per-function "kagura_<pass>" annotation
//        so that shouldObfuscate() picks it up without touching global flags.
//
// This pass is a module pass that runs BEFORE all other kagura passes.
// It never overrides explicit per-function annotations (kagura_nofla etc.)
// or globally-disabled passes.
//
// Pass key:   "kagura-autoselect"
// CLI flag:   -kagura-autoselect
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/Infrastructure.h"
#include "kagura/Utils.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#define DEBUG_TYPE "kagura-autoselect"

using namespace llvm;

// ---- Risk scoring ----------------------------------------------------------

namespace {

struct RiskFeatures {
  unsigned BBs        = 0;
  unsigned Insts      = 0;
  unsigned Edges      = 0;
  unsigned IntAllocas = 0;  // candidate for MVO
  unsigned PtrAllocas = 0;  // candidate for PE
  unsigned ExtCalls   = 0;  // external function calls
  bool     HasStrings = false;

  unsigned cyclomatic() const {
    return (Edges >= BBs) ? Edges - BBs + 2 : 1;
  }

  // Composite risk score (0–100 scale).
  // Weights are intentionally conservative to avoid over-obfuscating.
  unsigned score() const {
    unsigned S = 0;
    S += std::min(cyclomatic() * 2u, 30u); // up to 30 pts
    S += std::min(Insts / 10u,        20u); // up to 20 pts
    S += std::min(IntAllocas * 3u,    15u); // up to 15 pts
    S += std::min(PtrAllocas * 3u,    15u); // up to 15 pts
    S += HasStrings ? 10u : 0u;             // 10 pts for string refs
    S += std::min(ExtCalls * 2u,      10u); // up to 10 pts
    return S;
  }
};

static RiskFeatures analyze(const Function &F) {
  RiskFeatures R;
  for (const auto &BB : F) {
    ++R.BBs;
    R.Edges += BB.getTerminator()->getNumSuccessors();
    for (const auto &I : BB) {
      ++R.Insts;
      if (const auto *AI = dyn_cast<AllocaInst>(&I)) {
        Type *Ty = AI->getAllocatedType();
        if (Ty->isIntegerTy())  ++R.IntAllocas;
        if (Ty->isPointerTy())  ++R.PtrAllocas;
      }
      if (const auto *CI = dyn_cast<CallInst>(&I)) {
        Function *Callee = CI->getCalledFunction();
        if (Callee && Callee->isDeclaration() && !Callee->isIntrinsic())
          ++R.ExtCalls;
        // Check for references to string globals
        for (unsigned Op = 0; Op < CI->getNumOperands(); ++Op) {
          if (auto *GV = dyn_cast<GlobalVariable>(
                  CI->getOperand(Op)->stripPointerCasts()))
            if (GV->isConstant() && GV->hasInitializer())
              if (auto *CDA = dyn_cast<ConstantDataArray>(GV->getInitializer()))
                if (CDA->isString())
                  R.HasStrings = true;
        }
      }
    }
  }
  return R;
}

/// The per-function passes AutoSelect arbitrates, paired with whether the user
/// enabled them. Only these are annotated; anything else is left untouched.
static SmallVector<std::pair<StringRef, bool>, 8> candidatePasses() {
  return {
      {"str", kagura::opt::STR}, {"bbr", kagura::opt::BBR},
      {"bcf", kagura::opt::BCF}, {"bbs", kagura::opt::BBS},
      {"mvo", kagura::opt::MVO}, {"fla", kagura::opt::FLA},
      {"sub", kagura::opt::SUB}, {"pe",  kagura::opt::PE},
  };
}

enum class ProtectionTier { Low, Medium, High };

static ProtectionTier tierFor(unsigned Score) {
  if (Score < 10) return ProtectionTier::Low;
  if (Score < 30) return ProtectionTier::Medium;
  return ProtectionTier::High;
}

/// Attach `kagura_<attr>` (force-enable) or `kagura_no<attr>` (force-disable)
/// to F as function metadata, unless the user already annotated it either way.
/// A user annotation always wins over an automatic decision.
static void annotateIfAbsent(Function &F, StringRef PassAttr, bool Enable) {
  if (kagura::hasAnnotation(F, ("kagura_" + PassAttr).str()))   return;
  if (kagura::hasAnnotation(F, ("kagura_no" + PassAttr).str())) return;

  LLVMContext &Ctx = F.getContext();
  MDNode *Node = MDNode::get(Ctx, MDString::get(Ctx,
      ("kagura.autoselect." + PassAttr).str()));
  std::string Key = Enable ? ("kagura_" + PassAttr).str()
                           : ("kagura_no" + PassAttr).str();
  F.setMetadata(Key, Node);
}

} // anonymous namespace

// ---- Pass entry point -------------------------------------------------------

namespace kagura {

PreservedAnalyses AutoSelectPass::run(Module &M, ModuleAnalysisManager &) {
  if (!kagura::opt::AutoSelect)
    return PreservedAnalyses::all();

  // C.1: On Wasm, FLA and VM passes are disabled (structured control flow
  // requirement).  AutoSelect must not annotate these passes on Wasm targets
  // even when the global flags are on — the per-function annotation would
  // bypass the guard inside each pass.
  const bool IsWasm = kagura::isWasmTarget(M);

  for (auto &F : M) {
    if (F.isDeclaration() || F.isVarArg()) continue;

    RiskFeatures Features = analyze(F);
    unsigned Score = Features.score();
    ProtectionTier Tier = tierFor(Score);

    LLVM_DEBUG(llvm::dbgs()
               << "[kagura-autoselect] " << F.getName()
               << " score=" << Score
               << " cyclo=" << Features.cyclomatic()
               << " insts=" << Features.Insts
               << "\n");

    // Which of the globally-enabled passes this function's risk score
    // warrants. AutoSelect can only ever narrow: a pass the user did not
    // enable is not in the pipeline at all, so annotating it would achieve
    // nothing, and turning on protection the user did not ask for would be a
    // surprising thing for an "auto" mode to do.
    StringSet<> Want;
    if (Features.HasStrings)
      Want.insert("str");

    switch (Tier) {
    case ProtectionTier::Low:
      // Lightweight: BBR only (+ STR above)
      Want.insert("bbr");
      break;

    case ProtectionTier::Medium:
      // Moderate: BCF + BBR + BBS + MVO
      Want.insert("bcf");
      Want.insert("bbr");
      Want.insert("bbs");
      if (Features.IntAllocas > 0) Want.insert("mvo");
      break;

    case ProtectionTier::High:
      // Heavy: FLA + BCF + BBR + BBS + MVO + PE + SUB.
      // FLA is skipped for very large functions to bound code-size blowup,
      // and on Wasm, which requires structured control flow.
      if (Features.Insts <= 200 && !IsWasm) Want.insert("fla");
      Want.insert("bcf");
      Want.insert("bbr");
      Want.insert("bbs");
      Want.insert("sub");
      if (Features.IntAllocas > 0) Want.insert("mvo");
      if (Features.PtrAllocas > 0) Want.insert("pe");
      break;
    }

    // Emit an explicit decision for every candidate pass the user enabled.
    // The force-disable half is what actually does the work: with the pass
    // already in the pipeline, a force-enable annotation only restates the
    // default, so annotating solely the wanted set — as this pass used to —
    // would leave behaviour unchanged even once the annotations were read.
    for (auto &[Attr, Enabled] : candidatePasses()) {
      if (!Enabled)
        continue;
      annotateIfAbsent(F, Attr, Want.contains(Attr));
    }
  }

  return PreservedAnalyses::all(); // annotations only, no IR change
}

} // namespace kagura
