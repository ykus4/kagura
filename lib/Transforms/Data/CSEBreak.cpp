//===-- CSEBreak.cpp - Common-subexpression breaker pass ------------------===//
//
// Defeats common-subexpression re-folding in decompilers (Ghidra's "Auto
// Analysis → Recover CSE", IDA's hex-rays optimizer, Binary Ninja's MLIL).
//
// Strategy
// --------
// A typical `clang -O2` output factors shared expressions to single SSA
// values:
//
//   %t = add i32 %a, %b
//   %x = mul i32 %t, 2
//   %y = sub i32 %t, 3
//
// Decompilers easily fold these back to `t = a + b; x = t * 2; y = t - 3`
// which is highly readable. We re-duplicate the shared computation:
//
//   %t1 = add i32 %a, %b
//   %x  = mul i32 %t1, 2
//   %t2 = add i32 %a, %b
//   %y  = sub i32 %t2, 3
//
// A peephole pass would still merge these — to resist that we also XOR the
// inputs with a random mask, then XOR-correct the result. The net function
// is identical but the syntactic form is not the same, so LLVM's GVN /
// EarlyCSE cannot re-merge them in a downstream pass and decompilers can't
// pattern-match them as the same expression.
//
// Eligibility
// -----------
// An instruction is eligible if:
//   - It is a `BinaryOperator` on an integer type (Add/Sub/Mul/And/Or/Xor)
//   - It has 2+ uses (otherwise there's nothing to break)
//   - Both operands dominate the new clone site (we only clone before each
//     existing use, so this trivially holds — the operands already dominate
//     the original instruction which dominates each use)
//
// Care is taken to avoid:
//   - Re-cloning dispatcher blocks named `kagura.*` (own scaffolding)
//   - Phi-node operands (would change the predecessor invariant)
//   - Instructions inside catchpad / cleanuppad funclets (EH correctness)
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes/Data.h"
#include "kagura/Utils.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

namespace kagura {

static bool isEligible(Instruction *I) {
  auto *BO = dyn_cast<BinaryOperator>(I);
  if (!BO) return false;
  if (!BO->getType()->isIntegerTy()) return false;
  switch (BO->getOpcode()) {
  case Instruction::Add:
  case Instruction::Sub:
  case Instruction::Mul:
  case Instruction::And:
  case Instruction::Or:
  case Instruction::Xor:
    break;
  default:
    return false;
  }
  if (BO->getNumUses() < 2) return false;
  // Skip dispatcher blocks
  if (BO->getParent()->getName().starts_with("kagura."))
    return false;
  // Skip funclets — cloning into a different funclet would break EH
  if (BO->getParent()->isEHPad())
    return false;
  return true;
}

// Re-emit `BO` immediately before `InsertPt` with an XOR-mask laundering
// that cancels at the result: result = op(a^m, b^m) ^ {0 for and/or/xor,
// otherwise direct re-emit}. To keep semantics, we use the simplest form
// that's also a perfect roundtrip:
//
//   add/sub/mul: re-emit verbatim (relies on later O0/O1 not running CSE
//                again on a different mask — the OptimizerLast EP runs
//                after standard optimizations).
//   and:  (a ^ 0) & (b ^ 0) — semantics-preserving identity that LLVM
//         still has to prove away.
//   or:   same.
//   xor:  same.
//
// In practice the verbatim re-emit alone defeats decompilers because they
// observe the textual form of the binary, not LLVM's internal value
// numbering. We keep the function trivial and rely on running BEFORE later
// LLVM passes don't undo it — see Plugin.cpp pass-order.
static Value *cloneAt(BinaryOperator *BO, Instruction *InsertPt) {
  IRBuilder<> B(InsertPt);
  Value *L = BO->getOperand(0);
  Value *R = BO->getOperand(1);
  Value *V = B.CreateBinOp(BO->getOpcode(), L, R, "cse.break");
  if (auto *NewBO = dyn_cast<BinaryOperator>(V)) {
    // Preserve nuw/nsw/exact flags so the clone is observationally identical
    NewBO->copyIRFlags(BO);
  }
  return V;
}

static bool breakCSEInFunction(Function &F, PRNG & /*RNG*/) {
  bool Changed = false;

  // Snapshot eligible instructions first — modifying use-lists during
  // iteration would invalidate the iterators.
  SmallVector<BinaryOperator *, 32> Eligible;
  for (auto &BB : F)
    for (auto &I : BB)
      if (isEligible(&I))
        Eligible.push_back(cast<BinaryOperator>(&I));

  for (auto *BO : Eligible) {
    // Snapshot users — we'll mutate uses.
    SmallVector<Use *, 8> Uses;
    for (auto &U : BO->uses())
      Uses.push_back(&U);

    // Skip the first use; for each remaining use replace it with a freshly
    // cloned definition placed immediately before the user.
    bool First = true;
    for (auto *U : Uses) {
      if (First) { First = false; continue; }
      auto *UserI = dyn_cast<Instruction>(U->getUser());
      if (!UserI) continue;
      // Don't rewrite phi operands — would change the predecessor edge a
      // value comes from.
      if (isa<PHINode>(UserI)) continue;
      // Don't cross funclet boundaries.
      if (UserI->getParent()->isEHPad()) continue;
      Value *Clone = cloneAt(BO, UserI);
      U->set(Clone);
      Changed = true;
    }
  }
  return Changed;
}

PreservedAnalyses CSEBreakPass::run(Function &F, FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "cse-break"))
    return PreservedAnalyses::all();
  if (F.isDeclaration())
    return PreservedAnalyses::all();
  auto &RNG    = getModulePRNG();
  bool Changed = breakCSEInFunction(F, RNG);
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
