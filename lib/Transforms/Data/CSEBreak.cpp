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
// A verbatim re-duplication like that is worthless on its own: the two
// expressions are syntactically identical over the same operands, which is
// exactly what value numbering merges. Measured, `opt -passes=early-cse`
// collapses the pair above back to one `add` in a single step.
//
// So each clone is laundered through a random per-clone mask that cancels at
// the result (see cloneAt below). The net value is unchanged, the syntactic
// form is not, and value numbering no longer sees a common subexpression.
//
// What this does and does not resist, measured rather than assumed:
//
//   early-cse       — resists. This is the pass the duplication is aimed at.
//   early-cse,gvn   — resists.
//   a full -O2      — does NOT resist. InstCombine and Reassociate know the
//                     algebraic identities and fold `((a+m)+b)-m` back to
//                     `a+b`, after which value numbering merges as before.
//
// That is acceptable because the pass runs on the OptimizerLast extension
// point, so in a normal build nothing algebraic runs after it. It is a real
// limitation under LTO, where the post-link pipeline reoptimises: prefer
// -kagura-lto-safe there. Defeating InstCombine as well would need the mask
// to come from a value it cannot reason about, at the cost of a memory
// access per clone.
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
#include "llvm/IR/Constants.h"
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
  if (isGenerated(*BO->getParent()) ||
      BO->getParent()->getName().starts_with("kagura."))
    return false;
  // Skip funclets — cloning into a different funclet would break EH
  if (BO->getParent()->isEHPad())
    return false;
  return true;
}

// Re-emit `BO` before `InsertPt`, laundered through a random per-clone mask
// that cancels exactly at the result.
//
// The verbatim re-emit this used to do was a no-op with a cost. The clones
// were textually identical expressions over the same operands, which is
// precisely what EarlyCSE and GVN exist to merge, and both run after this
// pass on the OptimizerLast extension point. The file header described the
// masking as if it were implemented; the RNG parameter was spelled
// `/*RNG*/`.
//
// One exact identity per opcode, all in modular arithmetic so they hold for
// every mask:
//
//   a + b  ==  ((a + m) + b) - m
//   a - b  ==  ((a + m) - b) - m
//   a * b  ==  ((a + m) * b) - (m * b)
//   a & b  ==  ((a ^ m) & b) ^ (m & b)
//   a | b  ==  ((a ^ m) | b) ^ (m & ~b)
//   a ^ b  ==  ((a ^ m) ^ b) ^ m
//
// nuw/nsw/exact are deliberately NOT copied onto these. The intermediates
// legitimately wrap — that is what makes the identity hold — so carrying a
// no-wrap promise onto them would make the value poison and hand the
// optimiser a licence to delete the whole chain. Dropping the flags only
// costs optimisation on the clone; the original keeps them.
static Value *cloneAt(BinaryOperator *BO, Instruction *InsertPt, PRNG &RNG) {
  IRBuilder<> B(InsertPt);
  Type  *Ty = BO->getType();
  Value *L  = BO->getOperand(0);
  Value *R  = BO->getOperand(1);

  auto *M = ConstantInt::get(
      Ty, randomForWidth(RNG, Ty->getIntegerBitWidth()));

  switch (BO->getOpcode()) {
  case Instruction::Add: {
    Value *T = B.CreateAdd(B.CreateAdd(L, M, "cse.mask"), R, "cse.break");
    return B.CreateSub(T, M, "cse.unmask");
  }
  case Instruction::Sub: {
    Value *T = B.CreateSub(B.CreateAdd(L, M, "cse.mask"), R, "cse.break");
    return B.CreateSub(T, M, "cse.unmask");
  }
  case Instruction::Mul: {
    Value *T = B.CreateMul(B.CreateAdd(L, M, "cse.mask"), R, "cse.break");
    return B.CreateSub(T, B.CreateMul(M, R, "cse.corr"), "cse.unmask");
  }
  case Instruction::And: {
    Value *T = B.CreateAnd(B.CreateXor(L, M, "cse.mask"), R, "cse.break");
    return B.CreateXor(T, B.CreateAnd(M, R, "cse.corr"), "cse.unmask");
  }
  case Instruction::Or: {
    Value *T  = B.CreateOr(B.CreateXor(L, M, "cse.mask"), R, "cse.break");
    Value *Cr = B.CreateAnd(M, B.CreateNot(R, "cse.nb"), "cse.corr");
    return B.CreateXor(T, Cr, "cse.unmask");
  }
  case Instruction::Xor: {
    Value *T = B.CreateXor(B.CreateXor(L, M, "cse.mask"), R, "cse.break");
    return B.CreateXor(T, M, "cse.unmask");
  }
  default:
    // isEligible() admits only the six above.
    llvm_unreachable("unhandled opcode in cloneAt");
  }
}

static bool breakCSEInFunction(Function &F, PRNG &RNG) {
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
      Value *Clone = cloneAt(BO, UserI, RNG);
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
