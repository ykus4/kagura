//===-- LoopTransform.cpp - Loop obfuscation transformations ---------------===//
//
// Applies several transformations to natural loops to complicate loop analysis
// by static analysis tools and decompilers:
//
//   1. Loop rotation bogus — inserts a dead counting variable in each latch
//      block that increments every iteration but is never read.  At analysis
//      time the variable looks like a loop-carried dependency, making it harder
//      to determine the actual trip count.
//
//   2. Invariant injection — inserts an opaque MBA dead-branch guard in the
//      loop preheader.  The predicate `(x | ~x) != -1` is always false, so the
//      branch is never taken, but solvers cannot trivially prove this.
//
//   3. Loop counter splitting — when a loop has a simple integer induction
//      variable `i`, replaces it with two 32-bit halves `i_low` and `i_high`
//      recombined as `i = i_low | (i_high << 32)`.  Forces any downstream
//      analysis to reason about the split representation.
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/CFG.h"
#include "kagura/Utils.h"

#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

using namespace llvm;

namespace kagura {

// ---- Helpers ----------------------------------------------------------------

/// Pick a representative integer Value* visible at the start of BB.
/// Prefers the first non-PHI integer instruction; falls back to a constant.
static Value *pickIntValue(BasicBlock *BB, IRBuilder<> &B) {
  for (auto &I : *BB)
    if (I.getType()->isIntegerTy() && !isa<PHINode>(&I))
      return &I;
  return ConstantInt::get(Type::getInt32Ty(BB->getContext()), 0xCAFEBABE);
}

/// Build an opaque false predicate: `(V | ~V) != -1`
/// Always evaluates to false but is expressed as non-trivial MBA so that
/// symbolic solvers cannot immediately constant-fold it.
static Value *buildOpaqueFalse(IRBuilder<> &B, Value *X) {
  LLVMContext &Ctx = B.getContext();
  auto *I32 = Type::getInt32Ty(Ctx);
  Value *V  = X;
  if (V->getType() != I32) {
    if (V->getType()->isIntegerTy())
      V = B.CreateZExtOrTrunc(V, I32, "lt.cast");
    else
      V = ConstantInt::get(I32, 0xDEADBEEF);
  }
  Value *NotV    = B.CreateNot(V, "lt.notv");
  Value *OrV     = B.CreateOr(V, NotV, "lt.or");
  Value *MinusOne = ConstantInt::get(I32, ~0U);
  // (V | ~V) is always -1, so this compare is always false.
  return B.CreateICmpNE(OrV, MinusOne, "lt.opaque");
}

// ---- Transformation 1: bogus counter in latch ------------------------------

/// Insert a dead alloca+load+add+store sequence in the latch block of L.
/// The counter is only ever written — never read after the store — which means
/// optimisers are free to remove it, but dynamic / taint-based analysis tools
/// will see a live counter variable and waste time tracking it.
static bool insertBogusCounter(Loop *L, IRBuilder<> &EntryB, PRNG &RNG) {
  BasicBlock *Latch = L->getLoopLatch();
  if (!Latch)
    return false;

  // Create an alloca in the function entry block so it is stack-allocated once.
  auto *CounterAlloca = EntryB.CreateAlloca(
      EntryB.getInt64Ty(), nullptr,
      "lt.bogus" + std::to_string(RNG.next32() & 0xFFFF));

  // Initialise to 0 right after the alloca.
  EntryB.CreateStore(EntryB.getInt64(0), CounterAlloca);

  // In the latch: load, increment, store.
  Instruction *LatchTerm = Latch->getTerminator();
  IRBuilder<> LatchB(LatchTerm);
  Value *OldVal = LatchB.CreateLoad(LatchB.getInt64Ty(), CounterAlloca,
                                    "lt.bogus.load");
  Value *NewVal =
      LatchB.CreateAdd(OldVal, LatchB.getInt64(1), "lt.bogus.inc");
  LatchB.CreateStore(NewVal, CounterAlloca);

  return true;
}

// ---- Transformation 2: opaque invariant in preheader -----------------------

/// Insert a dead conditional branch guarded by an opaque false predicate into
/// the loop preheader.  The false-branch target is an unreachable block, so
/// execution is never redirected; the predicate just adds noise to CFG analysis.
static bool insertOpaqueInvariant(Loop *L, Function *F) {
  BasicBlock *Preheader = L->getLoopPreheader();
  if (!Preheader)
    return false;

  // We will split the preheader just before its terminator and insert the
  // opaque branch between the two halves.
  Instruction *Term = Preheader->getTerminator();
  IRBuilder<> B(Term);

  Value *X    = pickIntValue(Preheader, B);
  Value *Cond = buildOpaqueFalse(B, X);

  // Create an unreachable sink block for the false branch.
  LLVMContext &Ctx = F->getContext();
  auto *DeadBB = BasicBlock::Create(Ctx, "lt.dead", F);
  IRBuilder<> DeadB(DeadBB);
  DeadB.CreateUnreachable();

  // The original terminator of the preheader already branches to the loop
  // header.  We want:
  //   if (opaque_false) -> DeadBB   (never taken)
  //   else              -> original successor (loop header)
  //
  // Grab the existing successor (loop header) from the original branch before
  // we erase it.
  BasicBlock *Header = L->getHeader();

  // Replace the unconditional branch with a conditional one.
  B.CreateCondBr(Cond, DeadBB, Header);
  Term->eraseFromParent();

  return true;
}

// ---- Transformation 3: loop counter splitting ------------------------------

/// If L has a single integer induction variable `i` driven by a PHI node of
/// the form `phi [init, preheader], [i+step, latch]`, replace it with two
/// 32-bit halves and recombine via `i = i_low | (i_high << 32)`.
///
/// After splitting all uses of the original phi are replaced with the combined
/// 64-bit value, making the induction variable appear as two separate counters
/// to simple pattern-matching analyses.
static bool splitLoopCounter(Loop *L, IRBuilder<> &EntryB) {
  BasicBlock *Header  = L->getHeader();
  BasicBlock *Latch   = L->getLoopLatch();
  BasicBlock *Preheader = L->getLoopPreheader();

  if (!Latch || !Preheader)
    return false;

  // Find a PHI node that looks like a simple integer induction variable:
  // phi [ C, Preheader ], [ phi + Step, Latch ]
  PHINode *IndVar = nullptr;
  BinaryOperator *StepInst = nullptr;

  for (auto &Phi : Header->phis()) {
    if (!Phi.getType()->isIntegerTy(64) && !Phi.getType()->isIntegerTy(32))
      continue;
    if (Phi.getNumIncomingValues() != 2)
      continue;

    // One incoming must be from preheader (init), the other from latch (step).
    int PreIdx  = Phi.getBasicBlockIndex(Preheader);
    int LatchIdx = Phi.getBasicBlockIndex(Latch);
    if (PreIdx == -1 || LatchIdx == -1)
      continue;

    Value *LatchVal = Phi.getIncomingValue(LatchIdx);
    auto *BO = dyn_cast<BinaryOperator>(LatchVal);
    if (!BO)
      continue;
    if (BO->getOpcode() != Instruction::Add)
      continue;
    // One operand of the add must be the phi itself.
    if (BO->getOperand(0) != &Phi && BO->getOperand(1) != &Phi)
      continue;

    IndVar   = &Phi;
    StepInst = BO;
    break;
  }

  if (!IndVar || !StepInst)
    return false;

  // Only handle 64-bit induction variables (most natural for splitting).
  // 32-bit phis are widened to 64 bit first.
  LLVMContext &Ctx  = Header->getContext();
  auto *I32 = Type::getInt32Ty(Ctx);
  auto *I64 = Type::getInt64Ty(Ctx);

  // Determine init value from preheader incoming.
  int PreIdx  = IndVar->getBasicBlockIndex(Preheader);
  Value *Init = IndVar->getIncomingValue(PreIdx);

  // Determine step value.
  Value *Step = (StepInst->getOperand(0) == IndVar) ? StepInst->getOperand(1)
                                                      : StepInst->getOperand(0);

  // The recombination sequence is emitted at the top of the header, so `Step`
  // has to be available there.  Constants and arguments always are; an
  // instruction only is when it is defined outside the loop (a value defined
  // outside a natural loop but used inside it necessarily dominates the
  // header).  A step computed inside the loop — e.g. in the latch — would not
  // dominate the new use, so bail out before emitting anything rather than
  // producing IR that fails the dominance check.
  if (auto *StepInstr = dyn_cast<Instruction>(Step))
    if (L->contains(StepInstr->getParent()))
      return false;

  // The header must have a position where non-PHI instructions may live; a
  // header that is an EH pad cannot host the recombination sequence.
  BasicBlock::iterator HeaderInsertPt = Header->getFirstInsertionPt();
  if (HeaderInsertPt == Header->end())
    return false;

  // Ensure init is i64.
  IRBuilder<> PreB(Preheader->getTerminator());
  Value *Init64 = Init->getType()->isIntegerTy(64)
                      ? Init
                      : PreB.CreateZExt(Init, I64, "lt.init64");

  // Split init into low/high halves.
  Value *InitLow  = PreB.CreateTrunc(Init64, I32, "lt.init_low");
  Value *InitHigh = PreB.CreateTrunc(
      PreB.CreateLShr(Init64, ConstantInt::get(I64, 32)), I32, "lt.init_high");

  // Insert PHI nodes for i_low and i_high at the very top of the header.
  //
  // Built through IRBuilder rather than PHINode::Create + insertBefore: the
  // Instruction* overload of insertBefore is deprecated from LLVM 18 on, and
  // the iterator overload that replaces it does not exist in 17. Positioning
  // the builder avoids needing either.
  IRBuilder<> HeadB(Header, Header->begin());
  auto *PhiLow  = HeadB.CreatePHI(I32, 2, "lt.i_low");
  auto *PhiHigh = HeadB.CreatePHI(I32, 2, "lt.i_high");

  PhiLow->addIncoming(InitLow,  Preheader);
  PhiHigh->addIncoming(InitHigh, Preheader);

  // Recombine: i = i_low | (i_high << 32).
  //
  // This must be emitted after *every* PHI in the header, not merely after the
  // two we just created: `PhiHigh->getNextNode()` is normally the original
  // induction PHI (and any other header PHIs), so anchoring the builder there
  // interleaves non-PHI instructions with the remaining PHIs and yields
  // "PHI nodes not grouped at top of basic block".  HeaderInsertPt was taken
  // before the new PHIs were inserted and still points at the first non-PHI
  // instruction of the header.
  IRBuilder<> CombineB(Header, HeaderInsertPt);
  Value *HighExt  = CombineB.CreateZExt(PhiHigh, I64, "lt.high_ext");
  Value *HighShl  = CombineB.CreateShl(HighExt, ConstantInt::get(I64, 32),
                                        "lt.high_shl");
  Value *LowExt   = CombineB.CreateZExt(PhiLow, I64, "lt.low_ext");
  Value *Combined = CombineB.CreateOr(LowExt, HighShl, "lt.combined");

  // Step must be i64 for the arithmetic on Combined.
  Value *Step64 = Step->getType()->isIntegerTy(64)
                      ? Step
                      : CombineB.CreateZExt(Step, I64, "lt.step64");
  Value *NextCombined =
      CombineB.CreateAdd(Combined, Step64, "lt.combined_next");

  // Split the updated combined value back into halves for the latch back-edge.
  IRBuilder<> LatchSplitB(Latch->getTerminator());
  Value *NextLow  = LatchSplitB.CreateTrunc(NextCombined, I32, "lt.next_low");
  Value *NextHigh = LatchSplitB.CreateTrunc(
      LatchSplitB.CreateLShr(NextCombined, ConstantInt::get(I64, 32)),
      I32, "lt.next_high");

  PhiLow->addIncoming(NextLow,   Latch);
  PhiHigh->addIncoming(NextHigh, Latch);

  // Replace all uses of the original PHI with the recombined value.
  // The original phi and its step instruction will become dead.
  Value *Replacement = Combined;
  if (IndVar->getType() != I64)
    Replacement = CombineB.CreateTrunc(Combined, IndVar->getType(), "lt.trunc");

  // Replacement lives after all header PHIs, so it dominates every use the
  // original PHI could legally have had (uses in the header below the PHI
  // block, uses in blocks the header dominates, and PHI uses whose incoming
  // block is dominated by the header).
  IndVar->replaceAllUsesWith(Replacement);

  // Remove the now-unused original PHI and, if nothing else referenced it, its
  // step instruction.  The PHI has to go first: it is the (sole remaining) user
  // of the step instruction via its latch incoming value.
  if (IndVar->use_empty())
    IndVar->eraseFromParent();
  if (StepInst->use_empty())
    StepInst->eraseFromParent();

  return true;
}

// ---- Pass entry point -------------------------------------------------------

static bool obfuscateLoop(Loop *L, Function &F,
                           IRBuilder<> &EntryB, PRNG &RNG,
                           bool DoCounter, bool DoInvariant, bool DoSplit) {
  bool Changed = false;

  if (DoCounter)
    Changed |= insertBogusCounter(L, EntryB, RNG);
  if (DoInvariant)
    Changed |= insertOpaqueInvariant(L, &F);
  if (DoSplit)
    Changed |= splitLoopCounter(L, EntryB);

  // Recurse into sub-loops.
  for (Loop *Sub : L->getSubLoops())
    Changed |= obfuscateLoop(Sub, F, EntryB, RNG, DoCounter, DoInvariant,
                              DoSplit);

  return Changed;
}

PreservedAnalyses LoopTransformPass::run(Function &F,
                                          FunctionAnalysisManager &FAM) {
  if (!shouldObfuscate(F, "lt"))
    return PreservedAnalyses::all();
  if (F.isDeclaration())
    return PreservedAnalyses::all();
  // 4.1.10: Loop transformations that insert new blocks or modify the
  // preheader can break EH unwind tables if landing pads are present.
  if (hasExceptionHandling(F))
    return PreservedAnalyses::all();

  auto &LI  = FAM.getResult<LoopAnalysis>(F);
  auto &RNG = getModulePRNG(*F.getParent());

  if (LI.empty())
    return PreservedAnalyses::all();

  // All allocas for bogus counters go into the entry block.
  Instruction *EntryInsertPt = &*F.getEntryBlock().getFirstInsertionPt();
  IRBuilder<> EntryB(EntryInsertPt);

  // Randomly enable each sub-transformation per invocation so that not every
  // loop in every function gets the exact same treatment.
  bool DoCounter  = (RNG.nextRange(0, 100) < 80); // 80 % chance
  bool DoInvariant = (RNG.nextRange(0, 100) < 60); // 60 % chance
  bool DoSplit    = (RNG.nextRange(0, 100) < 40); // 40 % chance

  bool Changed = false;
  for (Loop *L : LI)
    Changed |= obfuscateLoop(L, F, EntryB, RNG, DoCounter, DoInvariant,
                              DoSplit);

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
