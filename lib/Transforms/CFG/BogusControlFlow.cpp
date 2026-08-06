//===-- BogusControlFlow.cpp - Bogus control flow with MBA predicates -----===//
//
// Injects dead basic blocks guarded by opaque predicates that are always true
// but difficult to evaluate statically or symbolically.
//
// Unlike DeClang (which uses FCMP_TRUE — trivially solved by any solver),
// we use Mixed Boolean-Arithmetic (MBA) predicates.  Multiple variants are
// implemented and selected at random to defeat static pattern matching:
//
//   (x | ~x) == -1           (always true — OR complement)
//   (x ^ ~x) == -1           (always true — XOR complement)
//   (x + ~x) == -1           (always true — ADD complement, i.e. x + (-x-1))
//   (x * (x+1)) & 1 == 0     (always true — product of consecutive ints is even)
//   ((x | 1) & 1) == 1       (always true — any number OR 1 is odd)
//   (x * (x-1)) & 1 == 0     (always true — product of consecutive ints is even)
//   ((x >> 1) << 1) | (x & 1) == x  (always true — bit round-trip identity)
//
// The "true" branch executes the original block; the "false" branch contains
// a semantically equivalent but junk-filled copy (never actually taken).
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

using namespace llvm;

namespace kagura {

// ---- Opaque predicate builders ----

// Normalise X to i32 for predicate construction.
static Value *toI32(IRBuilder<> &B, Value *X, uint32_t FallbackConst) {
  auto *I32 = Type::getInt32Ty(B.getContext());
  if (X->getType() == I32)
    return X;
  if (X->getType()->isIntegerTy())
    return B.CreateZExtOrTrunc(X, I32, "bcf.cast");
  return ConstantInt::get(I32, FallbackConst);
}

// Predicate 0: (V | ~V) == -1   (OR complement — always true)
static Value *buildPred0(IRBuilder<> &B, Value *X) {
  Value *V    = toI32(B, X, 0x12345678);
  auto *I32   = Type::getInt32Ty(B.getContext());
  Value *NotV = B.CreateNot(V, "bcf.notv");
  Value *OrV  = B.CreateOr(V, NotV, "bcf.or");
  return B.CreateICmpEQ(OrV, ConstantInt::get(I32, ~0U), "bcf.pred");
}

// Predicate 1: (V ^ ~V) == -1   (XOR complement — always true)
static Value *buildPred1(IRBuilder<> &B, Value *X) {
  Value *V    = toI32(B, X, 0xABCDEF01);
  auto *I32   = Type::getInt32Ty(B.getContext());
  Value *NotV = B.CreateNot(V, "bcf.notv");
  Value *XorV = B.CreateXor(V, NotV, "bcf.xor");
  return B.CreateICmpEQ(XorV, ConstantInt::get(I32, ~0U), "bcf.pred");
}

// Predicate 2: (V + ~V) == -1   (ADD complement: V + (-V-1) == -1 always)
static Value *buildPred2(IRBuilder<> &B, Value *X) {
  Value *V    = toI32(B, X, 0xFEDCBA98);
  auto *I32   = Type::getInt32Ty(B.getContext());
  Value *NotV = B.CreateNot(V, "bcf.notv");
  Value *Sum  = B.CreateAdd(V, NotV, "bcf.add");
  return B.CreateICmpEQ(Sum, ConstantInt::get(I32, ~0U), "bcf.pred");
}

// Predicate 3: (V * (V+1)) & 1 == 0   (product of consecutive ints is even)
static Value *buildPred3(IRBuilder<> &B, Value *X) {
  Value *V    = toI32(B, X, 0x13579BDF);
  auto *I32   = Type::getInt32Ty(B.getContext());
  Value *Vp1  = B.CreateAdd(V, ConstantInt::get(I32, 1), "bcf.vp1");
  Value *Prod = B.CreateMul(V, Vp1, "bcf.mul");
  Value *And1 = B.CreateAnd(Prod, ConstantInt::get(I32, 1), "bcf.and");
  return B.CreateICmpEQ(And1, ConstantInt::get(I32, 0), "bcf.pred");
}

// Predicate 4: (V * (V-1)) & 1 == 0   (same: n*(n-1) is also always even)
static Value *buildPred4(IRBuilder<> &B, Value *X) {
  Value *V    = toI32(B, X, 0x2468ACE0);
  auto *I32   = Type::getInt32Ty(B.getContext());
  Value *Vm1  = B.CreateSub(V, ConstantInt::get(I32, 1), "bcf.vm1");
  Value *Prod = B.CreateMul(V, Vm1, "bcf.mul");
  Value *And1 = B.CreateAnd(Prod, ConstantInt::get(I32, 1), "bcf.and");
  return B.CreateICmpEQ(And1, ConstantInt::get(I32, 0), "bcf.pred");
}

// Predicate 5: (V | 1) & 1 == 1   (OR with 1 is always odd)
static Value *buildPred5(IRBuilder<> &B, Value *X) {
  Value *V    = toI32(B, X, 0x11223344);
  auto *I32   = Type::getInt32Ty(B.getContext());
  Value *Or1  = B.CreateOr(V, ConstantInt::get(I32, 1), "bcf.or1");
  Value *And1 = B.CreateAnd(Or1, ConstantInt::get(I32, 1), "bcf.and");
  return B.CreateICmpEQ(And1, ConstantInt::get(I32, 1), "bcf.pred");
}

// Predicate 6: ((V >> 1) << 1) | (V & 1) == V   (bit round-trip identity)
static Value *buildPred6(IRBuilder<> &B, Value *X) {
  Value *V    = toI32(B, X, 0x55AA55AA);
  auto *I32   = Type::getInt32Ty(B.getContext());
  Value *Shr  = B.CreateLShr(V, ConstantInt::get(I32, 1), "bcf.shr");
  Value *Shl  = B.CreateShl(Shr, ConstantInt::get(I32, 1), "bcf.shl");
  Value *Lo   = B.CreateAnd(V, ConstantInt::get(I32, 1), "bcf.lo");
  Value *Rec  = B.CreateOr(Shl, Lo, "bcf.rec");
  return B.CreateICmpEQ(Rec, V, "bcf.pred");
}

using PredicateBuilder = Value *(*)(IRBuilder<> &, Value *);
static constexpr PredicateBuilder kTruePredicates[] = {
    buildPred0, buildPred1, buildPred2, buildPred3,
    buildPred4, buildPred5, buildPred6,
};
static constexpr unsigned kNumTruePredicates =
    sizeof(kTruePredicates) / sizeof(kTruePredicates[0]);

// Select a predicate at random and build it.
static Value *buildMBAOpaqueTrue(IRBuilder<> &B, Value *X, PRNG &RNG) {
  unsigned Idx = static_cast<unsigned>(RNG.nextRange(0, kNumTruePredicates));
  return kTruePredicates[Idx](B, X);
}

// Pick a "random" existing integer value from the block (first int SSA value).
static Value *pickIntValue(BasicBlock *BB) {
  for (auto &I : *BB)
    if (I.getType()->isIntegerTy() && !isa<PHINode>(&I))
      return &I;
  // Fallback: use a constant
  return ConstantInt::get(Type::getInt32Ty(BB->getContext()), 0xCAFEBABE);
}

// Make a rough clone of BB (only copy non-terminator instructions with junk).
static BasicBlock *makeBogusClone(BasicBlock *BB, Function *F) {
  LLVMContext &Ctx = F->getContext();
  auto *Clone = BasicBlock::Create(Ctx, "bcf.bogus", F);
  IRBuilder<> B(Clone);

  // Copy instructions but replace operands with undef to create junk
  for (auto &I : *BB) {
    if (I.isTerminator())
      continue;
    if (isa<PHINode>(&I))
      continue;
    // Simple junk: just add a nop integer op
    if (I.getType()->isIntegerTy(32)) {
      auto *Undef = UndefValue::get(I.getType());
      B.CreateAdd(Undef, ConstantInt::get(I.getType(), 1), "bcf.junk");
    }
  }
  // Bogus block loops back into itself (never actually entered)
  // Note: use unreachable rather than self-loop to avoid interfering with
  // existing loop structures (e.g., CFG flattening's loop header).
  B.CreateUnreachable();
  return Clone;
}

static bool insertBogusFlow(Function &F, uint32_t Probability,
                              uint32_t Iterations, PRNG &RNG) {
  if (F.isDeclaration() || F.size() < 2)
    return false;

  bool Changed = false;

  for (uint32_t Iter = 0; Iter < Iterations; ++Iter) {
    auto Blocks = getBlocks(F);

    for (auto *BB : Blocks) {
      if (RNG.nextRange(0, 100) >= Probability)
        continue;
      if (BB->getTerminator() == nullptr)
        continue;
      // Don't inject into blocks ending with InvokeInst
      if (isa<InvokeInst>(BB->getTerminator()))
        continue;
      // Don't inject into kagura's own dispatcher/loop blocks
      if (BB->getName().starts_with("kagura."))
        continue;
      // Don't inject into blocks with SwitchInst (flattening dispatcher)
      if (isa<SwitchInst>(BB->getTerminator()))
        continue;

      // Split BB at the first non-PHI / non-debug instruction
      BasicBlock::iterator SplitPoint = BB->getFirstNonPHIOrDbgOrAlloca();
      if (SplitPoint == BB->end())
        continue;

      BasicBlock *OrigTail = BB->splitBasicBlock(SplitPoint, "bcf.orig");

      // Create bogus clone (junk block that loops to itself)
      BasicBlock *BogusBlock = makeBogusClone(OrigTail, &F);

      // Replace BB's unconditional branch with:
      //   if (MBA_opaque_true)  jump OrigTail
      //   else                  jump BogusBlock
      Instruction *OldTerm = BB->getTerminator();
      IRBuilder<> B(OldTerm);
      Value *X    = pickIntValue(BB);
      Value *Cond = buildMBAOpaqueTrue(B, X, RNG);
      B.CreateCondBr(Cond, OrigTail, BogusBlock);
      OldTerm->eraseFromParent();

      Changed = true;
    }
  }

  return Changed;
}

PreservedAnalyses BogusControlFlowPass::run(Function &F,
                                             FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "bcf"))
    return PreservedAnalyses::all();
  auto &RNG    = getModulePRNG();
  bool Changed = insertBogusFlow(F, Probability, Iterations, RNG);
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
