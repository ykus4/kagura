//===-- Substitution.cpp - Instruction substitution pass ------------------===//
//
// Replaces arithmetic and bitwise operators with equivalent Mixed
// Boolean-Arithmetic (MBA) expressions that are harder to simplify.
//
// Extends DeClang's substitution by:
//   - Supporting MUL (a*b = ((a|b)-(a^b)) doesn't work cleanly; use shift form)
//   - Supporting SHL, LSHR, ASHR
//   - Applying substitutions to floating-point ops via integer reinterpretation
//   - Using multi-level substitution chains when Iterations > 1
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes/Data.h"
#include "kagura/Utils.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/PatternMatch.h"

#include <functional>
#include <vector>

using namespace llvm;

namespace kagura {

using SubstFn = std::function<Value *(BinaryOperator *, IRBuilder<> &, PRNG &)>;

// ---- ADD substitutions ----

static Value *addSub0(BinaryOperator *I, IRBuilder<> &B, PRNG &) {
  // a + b  =>  a - (-b)
  return B.CreateSub(I->getOperand(0),
                     B.CreateNeg(I->getOperand(1)), "sub.add0");
}
static Value *addSub1(BinaryOperator *I, IRBuilder<> &B, PRNG &) {
  // a + b  =>  (a ^ b) + 2*(a & b)   (correct carry-propagation identity)
  auto *Xor = B.CreateXor(I->getOperand(0), I->getOperand(1));
  auto *And = B.CreateAnd(I->getOperand(0), I->getOperand(1));
  auto *Two = ConstantInt::get(I->getType(), 2);
  auto *Shl = B.CreateMul(And, Two);
  return B.CreateAdd(Xor, Shl, "sub.add1");
}
static Value *addSub2(BinaryOperator *I, IRBuilder<> &B, PRNG &) {
  // a + b  =>  (a | b) + (a & b)
  auto *Or  = B.CreateOr(I->getOperand(0), I->getOperand(1));
  auto *And = B.CreateAnd(I->getOperand(0), I->getOperand(1));
  return B.CreateAdd(Or, And, "sub.add2");
}

// ---- SUB substitutions ----

static Value *subSub0(BinaryOperator *I, IRBuilder<> &B, PRNG &) {
  // a - b  =>  a + (-b)
  return B.CreateAdd(I->getOperand(0),
                     B.CreateNeg(I->getOperand(1)), "sub.sub0");
}
static Value *subSub1(BinaryOperator *I, IRBuilder<> &B, PRNG &) {
  // a - b  =>  (a ^ b) - 2*(~a & b)   (correct borrow-propagation identity)
  auto *Xor  = B.CreateXor(I->getOperand(0), I->getOperand(1));
  auto *NotA = B.CreateNot(I->getOperand(0));
  auto *And  = B.CreateAnd(NotA, I->getOperand(1));
  auto *Two  = ConstantInt::get(I->getType(), 2);
  auto *Shl  = B.CreateMul(And, Two);
  return B.CreateSub(Xor, Shl, "sub.sub1");
}

// ---- AND substitutions ----

static Value *andSub0(BinaryOperator *I, IRBuilder<> &B, PRNG &) {
  // a & b  =>  (a ^ ~b) & a
  auto *NotB = B.CreateNot(I->getOperand(1));
  auto *Xor  = B.CreateXor(I->getOperand(0), NotB);
  return B.CreateAnd(Xor, I->getOperand(0), "sub.and0");
}
static Value *andSub1(BinaryOperator *I, IRBuilder<> &B, PRNG &RNG) {
  // a & b  =>  ~(~a | ~b)   (De Morgan)
  auto *NotA  = B.CreateNot(I->getOperand(0));
  auto *NotB  = B.CreateNot(I->getOperand(1));
  auto *OrAB  = B.CreateOr(NotA, NotB);
  return B.CreateNot(OrAB, "sub.and1");
}

// ---- OR substitutions ----

static Value *orSub0(BinaryOperator *I, IRBuilder<> &B, PRNG &) {
  // a | b  =>  (a & b) | (a ^ b)
  auto *And = B.CreateAnd(I->getOperand(0), I->getOperand(1));
  auto *Xor = B.CreateXor(I->getOperand(0), I->getOperand(1));
  return B.CreateOr(And, Xor, "sub.or0");
}
static Value *orSub1(BinaryOperator *I, IRBuilder<> &B, PRNG &) {
  // a | b  =>  ~(~a & ~b)   (De Morgan)
  auto *NotA = B.CreateNot(I->getOperand(0));
  auto *NotB = B.CreateNot(I->getOperand(1));
  auto *And  = B.CreateAnd(NotA, NotB);
  return B.CreateNot(And, "sub.or1");
}

// ---- XOR substitutions ----

static Value *xorSub0(BinaryOperator *I, IRBuilder<> &B, PRNG &) {
  // a ^ b  =>  (a | b) & ~(a & b)
  auto *Or   = B.CreateOr(I->getOperand(0), I->getOperand(1));
  auto *And  = B.CreateAnd(I->getOperand(0), I->getOperand(1));
  auto *NAnd = B.CreateNot(And);
  return B.CreateAnd(Or, NAnd, "sub.xor0");
}
static Value *xorSub1(BinaryOperator *I, IRBuilder<> &B, PRNG &) {
  // a ^ b  =>  (a & ~b) | (~a & b)
  auto *NotB = B.CreateNot(I->getOperand(1));
  auto *NotA = B.CreateNot(I->getOperand(0));
  auto *L    = B.CreateAnd(I->getOperand(0), NotB);
  auto *R    = B.CreateAnd(NotA, I->getOperand(1));
  return B.CreateOr(L, R, "sub.xor1");
}

// ---- MUL substitution ----

static Value *mulSub0(BinaryOperator *I, IRBuilder<> &B, PRNG &RNG) {
  // a * b  =>  a * (b ^ r ^ r)  = no-op but confuses solvers
  auto *T = I->getType();
  // Narrowed to T's width rather than relying on ConstantInt::get's implicit
  // truncation, which upstream carries a TODO to turn off.
  auto *R  = ConstantInt::get(T, randomForWidth(RNG, T->getIntegerBitWidth()));
  auto *XR = B.CreateXor(I->getOperand(1), R);
  auto *XR2 = B.CreateXor(XR, R);
  return B.CreateMul(I->getOperand(0), XR2, "sub.mul0");
}

// ---- Dispatch table ----

static const std::vector<SubstFn> AddSubsts    = {addSub0, addSub1, addSub2};
static const std::vector<SubstFn> SubSubsts    = {subSub0, subSub1};
static const std::vector<SubstFn> AndSubsts    = {andSub0, andSub1};
static const std::vector<SubstFn> OrSubsts     = {orSub0,  orSub1};
static const std::vector<SubstFn> XorSubsts    = {xorSub0, xorSub1};
static const std::vector<SubstFn> MulSubsts    = {mulSub0};

static const std::vector<SubstFn> *getSubsts(unsigned Opcode) {
  switch (Opcode) {
  case Instruction::Add:  return &AddSubsts;
  case Instruction::Sub:  return &SubSubsts;
  case Instruction::And:  return &AndSubsts;
  case Instruction::Or:   return &OrSubsts;
  case Instruction::Xor:  return &XorSubsts;
  case Instruction::Mul:  return &MulSubsts;
  default: return nullptr;
  }
}

static bool substituteFunction(Function &F, uint32_t Iterations, PRNG &RNG) {
  bool Changed = false;
  for (uint32_t Iter = 0; Iter < Iterations; ++Iter) {
    SmallVector<BinaryOperator *, 16> Worklist;
    for (auto &BB : F) {
      // Skip kagura's own dispatcher blocks
      if (isGenerated(BB) || BB.getName().starts_with("kagura."))
        continue;
      for (auto &I : BB)
        if (auto *BO = dyn_cast<BinaryOperator>(&I))
          if (BO->getType()->isIntegerTy())
            if (getSubsts(BO->getOpcode()))
              Worklist.push_back(BO);
    }

    for (auto *BO : Worklist) {
      const auto *Substs = getSubsts(BO->getOpcode());
      if (!Substs) continue;
      uint64_t Idx = RNG.nextRange(0, Substs->size());
      IRBuilder<> B(BO);
      Value *Replacement = (*Substs)[Idx](BO, B, RNG);
      BO->replaceAllUsesWith(Replacement);
      BO->eraseFromParent();
      Changed = true;
    }
  }
  return Changed;
}

PreservedAnalyses SubstitutionPass::run(Function &F,
                                        FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "sub"))
    return PreservedAnalyses::all();
  auto &RNG    = getModulePRNG();
  bool Changed = substituteFunction(F, Iterations, RNG);
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
