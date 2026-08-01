//===-- ConstantObfuscation.cpp - Integer/float constant MBA obfuscation --===//
//
// Replaces integer and floating-point constant operands with equivalent
// computations that are harder to reason about statically.
//
// Integer MBA identities (for 32/64-bit integers, value V):
//   1. V  =>  (V ^ R) ^ R                     (double XOR with random R)
//   2. V  =>  (V + R) - R                     (add/sub with random R)
//   3. V  =>  ((V | ~V) & V)                  (identity via tautology)
//   4. V  =>  (V * R) * modular_inverse(R)    (multiplicative, R must be odd)
//
// 4.2.9: Float/double constant obfuscation:
//   Float F  =>  bitcast( bitcast(F) ^ R ^ R )  (XOR through integer domain)
//   Double D =>  bitcast( bitcast(D) ^ R ^ R )  (same idea for 64-bit)
//
// Each constant is replaced with a randomly chosen identity.
// Only replaces constants in user functions, not in kagura's own helpers.
//
// NOTE: every identity below is built from an operand that is itself a
// constant, so the builder MUST NOT constant-fold.  The default IRBuilder<>
// uses ConstantFolder, which evaluates e.g. (V ^ R) ^ R straight back to V and
// hands the original ConstantInt back — setOperand() then stores the value that
// was already there and the pass silently becomes a no-op.  IRBuilder<NoFolder>
// emits the instructions verbatim, which is the whole point of the pass.
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"

using namespace llvm;

namespace kagura {

// Compute modular multiplicative inverse of odd integer x mod 2^bits
// using extended Euclidean algorithm (Newton's method for 2^n).
static uint64_t modInverse(uint64_t x, unsigned bits) {
  assert(x & 1 && "x must be odd for modular inverse to exist");
  uint64_t inv = 1;
  for (unsigned i = 0; i < bits - 1; ++i)
    inv = inv * (2 - x * inv);
  if (bits < 64)
    inv &= (1ULL << bits) - 1;
  return inv;
}

// Replace a ConstantInt CI (used as operand OpIdx in instruction I) with an
// MBA expression that evaluates to the same value.
static bool obfuscateConstant(Instruction *I, unsigned OpIdx,
                               ConstantInt *CI, PRNG &RNG) {
  // Only handle i8..i64
  unsigned Bits = CI->getBitWidth();
  if (Bits < 8 || Bits > 64)
    return false;

  // Skip zero and all-ones (they appear in many structural patterns)
  uint64_t Val = CI->getZExtValue();
  if (Val == 0 || Val == ((Bits == 64) ? ~0ULL : (1ULL << Bits) - 1))
    return false;

  IRBuilder<NoFolder> B(I);
  Type *Ty = CI->getType();

  // Pick a random identity transformation
  uint32_t Choice = RNG.next32() % 4;
  Value *Result = nullptr;

  switch (Choice) {
  case 0: {
    // (V ^ R) ^ R
    uint64_t R = RNG.next() & ((Bits == 64) ? ~0ULL : (1ULL << Bits) - 1);
    auto *RC  = ConstantInt::get(Ty, R);
    auto *Xor1 = B.CreateXor(CI, RC, "co.xr1");
    Result     = B.CreateXor(Xor1, RC, "co.xr2");
    break;
  }
  case 1: {
    // (V + R) - R
    uint64_t R = RNG.next() & ((Bits == 64) ? ~0ULL : (1ULL << Bits) - 1);
    auto *RC   = ConstantInt::get(Ty, R);
    auto *Add  = B.CreateAdd(CI, RC, "co.ar1");
    Result     = B.CreateSub(Add, RC, "co.ar2");
    break;
  }
  case 2: {
    // ((V | ~V) & V)  — always == V since (V | ~V) == all-ones
    auto *NotV = B.CreateNot(CI, "co.notv");
    auto *Or   = B.CreateOr(CI, NotV, "co.or");
    Result     = B.CreateAnd(Or, CI, "co.and");
    break;
  }
  case 3: {
    // (V * R) * R_inv   where R is a random odd number
    uint64_t Mask  = (Bits == 64) ? ~0ULL : (1ULL << Bits) - 1;
    uint64_t R     = (RNG.next() | 1) & Mask; // force odd
    uint64_t RInv  = modInverse(R, Bits) & Mask;
    auto *RC       = ConstantInt::get(Ty, R);
    auto *RInvC    = ConstantInt::get(Ty, RInv);
    auto *Mul1     = B.CreateMul(CI, RC, "co.mr1");
    Result         = B.CreateMul(Mul1, RInvC, "co.mr2");
    break;
  }
  }

  if (!Result)
    return false;

  I->setOperand(OpIdx, Result);
  return true;
}

// 4.2.9: Obfuscate a float or double constant by XOR-ing the bit representation
// with a random integer key in the integer domain, then bitcasting back.
//   float  F => bitcast_f32( bitcast_i32(F) ^ R ^ R )
// The double XOR cancels at runtime but the pattern resists naive constant
// folding in disassemblers and decompilers that don't model bitcasts.
static bool obfuscateFPConstant(Instruction *I, unsigned OpIdx,
                                 ConstantFP *CFP, PRNG &RNG) {
  LLVMContext &Ctx = I->getContext();
  Type *FTy = CFP->getType();
  bool IsDouble = FTy->isDoubleTy();
  bool IsFloat  = FTy->isFloatTy();
  if (!IsFloat && !IsDouble)
    return false;

  unsigned Bits = IsDouble ? 64 : 32;
  Type *ITy = IsDouble ? Type::getInt64Ty(Ctx) : Type::getInt32Ty(Ctx);

  uint64_t FBits = IsDouble
      ? CFP->getValueAPF().bitcastToAPInt().getZExtValue()
      : (uint64_t)CFP->getValueAPF().bitcastToAPInt().getZExtValue();

  uint64_t R = RNG.next() & ((Bits == 64) ? ~0ULL : 0xFFFFFFFFULL);

  IRBuilder<NoFolder> B(I);
  // Build: bitcast_fp( bitcast_int(FP_constant) ^ R ^ R )
  // The two XORs cancel — but the pattern is non-trivial for static analysis.
  auto *FBitsConst = ConstantInt::get(ITy, FBits);
  auto *RConst     = ConstantInt::get(ITy, R);
  auto *Xor1 = B.CreateXor(FBitsConst, RConst, "co.fxr1");
  auto *Xor2 = B.CreateXor(Xor1, RConst, "co.fxr2");
  auto *FPResult = B.CreateBitCast(Xor2, FTy, "co.fp");

  I->setOperand(OpIdx, FPResult);
  return true;
}

/// Can operand OpIdx of I be replaced by a computed value?
///
/// Several instructions require a *literal* constant in particular operand
/// slots, and the verifier rejects anything else. Replacing an operand with an
/// MBA expression there produces a module LLVM refuses to compile — which is
/// what happened once this pass started working: a `switch` case value became
/// `i8 %co.ar2` and clang aborted with "Case value is not a constant integer".
static bool operandIsReplaceable(const Instruction &I, unsigned OpIdx) {
  // A switch's case values must be ConstantInt. Only the condition (operand 0)
  // is a free-form value.
  if (isa<SwitchInst>(&I))
    return OpIdx == 0;

  // PHI incoming values belong to predecessor edges; a value computed here
  // would not dominate its use.
  if (isa<PHINode>(&I))
    return false;

  // An EH pad has to remain the first instruction of its block, so nothing can
  // be inserted in front of it.
  if (I.isEHPad())
    return false;

  // landingpad clauses must be Constants.
  if (isa<LandingPadInst>(&I))
    return false;

  // Intrinsics take immarg parameters that must be literals, and the callee
  // operand must stay a Function. Covers call, invoke and callbr.
  if (isa<CallBase>(&I))
    return false;

  // GEP indices into a struct type must be constant i32.
  if (isa<GetElementPtrInst>(&I))
    return false;

  // The allocated count may legally be dynamic, but turning a static alloca
  // into a dynamic one changes stack behaviour for no obfuscation benefit.
  if (isa<AllocaInst>(&I))
    return false;

  // ShuffleVector's mask is a separate field in current LLVM but was an
  // operand historically; skip it so this stays correct across 17..22.
  if (isa<ShuffleVectorInst>(&I))
    return false;

  return true;
}

static bool obfuscateFunction(Function &F, PRNG &RNG) {
  bool Changed = false;

  for (auto &BB : F) {
    if (BB.getName().starts_with("kagura."))
      continue;
    for (auto &I : BB) {
      for (unsigned OpIdx = 0; OpIdx < I.getNumOperands(); ++OpIdx) {
        if (!operandIsReplaceable(I, OpIdx))
          continue;
        Value *Op = I.getOperand(OpIdx);
        // 30% chance per constant to avoid code bloat
        if (RNG.nextRange(0, 100) >= 30)
          continue;
        if (auto *CI = dyn_cast<ConstantInt>(Op)) {
          Changed |= obfuscateConstant(&I, OpIdx, CI, RNG);
        } else if (auto *CFP = dyn_cast<ConstantFP>(Op)) {
          // 4.2.9: Also obfuscate float/double constants
          Changed |= obfuscateFPConstant(&I, OpIdx, CFP, RNG);
        }
      }
    }
  }

  return Changed;
}

PreservedAnalyses ConstantObfuscationPass::run(Function &F,
                                                FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "co"))
    return PreservedAnalyses::all();
  auto &RNG    = getModulePRNG();
  bool Changed = obfuscateFunction(F, RNG);
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
