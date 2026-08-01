//===-- MemoryValueObfuscation.cpp - In-memory value XOR obfuscation ------===//
//
// 4.5.1: Obfuscates local (alloca'd) integer variables by wrapping every
// store/load pair with a compile-time-chosen XOR key.
//
// Strategy:
//   For each AllocaInst of an integer type (i8/i16/i32/i64) whose address does
//   not escape the function:
//     - At every StoreInst writing into the alloca, XOR the stored value with
//       the key before storing (encrypt).
//     - At every LoadInst reading from the alloca, XOR the loaded value with
//       the same key after loading (decrypt).
//
// The key is a random 64-bit constant truncated to the alloca's element width,
// generated fresh per function using the module PRNG.
//
// Preconditions / conservatism:
//   - Only allocas with a single integer type element are transformed.
//   - The alloca's address must not be taken and stored/passed to calls
//     (isAddressTaken() check) to avoid breaking aliased access.
//   - PHI / select uses of the alloca pointer are skipped (rare edge case).
//
// Pass key:   "kagura-mvo"
// CLI flag:   -kagura-mvo
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace kagura {

// ---- Helpers ---------------------------------------------------------------

static bool isSupportedWidth(unsigned Bits) {
  return Bits == 8 || Bits == 16 || Bits == 32 || Bits == 64;
}

/// All-ones mask for an N-bit value, avoiding the UB of `1ULL << 64`.
static uint64_t maskForWidth(unsigned Bits) {
  return Bits >= 64 ? ~0ULL : ((1ULL << Bits) - 1);
}

/// Returns true if the alloca pointer escapes the function (address taken).
/// We consider an address "escaped" if it is passed to a Call/Invoke, stored
/// into memory, or used in a PHI/Select.
static bool allocaEscapes(const AllocaInst *AI) {
  for (const auto *U : AI->users()) {
    if (isa<LoadInst>(U) || isa<StoreInst>(U)) {
      // A store WHERE AI is the VALUE operand (not the pointer) is an escape.
      if (const auto *SI = dyn_cast<StoreInst>(U))
        if (SI->getValueOperand() == AI)
          return true;
      continue;
    }
    // Any other use (call, GEP, bitcast, PHI, select) = escape
    return true;
  }
  return false;
}

/// Returns true if this alloca is the dispatch variable injected by FLA.
/// After optimization the alloca loses its name, so we detect it structurally:
/// any load from the alloca feeds directly into a SwitchInst.
static bool isFLADispatchAlloca(const AllocaInst *AI) {
  for (const auto *U : AI->users()) {
    const auto *LI = dyn_cast<LoadInst>(U);
    if (!LI)
      continue;
    for (const auto *LU : LI->users())
      if (isa<SwitchInst>(LU))
        return true;
  }
  return false;
}

// ---- Pass entry point -------------------------------------------------------

PreservedAnalyses MemoryValueObfuscationPass::run(Function &F,
                                                   FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "mvo"))
    return PreservedAnalyses::all();
  // EH functions are allowed: allocas in non-EH blocks are safe to transform.
  // The allocaEscapes() check already rejects any alloca whose address is
  // passed to an invoke or otherwise escapes.

  PRNG &RNG    = getModulePRNG();
  bool Changed = false;

  // Collect eligible allocas upfront (avoid iterator invalidation).
  SmallVector<AllocaInst *, 16> Targets;
  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *AI = dyn_cast<AllocaInst>(&I)) {
        // Skip kagura's own injected allocas (e.g. FLA's dispatch variable).
        // After optimization the name is stripped, so detect structurally.
        if (AI->getName().starts_with("kagura."))
          continue;
        if (isFLADispatchAlloca(AI))
          continue;
        Type *Ty = AI->getAllocatedType();
        if (!Ty->isIntegerTy())
          continue;
        if (!isSupportedWidth(Ty->getIntegerBitWidth()))
          continue;
        if (AI->isArrayAllocation())
          continue; // variable-length alloca — skip
        if (allocaEscapes(AI))
          continue;
        Targets.push_back(AI);
      }

  for (AllocaInst *AI : Targets) {
    Type *IntTy    = AI->getAllocatedType();
    unsigned Bits  = IntTy->getIntegerBitWidth();
    // Mask the 64-bit draw down to the alloca's width before handing it to
    // APInt: the APInt(BitWidth, uint64_t) constructor asserts that the value
    // already fits, so an unmasked draw crashes an assertions-enabled build for
    // every i8/i16/i32 alloca.
    uint64_t RawK  = RNG.next() & maskForWidth(Bits);
    APInt Key(Bits, RawK);
    auto *KeyConst = ConstantInt::get(IntTy, Key);

    // Collect all stores/loads from this alloca.
    SmallVector<StoreInst *, 8> Stores;
    SmallVector<LoadInst  *, 8> Loads;
    for (auto *U : AI->users()) {
      if (auto *SI = dyn_cast<StoreInst>(U))
        if (SI->getPointerOperand() == AI)
          Stores.push_back(SI);
      if (auto *LI = dyn_cast<LoadInst>(U))
        Loads.push_back(LI);
    }

    if (Stores.empty() || Loads.empty())
      continue;

    // Encrypt: before each store, XOR the value with Key.
    for (StoreInst *SI : Stores) {
      IRBuilder<> B(SI);
      Value *Plain = SI->getValueOperand();
      Value *Enc   = B.CreateXor(Plain, KeyConst, Plain->getName() + ".mvo");
      SI->setOperand(0, Enc); // replace value operand
    }

    // Decrypt: after each load, XOR the result with Key.
    for (LoadInst *LI : Loads) {
      IRBuilder<> B(LI->getNextNode());
      Value *Enc   = LI;
      Value *Plain = B.CreateXor(Enc, KeyConst, LI->getName() + ".mvo");
      LI->replaceUsesWithIf(Plain, [&](Use &U) {
        return U.getUser() != Plain;
      });
    }

    Changed = true;
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
