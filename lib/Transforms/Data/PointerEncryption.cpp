//===-- PointerEncryption.cpp - In-memory pointer address obfuscation -----===//
//
// 4.5.2: Obfuscates local (alloca'd) pointer variables by XOR-encrypting the
// stored address with a compile-time-chosen per-alloca key.
//
// Strategy:
//   For each AllocaInst of a pointer type whose address does not escape the
//   function:
//     - At every StoreInst writing a pointer value, ptrtoint the pointer,
//       XOR with the key, and store as the target's intptr width.
//     - At every LoadInst reading from the alloca, load intptr, XOR with the
//       key, and inttoptr back to the original pointer type.
//
// This makes it hard for memory dump analysis to follow raw pointer values from
// a game object's field directly to heap addresses.
//
// Preconditions:
//   - Only allocas with a pointer element type are transformed.
//   - The alloca address must not escape (no calls, no GEP chains, etc.).
//   - Functions with exception handling are skipped.
//
// Pass key:   "kagura-pe"
// CLI flag:   -kagura-pe   (reuses opt::PE — added to Options.h/.cpp)
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/Data.h"
#include "kagura/Utils.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DataLayout.h"

using namespace llvm;

namespace kagura {

// ---- Helpers ---------------------------------------------------------------

/// True if every use of AI is a load or a store-to-pointer (not store-of-ptr).
static bool pointerAllocaEscapes(const AllocaInst *AI) {
  for (const auto *U : AI->users()) {
    if (const auto *LI = dyn_cast<LoadInst>(U)) {
      (void)LI;
      continue;
    }
    if (const auto *SI = dyn_cast<StoreInst>(U)) {
      // A store where AI is the VALUE operand is an escape.
      if (SI->getValueOperand() == AI)
        return true;
      // A store where AI is the POINTER operand is normal.
      continue;
    }
    // Any other use = escape
    return true;
  }
  return false;
}

// ---- Pass entry point -------------------------------------------------------

PreservedAnalyses PointerEncryptionPass::run(Function &F,
                                              FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "pe"))
    return PreservedAnalyses::all();
  // EH functions are allowed: the pointerAllocaEscapes() check already rejects
  // any alloca whose address flows into an invoke or otherwise escapes the
  // function, so non-EH allocas are safe to transform.

  LLVMContext &Ctx = F.getContext();
  auto *PtrTy  = PointerType::getUnqual(Ctx);
  const DataLayout &DL = F.getParent()->getDataLayout();
  unsigned PtrBits = DL.getPointerSizeInBits();
  if (PtrBits == 0)
    return PreservedAnalyses::all();
  auto *IntPtrTy = Type::getIntNTy(Ctx, PtrBits);

  PRNG &RNG    = getModulePRNG();
  bool Changed = false;

  // Collect eligible pointer allocas upfront (avoid invalidation).
  SmallVector<AllocaInst *, 16> Targets;
  for (auto &BB : F) {
    for (auto &I : BB) {
      auto *AI = dyn_cast<AllocaInst>(&I);
      if (!AI) continue;
      // Must allocate a pointer type
      if (!AI->getAllocatedType()->isPointerTy()) continue;
      // Must be a single element (not array alloca)
      if (AI->isArrayAllocation()) continue;
      // Address must not escape
      if (pointerAllocaEscapes(AI)) continue;
      Targets.push_back(AI);
    }
  }

  for (auto *AI : Targets) {
    APInt Key(PtrBits, RNG.next());

    // The alloca remains a pointer-sized slot; loads/stores are rewritten to
    // use the target's intptr width.
    AI->mutateType(PtrTy);          // alloca ptr type stays ptr (opaque)
    // We'll insert ptrtoint/xor/store and load/xor/inttoptr around uses.

    // Collect stores and loads before mutation.
    SmallVector<StoreInst *, 8> Stores;
    SmallVector<LoadInst *, 8>  Loads;
    for (auto *U : AI->users()) {
      if (auto *SI = dyn_cast<StoreInst>(U))
        if (SI->getPointerOperand() == AI)
          Stores.push_back(SI);
      if (auto *LI = dyn_cast<LoadInst>(U))
        Loads.push_back(LI);
    }

    auto *KeyConst = ConstantInt::get(IntPtrTy, Key);

    // Rewrite stores: ptr -> ptrtoint -> xor -> store intptr
    for (auto *SI : Stores) {
      Value *Ptr = SI->getValueOperand();
      IRBuilder<> B(SI);
      Value *AsInt    = B.CreatePtrToInt(Ptr, IntPtrTy, "pe.p2i");
      Value *Encrypted = B.CreateXor(AsInt, KeyConst, "pe.enc");
      // Replace the store value with the encrypted integer.
      // We store the target's intptr width into the pointer-sized alloca slot.
      // Since the alloca stays opaque-ptr, just bitcast:
      auto *NewStore = B.CreateStore(Encrypted,
          B.CreateBitCast(AI, PointerType::getUnqual(Ctx)));
      (void)NewStore;
      SI->eraseFromParent();
      Changed = true;
    }

    // Rewrite loads: load intptr -> xor -> inttoptr
    for (auto *LI : Loads) {
      Type *OrigTy = LI->getType();
      IRBuilder<> B(LI);
      auto *LoadInt  = B.CreateLoad(IntPtrTy,
          B.CreateBitCast(AI, PointerType::getUnqual(Ctx)), "pe.raw");
      Value *Decrypted = B.CreateXor(LoadInt, KeyConst, "pe.dec");
      Value *AsPtr     = B.CreateIntToPtr(Decrypted, OrigTy, "pe.ptr");
      LI->replaceAllUsesWith(AsPtr);
      LI->eraseFromParent();
      Changed = true;
    }

    if (Changed)
      markObfuscated(F, "pe");
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
