//===-- GlobalEncryption.cpp - Compile-time global variable encryption ----===//
//
// For every non-string GlobalVariable with private/internal linkage that holds
// a constant integer or a constant array of integers, this pass:
//   1. XOR-encrypts the value(s) at compile time (key ^ index for arrays).
//   2. Replaces every load of the global with a load + XOR immediate.
//
// No runtime stub is required: decryption happens inline at every load site.
// This keeps the implementation simple and avoids initializer-ordering issues.
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/Data.h"
#include "kagura/Utils.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>

using namespace llvm;

namespace kagura {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return true if GV should be skipped regardless of other criteria.
static bool shouldSkipGlobal(const GlobalVariable &GV) {
  StringRef Name = GV.getName();
  // Preserve kagura_ internals and all LLVM-reserved names.
  if (Name.starts_with("kagura_") || Name.starts_with("llvm."))
    return true;
  return false;
}

/// Return true if Ty is [N x iW] where iW is a supported integer width.
static bool isSupportedIntArrayTy(Type *Ty) {
  auto *AT = dyn_cast<ArrayType>(Ty);
  if (!AT)
    return false;
  return isSupportedIntType(AT->getElementType());
}

/// Return true if the initializer is a ConstantDataArray of strings.
/// We must not encrypt string literals here (StringEncryptionPass owns those).
static bool isStringGlobal(const GlobalVariable &GV) {
  auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
  return CDA && CDA->isString();
}

/// Return true if GV has at least one use that is (or transitively leads to)
/// a LoadInst inside a function body.
static bool hasLoadUseInFunction(const GlobalVariable &GV) {
  for (const auto *U : GV.users()) {
    if (isa<LoadInst>(U))
      return true;
    // ConstantExpr GEP/bitcast wrapping the global
    if (const auto *CE = dyn_cast<ConstantExpr>(U)) {
      for (const auto *CEU : CE->users())
        if (isa<LoadInst>(CEU))
          return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

struct EligibleGlobal {
  GlobalVariable *GV;
  bool            IsArray; // true = [N x iW], false = scalar iW
};

static std::vector<EligibleGlobal> collectEligibleGlobals(Module &M) {
  std::vector<EligibleGlobal> Result;

  for (auto &GV : M.globals()) {
    // Must be a constant with an initializer.
    if (!GV.isConstant() || !GV.hasInitializer())
      continue;

    // Only private / internal linkage.
    if (!GV.hasPrivateLinkage() && !GV.hasInternalLinkage())
      continue;

    // Skip anything we should not touch.
    if (shouldSkipGlobal(GV))
      continue;

    Type *ValTy = GV.getValueType();

    if (isSupportedIntType(ValTy)) {
      // Scalar integer constant: initializer must be ConstantInt.
      if (!isa<ConstantInt>(GV.getInitializer()))
        continue;
      if (!hasLoadUseInFunction(GV))
        continue;
      Result.push_back({&GV, /*IsArray=*/false});
      continue;
    }

    if (isSupportedIntArrayTy(ValTy)) {
      // Array of integers: must NOT be a string.
      if (isStringGlobal(GV))
        continue;
      // Initializer must be ConstantDataArray or ConstantArray.
      if (!isa<ConstantDataArray>(GV.getInitializer()) &&
          !isa<ConstantArray>(GV.getInitializer()))
        continue;
      if (!hasLoadUseInFunction(GV))
        continue;
      Result.push_back({&GV, /*IsArray=*/true});
    }
  }

  return Result;
}

// ---------------------------------------------------------------------------
// Encryption helpers
// ---------------------------------------------------------------------------

/// Return the APInt value held by a constant integer element at index Idx of
/// either a ConstantDataArray or ConstantArray, or nullopt if the element is
/// not a plain constant integer.
///
/// The nullopt matters. This used to fall back to APInt::getZero() with a
/// comment saying "key ^ 0 = key, still encrypts" — true, and beside the
/// point: the *plaintext* was replaced by zero. A ConstantArray element that
/// is an undef, a poison, or a relocatable expression rather than a
/// ConstantInt had its real value discarded at compile time, and every load
/// of it then decrypted cleanly to 0. Silent data corruption, in the pass
/// whose whole job is to be value-preserving. The caller declines the global
/// now instead of encrypting something it cannot read.
static std::optional<APInt> getArrayElement(Constant *Init, uint64_t Idx,
                                            Type *ElemTy) {
  if (auto *CDA = dyn_cast<ConstantDataArray>(Init)) {
    // ConstantDataArray stores raw data; use getElementAsInteger.
    return APInt(ElemTy->getIntegerBitWidth(),
                 CDA->getElementAsInteger(Idx));
  }
  if (auto *CA = dyn_cast<ConstantArray>(Init)) {
    if (auto *CI = dyn_cast<ConstantInt>(CA->getOperand(Idx)))
      return CI->getValue();
  }
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Load replacement
// ---------------------------------------------------------------------------

/// Walk all users of GV (and ConstantExpr wrappers), collect every LoadInst.
static SmallVector<LoadInst *, 8> collectLoads(GlobalVariable *GV) {
  SmallVector<LoadInst *, 8> Loads;
  for (auto *U : GV->users()) {
    if (auto *LI = dyn_cast<LoadInst>(U)) {
      Loads.push_back(LI);
      continue;
    }
    // ConstantExpr (GEP/bitcast) – only consider direct loads from them for
    // the scalar case; array element loads are handled separately below.
    if (auto *CE = dyn_cast<ConstantExpr>(U)) {
      for (auto *CEU : CE->users())
        if (auto *LI = dyn_cast<LoadInst>(CEU))
          Loads.push_back(LI);
    }
  }
  return Loads;
}

// ---------------------------------------------------------------------------
// Scalar integer global encryption
// ---------------------------------------------------------------------------

/// Encrypt a scalar integer global and inline-decrypt at each load site.
///
///  Before:  @foo = private constant i32 42
///           %v = load i32, ptr @foo
///
///  After:   @foo = private constant i32 (42 ^ K)
///           %enc = load i32, ptr @foo
///           %v   = xor i32 %enc, K        ; replaces original %v
static bool encryptScalarGlobal(GlobalVariable *GV, PRNG &RNG) {
  auto *CI = cast<ConstantInt>(GV->getInitializer());
  Type *IntTy = CI->getType();
  unsigned Bits = IntTy->getIntegerBitWidth();

  // Generate a key with the same bit width.
  uint64_t RawKey = (Bits <= 32 ? RNG.next32() : RNG.next()) & maskForWidth(Bits);

  APInt Key(Bits, RawKey);
  APInt PlainVal = CI->getValue();
  APInt EncVal   = PlainVal ^ Key;

  // Collect loads BEFORE mutating the global (invalidates nothing yet).
  SmallVector<LoadInst *, 8> Loads = collectLoads(GV);
  if (Loads.empty())
    return false;

  // Update the initializer to the encrypted value.
  GV->setInitializer(ConstantInt::get(IntTy, EncVal));
  // The global must be mutable at runtime so the linker does not fold it.
  GV->setConstant(false);

  // At every load site, inject: %plain = xor %loaded, K
  auto *KeyConst = ConstantInt::get(IntTy, Key);
  for (LoadInst *LI : Loads) {
    IRBuilder<> B(LI->getNextNode());
    auto *Decrypted = B.CreateXor(LI, KeyConst, LI->getName() + ".dec");
    // Replace all uses of the original load value with the decrypted one,
    // but NOT the XOR instruction's own operand.
    LI->replaceUsesWithIf(Decrypted, [&](Use &U) {
      return U.getUser() != Decrypted;
    });
  }

  return true;
}

// ---------------------------------------------------------------------------
// Array of integers global encryption
// ---------------------------------------------------------------------------

/// Collect all GetElementPtrInst (and ConstantExpr-GEP) users that index into
/// GV, together with the constant index used, and the subsequent LoadInst.
///
/// For each such pair (GEP, LI) where GEP is `getelementptr [N x iW], ptr @GV,
/// i64 0, i64 <idx>` and LI is `load iW, ptr GEP`, we record (LI, idx).
struct ArrayLoad {
  LoadInst *LI;
  uint64_t  ElemIdx;
};

static SmallVector<ArrayLoad, 16> collectArrayLoads(GlobalVariable *GV) {
  SmallVector<ArrayLoad, 16> Result;
  auto *ArrTy = cast<ArrayType>(GV->getValueType());
  uint64_t NumElems = ArrTy->getNumElements();

  auto handleGEP = [&](Value *GEPVal) {
    // We expect: GEP [N x iW], ptr @GV, i64 0, i64 <idx>
    uint64_t ElemIdx = UINT64_MAX;
    if (auto *GEP = dyn_cast<GetElementPtrInst>(GEPVal)) {
      if (GEP->getNumIndices() == 2) {
        auto *I0 = dyn_cast<ConstantInt>(GEP->getOperand(1));
        auto *I1 = dyn_cast<ConstantInt>(GEP->getOperand(2));
        if (I0 && I0->isZero() && I1)
          ElemIdx = I1->getZExtValue();
      }
    } else if (auto *CE = dyn_cast<ConstantExpr>(GEPVal)) {
      if (CE->getOpcode() == Instruction::GetElementPtr &&
          CE->getNumOperands() == 3) {
        auto *I0 = dyn_cast<ConstantInt>(CE->getOperand(1));
        auto *I1 = dyn_cast<ConstantInt>(CE->getOperand(2));
        if (I0 && I0->isZero() && I1)
          ElemIdx = I1->getZExtValue();
      }
    }
    if (ElemIdx == UINT64_MAX || ElemIdx >= NumElems)
      return;

    // Collect loads from this GEP.
    for (auto *U : GEPVal->users()) {
      if (auto *LI = dyn_cast<LoadInst>(U))
        Result.push_back({LI, ElemIdx});
    }
  };

  for (auto *U : GV->users()) {
    handleGEP(U);
    // Also handle ConstantExpr wrapped around another ConstantExpr (rare).
    if (auto *CE = dyn_cast<ConstantExpr>(U))
      for (auto *CEU : CE->users())
        handleGEP(CEU);
  }

  return Result;
}

/// Encrypt an array-of-integers global: each element[i] is XOR'd with
/// (BaseKey ^ i), giving a distinct effective key per element.
///
///  Before:  @arr = private constant [3 x i32] [i32 1, i32 2, i32 3]
///
///  After:   @arr = private constant [3 x i32] [i32 (1^K0), i32 (2^K1), i32 (3^K2)]
///           ; Ki = BaseKey ^ i
///           ; at each load site for element i:
///           %enc = load i32, ptr <gep @arr, 0, i>
///           %v   = xor i32 %enc, Ki
static bool encryptArrayGlobal(GlobalVariable *GV, PRNG &RNG) {
  auto *ArrTy   = cast<ArrayType>(GV->getValueType());
  Type *ElemTy  = ArrTy->getElementType();
  uint64_t N    = ArrTy->getNumElements();
  unsigned Bits = ElemTy->getIntegerBitWidth();

  // Collect loads before touching the global.
  SmallVector<ArrayLoad, 16> Loads = collectArrayLoads(GV);
  if (Loads.empty())
    return false;

  // Generate one base key; per-element key = BaseKey ^ index.
  uint64_t BaseKeyRaw =
      (Bits <= 32 ? RNG.next32() : RNG.next()) & maskForWidth(Bits);
  APInt BaseKey(Bits, BaseKeyRaw);

  // Build encrypted initializer elements.
  Constant *OldInit = GV->getInitializer();
  std::vector<Constant *> EncElems;
  EncElems.reserve(N);
  // The index is mixed into the key, so it has to be narrowed to the *element*
  // width, not used raw: a [512 x i8] global asserts at I == 256 otherwise.
  // Encryption and decryption both go through elemKey(), so the two cannot
  // disagree about the narrowing.
  auto elemKey = [&](uint64_t Idx) {
    return BaseKey ^ APInt(Bits, Idx & maskForWidth(Bits));
  };

  for (uint64_t I = 0; I < N; ++I) {
    std::optional<APInt> PlainVal = getArrayElement(OldInit, I, ElemTy);
    // An element whose value we cannot read is an element we cannot encrypt
    // without losing it. Leave the whole global alone; nothing has been
    // mutated yet at this point.
    if (!PlainVal)
      return false;
    APInt EncVal = *PlainVal ^ elemKey(I);
    EncElems.push_back(ConstantInt::get(ElemTy, EncVal));
  }
  auto *NewInit = ConstantArray::get(ArrTy, EncElems);
  GV->setInitializer(NewInit);
  GV->setConstant(false);

  // At each load site for element[i], inject XOR with (BaseKey ^ i).
  for (auto &AL : Loads) {
    APInt ElemKey  = elemKey(AL.ElemIdx);
    auto *KeyConst = ConstantInt::get(ElemTy, ElemKey);
    IRBuilder<> B(AL.LI->getNextNode());
    auto *Decrypted = B.CreateXor(AL.LI, KeyConst,
                                  AL.LI->getName() + ".dec");
    AL.LI->replaceUsesWithIf(Decrypted, [&](Use &U) {
      return U.getUser() != Decrypted;
    });
  }

  return true;
}

// ---------------------------------------------------------------------------
// Pass entry point
// ---------------------------------------------------------------------------

PreservedAnalyses GlobalEncryptionPass::run(Module &M,
                                             ModuleAnalysisManager &) {
  auto Eligible = collectEligibleGlobals(M);
  if (Eligible.empty())
    return PreservedAnalyses::all();

  PRNG &RNG    = getModulePRNG(M);
  bool Changed = false;

  for (auto &EG : Eligible) {
    bool Ok = EG.IsArray ? encryptArrayGlobal(EG.GV, RNG)
                         : encryptScalarGlobal(EG.GV, RNG);
    Changed |= Ok;
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
