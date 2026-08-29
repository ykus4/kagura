//===-- EncryptedLookupTable.cpp - Encrypted lookup table encoding --------===//
//
// 4.2.10: Encrypted lookup table (table encoding).
//
// Switch statements and array-based dispatch tables are common targets for
// reverse engineering: the table structure immediately reveals the set of
// valid inputs and their corresponding outputs.
//
// This pass transforms switch statements into encrypted lookup tables:
//
//   Before:
//     switch (x) {
//       case 0: return 10;
//       case 1: return 20;
//       case 2: return 30;
//     }
//
//   After:
//     static const uint8_t enc_tbl[] = { 10^K, 20^K, 30^K, ... };
//     return enc_tbl[x] ^ K;  // K = runtime key
//
// Strategy:
//   1. Find switch instructions whose cases map small integer inputs to
//      small integer constants (i.e., the switch is a pure lookup table).
//   2. Build a compact table of the values, XOR-encrypt each entry with
//      a per-switch random key.
//   3. Replace the switch with a bounds-checked table load + XOR decrypt.
//
// Eligibility criteria:
//   - All case values are contiguous integers in [0, N) (N <= 256).
//   - Each case terminates with a `ret` of a constant integer value.
//   - The default case either falls through or returns 0 / -1.
//
// Pass key:   "kagura-elt"
// CLI flag:   -kagura-elt
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/Data.h"
#include "kagura/Utils.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

#include <algorithm>
#include <vector>

using namespace llvm;

namespace kagura {

// ---- Helpers ---------------------------------------------------------------

/// Returns true if SI is an eligible lookup-table switch.
/// Populates CaseValues (input→output pairs) if eligible.
static bool isLookupSwitch(SwitchInst *SI,
                            std::vector<std::pair<int64_t, int64_t>> &Cases) {
  if (!SI) return false;
  if (SI->getNumCases() < 2 || SI->getNumCases() > 64) return false;

  // All cases must jump to distinct successors that each contain exactly
  // one instruction: a ret of a ConstantInt.
  for (auto &C : SI->cases()) {
    int64_t CaseVal = C.getCaseValue()->getSExtValue();
    BasicBlock *Dest = C.getCaseSuccessor();
    if (Dest->size() != 1) return false;
    auto *RI = dyn_cast<ReturnInst>(&Dest->front());
    if (!RI || !RI->getReturnValue()) return false;
    auto *CI = dyn_cast<ConstantInt>(RI->getReturnValue());
    if (!CI) return false;
    Cases.emplace_back(CaseVal, CI->getSExtValue());
  }

  if (Cases.empty()) return false;

  // Cases must be contiguous starting from 0
  int64_t MinCase = Cases[0].first;
  for (auto &[Key, _] : Cases) MinCase = std::min(MinCase, Key);
  if (MinCase != 0) return false;

  int64_t MaxCase = 0;
  for (auto &[Key, _] : Cases) MaxCase = std::max(MaxCase, Key);
  if (MaxCase != (int64_t)(Cases.size() - 1)) return false;

  // All output values must fit in 8 bits for compact table
  for (auto &[_, Val] : Cases)
    if (Val < 0 || Val > 255) return false;

  return true;
}

// ---- Pass entry point ------------------------------------------------------

PreservedAnalyses EncryptedLookupTablePass::run(Function &F,
                                                  FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "elt")) return PreservedAnalyses::all();
  if (F.isDeclaration()) return PreservedAnalyses::all();
  if (hasExceptionHandling(F)) return PreservedAnalyses::all();

  Module &M     = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  PRNG &RNG     = getModulePRNG(*F.getParent());
  bool Changed  = false;

  SmallVector<SwitchInst *, 16> Switches;
  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *SI = dyn_cast<SwitchInst>(&I))
        Switches.push_back(SI);

  for (auto *SI : Switches) {
    std::vector<std::pair<int64_t, int64_t>> Cases;
    if (!isLookupSwitch(SI, Cases)) continue;

    // Sort cases by key to build contiguous table
    std::sort(Cases.begin(), Cases.end());
    size_t N = Cases.size();

    // XOR key (non-zero)
    uint8_t Key = static_cast<uint8_t>(RNG.next32() | 0x01u);

    // Build encrypted table bytes
    std::vector<uint8_t> TableBytes(N);
    for (size_t i = 0; i < N; ++i)
      TableBytes[i] = static_cast<uint8_t>(Cases[i].second) ^ Key;

    // Create global table
    auto *I8Ty    = Type::getInt8Ty(Ctx);
    auto *ArrTy   = ArrayType::get(I8Ty, N);
    std::string TblName = ("kagura.elt." + F.getName()).str();
    auto *TableGV = createPrivateByteGlobal(M,
                        llvm::ArrayRef<uint8_t>(TableBytes),
                        TblName,
                        /*IsConstant=*/true);

    // Replace switch with: bounds_check → table_load → xor
    BasicBlock *SwitchBB = SI->getParent();
    BasicBlock *DefaultBB = SI->getDefaultDest();

    Value *Cond = SI->getCondition();
    IRBuilder<> B(SI);

    auto *I64Ty = Type::getInt64Ty(Ctx);
    Value *CondExt = B.CreateZExt(Cond, I64Ty, "elt.idx");
    Value *BoundVal = ConstantInt::get(I64Ty, (uint64_t)N);

    // Bounds check: if idx >= N, jump to default
    Value *InBounds = B.CreateICmpULT(CondExt, BoundVal, "elt.inbounds");
    BasicBlock *LoadBB = BasicBlock::Create(Ctx, "elt.load", &F, DefaultBB);
    BasicBlock *RetBB  = BasicBlock::Create(Ctx, "elt.ret",  &F, DefaultBB);
    B.CreateCondBr(InBounds, LoadBB, DefaultBB);

    // Load from encrypted table
    IRBuilder<> LB(LoadBB);
    auto *GEP = LB.CreateInBoundsGEP(ArrTy, TableGV,
                    {ConstantInt::get(I64Ty, 0), CondExt}, "elt.gep");
    auto *Enc = LB.CreateLoad(I8Ty, GEP, "elt.enc");
    auto *Dec = LB.CreateXor(Enc, ConstantInt::get(I8Ty, Key), "elt.dec");
    auto *RetTy = cast<IntegerType>(SI->getCondition()->getType());
    Value *Extended = LB.CreateZExt(Dec, RetTy, "elt.val");
    LB.CreateBr(RetBB);

    // Return the decrypted value
    IRBuilder<> RB(RetBB);
    RB.CreateRet(Extended);

    SI->eraseFromParent();
    markObfuscated(F, "elt");
    Changed = true;
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
