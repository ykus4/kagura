//===-- ControlFlowFlattening.cpp - CFG flattening pass -------------------===//
//
// Converts function control flow into a switch-based state machine.
// Uses New Pass Manager API (PassInfoMixin).
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include <map>
#include <vector>

using namespace llvm;

namespace kagura {

static bool flattenFunction(Function &F, PRNG &RNG) {
  if (F.isDeclaration() || F.size() < 3)
    return false;
  for (auto &BB : F)
    if (isa<IndirectBrInst>(BB.getTerminator()) ||
        isa<InvokeInst>(BB.getTerminator()))
      return false;

  LLVMContext &Ctx = F.getContext();
  auto *Int32Ty    = Type::getInt32Ty(Ctx);

  // Step 1: Demote PHI nodes to memory
  demotePhis(F);

  // Step 2: Collect original blocks (entry + rest)
  // After demotePhis, re-collect since BB list may have changed
  BasicBlock *OrigEntry = &F.getEntryBlock();
  std::vector<BasicBlock *> WorkBlocks;
  for (auto &BB : F)
    if (&BB != OrigEntry)
      WorkBlocks.push_back(&BB);

  if (WorkBlocks.empty())
    return false;

  // Step 3: Assign case values
  std::map<BasicBlock *, uint32_t> CaseMap;
  for (auto *BB : WorkBlocks) {
    uint32_t Val;
    do { Val = RNG.next32(); } while (Val == 0);
    CaseMap[BB] = Val;
  }

  // Step 4: Insert alloca for the switch variable AT THE TOP of OrigEntry
  // (must be in entry block for alloca to be valid)
  IRBuilder<> AllocaBuilder(&*OrigEntry->getFirstInsertionPt());
  auto *SwitchVar = AllocaBuilder.CreateAlloca(Int32Ty, nullptr, "kagura.sw");

  // Step 5: Find the entry block's first successor to set initial switchVar
  // The entry block ends with an unconditional branch after demotePhis
  Instruction *EntryTerm = OrigEntry->getTerminator();
  BasicBlock *EntrySucc = nullptr;
  if (auto *Br = dyn_cast<BranchInst>(EntryTerm))
    EntrySucc = Br->getSuccessor(0);

  // Step 6: Split entry block just before the terminator to create a
  // "pre-loop" block that sets the initial switch value and jumps to the loop
  BasicBlock *PreLoop =
      BasicBlock::Create(Ctx, "kagura.preloop", &F);

  // Build the loop header and loop-end blocks
  BasicBlock *LoopHeader =
      BasicBlock::Create(Ctx, "kagura.loop", &F);
  BasicBlock *LoopEnd =
      BasicBlock::Create(Ctx, "kagura.loopend", &F);
  BasicBlock *DefaultBB =
      BasicBlock::Create(Ctx, "kagura.default", &F);
  IRBuilder<>(DefaultBB).CreateUnreachable();

  // Replace OrigEntry's terminator with: store initVal; br PreLoop
  // For conditional branches, use a select to pick the correct initial
  // switch value so both paths are faithfully represented.
  {
    IRBuilder<> B(EntryTerm);
    Value *InitVal = nullptr;
    if (auto *CondBr = dyn_cast<BranchInst>(EntryTerm);
        CondBr && CondBr->isConditional()) {
      BasicBlock *TrueBB  = CondBr->getSuccessor(0);
      BasicBlock *FalseBB = CondBr->getSuccessor(1);
      uint32_t TV = CaseMap.count(TrueBB)  ? CaseMap[TrueBB]  : 0;
      uint32_t FV = CaseMap.count(FalseBB) ? CaseMap[FalseBB] : 0;
      InitVal = B.CreateSelect(CondBr->getCondition(),
                               ConstantInt::get(Int32Ty, TV),
                               ConstantInt::get(Int32Ty, FV),
                               "kagura.init");
    } else {
      uint32_t IV = (EntrySucc && CaseMap.count(EntrySucc))
                        ? CaseMap[EntrySucc]
                        : 0;
      InitVal = ConstantInt::get(Int32Ty, IV);
    }
    B.CreateStore(InitVal, SwitchVar);
    B.CreateBr(PreLoop);
    EntryTerm->eraseFromParent();
  }

  // PreLoop -> LoopHeader
  IRBuilder<>(PreLoop).CreateBr(LoopHeader);

  // LoopHeader: load switchVar -> switch
  IRBuilder<> LB(LoopHeader);
  auto *SW     = LB.CreateLoad(Int32Ty, SwitchVar, "kagura.sw.val");
  auto *Switch = LB.CreateSwitch(SW, DefaultBB, WorkBlocks.size());

  // LoopEnd -> LoopHeader
  IRBuilder<>(LoopEnd).CreateBr(LoopHeader);

  // Step 7: Wire each work block into the switch
  for (auto *BB : WorkBlocks) {
    Switch->addCase(ConstantInt::get(Int32Ty, CaseMap[BB]), BB);

    Instruction *Term = BB->getTerminator();
    IRBuilder<> TB(Term);

    if (isa<ReturnInst>(Term))
      continue; // returns exit the function directly

    if (auto *Br = dyn_cast<BranchInst>(Term)) {
      if (Br->isUnconditional()) {
        BasicBlock *Succ = Br->getSuccessor(0);
        uint32_t NextVal =
            CaseMap.count(Succ) ? CaseMap[Succ] : 0;
        TB.CreateStore(ConstantInt::get(Int32Ty, NextVal), SwitchVar);
        Br->eraseFromParent();
        IRBuilder<>(BB).CreateBr(LoopEnd);
      } else {
        // Conditional: use select to pick the next case value
        BasicBlock *TBB = Br->getSuccessor(0);
        BasicBlock *FBB = Br->getSuccessor(1);
        uint32_t TV = CaseMap.count(TBB) ? CaseMap[TBB] : 0;
        uint32_t FV = CaseMap.count(FBB) ? CaseMap[FBB] : 0;
        Value *Cond = Br->getCondition();
        auto *Sel   = TB.CreateSelect(Cond,
                                      ConstantInt::get(Int32Ty, TV),
                                      ConstantInt::get(Int32Ty, FV),
                                      "kagura.sel");
        TB.CreateStore(Sel, SwitchVar);
        Br->eraseFromParent();
        IRBuilder<>(BB).CreateBr(LoopEnd);
      }
      continue;
    }
    // Other terminators: leave unchanged (e.g., unreachable)
  }

  return true;
}

PreservedAnalyses
ControlFlowFlatteningPass::run(Function &F, FunctionAnalysisManager &) {
  // C.1: FLA rewires the entire CFG into a switch dispatch and relies on
  // reg2mem (DemotePHIToStack / DemoteRegToStack).  The Wasm target requires
  // structured control flow and does not support arbitrary CFG reshaping.
  if (kagura::isWasmTarget(*F.getParent()))
    return PreservedAnalyses::all();

  if (!shouldObfuscate(F, "fla"))
    return PreservedAnalyses::all();
  auto &RNG    = getModulePRNG();
  bool Changed = flattenFunction(F, RNG);
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
