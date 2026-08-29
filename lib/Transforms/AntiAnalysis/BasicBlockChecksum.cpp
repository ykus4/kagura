//===-- BasicBlockChecksum.cpp - Fine-grained BB-level integrity check ----===//
//
// 4.3.16: Injects a compile-time FNV-1a-32 checksum of each basic block's
// instruction opcodes as a runtime guard.  At function entry a guard variable
// is set to the expected checksum; the first instruction of each guarded block
// recomputes the checksum and calls kagura_on_tamper_detected() if it mismatches.
//
// Strategy:
//   For a random subset of basic blocks (30%):
//   1. At compile time, compute FNV-1a-32 over the sequence of instruction
//      opcode bytes in that block.
//   2. At the START of the block, emit:
//        if (kagura_bb_check(block_id, expected_cksum) == 0)
//          kagura_on_tamper_detected();
//   The runtime function kagura_bb_check() computes the opcode hash of the
//   in-memory code at the given address and compares it to expected_cksum.
//
// Note: This is a "soft" check — binary patching that modifies instruction
// opcodes will trip the check; NOPs inserted to change timing will not unless
// they change opcode sequences checked.
//
// Pass key:   "kagura-bbcheck"
// CLI flag:   -kagura-bbcheck
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/AntiAnalysis.h"
#include "kagura/Utils.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

using namespace llvm;

namespace kagura {

// FNV-1a over the low opcode byte of every instruction in a basic block.
// Deliberately narrower than AntiTamper's whole-function hash, which feeds all
// four opcode bytes; the two are independent mechanisms.
static uint32_t bbChecksum(const BasicBlock &BB) {
  uint32_t H = fnv1a32Init();
  for (const Instruction &I : BB)
    H = fnv1a32Update(H, static_cast<uint8_t>(I.getOpcode()));
  return H;
}

PreservedAnalyses BasicBlockChecksumPass::run(Function &F,
                                               FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "bbcheck"))
    return PreservedAnalyses::all();
  if (F.isDeclaration())
    return PreservedAnalyses::all();
  if (hasExceptionHandling(F))
    return PreservedAnalyses::all();

  Module &M     = *F.getParent();
  LLVMContext &Ctx = M.getContext();

  PRNG &RNG = getModulePRNG();
  uint32_t BlockID = 0;

  // Choose the blocks before touching the module.
  //
  // The two getOrInsertFunction calls below used to run first, so a function
  // where the 30% draw never fired still added two declarations to the module
  // and then returned PreservedAnalyses::all() — a mutation reported as no
  // change. (A function pass adding module-level declarations at all is
  // already outside what the new pass manager promises; doing it and denying
  // it is worse.) Note the draw is consumed for every block, including the
  // ones rejected afterwards, which is deliberate: the key stream must not
  // depend on which blocks happen to be EH or entry.
  SmallVector<std::pair<BasicBlock *, uint32_t>, 32> Targets;
  for (auto &BB : F) {
    ++BlockID;
    // Instrument ~30% of blocks
    if (RNG.nextRange(0, 100) >= 30) continue;
    // Skip entry (too much mutation risk) and EH blocks
    if (&BB == &F.getEntryBlock()) continue;
    if (isEHBlock(BB)) continue;
    Targets.push_back({&BB, BlockID});
  }

  if (Targets.empty())
    return PreservedAnalyses::all();

  // Declare:  int  kagura_bb_check(uint32_t block_id, uint32_t expected);
  auto *Int32Ty = Type::getInt32Ty(Ctx);
  auto *FTy     = FunctionType::get(Int32Ty, {Int32Ty, Int32Ty}, false);
  FunctionCallee BBCheckFn = M.getOrInsertFunction("kagura_bb_check", FTy);

  // Declare:  void kagura_on_tamper_detected();
  auto *VoidTy   = Type::getVoidTy(Ctx);
  FunctionCallee TamperFn = M.getOrInsertFunction(
      "kagura_on_tamper_detected",
      FunctionType::get(VoidTy, false));

  bool Changed = false;

  for (auto &[BB, ThisBlockID] : Targets) {
    BlockID = ThisBlockID;

    uint32_t Cksum = bbChecksum(*BB);

    // Insert check at the very beginning of the block.
    Instruction *InsertPt = &*BB->getFirstInsertionPt();
    IRBuilder<> B(InsertPt);

    Value *ChkResult = B.CreateCall(BBCheckFn, {
        ConstantInt::get(Int32Ty, BlockID),
        ConstantInt::get(Int32Ty, Cksum)});
    Value *IsZero = B.CreateICmpEQ(ChkResult, ConstantInt::get(Int32Ty, 0));

    // Split block at the check point; if check fails, call tamper handler.
    BasicBlock *TamperBB = BasicBlock::Create(Ctx, "bbchk.tamper", &F);
    BasicBlock *ContinueBB = BB->splitBasicBlock(InsertPt, "bbchk.ok");

    // Replace original unconditional branch with conditional
    BB->getTerminator()->eraseFromParent();
    IRBuilder<> BrB(BB);
    BrB.CreateCondBr(IsZero, TamperBB, ContinueBB);

    IRBuilder<> TamperB(TamperBB);
    TamperB.CreateCall(TamperFn, {});
    TamperB.CreateUnreachable();

    Changed = true;
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
