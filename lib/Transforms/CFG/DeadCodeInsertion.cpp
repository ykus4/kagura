//===-- DeadCodeInsertion.cpp - Insert unreachable junk blocks ------------===//
//
// Inserts syntactically plausible but semantically dead basic blocks into
// each function.  Dead blocks are:
//
//   - Never branched to from live code (reachable only via opaque false pred)
//   - Terminated by `unreachable` so LLVM cannot accidentally fold them
//   - Filled with arithmetic junk that looks like real code to a disassembler
//
// Construction per function:
//   1. For each live BB (skipping entry and BBs already unreachable):
//      - With probability `Probability`%, insert one dead block immediately
//        after the live BB.
//   2. The dead block body is a random sequence of add/sub/xor/mul
//      instructions on a dummy alloca, followed by `unreachable`.
//   3. An unreachable BB is never emitted into real code paths; it purely
//      pollutes the disassembly and inflates CFG complexity.
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include <vector>

using namespace llvm;

namespace kagura {

// Emit a sequence of junk arithmetic instructions into BB.
// Uses a stack-allocated i32 as the operand so the instructions reference
// something addressable — this makes the block look non-trivially dead to
// a static analyzer scanning for obviously dead stores.
static void fillJunkBody(IRBuilder<> &B, PRNG &RNG, unsigned NumOps) {
  LLVMContext &Ctx = B.getContext();
  Type *I32 = Type::getInt32Ty(Ctx);

  AllocaInst *Slot = B.CreateAlloca(I32, nullptr, "dci.slot");
  Value *V = ConstantInt::get(I32, static_cast<uint32_t>(RNG.next32()));
  B.CreateStore(V, Slot);

  for (unsigned I = 0; I < NumOps; ++I) {
    Value *Cur = B.CreateLoad(I32, Slot, "dci.v");
    auto K = ConstantInt::get(I32, static_cast<uint32_t>(RNG.next32() | 1u));
    Value *Next;
    switch (RNG.nextRange(0, 4)) {
    case 0:  Next = B.CreateAdd(Cur, K, "dci.add"); break;
    case 1:  Next = B.CreateSub(Cur, K, "dci.sub"); break;
    case 2:  Next = B.CreateXor(Cur, K, "dci.xor"); break;
    default: Next = B.CreateMul(Cur, K, "dci.mul"); break;
    }
    B.CreateStore(Next, Slot);
  }
}

PreservedAnalyses DeadCodeInsertionPass::run(Function &F,
                                             FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "dci"))
    return PreservedAnalyses::all();
  if (F.isDeclaration() || F.size() < 2)
    return PreservedAnalyses::all();
  // 4.1.10: Dead blocks inserted between an invoke and its landing pad would
  // violate EH predecessor constraints.  Skip EH functions entirely.
  if (hasExceptionHandling(F))
    return PreservedAnalyses::all();

  PRNG &RNG = getModulePRNG();
  uint32_t Prob = kagura::opt::DCIProb;
  if (Prob == 0) Prob = 40;
  if (Prob > 100) Prob = 100;

  LLVMContext &Ctx = F.getContext();

  // Snapshot live blocks to avoid iterating over newly inserted dead blocks
  std::vector<BasicBlock *> LiveBlocks;
  LiveBlocks.reserve(F.size());
  for (auto &BB : F)
    LiveBlocks.push_back(&BB);

  bool Changed = false;
  for (BasicBlock *LiveBB : LiveBlocks) {
    if (LiveBB == &F.getEntryBlock())
      continue;
    // Probabilistic insertion
    if ((RNG.next32() % 100) >= Prob)
      continue;

    // Create dead block immediately after LiveBB
    BasicBlock *Dead = BasicBlock::Create(Ctx, "dci.dead", &F);
    Dead->moveAfter(LiveBB);

    IRBuilder<> B(Dead);
    unsigned NumOps = static_cast<unsigned>(RNG.nextRange(3, 9));
    fillJunkBody(B, RNG, NumOps);
    B.CreateUnreachable();

    Changed = true;
  }

  if (!Changed)
    return PreservedAnalyses::all();

  PreservedAnalyses PA;
  PA.preserveSet<CFGAnalyses>();
  return PA;
}

} // namespace kagura
