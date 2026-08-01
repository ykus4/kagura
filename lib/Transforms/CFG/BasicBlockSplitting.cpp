//===-- BasicBlockSplitting.cpp - Split large basic blocks ----------------===//
//
// Splits large basic blocks into smaller pieces by inserting unconditional
// branches at random split points.  The effect is purely structural: the CFG
// gains more nodes, making decompiler output harder to read and inflating the
// apparent complexity of the function.
//
// Unlike ControlFlowFlattening (which restructures the entire CFG) this pass
// makes only local changes and is safe to run alongside other passes without
// risk of invalidating PHI nodes or dominator trees in complex ways.
//
// Algorithm per function
// ----------------------
//   1. Collect all basic blocks.
//   2. For each BB with more than MinInstructions non-terminator instructions:
//      a. Pick a random split point in [MinInstructions, size-1).
//      b. Call llvm::SplitBlock() at that instruction.
//      c. Repeat up to MaxSplitsPerBlock times per original block.
//
// CLI flags
// ---------
//   -kagura-bbs                Enable basic block splitting
//   -kagura-bbs-min=<N>        Minimum instructions before a split point (default: 3)
//   -kagura-bbs-max-splits=<N> Maximum splits per block (default: 2)
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <vector>

using namespace llvm;

static cl::opt<uint32_t> BBSMin(
    "kagura-bbs-min",
    cl::desc("[Kagura] Min instructions before split point (default: 3)"),
    cl::init(3));

static cl::opt<uint32_t> BBSMaxSplits(
    "kagura-bbs-max-splits",
    cl::desc("[Kagura] Max splits per block (default: 2)"),
    cl::init(2));

namespace kagura {

PreservedAnalyses BasicBlockSplittingPass::run(Function &F,
                                               FunctionAnalysisManager &AM) {
  if (!shouldObfuscate(F, "bbs"))
    return PreservedAnalyses::all();
  if (F.isDeclaration())
    return PreservedAnalyses::all();
  // 4.1.10: Skip functions with exception-handling constructs.  SplitBlock
  // does not update landing-pad predecessor lists, so splitting EH blocks
  // can produce invalid IR.
  if (hasExceptionHandling(F))
    return PreservedAnalyses::all();

  PRNG &RNG = getModulePRNG();
  uint32_t Min       = BBSMin   > 0 ? BBSMin   : 3u;
  uint32_t MaxSplits = BBSMaxSplits > 0 ? BBSMaxSplits : 2u;

  // Snapshot: only split original blocks, not ones we create in this pass.
  std::vector<BasicBlock *> Blocks;
  Blocks.reserve(F.size());
  for (auto &BB : F)
    Blocks.push_back(&BB);

  bool Changed = false;

  for (BasicBlock *BB : Blocks) {
    // Count non-terminator instructions
    unsigned Count = 0;
    for (auto &I : *BB)
      if (!I.isTerminator())
        ++Count;

    if (Count <= Min)
      continue;

    // Perform up to MaxSplits splits on this block.
    // After each split the "tail" is a new block; we do not recurse into it.
    BasicBlock *Current = BB;
    for (uint32_t S = 0; S < MaxSplits; ++S) {
      // Recount instructions in the current (possibly already-split) block
      unsigned CurCount = 0;
      for (auto &I : *Current)
        if (!I.isTerminator())
          ++CurCount;

      if (CurCount <= Min)
        break;

      // Pick a random split point in [Min, CurCount)
      unsigned SplitIdx = static_cast<unsigned>(
          RNG.nextRange(Min, CurCount));

      // Advance iterator to the split point
      auto It = Current->begin();
      for (unsigned I = 0; I < SplitIdx; ++I)
        ++It;

      // Skip PHI nodes — SplitBlock requires the split point to be non-PHI
      while (isa<PHINode>(*It))
        ++It;

      if (It == Current->end() || It->isTerminator())
        break;

      // SplitBlock inserts an unconditional branch from Current to the new BB.
      BasicBlock *NewBB = SplitBlock(Current, &*It);
      Changed = true;

      // Continue splitting from the new tail block
      Current = NewBB;
    }
  }

  if (!Changed)
    return PreservedAnalyses::all();

  // SplitBlock preserves the dominator tree but invalidates CFGAnalyses.
  PreservedAnalyses PA;
  PA.preserve<DominatorTreeAnalysis>();
  return PA;
}

} // namespace kagura
