//===-- Passes/CFG.h - Control-flow structure passes ----------------------===//
//
// Passes that change the shape of the control-flow graph. Sources in
// lib/Transforms/CFG/.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "llvm/IR/PassManager.h"

namespace kagura {

/// Flattens function CFG into a switch-based dispatcher.
struct ControlFlowFlatteningPass
    : public llvm::PassInfoMixin<ControlFlowFlatteningPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Injects bogus control flow with opaque predicates.
struct BogusControlFlowPass
    : public llvm::PassInfoMixin<BogusControlFlowPass> {
  uint32_t Probability = 30; // % of basic blocks to obfuscate
  uint32_t Iterations  = 1;

  BogusControlFlowPass() = default;
  BogusControlFlowPass(uint32_t Prob, uint32_t Iter)
      : Probability(Prob), Iterations(Iter) {}

  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Replaces direct function calls with indirect calls through per-callsite
/// function pointer globals, defeating static call graph analysis.
struct IndirectBranchPass : public llvm::PassInfoMixin<IndirectBranchPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Obfuscates loop structures: bogus dead counters, opaque invariant branches,
/// and 64-bit induction variable splitting into i_low / i_high halves.
struct LoopTransformPass : public llvm::PassInfoMixin<LoopTransformPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Splits large basic blocks at random points by inserting unconditional
/// branches, inflating CFG node count without changing semantics.
struct BasicBlockSplittingPass
    : public llvm::PassInfoMixin<BasicBlockSplittingPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Randomly shuffles the physical order of basic blocks within a function.
/// CFG edges are unchanged; only the layout is permuted to confuse linear
/// disassemblers and increase reverse-engineering cost.
struct BasicBlockReorderingPass
    : public llvm::PassInfoMixin<BasicBlockReorderingPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Inserts syntactically plausible but semantically dead basic blocks
/// (terminated by `unreachable`) into functions to inflate CFG complexity
/// and mislead static analysis tools.
struct DeadCodeInsertionPass
    : public llvm::PassInfoMixin<DeadCodeInsertionPass> {
  llvm::PreservedAnalyses run(llvm::Function &F,
                               llvm::FunctionAnalysisManager &FAM);
  static bool isRequired() { return false; }
};

/// Splits large functions (>= 5 BBs) by extracting eligible interior basic
/// blocks into separate outlined helper functions and replacing each extracted
/// block with a call + unconditional branch to the original successor.
/// Eligible blocks: no PHI nodes, no calls, unconditional branch terminator,
/// successor has no PHI nodes, live-in count <= 8.
struct FunctionSplitPass : public llvm::PassInfoMixin<FunctionSplitPass> {
  llvm::PreservedAnalyses run(llvm::Module &M,
                               llvm::ModuleAnalysisManager &MAM);
  static bool isRequired() { return false; }
};

} // namespace kagura
