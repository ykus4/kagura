//===-- Telemetry.cpp - Cheat signal telemetry injection -------------------===//
//
// 4.5.6: Inserts calls to a user-provided telemetry callback at the entry of
// selected functions to collect cheat-indicative behavioral signals.
//
// The injected call is:
//   void kagura_telemetry_event(uint32_t event_id);
//
// where event_id is a per-function compile-time constant derived from the
// function name hash.  The game backend can use these event IDs to detect
// anomalous call patterns (e.g. a function being called at an impossible rate).
//
// The pass only instruments functions that:
//   1. Are user-space (no kagura_ prefix)
//   2. Pass the shouldObfuscate() filter
//   3. Have the kagura_telemetry annotation OR match the global flag
//
// Pass key:   "kagura-telemetry"
// CLI flag:   -kagura-telemetry
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

PreservedAnalyses TelemetryPass::run(Function &F, FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "telemetry"))
    return PreservedAnalyses::all();
  if (F.isDeclaration())
    return PreservedAnalyses::all();

  Module &M     = *F.getParent();
  LLVMContext &Ctx = M.getContext();

  // Declare kagura_telemetry_event(uint32_t event_id)
  auto *VoidTy  = Type::getVoidTy(Ctx);
  auto *Int32Ty = Type::getInt32Ty(Ctx);
  auto *FTy     = FunctionType::get(VoidTy, {Int32Ty}, false);
  FunctionCallee TelFn = M.getOrInsertFunction("kagura_telemetry_event", FTy);

  // Compute event ID from function name
  uint32_t EventID = fnv1a32(F.getName());

  // Insert call at function entry (after alloca block, first non-alloca point)
  BasicBlock &Entry = F.getEntryBlock();
  Instruction *InsertPt = &*Entry.getFirstInsertionPt();
  IRBuilder<> B(InsertPt);
  B.CreateCall(TelFn, {ConstantInt::get(Int32Ty, EventID)});

  markObfuscated(F, "telemetry");
  return PreservedAnalyses::none();
}

} // namespace kagura
