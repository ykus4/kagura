//===-- FunctionSplit.cpp - Function splitting / CFG fragmentation --------===//
//
// Splits large functions by extracting "cold" basic blocks (those not on the
// entry/return path) into separate outlined helper functions, then replacing
// the original block with a call to the helper followed by an unconditional
// branch to the block's first successor.
//
// The net effect is that decompilers see a fragmented call graph instead of a
// single large function body, making manual analysis significantly harder.
//
// Pass key:   "fsplit"
// CLI flag:   -kagura-fsplit
//
// Eligibility criteria for a function:
//   - Not a declaration, not an intrinsic, not vararg
//   - shouldObfuscate() returns true
//   - Has >= 5 basic blocks (splitting tiny functions isn't useful)
//
// Eligibility criteria for a basic block:
//   - Not the entry block
//   - Does not contain a ReturnInst or UnreachableInst (exit blocks)
//   - Has no PHI nodes (live-in analysis via alloca is already done before
//     this pass; skip blocks that still have phis to be safe)
//   - Has no call/invoke instructions (avoids ABI and stack-frame complexity)
//   - Has exactly one predecessor and one successor (linear chain member)
//
// Extraction strategy (manual; avoids CodeExtractor's limitations):
//   For each eligible block BB with predecessor Pred and successor Succ:
//     1. Collect all Values defined *outside* BB but used *inside* BB
//        (live-in set), capped at MaxArgs to keep the ABI tractable.
//     2. Create a new Function F_helper(live-in...) -> void in the same module,
//        with internal linkage and an obfuscated name.
//     3. Clone BB's instructions into F_helper's entry block, rewriting
//        operand references to the new function's arguments.
//     4. Append an unconditional branch to a new "ret void" block in F_helper
//        (the block's own terminator is replaced by ret void if the block
//        originally branched unconditionally to Succ).
//     5. In the original function, replace BB's content with:
//          call void @F_helper(live-in...)
//          br Succ
//        and delete the now-empty original block.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "kagura-fsplit"

#include "kagura/Options.h"
#include "kagura/Passes/CFG.h"
#include "kagura/Utils.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <vector>
#include <string>

using namespace llvm;

namespace kagura {

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

/// Returns true if a call instruction is safe to extract into a helper:
///   - Direct call to a known function (not indirect, not inline asm)
///   - Not an invoke (no EH edge)
///   - Not a call to an intrinsic (they may have special semantics / sideband
///     effects that break when moved to a different function frame)
///   - Not a variadic call (ABI complexity)
///   - Not a musttail call (it must be immediately followed by a matching ret)
static bool isLeafSafeCall(const CallInst &CI) {
  if (CI.isInlineAsm()) return false;
  if (CI.isIndirectCall()) return false;
  if (CI.isMustTailCall()) return false;
  Function *Callee = CI.getCalledFunction();
  if (!Callee) return false;
  if (Callee->isIntrinsic()) return false;
  if (Callee->isVarArg()) return false;
  return true;
}

/// Returns true if BB contains any instruction that is unsafe to extract:
///   - InvokeInst (EH edge into landing pad)
///   - Unsafe CallInst (indirect, intrinsic, vararg)
static bool hasUnsafeCallInsts(const BasicBlock &BB) {
  for (const auto &I : BB) {
    if (isa<InvokeInst>(I)) return true;
    if (const auto *CI = dyn_cast<CallInst>(&I))
      if (!isLeafSafeCall(*CI)) return true;
  }
  return false;
}

/// Returns true if BB contains a return or unreachable terminator.
static bool isExitBlock(const BasicBlock &BB) {
  const Instruction *Term = BB.getTerminator();
  return isa<ReturnInst>(Term) || isa<UnreachableInst>(Term);
}

/// Collect all Values that are defined *outside* BB but used *inside* BB.
/// These become the live-in arguments of the outlined helper.
static std::vector<Value *> collectLiveIns(BasicBlock *BB) {
  std::vector<Value *> LiveIns;
  // Track values already added to avoid duplicates.
  SmallPtrSet<Value *, 16> Seen;

  for (Instruction &I : *BB) {
    for (Use &U : I.operands()) {
      Value *V = U.get();
      // Constants, globals, and inline asm are not live-ins.
      if (isa<Constant>(V) || isa<BasicBlock>(V) || isa<MetadataAsValue>(V))
        continue;
      // Arguments and instructions defined in OTHER blocks are live-ins.
      if (auto *Inst = dyn_cast<Instruction>(V)) {
        if (Inst->getParent() == BB)
          continue; // defined inside BB, not a live-in
      }
      if (Seen.insert(V).second)
        LiveIns.push_back(V);
    }
  }
  return LiveIns;
}

/// Collect all instructions defined *inside* BB whose value is used *outside*
/// BB.  Every one of them has to be handed back to the caller once the block
/// has been outlined, otherwise the surrounding function is left referring to
/// instructions that no longer exist.
static std::vector<Instruction *> collectLiveOuts(BasicBlock *BB) {
  std::vector<Instruction *> LiveOuts;
  for (Instruction &I : *BB) {
    if (I.isTerminator() || I.getType()->isVoidTy())
      continue;
    for (User *U : I.users()) {
      auto *UI = dyn_cast<Instruction>(U);
      if (!UI || UI->getParent() != BB) {
        LiveOuts.push_back(&I);
        break;
      }
    }
  }
  return LiveOuts;
}

/// Returns true if BB holds something that cannot be relocated into another
/// function frame even though its instructions look harmless:
///   - allocas (their storage would die when the helper returns)
///   - token-typed values (cannot be spilled through memory)
///   - swifterror values (need matching parameter attributes)
static bool hasUnrelocatableInsts(const BasicBlock &BB) {
  for (const Instruction &I : BB) {
    if (isa<AllocaInst>(I))
      return true;
    if (I.getType()->isTokenTy())
      return true;
    if (I.isEHPad())
      return true;
    for (const Use &U : I.operands())
      if (U.get()->isSwiftError())
        return true;
  }
  return false;
}

/// Build an obfuscated name for the outlined helper.
static std::string makeHelperName(const Function &Parent, unsigned Index,
                                  PRNG &RNG) {
  // Use a hex suffix derived from the PRNG so names look random.
  uint64_t Tag = RNG.next();
  std::string Name;
  raw_string_ostream OS(Name);
  OS << "__kg_" << Parent.getName() << "_bb" << Index
     << "_" << format_hex_no_prefix(Tag & 0xFFFFFF, 6);
  OS.flush();
  return Name;
}

// --------------------------------------------------------------------------
// Core extraction logic
// --------------------------------------------------------------------------

/// Maximum number of live-in arguments we are willing to pass.
/// Blocks with more live-ins are skipped to keep the generated ABI sane.
static constexpr unsigned MaxArgs = 8;

/// Try to extract BB into a new helper function.
/// Returns true if extraction succeeded and the CFG was modified.
static bool extractBlock(BasicBlock *BB, unsigned Index, PRNG &RNG) {
  Function *ParentFn = BB->getParent();
  Module *M = ParentFn->getParent();
  LLVMContext &Ctx = M->getContext();

  // --- Precondition checks (guard) ---

  // Skip if PHI nodes are present.
  if (isa<PHINode>(BB->front()))
    return false;

  // Skip if the block contains unsafe calls (invoke, indirect, intrinsic, vararg).
  // Simple direct calls to non-intrinsic functions are safe to extract.
  if (hasUnsafeCallInsts(*BB))
    return false;

  // Skip exit blocks (return / unreachable).
  if (isExitBlock(*BB))
    return false;

  // Skip blocks holding values that cannot survive the move to another frame.
  if (hasUnrelocatableInsts(*BB))
    return false;

  // We only handle blocks with exactly one unconditional branch as terminator.
  auto *Term = dyn_cast<BranchInst>(BB->getTerminator());
  if (!Term || !Term->isUnconditional())
    return false;

  // Nothing to outline if the block is just a branch.
  if (&BB->front() == Term)
    return false;

  // --- Live-in / live-out computation ---

  std::vector<Value *> LiveIns = collectLiveIns(BB);

  // Values computed in BB but consumed by the rest of the function.  The helper
  // returns void, so each of them is handed back through a caller-allocated
  // out-parameter: the helper stores into it, the caller reloads it right after
  // the call and rewires the outside uses to that load.
  //
  // Getting this wrong is what made the pass miscompile: the previous version
  // simply erased BB's instructions, leaving every outside user (and every
  // later instruction of BB itself, since the erase ran front-to-back) pointing
  // at freed memory.  The recycled allocations then showed up as
  // "PHI node operands are not the same type as the result" — or crashed opt
  // outright.
  std::vector<Instruction *> LiveOuts = collectLiveOuts(BB);

  if (LiveIns.size() + LiveOuts.size() > MaxArgs)
    return false; // too many arguments

  // --- Build the helper function signature ---

  std::vector<Type *> ParamTypes;
  ParamTypes.reserve(LiveIns.size() + LiveOuts.size());
  for (Value *V : LiveIns)
    ParamTypes.push_back(V->getType());
  // The out-parameters point at allocas, so they must use the target's alloca
  // address space rather than a hard-coded 0.
  Type *PtrTy = PointerType::get(Ctx, M->getDataLayout().getAllocaAddrSpace());
  for (unsigned I = 0, E = LiveOuts.size(); I != E; ++I)
    ParamTypes.push_back(PtrTy);

  FunctionType *HelperTy =
      FunctionType::get(Type::getVoidTy(Ctx), ParamTypes, /*isVarArg=*/false);

  std::string HelperName = makeHelperName(*ParentFn, Index, RNG);
  Function *Helper = Function::Create(HelperTy, GlobalValue::InternalLinkage,
                                      HelperName, M);
  Helper->setCallingConv(CallingConv::C);
  // Only claim nounwind when nothing in the block can actually throw, otherwise
  // an unwind edge through the helper would be miscompiled into a terminate.
  if (llvm::all_of(*BB, [](const Instruction &I) {
        const auto *CI = dyn_cast<CallInst>(&I);
        return !CI || CI->doesNotThrow();
      }))
    Helper->addFnAttr(Attribute::NoUnwind);

  // --- Build a mapping: original live-in Value* -> helper argument ---

  ValueToValueMapTy VMap;
  SmallVector<Argument *, 4> OutArgs;
  {
    unsigned Idx = 0;
    for (Argument &Arg : Helper->args()) {
      if (Idx < LiveIns.size()) {
        Arg.setName(LiveIns[Idx]->getName());
        VMap[LiveIns[Idx]] = &Arg;
      } else {
        Arg.setName(LiveOuts[Idx - LiveIns.size()]->getName() + ".out");
        OutArgs.push_back(&Arg);
      }
      ++Idx;
    }
  }

  // --- Clone BB's instructions into the helper ---

  BasicBlock *HelperEntry =
      BasicBlock::Create(Ctx, "entry", Helper);

  // Clone each instruction except the terminator, remapping operands.
  for (auto It = BB->begin(), End = --BB->end(); It != End; ++It) {
    Instruction *Clone = It->clone();
    Clone->setName(It->getName());
    // The clone lives in a different function, so a !dbg location scoped to
    // the parent's DISubprogram would be rejected by the verifier.
    Clone->setDebugLoc(DebugLoc());
    // `tail` is only a hint; drop it rather than re-prove it in the new frame.
    if (auto *CloneCall = dyn_cast<CallInst>(Clone))
      CloneCall->setTailCallKind(CallInst::TCK_None);
    Clone->insertInto(HelperEntry, HelperEntry->end());
    // Record the mapping so later clones can reference this value.
    VMap[&*It] = Clone;
  }

  // Remap operands of all cloned instructions using VMap.
  for (Instruction &I : *HelperEntry) {
    for (Use &U : I.operands()) {
      Value *OldVal = U.get();
      auto It = VMap.find(OldVal);
      if (It != VMap.end())
        U.set(It->second);
    }
  }

  // Write every live-out back through its out-parameter, then return.
  IRBuilder<> HelperB(HelperEntry);
  for (unsigned I = 0, E = LiveOuts.size(); I != E; ++I)
    HelperB.CreateStore(VMap[LiveOuts[I]], OutArgs[I]);
  HelperB.CreateRetVoid();

  // --- Replace BB's body in the parent function with a call + branch ---

  // One static alloca per live-out, in the parent's entry block so that
  // extracting a block inside a loop does not grow the stack per iteration.
  IRBuilder<> AllocaB(&*ParentFn->getEntryBlock().getFirstInsertionPt());
  SmallVector<Value *, 4> OutSlots;
  OutSlots.reserve(LiveOuts.size());
  for (Instruction *LO : LiveOuts)
    OutSlots.push_back(
        AllocaB.CreateAlloca(LO->getType(), nullptr, LO->getName() + ".slot"));

  // Snapshot the original instructions before we add anything to BB.
  std::vector<Instruction *> ToErase;
  for (auto It = BB->begin(), End = --BB->end(); It != End; ++It)
    ToErase.push_back(&*It);

  // Insert the call to the helper before the terminator.
  IRBuilder<> CallBuilder(BB->getTerminator());
  SmallVector<Value *, 8> Args(LiveIns.begin(), LiveIns.end());
  Args.append(OutSlots.begin(), OutSlots.end());
  CallBuilder.CreateCall(HelperTy, Helper, Args);

  // Reload the live-outs and redirect every use outside BB to the reloaded
  // value.  The loads sit at the end of BB, which dominates every block that
  // the original definitions dominated, so this is always legal — including
  // PHI uses whose incoming edge comes from BB.
  for (unsigned I = 0, E = LiveOuts.size(); I != E; ++I) {
    Value *Reloaded = CallBuilder.CreateLoad(LiveOuts[I]->getType(), OutSlots[I],
                                             LiveOuts[I]->getName() + ".reload");
    LiveOuts[I]->replaceUsesOutsideBlock(Reloaded, BB);
  }

  // The existing unconditional branch to Succ stays as-is — we just remove
  // the original instructions that were doing the work.  Erase back-to-front:
  // a value defined in BB can only be used by instructions *later* in BB (the
  // block has no PHIs), so by the time we reach a definition all of its
  // in-block users are already gone, and all of its out-of-block users have
  // been rewired to the reload above.  Erasing front-to-back — what the old
  // code did — destroyed values that were still referenced.
  for (auto It = ToErase.rbegin(), End = ToErase.rend(); It != End; ++It) {
    Instruction *Orig = *It;
    // Unreachable by the argument above; stop rather than free a live value.
    if (!Orig->use_empty())
      break;
    Orig->eraseFromParent();
  }

  return true;
}

// --------------------------------------------------------------------------
// Pass entry point
// --------------------------------------------------------------------------

PreservedAnalyses FunctionSplitPass::run(Module &M,
                                          ModuleAnalysisManager & /*MAM*/) {
  bool AnyChanged = false;
  PRNG &RNG = getModulePRNG(M);

  // Collect functions to process up-front; extractBlock may add new Functions
  // to the module that we must not re-visit.
  std::vector<Function *> Worklist;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    if (F.isVarArg())
      continue;
    if (F.hasFnAttribute(Attribute::Naked))
      continue;
    if (!shouldObfuscate(F, "fsplit"))
      continue;
    if (F.size() < 5)
      continue;
    Worklist.push_back(&F);
  }

  for (Function *F : Worklist) {
    // Collect candidate blocks before we start modifying the function.
    // We snapshot them so that newly created blocks aren't considered.
    std::vector<BasicBlock *> Candidates;
    BasicBlock *Entry = &F->getEntryBlock();

    for (BasicBlock &BB : *F) {
      if (&BB == Entry)
        continue;
      if (isExitBlock(BB))
        continue;
      Candidates.push_back(&BB);
    }

    unsigned ExtractedCount = 0;
    for (unsigned I = 0, E = Candidates.size(); I < E; ++I) {
      BasicBlock *BB = Candidates[I];
      // The block may have been deleted (e.g., merged) in a prior iteration
      // within the same function. Validate the parent is still this function.
      if (BB->getParent() != F)
        continue;

      if (extractBlock(BB, I, RNG)) {
        ++ExtractedCount;
        AnyChanged = true;
      }
    }

    if (ExtractedCount > 0) {
      LLVM_DEBUG(dbgs() << "[kagura-fsplit] " << F->getName() << ": extracted "
                        << ExtractedCount << " block(s)\n");
    }
  }

  return AnyChanged ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura

#undef DEBUG_TYPE
