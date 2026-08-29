//===-- IndirectBranch.cpp - Indirect call dispatch table obfuscation -----===//
//
// Replaces direct function calls with indirect calls through per-callsite
// function pointer globals, making static call graph analysis significantly
// harder for reverse engineers and binary analysis tools.
//
// For each qualifying direct CallInst:
//   1. A private GlobalVariable of function-pointer type is created with the
//      callee as its initializer and a randomised name (__kagura_fptr_<hex>).
//   2. The function pointer is loaded at runtime from that global.
//   3. A new indirect CallInst is built from the loaded pointer, preserving
//      the original calling convention, attributes, and operand bundle.
//   4. The original direct call is replaced and erased.
//
// Calls that are skipped:
//   - Declaration-only callees (no body in this module)
//   - Callees whose name starts with "kagura_" (our own runtime helpers)
//   - Callees defined in a different Module (cross-module indirect call would
//     require at least a declaration in this module, which we already check via
//     isDeclaration(); this guard is kept explicit for clarity)
//   - LLVM intrinsics
//   - Calls with operand bundles that would make cloning unsafe (e.g. deopt,
//     funclet bundles that require a direct callee token)
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/CFG.h"
#include "kagura/Utils.h"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;

namespace kagura {

// ---- Helpers ----

/// Generate a randomised hex suffix for the fptr global name.
static std::string randomSuffix(PRNG &RNG) {
  uint64_t Val = RNG.next();
  std::string S;
  llvm::raw_string_ostream OS(S);
  OS << llvm::format_hex_no_prefix(Val, 16);
  return OS.str();
}

/// Return true if this call has operand bundles that prevent safe cloning
/// into an indirect call (funclet bundles encode the callee's identity in
/// the bundle token; deopt bundles are generally safe but kept for conservatism
/// if the bundle tag is unrecognised).
static bool hasUnsafeOperandBundles(const CallInst &CI) {
  for (unsigned i = 0, e = CI.getNumOperandBundles(); i != e; ++i) {
    OperandBundleUse B = CI.getOperandBundleAt(i);
    // "funclet" bundles tie the call to a specific funclet pad — skip.
    if (B.getTagName() == "funclet")
      return true;
  }
  return false;
}

/// Return true if Callee is a function defined in the same Module as Caller.
static bool isSameModuleDefinition(const Function &Caller,
                                   const Function &Callee) {
  return !Callee.isDeclaration() && Callee.getParent() == Caller.getParent();
}

// ---- Per-call transformation ----

/// Replace a single direct CallInst with an indirect call through a freshly
/// created function-pointer GlobalVariable.  Returns the new CallInst, or
/// nullptr if the call was not transformed.
static CallInst *indirectifyCall(CallInst &CI, Function &ParentFn, PRNG &RNG) {
  Function *Callee = CI.getCalledFunction();
  if (!Callee)
    return nullptr; // already indirect

  // --- Skip predicates ---
  if (Callee->isIntrinsic())
    return nullptr;
  if (!isSameModuleDefinition(ParentFn, *Callee))
    return nullptr;
  if (isKaguraSymbol(Callee->getName()))
    return nullptr;
  if (hasUnsafeOperandBundles(CI))
    return nullptr;
  // musttail requires the call to be immediately followed by a ret of its
  // result and the signatures to match exactly. Routing it through a loaded
  // function pointer breaks that contract; FunctionSplit already declines
  // these for the same reason.
  if (CI.isMustTailCall())
    return nullptr;

  Module &M          = *ParentFn.getParent();
  LLVMContext &Ctx   = M.getContext();
  // The *call site's* type, not the callee's. They differ whenever a
  // declaration in scope disagrees with the definition — pre-prototype C, a
  // varargs/non-varargs mismatch, a bitcast call — and rebuilding the call
  // with the callee's type then asserts on the argument count or types
  // instead of declining.
  FunctionType *FTy  = CI.getFunctionType();

  // --- Create the function-pointer global ---
  // Type: ptr (opaque pointer mode) or FTy* in typed-pointer builds.
  // We store it as the callee's function-pointer type so the load returns
  // the right pointer type for the indirect call.
  PointerType *FPtrTy = PointerType::getUnqual(Ctx);
  std::string GVName  = "__kagura_fptr_" + randomSuffix(RNG);

  auto *FPtrGV = new GlobalVariable(
      M,
      /*Ty=*/FPtrTy,
      /*isConstant=*/false, // non-const so optimisers don't fold it away
      GlobalValue::PrivateLinkage,
      /*Initializer=*/Callee,
      GVName);
  FPtrGV->setAlignment(Align(8));
  // Mark as used so the linker doesn't strip it under LTO.
  // (A PrivateLinkage global with a load cannot be stripped, but this keeps
  // intent explicit.)

  // --- Emit: load fptr, then indirect call ---
  IRBuilder<> B(&CI);
  Value *LoadedFPtr = B.CreateAlignedLoad(FPtrTy, FPtrGV, Align(8),
                                          /*isVolatile=*/false, "ibr.fptr");

  // Rebuild the call through the shared helper rather than by hand: the
  // "copy cc, attributes, tail-call kind, debug location and fast-math
  // flags" block was open-coded in four places, and one copy had already
  // lost copyFastMathFlags. See replaceCalleeWith() in Utils.h.
  return replaceCalleeWith(&CI, FTy, LoadedFPtr);
}

// ---- Main per-function worker ----

static bool indirectifyCalls(Function &F, PRNG &RNG) {
  if (F.isDeclaration())
    return false;

  // Collect all direct calls first; mutating the instruction list while
  // iterating over it is unsafe.
  SmallVector<CallInst *, 32> Worklist;
  for (auto &BB : F) {
    // Don't touch kagura's own injected blocks
    if (isGenerated(BB) || BB.getName().starts_with("kagura."))
      continue;
    for (auto &I : BB) {
      auto *CI = dyn_cast<CallInst>(&I);
      if (!CI)
        continue;
      if (CI->getCalledFunction()) // only direct calls
        Worklist.push_back(CI);
    }
  }

  bool Changed = false;
  for (auto *CI : Worklist)
    if (indirectifyCall(*CI, F, RNG))
      Changed = true;

  return Changed;
}

// ---- Pass entry point ----

PreservedAnalyses IndirectBranchPass::run(Function &F,
                                           FunctionAnalysisManager &) {
  if (!shouldObfuscate(F, "ibr"))
    return PreservedAnalyses::all();

  auto &RNG    = getModulePRNG(*F.getParent());
  bool Changed = indirectifyCalls(F, RNG);
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
