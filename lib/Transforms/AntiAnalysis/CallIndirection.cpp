//===-- CallIndirection.cpp - External call thunk table obfuscation -------===//
//
// Routes calls to external functions (declarations only, e.g. libc / system
// APIs) through a runtime-resolved thunk table, defeating IDA's static import
// table analysis and making it impossible to determine which library functions
// are called without running the binary.
//
// For each unique external callee discovered across the whole module:
//   1. A slot is reserved in the global array __kagura_thunk_table ([N x ptr],
//      zeroinitializer so it is placed in BSS).
//   2. Every call site is replaced with:
//        %p = load ptr, ptr getelementptr(__kagura_thunk_table, 0, slot_idx)
//        call %p(original_args...)
//   3. A module constructor (kagura_init_thunk_table, priority 65535) calls
//      dlsym(RTLD_DEFAULT, "symbol_name") for each slot at startup, populating
//      the table before any user code runs.
//
// Calls that are skipped:
//   - Calls to defined (non-declaration) functions in this module
//   - LLVM intrinsics (name starts with "llvm.")
//   - Kagura runtime helpers (name starts with "kagura_")
//   - Indirect calls (callee already unknown statically)
//   - Calls with funclet operand bundles
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/AntiAnalysis.h"
#include "kagura/Utils.h"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <map>
#include <string>
#include <vector>

using namespace llvm;

namespace kagura {

// ---- Helpers ----

/// Return true if this call has a funclet operand bundle (prevents safe
/// cloning into an indirect call).
static bool hasFuncletBundle(const CallInst &CI) {
  for (unsigned I = 0, E = CI.getNumOperandBundles(); I != E; ++I)
    if (CI.getOperandBundleAt(I).getTagName() == "funclet")
      return true;
  return false;
}

/// Return true if Callee is an external function that should be intercepted.
static bool isInterceptableExternal(const Function &Callee) {
  if (!Callee.isDeclaration())
    return false; // defined in this module — IndirectBranch handles those
  if (Callee.isIntrinsic())
    return false;
  if (Callee.getName().starts_with("llvm."))
    return false;
  if (Callee.getName().starts_with("kagura_"))
    return false;
  return true;
}

// ---- Collect phase ----

/// Scan the whole module and return every unique external callee that should
/// be thunked, preserving first-encounter order.
static std::vector<Function *> collectExternalCallees(Module &M) {
  std::map<Function *, unsigned> Seen;
  std::vector<Function *> Ordered;

  for (auto &F : M) {
    if (F.isDeclaration())
      continue;
    for (auto &BB : F) {
      for (auto &I : BB) {
        auto *CI = dyn_cast<CallInst>(&I);
        if (!CI)
          continue;
        Function *Callee = CI->getCalledFunction();
        if (!Callee)
          continue; // indirect already
        if (!isInterceptableExternal(*Callee))
          continue;
        if (hasFuncletBundle(*CI))
          continue;
        if (Seen.count(Callee) == 0) {
          Seen[Callee] = static_cast<unsigned>(Ordered.size());
          Ordered.push_back(Callee);
        }
      }
    }
  }
  return Ordered;
}

// ---- Build thunk table global ----

/// Create `@__kagura_thunk_table = internal global [N x ptr] zeroinitializer`
static GlobalVariable *buildThunkTable(Module &M, unsigned N) {
  LLVMContext &Ctx   = M.getContext();
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  ArrayType  *ArrTy  = ArrayType::get(PtrTy, N);

  auto *GV = new GlobalVariable(
      M,
      ArrTy,
      /*isConstant=*/false,
      GlobalValue::InternalLinkage,
      ConstantAggregateZero::get(ArrTy),
      "__kagura_thunk_table");
  GV->setAlignment(Align(8));
  return GV;
}

// ---- Build constructor ----

/// Declare `void *dlsym(void *, const char *)` in the module (idempotent).
static Function *getOrDeclareDlsym(Module &M) {
  LLVMContext &Ctx   = M.getContext();
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  auto *FTy = FunctionType::get(PtrTy, {PtrTy, PtrTy}, /*isVarArg=*/false);
  return cast<Function>(M.getOrInsertFunction("dlsym", FTy).getCallee());
}

/// Build the constructor `void kagura_init_thunk_table(void)` that fills each
/// slot of the thunk table via dlsym(RTLD_DEFAULT, "name").
///
/// Rather than embed a platform-specific RTLD_DEFAULT constant in IR, we
/// call the runtime helper `kagura_rtld_default_handle()` which returns the
/// correct handle for the current platform (NULL on Linux/Android,
/// (void*)-2 on macOS/iOS).  The helper is defined in anti_debug.c.
static Function *buildInitConstructor(Module &M, GlobalVariable *ThunkTable,
                                       const std::vector<Function *> &Callees) {
  LLVMContext  &Ctx   = M.getContext();
  PointerType  *PtrTy = PointerType::getUnqual(Ctx);
  auto *Int64Ty = Type::getInt64Ty(Ctx);

  // void kagura_init_thunk_table(void)
  auto *Ctor = createCtorFunction(M, "kagura_init_thunk_table");
  Ctor->addFnAttr(Attribute::NoInline);
  Ctor->addFnAttr(Attribute::NoUnwind);

  auto *Entry = &Ctor->getEntryBlock();
  IRBuilder<> B(Entry);

  Function *DlsymFn        = getOrDeclareDlsym(M);
  FunctionType *DlsymFTy   = DlsymFn->getFunctionType();
  ArrayType    *TableArrTy = cast<ArrayType>(ThunkTable->getValueType());

  // Get RTLD_DEFAULT from a runtime helper to handle macOS vs Linux difference.
  // kagura_rtld_default_handle() returns (void*)-2 on Apple, NULL on Linux.
  auto *RtldFTy = FunctionType::get(PtrTy, false);
  auto *RtldFn  = cast<Function>(
      M.getOrInsertFunction("kagura_rtld_default_handle", RtldFTy).getCallee());
  RtldFn->addFnAttr(Attribute::NoUnwind);
  Value *RtldDefault = B.CreateCall(RtldFTy, RtldFn, {}, "rtld_default");

  for (unsigned Idx = 0, N = static_cast<unsigned>(Callees.size());
       Idx < N; ++Idx) {
    StringRef SymName = Callees[Idx]->getName();

    // Build a private global for the symbol name string
    Constant *NameStr = ConstantDataArray::getString(Ctx, SymName, /*AddNull=*/true);
    auto *NameGV = new GlobalVariable(M, NameStr->getType(),
                                      /*isConstant=*/true,
                                      GlobalValue::PrivateLinkage,
                                      NameStr,
                                      "__kagura_sym_" + SymName.str());
    NameGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    NameGV->setAlignment(Align(1));

    // Cast to ptr for the dlsym call
    Value *NamePtr = B.CreateInBoundsGEP(
        NameGV->getValueType(), NameGV,
        {ConstantInt::get(Int64Ty, 0), ConstantInt::get(Int64Ty, 0)},
        "sym_name_ptr");

    // resolved = dlsym(RTLD_DEFAULT, "name")
    Value *Resolved = B.CreateCall(DlsymFTy, DlsymFn,
                                   {RtldDefault, NamePtr}, "resolved");

    // Store into table[Idx]
    Value *SlotPtr = B.CreateInBoundsGEP(
        TableArrTy, ThunkTable,
        {ConstantInt::get(Int64Ty, 0), ConstantInt::get(Int64Ty, Idx)},
        "slot_ptr");
    B.CreateAlignedStore(Resolved, SlotPtr, Align(8));
  }

  B.CreateRetVoid();
  return Ctor;
}

// ---- Rewrite call sites ----

/// Replace every interceptable call to Callee with an indirect call through
/// the thunk table slot at SlotIdx.  Returns the number of call sites rewritten.
static unsigned rewriteCallSites(Function &Callee, unsigned SlotIdx,
                                  GlobalVariable *ThunkTable, Module &M) {
  LLVMContext &Ctx      = M.getContext();
  auto *Int64Ty         = Type::getInt64Ty(Ctx);
  ArrayType *TableArrTy = cast<ArrayType>(ThunkTable->getValueType());
  PointerType *PtrTy    = PointerType::getUnqual(Ctx);
  FunctionType *CalleeFTy = Callee.getFunctionType();

  // Collect all call sites first — mutating while iterating is unsafe.
  SmallVector<CallInst *, 16> Worklist;
  for (auto &U : Callee.uses()) {
    auto *CI = dyn_cast<CallInst>(U.getUser());
    if (!CI)
      continue;
    if (CI->getCalledOperand() != &Callee)
      continue; // used as a value, not as callee
    if (hasFuncletBundle(*CI))
      continue;
    Worklist.push_back(CI);
  }

  unsigned Count = 0;
  for (auto *CI : Worklist) {
    IRBuilder<> B(CI);

    // %slot_ptr = getelementptr __kagura_thunk_table, 0, SlotIdx
    Value *SlotPtr = B.CreateInBoundsGEP(
        TableArrTy, ThunkTable,
        {ConstantInt::get(Int64Ty, 0), ConstantInt::get(Int64Ty, SlotIdx)},
        "ci.slot_ptr");

    // %fn_ptr = load ptr, ptr %slot_ptr
    Value *FnPtr = B.CreateAlignedLoad(PtrTy, SlotPtr, Align(8),
                                       /*isVolatile=*/false, "ci.fn_ptr");

    // Collect args and operand bundles
    SmallVector<Value *, 8> Args(CI->args());
    SmallVector<OperandBundleDef, 2> Bundles;
    for (unsigned I = 0, E = CI->getNumOperandBundles(); I != E; ++I)
      Bundles.emplace_back(CI->getOperandBundleAt(I));

    CallInst *NewCI = B.CreateCall(CalleeFTy, FnPtr, Args, Bundles, "");
    NewCI->setCallingConv(CI->getCallingConv());
    NewCI->setAttributes(CI->getAttributes());
    NewCI->setTailCallKind(CI->getTailCallKind());
    NewCI->setDebugLoc(CI->getDebugLoc());
    if (CI->getType()->isFPOrFPVectorTy())
      NewCI->copyFastMathFlags(CI);

    if (!CI->getType()->isVoidTy())
      CI->replaceAllUsesWith(NewCI);
    CI->eraseFromParent();
    ++Count;
  }
  return Count;
}

// ---- Pass entry point ----

PreservedAnalyses CallIndirectionPass::run(Module &M,
                                            ModuleAnalysisManager &) {
  // No `if (!opt::CI) return` here: whether this pass runs is decided when the
  // pipeline is built (Plugin.cpp), and `opt -passes=kagura-ci` never sets the
  // flag — so re-checking it made that entry point a silent no-op. See the
  // note on shouldObfuscate() in Utils.h.

  // 1. Collect unique external callees across the module.
  std::vector<Function *> Callees = collectExternalCallees(M);
  if (Callees.empty())
    return PreservedAnalyses::all();

  // 2. Build the thunk table global.
  GlobalVariable *ThunkTable =
      buildThunkTable(M, static_cast<unsigned>(Callees.size()));

  // 3. Rewrite every call site for each external callee.
  for (unsigned Idx = 0; Idx < Callees.size(); ++Idx)
    rewriteCallSites(*Callees[Idx], Idx, ThunkTable, M);

  // 4. Build and register the constructor that fills the table at startup.
  Function *Ctor = buildInitConstructor(M, ThunkTable, Callees);
  // Priority 65535 = very late, after most other constructors.
  appendKaguraCtor(M, Ctor, CtorPriority::ThunkTable);

  return PreservedAnalyses::none();
}

} // namespace kagura
