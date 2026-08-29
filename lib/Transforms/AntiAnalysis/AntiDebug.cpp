//===-- AntiDebug.cpp - Anti-debug / Anti-Frida injection pass ------------===//
//
// Injects anti-analysis checks into module constructors so they run before
// any user code.  Targets: iOS and Android.
//
// iOS checks:
//   - sysctl PT_DENY_ATTACH (self-ptrace)
//   - Check for Frida dylib names in DYLD_INSERT_LIBRARIES
//   - Scan loaded dylibs via dyld_image_count / _dyld_get_image_name
//
// Android checks:
//   - Read /proc/self/maps for frida-agent / substrate entries
//   - Connect to 127.0.0.1:27042 (Frida default port) and abort if open
//   - Check /proc/self/status for TracerPid != 0
//
// The injected checks call abort() on detection.  Users can customize the
// response by providing a weak symbol: void kagura_on_tamper_detected(void).
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes/AntiAnalysis.h"
#include "kagura/Utils.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace kagura {

// Build void kagura_anti_debug_init() — a module constructor
static Function *buildAntiDebugConstructor(Module &M, bool AntiFramework,
                                            bool AntiPtrace) {
  LLVMContext &Ctx = M.getContext();
  IRBuilder<> B(Ctx);

  auto *VoidTy  = Type::getVoidTy(Ctx);
  auto *Int32Ty = Type::getInt32Ty(Ctx);
  auto *Int8Ty  = Type::getInt8Ty(Ctx);
  auto *PtrTy   = PointerType::getUnqual(Ctx);

  auto *FTy = FunctionType::get(VoidTy, false);
  auto *F   = Function::Create(FTy, Function::InternalLinkage,
                               "kagura_anti_debug_init", M);
  F->addFnAttr(Attribute::NoUnwind);

  auto *Entry = BasicBlock::Create(Ctx, "entry", F);
  auto *End   = BasicBlock::Create(Ctx, "end", F);
  B.SetInsertPoint(Entry);
  // Entry block will be terminated after building the check chain.

  // ---- Declare external functions ----

  // abort()
  auto *AbortFTy = FunctionType::get(VoidTy, false);
  auto *AbortFn  = getOrDeclare(M, "abort", AbortFTy);

  // kagura_on_tamper_detected() — weak user hook.
  //
  // Looked up rather than created outright. Function::Create with a name the
  // module already has does not fail, it *renames*: with -kagura-bbcheck also
  // enabled — which the STRONG profile does — BasicBlockChecksum declares this
  // symbol first, and the definition below landed as
  // @kagura_on_tamper_detected.1. That left the real name an undefined
  // declaration and the default implementation a dead copy nobody calls, so
  // the pass silently stopped providing the abort() default it advertises.
  auto *HookFn = getOrDeclare(M, "kagura_on_tamper_detected", FTy);
  HookFn->addFnAttr(Attribute::NoUnwind);
  // Default implementation: just call abort. Only when nothing has defined it
  // yet — a body already present belongs to another kagura pass or to the
  // user, and either outranks this default.
  if (HookFn->isDeclaration()) {
    HookFn->setLinkage(Function::WeakAnyLinkage);
    auto *HookEntry = BasicBlock::Create(Ctx, "entry", HookFn);
    IRBuilder<> HB(HookEntry);
    HB.CreateCall(AbortFn);
    HB.CreateUnreachable();
  }

  if (AntiPtrace) {
    // --- iOS: PT_DENY_ATTACH via sysctl ---
    // int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp,
    //            void *newp, size_t newlen)
    // name = {CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1, getpid()}
    // We use getpid() + sysctl to request PT_DENY_ATTACH (31).
    //
    // For simplicity we use ptrace(PT_DENY_ATTACH=31, 0, 0, 0) on iOS:
    // ptrace is also available on Android for self-detection.

    // int ptrace(int request, pid_t pid, caddr_t addr, int data)
    auto *PtraceFTy = FunctionType::get(
        Int32Ty, {Int32Ty, Int32Ty, PtrTy, Int32Ty}, false);
    auto *PtraceFn = getOrDeclare(M, "ptrace", PtraceFTy);

    auto *PtBlock = BasicBlock::Create(Ctx, "ptrace_check", F, End);
    B.CreateBr(PtBlock);
    B.SetInsertPoint(PtBlock);

    // ptrace(31 /*PT_DENY_ATTACH*/, 0, null, 0)
    auto *PT31 = ConstantInt::get(Int32Ty, 31);
    auto *Zero = ConstantInt::get(Int32Ty, 0);
    auto *Null = ConstantPointerNull::get(PtrTy);
    B.CreateCall(PtraceFTy, PtraceFn, {PT31, Zero, Null, Zero});
    B.CreateBr(End);
    B.SetInsertPoint(End);
  } else {
    B.CreateBr(End);
    B.SetInsertPoint(End);
  }

  // Helper: append a check-and-branch block after `Prev`, returns the "ok" BB.
  // check_fn()  -> i32; if non-zero call HookFn, else continue.
  auto appendIntCheck = [&](BasicBlock *Prev, StringRef CheckName,
                             StringRef BlockName) -> BasicBlock * {
    auto *CheckFTy    = FunctionType::get(Int32Ty, false);
    auto *CheckFn     = getOrDeclare(M, CheckName, CheckFTy);
    auto *CheckBlock  = BasicBlock::Create(Ctx, BlockName, F);
    auto *DetectBlock = BasicBlock::Create(Ctx, (BlockName + ".det").str(), F);
    auto *OkBlock     = BasicBlock::Create(Ctx, (BlockName + ".ok").str(), F);

    // Wire previous block -> check block
    Instruction *PrevTerm = Prev->getTerminator();
    if (PrevTerm) PrevTerm->eraseFromParent();
    IRBuilder<>(Prev).CreateBr(CheckBlock);

    IRBuilder<> CB(CheckBlock);
    auto *Result  = CB.CreateCall(CheckFTy, CheckFn, {}, CheckName + ".r");
    auto *IsNonZero = CB.CreateICmpNE(Result, ConstantInt::get(Int32Ty, 0));
    CB.CreateCondBr(IsNonZero, DetectBlock, OkBlock);

    IRBuilder<> DB(DetectBlock);
    DB.CreateCall(FTy, HookFn);
    DB.CreateUnreachable();

    return OkBlock;
  };

  if (AntiFramework) {
    // Check chain: TracerPid -> hooks -> breakpoints -> emulator
    BasicBlock *Cur = End;
    Cur = appendIntCheck(Cur, "kagura_check_tracer_pid", "check_tracer");
    Cur = appendIntCheck(Cur, "kagura_check_inline_hooks", "check_hooks");
    Cur = appendIntCheck(Cur, "kagura_check_got_hooks",    "check_got");
    Cur = appendIntCheck(Cur, "kagura_check_sw_breakpoints", "check_sw_bp");
    Cur = appendIntCheck(Cur, "kagura_check_hw_breakpoints", "check_hw_bp");
    Cur = appendIntCheck(Cur, "kagura_check_emulator",    "check_emu");

    IRBuilder<>(Cur).CreateRetVoid();
    return F;
  }

  // No AntiFramework path: just return
  IRBuilder<>(End).CreateRetVoid();
  return F;
}

PreservedAnalyses AntiDebugPass::run(Module &M, ModuleAnalysisManager &) {
  // C.1: Anti-debug checks rely on platform syscalls (ptrace, /proc, Mach-O
  // dylib introspection) that do not exist in WebAssembly sandboxes.
  if (kagura::isWasmTarget(M))
    return PreservedAnalyses::all();

  auto *Ctor = buildAntiDebugConstructor(M, AntiFramework, AntiPtrace);
  // Register as module constructor (priority 0 = runs first)
  appendKaguraCtor(M, Ctor, CtorPriority::AntiDebug);
  return PreservedAnalyses::none();
}

} // namespace kagura
