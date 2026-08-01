//===-- PointerAuth.cpp - Pointer authentication for function pointers ----===//
//
// Implements pointer authentication for function pointers stored in
// module-level globals.  Provides two backends:
//
// --- Software PAC (all targets) ---
//
// Simulates hardware PAC in software using XOR-tagging:
//   1. The compile-time initializer is replaced with a tagged i64:
//        tagged_val = ptr_to_int(original_fn) ^ kagura_pac_key
//   2. Every LoadInst that feeds into a CallInst is rewritten:
//        raw_i64  = load i64, @global
//        untagged = raw_i64 ^ kagura_pac_key
//        fn_ptr   = int_to_ptr(untagged)
//        call fn_ptr(...)
// The key is a runtime-initialised i64 global (kagura_pac_key).
//
// --- Hardware PAC (arm64e targets only, 4.1.8) ---
//
// On arm64e targets, LLVM provides the `llvm.ptrauth.sign` and
// `llvm.ptrauth.auth` intrinsics that lower to the native `pacia`/`autia`
// instructions.  When the module triple is arm64e:
//   1. At each initialiser site, replace the function pointer with:
//        signed = call @llvm.ptrauth.sign(ptr fn, i32 0, i64 disc)
//      where disc is a 48-bit discriminator derived from the global's name.
//   2. At each load+call site, insert:
//        auth_ptr = call @llvm.ptrauth.auth(ptr loaded_ptr, i32 0, i64 disc)
//        call auth_ptr(...)
//
// The ptrauth key 0 (IA) is used because we are authenticating instruction
// (code) pointers.  Key 1 (IB) is the alternative for data pointers.
//
// Globals that are skipped:
//   - Non-constant function-pointer globals (mutation tracking too complex)
//   - Globals whose initializer is not a Function constant or null
//   - Globals whose name starts with "kagura_" or "llvm."
//   - Globals with no uses (dead)
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "kagura-pac"

#include "kagura/Options.h"
#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/Attributes.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <vector>

using namespace llvm;

namespace kagura {

// ---- Helpers ----

/// Return true if Ty is (or decays to) a pointer-to-function type.
static bool isFunctionPointerType(Type *Ty) {
  // In opaque-pointer LLVM, all pointers are "ptr"; we must look at the
  // global's initializer to determine whether it holds a function pointer.
  // This helper is used together with initializer checks below.
  return Ty->isPointerTy();
}

/// Return true if the constant C is a direct function reference or null.
static bool isFunctionPointerConstant(const Constant *C) {
  if (isa<Function>(C))
    return true;
  if (isa<ConstantPointerNull>(C))
    return true;
  return false;
}

/// Return true if GV is a function-pointer global we should tag.
static bool isTaggableGlobal(const GlobalVariable &GV) {
  if (GV.getName().starts_with("kagura_"))
    return false;
  if (GV.getName().starts_with("llvm."))
    return false;
  if (!GV.hasInitializer())
    return false;
  if (GV.use_empty())
    return false;
  // Value type must be ptr (opaque pointer mode)
  if (!isFunctionPointerType(GV.getValueType()))
    return false;
  // Initializer must be a direct function reference or null pointer
  if (!isFunctionPointerConstant(GV.getInitializer()))
    return false;
  return true;
}

// ---- Build / get kagura_pac_key ----

/// Return (or create) the `@kagura_pac_key = internal global i64 0` global.
static GlobalVariable *getOrCreatePacKey(Module &M) {
  if (auto *Existing = M.getNamedGlobal("kagura_pac_key"))
    return Existing;

  auto *Int64Ty = Type::getInt64Ty(M.getContext());
  auto *GV = new GlobalVariable(M, Int64Ty,
                                /*isConstant=*/false,
                                GlobalValue::InternalLinkage,
                                ConstantInt::get(Int64Ty, 0),
                                "kagura_pac_key");
  GV->setAlignment(Align(8));
  return GV;
}

// ---- Build key-init constructor ----

/// Build `void kagura_init_pac_key(void)` that sets kagura_pac_key to a
/// random 64-bit value obtained from kagura_random_u64() (runtime symbol).
static Function *buildPacKeyConstructor(Module &M, GlobalVariable *PacKey) {
  LLVMContext &Ctx  = M.getContext();
  auto *Int64Ty     = Type::getInt64Ty(Ctx);

  // Declare kagura_random_u64: i64 ()
  auto *RngFTy = FunctionType::get(Int64Ty, false);
  auto *RngFn  = cast<Function>(
      M.getOrInsertFunction("kagura_random_u64", RngFTy).getCallee());

  // void kagura_init_pac_key(void)
  auto *Ctor = createCtorFunction(M, "kagura_init_pac_key");
  Ctor->addFnAttr(Attribute::NoInline);
  Ctor->addFnAttr(Attribute::NoUnwind);

  auto *Entry = &Ctor->getEntryBlock();
  IRBuilder<> B(Entry);

  // kagura_pac_key = kagura_random_u64()
  Value *Key = B.CreateCall(RngFTy, RngFn, {}, "pac_key");
  B.CreateAlignedStore(Key, PacKey, Align(8));
  B.CreateRetVoid();

  return Ctor;
}

// ---- Tag the initializer of a global ----

/// Replace a function-pointer global's initializer with a tagged i64:
///   tagged = ptr_to_int(fn) ^ 0      (key is 0 at compile time)
/// The global's type is changed from ptr to i64 in-place by creating a new
/// global and replacing all uses.  Returns the replacement i64 global, or
/// nullptr if the transformation was skipped.
static GlobalVariable *tagGlobal(GlobalVariable *GV, Module &M) {
  LLVMContext &Ctx  = M.getContext();
  auto *Int64Ty     = Type::getInt64Ty(Ctx);

  Constant *Init = GV->getInitializer();

  // Compute the compile-time tagged value.
  // At compile time kagura_pac_key == 0, so tagged = ptr_to_int(fn) ^ 0
  // = ptr_to_int(fn).  The XOR with the real key happens at runtime in
  // the call-site rewrite (via kagura_pac_key load).
  Constant *TaggedInit;
  if (isa<ConstantPointerNull>(Init)) {
    TaggedInit = ConstantInt::get(Int64Ty, 0);
  } else {
    // ptr_to_int(fn) as a ConstantExpr
    TaggedInit = ConstantExpr::getPtrToInt(Init, Int64Ty);
  }

  // Create the new i64 global with identical linkage/visibility/alignment.
  auto *Tagged = new GlobalVariable(M, Int64Ty,
                                    /*isConstant=*/false,
                                    GV->getLinkage(),
                                    TaggedInit,
                                    GV->getName() + ".pac");
  Tagged->setAlignment(Align(8));
  Tagged->setVisibility(GV->getVisibility());
  Tagged->setUnnamedAddr(GV->getUnnamedAddr());
  Tagged->setSection(GV->getSection());

  return Tagged;
}

// ---- Rewrite load+call pairs ----

/// For every LoadInst from TaggedGV that flows directly into a CallInst as the
/// callee operand, insert XOR-untag + inttoptr before the call.  Returns the
/// number of call sites rewritten.
static unsigned rewriteLoadCallPairs(GlobalVariable *TaggedGV,
                                      FunctionType *CalleeFTy, Module &M,
                                      GlobalVariable *PacKey) {
  LLVMContext &Ctx   = M.getContext();
  auto *Int64Ty      = Type::getInt64Ty(Ctx);
  PointerType *PtrTy = PointerType::getUnqual(Ctx);

  SmallVector<LoadInst *, 16> Loads;
  for (auto &U : TaggedGV->uses()) {
    auto *LI = dyn_cast<LoadInst>(U.getUser());
    if (!LI)
      continue;
    Loads.push_back(LI);
  }

  unsigned Count = 0;
  for (auto *LI : Loads) {
    // Collect call uses of this load result.
    SmallVector<CallInst *, 8> CallUses;
    for (auto &U : LI->uses()) {
      auto *CI = dyn_cast<CallInst>(U.getUser());
      if (!CI)
        continue;
      // The load must feed the callee operand (not an argument).
      if (CI->getCalledOperand() != LI)
        continue;
      CallUses.push_back(CI);
    }
    if (CallUses.empty())
      continue;

    // Insert untag sequence right after the load.
    IRBuilder<> B(LI->getNextNode());

    // raw_i64 = LI (already loaded as i64 from the tagged global)
    // key     = load i64, @kagura_pac_key
    Value *Key = B.CreateAlignedLoad(Int64Ty, PacKey, Align(8),
                                     /*isVolatile=*/false, "pac.key");
    // untagged_i64 = raw_i64 ^ key
    Value *Untagged = B.CreateXor(LI, Key, "pac.untagged");
    // fn_ptr = inttoptr(untagged_i64)
    Value *FnPtr = B.CreateIntToPtr(Untagged, PtrTy, "pac.fn_ptr");

    for (auto *CI : CallUses) {
      // Replace the callee operand with the untagged function pointer.
      // Build a new call instruction to get the right FunctionType.
      IRBuilder<> CB(CI);
      SmallVector<Value *, 8> Args(CI->args());
      SmallVector<OperandBundleDef, 2> Bundles;
      for (unsigned I = 0, E = CI->getNumOperandBundles(); I != E; ++I)
        Bundles.emplace_back(CI->getOperandBundleAt(I));

      CallInst *NewCI = CB.CreateCall(CalleeFTy, FnPtr, Args, Bundles, "");
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
  }
  return Count;
}

// ---- Hardware PAC helpers (arm64e, 4.1.8) --------------------------------

/// Compute a 16-bit discriminator from a global's name via FNV-1a-32.
/// Only the low 16 bits are used (hardware PAC discriminator width).
static uint64_t computeDiscriminator(StringRef Name) {
  return static_cast<uint64_t>(fnv1a32(Name) & 0xFFFFu);
}

/// Return the @llvm.ptrauth.sign intrinsic (LLVM 17+ with ptrauth support).
/// Returns nullptr if the intrinsic is not available in this build.
static Function *getPtrauthSignIntrinsic(Module &M) {
  LLVMContext &Ctx = M.getContext();
  // llvm.ptrauth.sign: (ptr, i32 key, i64 discriminator) -> ptr
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  FunctionType *FTy = FunctionType::get(PtrTy, {PtrTy, I32Ty, I64Ty}, false);
  FunctionCallee Callee = M.getOrInsertFunction("llvm.ptrauth.sign", FTy);
  return dyn_cast<Function>(Callee.getCallee());
}

/// Return the @llvm.ptrauth.auth intrinsic.
static Function *getPtrauthAuthIntrinsic(Module &M) {
  LLVMContext &Ctx = M.getContext();
  PointerType *PtrTy = PointerType::getUnqual(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  FunctionType *FTy = FunctionType::get(PtrTy, {PtrTy, I32Ty, I64Ty}, false);
  FunctionCallee Callee = M.getOrInsertFunction("llvm.ptrauth.auth", FTy);
  return dyn_cast<Function>(Callee.getCallee());
}

/// Hardware PAC: sign the function pointer initializer in GV using pacia (key 0).
/// Changes the global to hold a signed ptr (still ptr type; no type change needed).
/// Returns the replacement global, or nullptr on failure.
static GlobalVariable *hwPACTagGlobal(GlobalVariable *GV, Module &M,
                                       Function *SignIntrinsic) {
  if (!SignIntrinsic) return nullptr;
  LLVMContext &Ctx = M.getContext();
  auto *PtrTy = PointerType::getUnqual(Ctx);
  auto *I32Ty = Type::getInt32Ty(Ctx);
  auto *I64Ty = Type::getInt64Ty(Ctx);

  // For hardware PAC, we keep the global as a ptr type but sign it.
  // Create a new global initialised to null; the actual signing happens
  // in a module constructor (we cannot call intrinsics in constant initializers).
  auto *Tagged = new GlobalVariable(M, PtrTy,
                                    /*isConstant=*/false,
                                    GV->getLinkage(),
                                    ConstantPointerNull::get(PtrTy),
                                    GV->getName() + ".hwpac");
  Tagged->setAlignment(GV->getAlign());
  Tagged->setVisibility(GV->getVisibility());
  Tagged->setSection(GV->getSection());

  // Build a constructor that signs the pointer and stores it.
  auto *Ctor = createCtorFunction(M, GV->getName() + ".hwpac.init");
  Ctor->addFnAttr(Attribute::NoInline);
  Ctor->addFnAttr(Attribute::NoUnwind);

  auto *Entry = &Ctor->getEntryBlock();
  IRBuilder<> B(Entry);

  Constant *OrigFn = GV->getInitializer();
  uint64_t  Disc   = computeDiscriminator(GV->getName());

  Value *Key0    = ConstantInt::get(I32Ty, 0); // IA key
  Value *DiscVal = ConstantInt::get(I64Ty, Disc);
  Value *Signed  = B.CreateCall(SignIntrinsic->getFunctionType(),
                                SignIntrinsic,
                                {OrigFn, Key0, DiscVal}, "hwpac.signed");
  B.CreateStore(Signed, Tagged);
  B.CreateRetVoid();

  appendKaguraCtor(M, Ctor, CtorPriority::HwPAC);
  return Tagged;
}

/// Hardware PAC: rewrite load+call pairs to authenticate the pointer.
static unsigned hwPACRewriteLoadCallPairs(GlobalVariable *TaggedGV,
                                          FunctionType *CalleeFTy, Module &M,
                                          Function *AuthIntrinsic,
                                          uint64_t Disc) {
  if (!AuthIntrinsic) return 0;
  LLVMContext &Ctx = M.getContext();
  auto *I32Ty  = Type::getInt32Ty(Ctx);
  auto *I64Ty  = Type::getInt64Ty(Ctx);
  auto *PtrTy  = PointerType::getUnqual(Ctx);

  SmallVector<LoadInst *, 16> Loads;
  for (auto &U : TaggedGV->uses()) {
    auto *LI = dyn_cast<LoadInst>(U.getUser());
    if (LI) Loads.push_back(LI);
  }

  unsigned Count = 0;
  for (auto *LI : Loads) {
    SmallVector<CallInst *, 8> CallUses;
    for (auto &U : LI->uses()) {
      auto *CI = dyn_cast<CallInst>(U.getUser());
      if (CI && CI->getCalledOperand() == LI)
        CallUses.push_back(CI);
    }
    if (CallUses.empty()) continue;

    IRBuilder<> B(LI->getNextNode());
    Value *Key0    = ConstantInt::get(I32Ty, 0);
    Value *DiscVal = ConstantInt::get(I64Ty, Disc);
    // The loaded value is already a ptr (hw PAC keeps ptr type).
    Value *AuthPtr = B.CreateCall(AuthIntrinsic->getFunctionType(),
                                  AuthIntrinsic,
                                  {LI, Key0, DiscVal}, "hwpac.auth");

    for (auto *CI : CallUses) {
      IRBuilder<> CB(CI);
      SmallVector<Value *, 8> Args(CI->args());
      SmallVector<OperandBundleDef, 2> Bundles;
      for (unsigned I = 0, E = CI->getNumOperandBundles(); I != E; ++I)
        Bundles.emplace_back(CI->getOperandBundleAt(I));
      CallInst *NewCI = CB.CreateCall(CalleeFTy, AuthPtr, Args, Bundles, "");
      NewCI->setCallingConv(CI->getCallingConv());
      NewCI->setAttributes(CI->getAttributes());
      NewCI->setTailCallKind(CI->getTailCallKind());
      NewCI->setDebugLoc(CI->getDebugLoc());
      if (!CI->getType()->isVoidTy())
        CI->replaceAllUsesWith(NewCI);
      CI->eraseFromParent();
      ++Count;
    }
  }
  return Count;
}

// ---- Pass entry point ----

PreservedAnalyses PointerAuthPass::run(Module &M, ModuleAnalysisManager &) {
  if (!kagura::opt::PAC)
    return PreservedAnalyses::all();

  // C.1: Pointer authentication uses hardware PAC (arm64e) or XOR tagging.
  // WebAssembly has neither native PAC nor mutable function-pointer globals
  // that benefit from software tagging — skip to avoid invalid lowering.
  if (kagura::isWasmTarget(M))
    return PreservedAnalyses::all();

  // 4.1.8: On arm64e, prefer hardware PAC (pacia/autia intrinsics).
  const bool UseHardwarePAC = kagura::isArm64eTarget(M);
  if (UseHardwarePAC) {
    LLVM_DEBUG(dbgs() << "[kagura-pac] arm64e: using hardware PAC (pacia/autia)\n");
  }

  // Collect taggable globals first; we'll mutate the module as we go.
  SmallVector<GlobalVariable *, 32> Targets;
  for (auto &GV : M.globals())
    if (isTaggableGlobal(GV))
      Targets.push_back(&GV);

  if (Targets.empty())
    return PreservedAnalyses::all();

  // Fetch hardware PAC intrinsics (only non-null on arm64e targets).
  Function *SignIntrinsic = UseHardwarePAC ? getPtrauthSignIntrinsic(M) : nullptr;
  Function *AuthIntrinsic = UseHardwarePAC ? getPtrauthAuthIntrinsic(M) : nullptr;

  GlobalVariable *PacKey = UseHardwarePAC ? nullptr : getOrCreatePacKey(M);
  bool Changed = false;

  for (auto *GV : Targets) {
    Constant *Init = GV->getInitializer();
    FunctionType *CalleeFTy = nullptr;
    if (auto *Fn = dyn_cast<Function>(Init))
      CalleeFTy = Fn->getFunctionType();
    else
      continue; // null-initialized; no call sites to rewrite yet

    if (UseHardwarePAC) {
      // --- Hardware PAC path (arm64e) ---
      uint64_t Disc = computeDiscriminator(GV->getName());
      GlobalVariable *Tagged = hwPACTagGlobal(GV, M, SignIntrinsic);
      if (!Tagged) continue;

      // Redirect loads from GV to Tagged (same ptr type).
      SmallVector<LoadInst *, 16> OrigLoads;
      for (auto &U : GV->uses()) {
        auto *LI = dyn_cast<LoadInst>(U.getUser());
        if (LI) OrigLoads.push_back(LI);
      }
      LLVMContext &Ctx = M.getContext();
      for (auto *LI : OrigLoads) {
        IRBuilder<> B(LI);
        auto *NewLI = B.CreateAlignedLoad(PointerType::getUnqual(Ctx),
                                          Tagged, GV->getAlign(),
                                          LI->isVolatile(), "hwpac.raw");
        NewLI->setDebugLoc(LI->getDebugLoc());
        LI->replaceAllUsesWith(NewLI);
        LI->eraseFromParent();
      }

      hwPACRewriteLoadCallPairs(Tagged, CalleeFTy, M, AuthIntrinsic, Disc);
      GV->replaceAllUsesWith(Tagged);
      GV->eraseFromParent();
    } else {
      // --- Software PAC path (all other targets) ---
      GlobalVariable *Tagged = tagGlobal(GV, M);

      SmallVector<LoadInst *, 16> OrigLoads;
      for (auto &U : GV->uses()) {
        auto *LI = dyn_cast<LoadInst>(U.getUser());
        if (LI) OrigLoads.push_back(LI);
      }
      for (auto *LI : OrigLoads) {
        IRBuilder<> B(LI);
        auto *NewLI = B.CreateAlignedLoad(Type::getInt64Ty(M.getContext()),
                                          Tagged, Align(8),
                                          LI->isVolatile(), "pac.raw");
        NewLI->setDebugLoc(LI->getDebugLoc());
        LI->replaceAllUsesWith(NewLI);
        LI->eraseFromParent();
      }

      rewriteLoadCallPairs(Tagged, CalleeFTy, M, PacKey);
      GV->replaceAllUsesWith(Tagged);
      GV->eraseFromParent();
    }

    Changed = true;
  }

  if (!Changed)
    return PreservedAnalyses::all();

  if (!UseHardwarePAC) {
    // Build and register the software PAC key initialisation constructor.
    // Priority 65534 so it runs just before the thunk table constructor (65535).
    Function *Ctor = buildPacKeyConstructor(M, PacKey);
    appendKaguraCtor(M, Ctor, CtorPriority::SwPAC);
  }

  return PreservedAnalyses::none();
}

} // namespace kagura

#undef DEBUG_TYPE
