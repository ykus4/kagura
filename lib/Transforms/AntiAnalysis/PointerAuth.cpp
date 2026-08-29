//===-- PointerAuth.cpp - Pointer authentication for function pointers ----===//
//
// Implements pointer authentication for function pointers stored in
// module-level globals.  Provides two backends:
//
// --- Software PAC (all targets) ---
//
// Simulates hardware PAC in software using XOR-tagging:
//   1. The compile-time initializer becomes a plain i64 ptr_to_int(fn).  It
//      cannot be tagged here: a ConstantExpr cannot reference kagura_pac_key,
//      which does not have its value until run time.
//   2. A constructor draws the key, XORs every slot from (1) with it, and
//      publishes the key.  This is the step that makes the tag real; without
//      it (2) and (3) disagree and every call jumps to fn ^ key.
//   3. Every LoadInst is rewritten to untag at the load:
//        raw_i64  = load i64, @global.pac
//        untagged = raw_i64 ^ kagura_pac_key
//        fn_ptr   = int_to_ptr(untagged)
//      and every StoreInst tags on the way in, so the slot is never observed
//      holding a value in the untagged domain after the constructor has run.
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
//   - Globals with a use that is not a load or a store into the slot, since
//     anything else can read or write the slot without going through the
//     tag/untag sequence
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "kagura-pac"

#include "kagura/Options.h"
#include "kagura/Passes/AntiAnalysis.h"
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

/// Return true if every use of GV is one this pass knows how to rewrite:
/// a load of the pointer, or a store *into* the slot.
///
/// This guard is load-bearing.  The software path replaces the `ptr` global
/// with an `i64` one holding a tagged value, then RAUWs the old global.  Both
/// are plain `ptr` values in opaque-pointer mode, so RAUW succeeds on any use
/// — including ones that read or write the slot without going through the
/// tag/untag sequence.  A `memcpy` from the global, or the address escaping to
/// another TU, would then observe (or install) a value in the wrong domain:
/// the reader untags something that was never tagged, and jumps to
/// `real_pointer ^ key`.  Rejecting the global is the only safe answer, since
/// the pass cannot see through those uses.
static bool hasOnlyRewritableUses(const GlobalVariable &GV) {
  for (const User *U : GV.users()) {
    if (isa<LoadInst>(U))
      continue;
    if (const auto *SI = dyn_cast<StoreInst>(U)) {
      // Storing *to* the slot is fine (we tag on the way in); storing the
      // global's address *somewhere else* lets it escape untagged.
      if (SI->getPointerOperand() == &GV)
        continue;
    }
    return false;
  }
  return true;
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
  if (!hasOnlyRewritableUses(GV))
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

/// Build `void kagura_init_pac_key(void)`: draw a random 64-bit key, XOR every
/// tagged global with it, and publish the key.
///
/// The XOR loop is what closes the tag/untag contract.  A `.pac` global is
/// emitted holding the *untagged* `ptrtoint(fn)`, because a ConstantExpr
/// initializer cannot reference a value that does not exist until run time.
/// Call sites, meanwhile, always compute `slot ^ kagura_pac_key`.  Those two
/// halves agree only while the key is still zero: publishing a random key
/// without re-tagging the slots leaves every rewritten call jumping to
/// `real_pointer ^ key`, which faults on the first indirect call.  This is not
/// hypothetical — it is what the pass shipped before this loop existed.
///
/// The pre-constructor state is self-consistent by the same argument
/// (`slot ^ 0 == slot`), so a constructor that runs earlier and calls through
/// one of these pointers still reaches the right function.  Between the two
/// stores below there is a window in which the slots and the key disagree;
/// that is unobservable in the single-threaded constructor phase this runs in,
/// and closing it properly would need the whole sequence to be atomic.
static Function *buildPacKeyConstructor(Module &M, GlobalVariable *PacKey,
                                        ArrayRef<GlobalVariable *> Tagged) {
  LLVMContext &Ctx  = M.getContext();
  auto *Int64Ty     = Type::getInt64Ty(Ctx);

  // Declare kagura_random_u64: i64 ().  Held as a FunctionCallee rather than
  // cast<Function>: if the module already declares the name with a different
  // signature, getOrInsertFunction hands back a bitcast ConstantExpr and the
  // cast would abort the compiler instead of the pass declining.
  auto *RngFTy = FunctionType::get(Int64Ty, false);
  FunctionCallee Rng = M.getOrInsertFunction("kagura_random_u64", RngFTy);

  // void kagura_init_pac_key(void)
  auto *Ctor = createCtorFunction(M, "kagura_init_pac_key");
  Ctor->addFnAttr(Attribute::NoInline);
  Ctor->addFnAttr(Attribute::NoUnwind);

  auto *Entry = &Ctor->getEntryBlock();
  IRBuilder<> B(Entry);

  // key = kagura_random_u64()
  Value *Key = B.CreateCall(Rng, {}, "pac_key");

  // for each slot: slot ^= key
  for (GlobalVariable *GV : Tagged) {
    Value *Raw    = B.CreateAlignedLoad(Int64Ty, GV, Align(8),
                                        /*isVolatile=*/false, "pac.init.raw");
    Value *Retag  = B.CreateXor(Raw, Key, "pac.init.tagged");
    B.CreateAlignedStore(Retag, GV, Align(8));
  }

  // kagura_pac_key = key
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

  // The initializer holds the *untagged* value: a ConstantExpr cannot
  // reference the key, which does not exist until kagura_init_pac_key runs.
  // That constructor XORs this slot with the key it draws, which is what makes
  // the `slot ^ kagura_pac_key` sequence at the call sites resolve back to the
  // real pointer.  Neither half is correct without the other.
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

// ---- Rewrite the uses of a software-tagged global ----

/// Move every use of GV onto the tagged i64 global, untagging on the way out
/// and tagging on the way in.
///
/// The untag is placed at the *load*, not at the call.  The previous shape
/// rewrote call sites and replaced the `ptr`-typed load with the `i64` one
/// via replaceAllUsesWith — a type-mismatched RAUW, which aborts any build
/// with assertions enabled and, without them, leaves transiently invalid IR
/// that only becomes valid again because the offending use is erased a few
/// lines later.  It also silently dropped every use that was not a direct
/// call: a comparison against the pointer, or passing it as an argument, kept
/// the raw tagged integer.  Untagging at the load makes all of those correct
/// and removes the need to reconstruct the call at all — which in turn drops
/// the old code's habit of rebuilding it with the *callee's* FunctionType
/// rather than the call site's, an assertion failure whenever the two differ.
static void rewriteSoftwareUses(GlobalVariable *GV, GlobalVariable *Tagged,
                                Module &M, GlobalVariable *PacKey) {
  LLVMContext &Ctx   = M.getContext();
  auto *Int64Ty      = Type::getInt64Ty(Ctx);
  PointerType *PtrTy = PointerType::getUnqual(Ctx);

  // Snapshot: the loop erases as it goes.  isTaggableGlobal already rejected
  // anything that is not a load or a store into the slot, so every user here
  // is an Instruction of one of those two kinds.
  SmallVector<Instruction *, 16> Uses;
  for (User *U : GV->users())
    Uses.push_back(cast<Instruction>(U));

  for (Instruction *I : Uses) {
    IRBuilder<> B(I);
    Value *Key = B.CreateAlignedLoad(Int64Ty, PacKey, Align(8),
                                     /*isVolatile=*/false, "pac.key");

    if (auto *LI = dyn_cast<LoadInst>(I)) {
      auto *Raw = B.CreateAlignedLoad(Int64Ty, Tagged, Align(8),
                                      LI->isVolatile(), "pac.raw");
      Raw->setDebugLoc(LI->getDebugLoc());
      Value *Untagged = B.CreateXor(Raw, Key, "pac.untagged");
      Value *FnPtr    = B.CreateIntToPtr(Untagged, PtrTy, "pac.fn_ptr");
      LI->replaceAllUsesWith(FnPtr); // ptr for ptr — the types agree
      LI->eraseFromParent();
      continue;
    }

    auto *SI  = cast<StoreInst>(I);
    Value *Raw = B.CreatePtrToInt(SI->getValueOperand(), Int64Ty, "pac.raw");
    Value *Tag = B.CreateXor(Raw, Key, "pac.tagged");
    auto *NewSI =
        B.CreateAlignedStore(Tag, Tagged, Align(8), SI->isVolatile());
    NewSI->setDebugLoc(SI->getDebugLoc());
    SI->eraseFromParent();
  }
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
  // No `if (!opt::PAC) return` here: whether this pass runs is decided when
  // the pipeline is built (Plugin.cpp), and `opt -passes=kagura-pac` never
  // sets the flag — so re-checking it made that entry point a silent no-op.
  // See the note on shouldObfuscate() in Utils.h; the same fix was applied to
  // the function passes and missed the module passes.

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

  // Created on first use, not up front: every target being null-initialised
  // sends the loop below straight to `continue`, and the pass then reported
  // PreservedAnalyses::all() having already added @kagura_pac_key to the
  // module.
  GlobalVariable *PacKey = nullptr;
  auto pacKey = [&]() -> GlobalVariable * {
    if (!PacKey)
      PacKey = getOrCreatePacKey(M);
    return PacKey;
  };
  bool Changed = false;

  // The slots the key-init constructor has to XOR once the key exists.
  SmallVector<GlobalVariable *, 32> SwTagged;

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
      rewriteSoftwareUses(GV, Tagged, M, pacKey());
      SwTagged.push_back(Tagged);

      // hasOnlyRewritableUses() guaranteed every use was a load or a store
      // into the slot, and rewriteSoftwareUses erased all of them, so nothing
      // is left pointing at the ptr-typed global.
      assert(GV->use_empty() && "untranslated use survived the rewrite");
      GV->eraseFromParent();
    }

    Changed = true;
  }

  if (!Changed)
    return PreservedAnalyses::all();

  if (!UseHardwarePAC && !SwTagged.empty()) {
    // Build and register the software PAC key initialisation constructor.
    // Priority 65534 so it runs just before the thunk table constructor (65535).
    Function *Ctor = buildPacKeyConstructor(M, PacKey, SwTagged);
    appendKaguraCtor(M, Ctor, CtorPriority::SwPAC);
  }

  return PreservedAnalyses::none();
}

} // namespace kagura

#undef DEBUG_TYPE
