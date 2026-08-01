//===-- WideStringEncryption.cpp - Wide / UTF-16 / CFString encryption ----===//
//
// 4.2.1 / A.2: Extends string encryption coverage to five additional string
// types that the narrow-char StringEncryption pass misses:
//
//   1. Wide character arrays (wchar_t / char16_t / char32_t)
//      LLVM represents these as ConstantDataArray of i16 or i32.  Each
//      code-unit is XOR-encrypted with the same cyclic 8-byte key used by
//      the narrow pass; the XOR is applied to the low byte of each unit so
//      the encryption is always invertible regardless of unit width.
//
//   2. UTF-16 string literals in Windows / COM style
//      Identified by i16 ConstantDataArrays whose content is plausibly UCS-2
//      (all code units < 0xD800 or valid surrogate pairs).
//
//   3. ObjC / CoreFoundation CFStringRef literals
//      In Apple Mach-O IR, `@"literal"` NSString / CFString constants are
//      represented as a ConstantStruct in the __DATA,__cfstring section with
//      the following layout:
//
//        { i64 isa_ptr, i64 flags, i8* chars, i64 len }
//
//      We locate these structs, extract the chars pointer, and encrypt the
//      backing i8 array using the same XOR scheme.  A module constructor
//      decrypts all CFString backing buffers before ObjC code runs.
//
//   4. Swift string constant globals
//      swiftc emits string literals as private/internal [N x i8] globals
//      whose names are Swift-mangled (start with "$s" or contain ".str").
//      We detect these by name pattern and apply the same XOR + module-
//      constructor scheme.  A priority-(-1) ctor ensures decryption happens
//      before Swift runtime initialisation.
//
//   5. Kotlin Native string constant globals
//      kotlinc-native emits UTF-8 string literals as private/internal
//      [N x i8] globals with Kotlin-specific mangling or section hints
//      (names starting with "kfun:", ".kotlin_string_pool", or the
//      kotlinx/kotlin namespace patterns in Itanium-style mangling).
//      Same XOR + module-constructor scheme; priority 0.
//
// Pass key:   "kagura-wstr"
// CLI flag:   -kagura-wstr
//
// Lazy-decrypt guards (4.2.4 style) are applied to wchar/UTF-16 strings.
// CFString / Swift / Kotlin buffers are decrypted once in a module
// constructor to avoid patching the runtime's internal string tables.
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <vector>

using namespace llvm;

namespace kagura {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns true if GV holds a wide-character array (i16 or i32 elements).
static bool isWideStringGlobal(const GlobalVariable &GV) {
  if (!GV.isConstant() || !GV.hasInitializer())
    return false;
  if (GV.getName().starts_with("kagura_") || GV.getName().starts_with("llvm.") ||
      GV.getName().starts_with("$kagura_"))
    return false;
  auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
  if (!CDA)
    return false;
  Type *ElemTy = CDA->getType()->getElementType();
  if (!ElemTy->isIntegerTy(16) && !ElemTy->isIntegerTy(32))
    return false;
  // Must have at least one non-null element (skip empty / null-only arrays).
  bool HasNonNull = false;
  for (unsigned I = 0; I < CDA->getNumElements(); ++I) {
    if (CDA->getElementAsInteger(I) != 0) {
      HasNonNull = true;
      break;
    }
  }
  return HasNonNull;
}

/// Returns true if GV looks like a Swift string literal constant emitted by
/// swiftc.  Swift mangles globals with a "$s" prefix; string storage globals
/// additionally carry ".str" or "Ss" (Swift.String) in their name.  We accept
/// any private/internal [N x i8] global whose name starts with "$s" to catch
/// the full range of Swift-generated string constants.
static bool isSwiftStringGlobal(const GlobalVariable &GV) {
  if (!GV.isConstant() || !GV.hasInitializer())
    return false;
  if (GV.getName().starts_with("kagura_") || GV.getName().starts_with("llvm."))
    return false;
  // Must be a byte array with printable content.
  auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
  if (!CDA || !CDA->isString())
    return false;
  if (CDA->getAsString().size() < 2)
    return false;
  // Linkage guard: Swift string literals are always private or internal.
  if (GV.getLinkage() != GlobalValue::PrivateLinkage &&
      GV.getLinkage() != GlobalValue::InternalLinkage)
    return false;
  StringRef N = GV.getName();
  // Swift mangled names start with "$s".
  if (N.starts_with("$s"))
    return true;
  // swiftc also emits un-mangled ".str" helper globals in some IR modes.
  if (N.contains(".str") && N.starts_with("_"))
    return true;
  return false;
}

/// Returns true if GV looks like a Kotlin Native string constant.
/// kotlinc-native emits UTF-8 string storage as private [N x i8] globals.
/// Identifiable patterns:
///   - name starts with "kfun:" (Kotlin function-qualified name)
///   - name starts with ".kotlin" (Kotlin internal section marker)
///   - name contains "_kotlin_" (Kotlin stdlib symbol)
///   - Itanium-mangled names containing "kotlin" namespace (N6kotlin)
static bool isKotlinStringGlobal(const GlobalVariable &GV) {
  if (!GV.isConstant() || !GV.hasInitializer())
    return false;
  if (GV.getName().starts_with("kagura_") || GV.getName().starts_with("llvm."))
    return false;
  auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
  if (!CDA || !CDA->isString())
    return false;
  if (CDA->getAsString().size() < 2)
    return false;
  if (GV.getLinkage() != GlobalValue::PrivateLinkage &&
      GV.getLinkage() != GlobalValue::InternalLinkage)
    return false;
  StringRef N = GV.getName();
  if (N.starts_with("kfun:") || N.starts_with(".kotlin"))
    return true;
  if (N.contains("_kotlin_") || N.contains("N6kotlin"))
    return true;
  return false;
}

/// Returns true if GV is a CFString struct (Apple __cfstring section).
static bool isCFStringGlobal(const GlobalVariable &GV) {
  if (!GV.hasSection())
    return false;
  StringRef Sec = GV.getSection();
  return Sec.contains("__cfstring") || Sec.contains("cfstring");
}

/// Extract the backing char array pointer from a CFString struct global.
/// Returns nullptr if the layout is not recognised.
static GlobalVariable *extractCFStringChars(GlobalVariable *CFGV) {
  auto *CS = dyn_cast<ConstantStruct>(CFGV->getInitializer());
  if (!CS || CS->getNumOperands() < 3)
    return nullptr;
  // Field 2 is the chars pointer.
  auto *CharOp = CS->getOperand(2)->stripPointerCasts();
  return dyn_cast<GlobalVariable>(CharOp);
}

// ---------------------------------------------------------------------------
// Wide-string XOR encryption
// ---------------------------------------------------------------------------

/// Encrypt a wide-character array in-place: XOR the low byte of each element.
/// Returns the encrypted element values.
static std::vector<uint64_t> encryptWideString(const ConstantDataArray *CDA,
                                                const uint8_t Key[8]) {
  unsigned N = CDA->getNumElements();
  std::vector<uint64_t> Enc(N);
  for (unsigned I = 0; I < N; ++I) {
    uint64_t Elem = CDA->getElementAsInteger(I);
    // XOR the low byte only so the encryption is unambiguous for both i16/i32.
    Enc[I] = Elem ^ static_cast<uint64_t>(Key[I % 8]);
  }
  return Enc;
}

/// Build a decryption function for a wide-string global.
/// void kagura_wdecrypt_<suffix>(void):
///   for i in [0, N): EncGV[i] ^= Key[i%8]
static Function *buildWideDecryptStub(Module &M, GlobalVariable *EncGV,
                                       unsigned N, unsigned ElemBits,
                                       const uint8_t Key[8], StringRef Suffix) {
  LLVMContext &Ctx = M.getContext();
  auto *VoidTy  = Type::getVoidTy(Ctx);
  auto *Int64Ty = Type::getInt64Ty(Ctx);
  auto *ElemTy  = Type::getIntNTy(Ctx, ElemBits);
  auto *ArrTy   = cast<ArrayType>(EncGV->getValueType());

  // Store key as private global
  auto *Int8Ty = Type::getInt8Ty(Ctx);
  std::vector<Constant *> KeyBytes;
  for (unsigned I = 0; I < 8; ++I)
    KeyBytes.push_back(ConstantInt::get(Int8Ty, Key[I]));
  auto *KeyArrTy = ArrayType::get(Int8Ty, 8);
  auto *KeyConst = ConstantArray::get(KeyArrTy, KeyBytes);
  auto *KeyGV    = new GlobalVariable(M, KeyArrTy, true,
                                      GlobalValue::PrivateLinkage, KeyConst,
                                      "kagura_wkey_" + Suffix);

  auto *FTy = FunctionType::get(VoidTy, false);
  auto *F   = Function::Create(FTy, Function::InternalLinkage,
                               "kagura_wdecrypt_" + Suffix, M);
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::NoUnwind);

  auto *Entry   = BasicBlock::Create(Ctx, "entry", F);
  auto *Loop    = BasicBlock::Create(Ctx, "loop",  F);
  auto *Body    = BasicBlock::Create(Ctx, "body",  F);
  auto *Exit    = BasicBlock::Create(Ctx, "exit",  F);

  IRBuilder<> B(Entry);
  auto *IdxAlloc = B.CreateAlloca(Int64Ty, nullptr, "idx");
  B.CreateStore(ConstantInt::get(Int64Ty, 0), IdxAlloc);
  B.CreateBr(Loop);

  B.SetInsertPoint(Loop);
  auto *Idx     = B.CreateLoad(Int64Ty, IdxAlloc, "i");
  auto *InRange = B.CreateICmpULT(Idx, ConstantInt::get(Int64Ty, N));
  B.CreateCondBr(InRange, Body, Exit);

  B.SetInsertPoint(Body);
  auto *KIdx  = B.CreateURem(Idx, ConstantInt::get(Int64Ty, 8), "kidx");
  auto *KPtr  = B.CreateInBoundsGEP(KeyArrTy, KeyGV,
                                    {ConstantInt::get(Int64Ty, 0), KIdx});
  auto *KByte = B.CreateLoad(Int8Ty, KPtr, "kb");
  // Extend key byte to element width.
  auto *KExtended = ElemBits > 8 ? B.CreateZExt(KByte, ElemTy, "kext")
                                  : static_cast<Value *>(KByte);

  auto *EPtr  = B.CreateInBoundsGEP(ArrTy, EncGV,
                                    {ConstantInt::get(Int64Ty, 0), Idx});
  auto *EVal  = B.CreateLoad(ElemTy, EPtr, "ev");
  auto *Plain = B.CreateXor(EVal, KExtended, "plain");
  B.CreateStore(Plain, EPtr);

  auto *Next = B.CreateAdd(Idx, ConstantInt::get(Int64Ty, 1), "next");
  B.CreateStore(Next, IdxAlloc);
  B.CreateBr(Loop);

  B.SetInsertPoint(Exit);
  B.CreateRetVoid();

  return F;
}

// ---------------------------------------------------------------------------
// CFString constructor injection
// ---------------------------------------------------------------------------

/// Build a module constructor that decrypts all CFString backing buffers.
/// Priority 0 so it runs before user constructors and before ObjC runtime.
static void buildCFStringDecryptCtor(
    Module &M,
    const SmallVector<std::pair<GlobalVariable *, Function *>, 8> &CFDecryptors) {
  if (CFDecryptors.empty())
    return;

  LLVMContext &Ctx = M.getContext();
  auto *Ctor = createCtorFunction(M, "kagura_cfstr_decrypt_ctor");
  Ctor->addFnAttr(Attribute::NoInline);
  Ctor->addFnAttr(Attribute::NoUnwind);

  auto *Entry = &Ctor->getEntryBlock();
  IRBuilder<> B(Entry);
  for (auto &[GV, DecFn] : CFDecryptors)
    B.CreateCall(DecFn);
  B.CreateRetVoid();

  appendKaguraCtor(M, Ctor, CtorPriority::RuntimeString);
}

// ---------------------------------------------------------------------------
// Swift / Kotlin string constructor injection
// ---------------------------------------------------------------------------

/// Build a single module constructor that calls all Swift or Kotlin string
/// decrypt stubs in order.  Priority controls ordering relative to runtimes:
///   Swift:  -1  (before Swift runtime init)
///   Kotlin:  0  (same priority as CFString; before Kotlin runtime)
static void buildRuntimeStringDecryptCtor(
    Module &M,
    const SmallVector<Function *, 8> &Stubs,
    StringRef CtorName,
    CtorPriority Priority) {
  if (Stubs.empty())
    return;
  auto *Ctor = createCtorFunction(M, CtorName);
  Ctor->addFnAttr(Attribute::NoInline);
  Ctor->addFnAttr(Attribute::NoUnwind);

  auto *Entry = &Ctor->getEntryBlock();
  IRBuilder<> B(Entry);
  for (auto *Stub : Stubs)
    B.CreateCall(Stub);
  B.CreateRetVoid();

  appendKaguraCtor(M, Ctor, Priority);
}

// ---------------------------------------------------------------------------
// Pass entry point
// ---------------------------------------------------------------------------

PreservedAnalyses WideStringEncryptionPass::run(Module &M,
                                                 ModuleAnalysisManager &) {
  if (!kagura::opt::WSTR)
    return PreservedAnalyses::all();

  auto &RNG    = getModulePRNG();
  bool Changed = false;

  // ---- Wide strings (i16 / i32 ConstantDataArray) -------------------------

  SmallVector<GlobalVariable *, 32> WideTargets;
  for (auto &GV : M.globals())
    if (isWideStringGlobal(GV))
      WideTargets.push_back(&GV);

  auto *Int8Ty = Type::getInt8Ty(M.getContext());

  for (auto *GV : WideTargets) {
    auto *CDA = cast<ConstantDataArray>(GV->getInitializer());
    unsigned N       = CDA->getNumElements();
    unsigned ElemBits = CDA->getType()->getElementType()->getIntegerBitWidth();

    uint8_t Key[8];
    uint64_t RandKey = RNG.next();
    for (unsigned I = 0; I < 8; ++I)
      Key[I] = static_cast<uint8_t>((RandKey >> (I * 8)) & 0xFF);

    auto EncVals = encryptWideString(CDA, Key);

    // Rebuild the initializer with encrypted values.
    auto *ElemTy = Type::getIntNTy(M.getContext(), ElemBits);
    auto *ArrTy  = ArrayType::get(ElemTy, N);
    std::vector<Constant *> EncElems;
    EncElems.reserve(N);
    for (uint64_t V : EncVals)
      EncElems.push_back(ConstantInt::get(ElemTy, V));
    auto *EncConst = ConstantArray::get(ArrTy, EncElems);

    std::string Suffix = std::to_string(RNG.next32());

    // Replace GV's initializer with the encrypted version.
    // GV must be mutable (not isConstant) for in-place runtime decryption.
    GV->setConstant(false);
    GV->setInitializer(EncConst);

    // Snapshot users BEFORE building the stub so that instructions inserted
    // inside the decrypt stub (which also reference GV) are not processed
    // by the lazy-guard loop below.
    SmallVector<User *, 8> Users(GV->users());

    // 4.2.4: per-string flag
    auto *FlagGV = new GlobalVariable(M, Int8Ty, /*isConstant=*/false,
                                      GlobalValue::PrivateLinkage,
                                      ConstantInt::get(Int8Ty, 0),
                                      "kagura_wflag_" + Suffix);
    FlagGV->setAlignment(Align(1));

    Function *Stub = buildWideDecryptStub(M, GV, N, ElemBits, Key, Suffix);

    // Inject lazy guard before every instruction that uses this global.
    for (auto *U : Users) {
      auto *Inst = dyn_cast<Instruction>(U);
      if (!Inst)
        continue;
      // PHI nodes cannot be split-points: skip them to avoid malformed IR.
      if (isa<PHINode>(Inst))
        continue;
      LLVMContext &Ctx = M.getContext();
      // Lazy guard: split block, check flag, call stub if 0, set flag.
      BasicBlock *CheckBB  = Inst->getParent();
      BasicBlock *MergeBB  = CheckBB->splitBasicBlock(Inst, "wlazy.merge");
      BasicBlock *DecryptBB = BasicBlock::Create(Ctx, "wlazy.decrypt",
                                                  Inst->getFunction(), MergeBB);
      CheckBB->getTerminator()->eraseFromParent();
      IRBuilder<> B(CheckBB);
      Value *Flag   = B.CreateLoad(Int8Ty, FlagGV, "wflag");
      Value *IsZero = B.CreateICmpEQ(Flag, ConstantInt::get(Int8Ty, 0));
      B.CreateCondBr(IsZero, DecryptBB, MergeBB);
      IRBuilder<> DB(DecryptBB);
      DB.CreateCall(Stub);
      DB.CreateStore(ConstantInt::get(Int8Ty, 1), FlagGV);
      DB.CreateBr(MergeBB);
    }

    Changed = true;
  }

  // ---- CFString backing buffers (Apple __cfstring section) ----------------

  SmallVector<std::pair<GlobalVariable *, Function *>, 8> CFDecryptors;

  for (auto &GV : M.globals()) {
    if (!isCFStringGlobal(GV))
      continue;
    GlobalVariable *CharGV = extractCFStringChars(&GV);
    if (!CharGV)
      continue;
    auto *CDA = dyn_cast<ConstantDataArray>(CharGV->getInitializer());
    if (!CDA || !CDA->isString())
      continue;

    StringRef Raw = CDA->getAsString();
    uint64_t Len  = Raw.size();

    uint8_t Key[8];
    uint64_t RandKey = RNG.next();
    for (unsigned I = 0; I < 8; ++I)
      Key[I] = static_cast<uint8_t>((RandKey >> (I * 8)) & 0xFF);

    // Encrypt
    std::vector<Constant *> EncBytes;
    EncBytes.reserve(Len);
    for (uint64_t I = 0; I < Len; ++I)
      EncBytes.push_back(ConstantInt::get(Int8Ty,
          static_cast<uint8_t>(Raw[I]) ^ Key[I % 8]));
    auto *EncConst = ConstantArray::get(
        ArrayType::get(Int8Ty, Len), EncBytes);

    CharGV->setConstant(false);
    CharGV->setInitializer(EncConst);

    std::string Suffix = std::to_string(RNG.next32());

    // Build narrow XOR decrypt stub (reuses wide helper for i8)
    Function *Stub = buildWideDecryptStub(
        M, CharGV, static_cast<unsigned>(Len), 8, Key, "cf_" + Suffix);
    CFDecryptors.push_back({CharGV, Stub});

    Changed = true;
  }

  buildCFStringDecryptCtor(M, CFDecryptors);

  // ---- Swift string constants ([N x i8] private globals, "$s" prefix) ------

  SmallVector<Function *, 8> SwiftStubs;

  for (auto &GV : M.globals()) {
    if (!isSwiftStringGlobal(GV))
      continue;
    auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
    if (!CDA)
      continue;
    StringRef Raw = CDA->getAsString();
    uint64_t Len  = Raw.size();

    uint8_t Key[8];
    uint64_t RandKey = RNG.next();
    for (unsigned I = 0; I < 8; ++I)
      Key[I] = static_cast<uint8_t>((RandKey >> (I * 8)) & 0xFF);

    // Encrypt in-place.
    std::vector<Constant *> EncBytes;
    EncBytes.reserve(Len);
    for (uint64_t I = 0; I < Len; ++I)
      EncBytes.push_back(ConstantInt::get(Int8Ty,
          static_cast<uint8_t>(Raw[I]) ^ Key[I % 8]));
    auto *EncConst = ConstantArray::get(ArrayType::get(Int8Ty, Len), EncBytes);

    const_cast<GlobalVariable &>(GV).setConstant(false);
    const_cast<GlobalVariable &>(GV).setInitializer(EncConst);

    std::string Suffix = std::to_string(RNG.next32());
    Function *Stub = buildWideDecryptStub(
        M, &const_cast<GlobalVariable &>(GV),
        static_cast<unsigned>(Len), 8, Key, "swift_" + Suffix);
    SwiftStubs.push_back(Stub);

    Changed = true;
  }

  buildRuntimeStringDecryptCtor(M, SwiftStubs,
                                 "kagura_swift_string_decrypt_ctor",
                                 CtorPriority::SwiftString);

  // ---- Kotlin Native string constants (private [N x i8], kotlin patterns) --

  SmallVector<Function *, 8> KotlinStubs;

  for (auto &GV : M.globals()) {
    if (!isKotlinStringGlobal(GV))
      continue;
    auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
    if (!CDA)
      continue;
    StringRef Raw = CDA->getAsString();
    uint64_t Len  = Raw.size();

    uint8_t Key[8];
    uint64_t RandKey = RNG.next();
    for (unsigned I = 0; I < 8; ++I)
      Key[I] = static_cast<uint8_t>((RandKey >> (I * 8)) & 0xFF);

    std::vector<Constant *> EncBytes;
    EncBytes.reserve(Len);
    for (uint64_t I = 0; I < Len; ++I)
      EncBytes.push_back(ConstantInt::get(Int8Ty,
          static_cast<uint8_t>(Raw[I]) ^ Key[I % 8]));
    auto *EncConst = ConstantArray::get(ArrayType::get(Int8Ty, Len), EncBytes);

    const_cast<GlobalVariable &>(GV).setConstant(false);
    const_cast<GlobalVariable &>(GV).setInitializer(EncConst);

    std::string Suffix = std::to_string(RNG.next32());
    Function *Stub = buildWideDecryptStub(
        M, &const_cast<GlobalVariable &>(GV),
        static_cast<unsigned>(Len), 8, Key, "kotlin_" + Suffix);
    KotlinStubs.push_back(Stub);

    Changed = true;
  }

  buildRuntimeStringDecryptCtor(M, KotlinStubs,
                                 "kagura_kotlin_string_decrypt_ctor",
                                 CtorPriority::RuntimeString);

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
