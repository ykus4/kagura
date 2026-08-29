#include "kagura/Options.h"
#include "kagura/Utils.h"
#include "llvm/ADT/StringRef.h"

#if __has_include("llvm/TargetParser/Triple.h")
#include "llvm/TargetParser/Triple.h"  // LLVM 20+
#else
#include "llvm/ADT/Triple.h"           // LLVM 17-19
#endif
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace kagura {

// ---- Annotation helpers ----

bool hasAnnotation(Function &F, StringRef Attr) {
  // Function metadata, written by AutoSelectPass. Checked first because it is
  // far cheaper than walking llvm.global.annotations, and because AutoSelect
  // runs before every pass that queries this.
  //
  // AutoSelect used to write this metadata while nothing ever read it, which
  // made the entire pass a no-op.
  if (F.hasMetadata(Attr))
    return true;

  Module *M = F.getParent();
  GlobalVariable *GA =
      M->getGlobalVariable("llvm.global.annotations");
  if (!GA)
    return false;
  auto *CA = dyn_cast<ConstantArray>(GA->getInitializer());
  if (!CA)
    return false;
  for (unsigned I = 0; I < CA->getNumOperands(); ++I) {
    auto *CS = dyn_cast<ConstantStruct>(CA->getOperand(I));
    if (!CS || CS->getNumOperands() < 2)
      continue;
    auto *FPtr =
        dyn_cast<Function>(CS->getOperand(0)->stripPointerCasts());
    if (FPtr != &F)
      continue;
    auto *GV =
        dyn_cast<GlobalVariable>(CS->getOperand(1)->stripPointerCasts());
    if (!GV || !GV->hasInitializer())
      continue;
    auto *Str = dyn_cast<ConstantDataArray>(GV->getInitializer());
    if (!Str)
      continue;
    if (Str->getAsCString().contains(Attr))
      return true;
  }
  return false;
}

// ---- Kagura-generated symbol recognition ----------------------------------

// ---- Generated-IR marker ---------------------------------------------------

static constexpr StringRef kGeneratedMD = "kagura.generated";

void markGenerated(Instruction &I) {
  I.setMetadata(kGeneratedMD, MDNode::get(I.getContext(), {}));
}

void markGenerated(BasicBlock &BB) {
  for (Instruction &I : BB)
    markGenerated(I);
}

bool isGenerated(const Instruction &I) {
  return I.getMetadata(kGeneratedMD) != nullptr;
}

bool isGenerated(const BasicBlock &BB) {
  for (const Instruction &I : BB)
    if (isGenerated(I))
      return true;
  return false;
}

bool isKaguraSymbol(StringRef Name) {
  // Every prefix any kagura pass emits. Keep in sync when adding a pass that
  // creates new globals or helper functions; a missing entry means later
  // passes re-obfuscate our own helpers and SymbolMap reports them as user
  // symbols.
  static constexpr StringRef Prefixes[] = {
      "kagura_",   // runtime calls, decrypt stubs, keys, flags, honey values
      "__kagura",  // CallIndirection thunk table, StringSplit initialisers
      "__kg_",     // FunctionSplit outlined helpers
      "kagura.",   // EncryptedLookupTable and ControlFlowFlattening globals
  };
  for (StringRef P : Prefixes)
    if (Name.starts_with(P))
      return true;
  return false;
}

// ---- Integer width helpers ------------------------------------------------

uint64_t maskForWidth(unsigned Bits) {
  return Bits >= 64 ? ~0ULL : ((1ULL << Bits) - 1);
}

uint64_t randomForWidth(PRNG &RNG, unsigned Bits) {
  // next32() below 32 bits keeps the draw count identical to what the passes
  // that already masked by hand were doing, so this does not perturb the key
  // stream of anything that was already correct.
  uint64_t Raw = Bits <= 32 ? RNG.next32() : RNG.next();
  return Raw & maskForWidth(Bits);
}

bool isSupportedIntWidth(unsigned Bits) {
  return Bits == 8 || Bits == 16 || Bits == 32 || Bits == 64;
}

bool isSupportedIntType(const Type *Ty) {
  return Ty->isIntegerTy() && isSupportedIntWidth(Ty->getIntegerBitWidth());
}

// ---- Hashing --------------------------------------------------------------

// FNV-1a parameters. Mirrored in runtime/core/hash.c — the runtime recomputes
// hashes that these produce at compile time, so the two must agree exactly.
static constexpr uint32_t kFnv1a32Offset = 0x811c9dc5u;
static constexpr uint32_t kFnv1a32Prime  = 0x01000193u;
static constexpr uint64_t kFnv1a64Offset = 0xcbf29ce484222325ULL;
static constexpr uint64_t kFnv1a64Prime  = 0x100000001b3ULL;

uint32_t fnv1a32(ArrayRef<uint8_t> Data) {
  uint32_t H = kFnv1a32Offset;
  for (uint8_t B : Data) {
    H ^= B;
    H *= kFnv1a32Prime;
  }
  return H;
}

uint32_t fnv1a32(StringRef S) {
  return fnv1a32(ArrayRef<uint8_t>(
      reinterpret_cast<const uint8_t *>(S.data()), S.size()));
}

uint64_t fnv1a64(StringRef S) {
  uint64_t H = kFnv1a64Offset;
  for (char C : S) {
    H ^= static_cast<uint8_t>(C);
    H *= kFnv1a64Prime;
  }
  return H;
}

// ---- Module constructors --------------------------------------------------

void appendKaguraCtor(Module &M, Function *Ctor, CtorPriority P) {
  appendToGlobalCtors(M, Ctor, static_cast<int>(P));
}

// ---- List-matching helpers (4.6.3 / 4.6.4) --------------------------------

/// Returns true if Name matches any pattern in the comma-separated list.
/// Patterns may use a trailing '*' glob (e.g. "my_prefix_*").
static bool matchesList(StringRef Name, StringRef List) {
  if (List.empty())
    return false;
  SmallVector<StringRef, 16> Patterns;
  List.split(Patterns, ',', /*MaxSplit=*/-1, /*KeepEmpty=*/false);
  for (StringRef Pat : Patterns) {
    Pat = Pat.trim();
    if (Pat.empty())
      continue;
    if (Pat.ends_with("*")) {
      if (Name.starts_with(Pat.drop_back(1)))
        return true;
    } else {
      if (Name == Pat)
        return true;
    }
  }
  return false;
}

bool shouldObfuscate(Function &F, StringRef PassAttr, bool GlobalFlag) {
  // Never obfuscate kagura's own injected helper functions.
  //
  // isKaguraSymbol rather than starts_with("kagura_"): the narrow test missed
  // the __kg_* helpers FunctionSplit outlines and the kagura.* globals
  // EncryptedLookupTable and ControlFlowFlattening emit, so later passes in
  // the same pipeline re-obfuscated them.
  if (isKaguraSymbol(F.getName()))
    return false;

  // 4.1.9: Sanitizer compatibility — skip obfuscation when ASan, TSan, UBSan,
  // or MSan function attributes are present to prevent false positives.
  // Functions built with sanitizers have __sanitizer_* attributes or
  // the "noinstrument" attribute set by the sanitizer runtime.
  if (F.hasFnAttribute(Attribute::SanitizeAddress) ||
      F.hasFnAttribute(Attribute::SanitizeThread)  ||
      F.hasFnAttribute(Attribute::SanitizeMemory)  ||
      F.hasFnAttribute(Attribute::SanitizeHWAddress))
    return false;

  StringRef Name = F.getName();

  // 4.6.3: force-protect list — overrides everything except deny
  if (!opt::ProtectList.empty() && matchesList(Name, opt::ProtectList))
    return true;

  // 4.6.4: denylist — explicit exclusion takes highest precedence
  if (!opt::DenyList.empty() && matchesList(Name, opt::DenyList))
    return false;

  // 4.8.2: hot path annotation — skip obfuscation on performance-critical funcs
  if (hasAnnotation(F, "kagura_hotpath"))
    return false;

  // 4.6.4: allowlist mode — when set, only matching symbols are obfuscated
  if (!opt::AllowList.empty() && !matchesList(Name, opt::AllowList))
    return false;

  std::string EnableAttr  = ("kagura_" + PassAttr).str();
  std::string DisableAttr = ("kagura_no" + PassAttr).str();
  if (hasAnnotation(F, DisableAttr))
    return false;
  if (hasAnnotation(F, EnableAttr))
    return true;
  return GlobalFlag;
}

// ---- PRNG ----

// Note: the -kagura-seed option is declared in Plugin.cpp to avoid
// duplicate registration. Access via getModulePRNG() which reads it.

// Fixed default seed used when neither -kagura-seed nor -kagura-build-id is
// given. Chosen so the tool is reproducible by default (same IR in -> same
// binary out), which is what CI and supply-chain verification want. Callers
// who need a unique key per build opt in with -kagura-build-id=<git-sha> or an
// explicit -kagura-seed; both feed through getModulePRNG() below.
static constexpr uint64_t kDefaultSeed = 0x6b6167757261ULL; // "kagura"

PRNG::PRNG(uint64_t Seed) {
  // A zero seed is treated as "use the deterministic default" rather than
  // reaching for wall-clock / std::random_device entropy: obfuscation keys are
  // embedded in (and recoverable from) the output binary regardless, so a
  // random default buys no real secrecy while destroying reproducibility.
  State = Seed ? Seed : kDefaultSeed;
}

uint64_t PRNG::next() {
  uint64_t Z = (State += 0x9e3779b97f4a7c15ULL);
  Z = (Z ^ (Z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  Z = (Z ^ (Z >> 27)) * 0x94d049bb133111ebULL;
  return Z ^ (Z >> 31);
}

uint32_t PRNG::next32() { return static_cast<uint32_t>(next()); }

uint64_t PRNG::nextRange(uint64_t Lo, uint64_t Hi) {
  assert(Hi > Lo);
  return Lo + (next() % (Hi - Lo));
}

static PRNG GlobalPRNG(0);

PRNG &getModulePRNG() {
  static bool Seeded = false;
  if (!Seeded) {
    uint64_t BaseSeed = opt::Seed;
    // 4.2.7: Mix BuildID into seed for per-build key rotation.
    // Using FNV-1a over the BuildID string ensures unique keys even when
    // the user specifies a fixed -kagura-seed for reproducible output.
    if (!opt::BuildID.empty()) {
      uint64_t Hash = 0xcbf29ce484222325ULL; // FNV offset basis
      for (char C : opt::BuildID.getValue()) {
        Hash ^= static_cast<uint8_t>(C);
        Hash *= 0x100000001b3ULL; // FNV prime
      }
      BaseSeed ^= Hash;
    }
    GlobalPRNG = PRNG(BaseSeed);
    Seeded = true;
  }
  return GlobalPRNG;
}

// ---- Exception-handling safety ----

bool hasExceptionHandling(const Function &F) {
  for (const BasicBlock &BB : F)
    for (const Instruction &I : BB)
      if (isa<InvokeInst>(I) || isa<LandingPadInst>(I) ||
          isa<ResumeInst>(I) || isa<CleanupPadInst>(I) ||
          isa<CatchPadInst>(I) || isa<CatchReturnInst>(I) ||
          isa<CleanupReturnInst>(I))
        return true;
  return false;
}

bool isEHBlock(const BasicBlock &BB) {
  const Instruction *First = &BB.front();
  if (isa<LandingPadInst>(First) || isa<CleanupPadInst>(First) ||
      isa<CatchPadInst>(First))
    return true;
  for (const Instruction &I : BB)
    if (isa<LandingPadInst>(I) || isa<CleanupPadInst>(I) ||
        isa<CatchPadInst>(I) || isa<ResumeInst>(I))
      return true;
  return false;
}

// ---- Target triple helpers ----

// Overload set: converts whichever type getTargetTriple() returns to std::string.
// LLVM 17-19 returns const std::string &; LLVM 20+ returns const Triple &.
static std::string tripleToString(const std::string &S) { return S; }
static std::string tripleToString(const llvm::Triple &T) { return T.str(); }

std::string getModuleTriple(const Module &M) {
  return tripleToString(M.getTargetTriple());
}

TargetArch getTargetArch(const Module &M) {
  std::string TripleStr = getModuleTriple(M);
  StringRef Triple(TripleStr);
  // arm64e must be checked before generic aarch64 since it is a substring match.
  if (Triple.contains("arm64e"))
    return TargetArch::ARM64e;
  if (Triple.starts_with("aarch64") || Triple.starts_with("arm64"))
    return TargetArch::ARM64;
  if (Triple.starts_with("armv7") || Triple.starts_with("thumbv7"))
    return TargetArch::ARMv7;
  if (Triple.starts_with("x86_64") || Triple.starts_with("amd64"))
    return TargetArch::X86_64;
  if (Triple.starts_with("wasm64"))
    return TargetArch::Wasm64;
  if (Triple.starts_with("wasm32"))
    return TargetArch::Wasm32;
  return TargetArch::Other;
}

bool isAArch64Target(const Module &M) {
  TargetArch A = getTargetArch(M);
  return A == TargetArch::ARM64 || A == TargetArch::ARM64e;
}

bool isArm64eTarget(const Module &M) {
  return getTargetArch(M) == TargetArch::ARM64e;
}

bool isARMv7Target(const Module &M) {
  return getTargetArch(M) == TargetArch::ARMv7;
}

bool isX86_64Target(const Module &M) {
  return getTargetArch(M) == TargetArch::X86_64;
}

bool isWasmTarget(const Module &M) {
  TargetArch A = getTargetArch(M);
  return A == TargetArch::Wasm32 || A == TargetArch::Wasm64;
}

// ---- IR helpers ----

void demotePhis(Function &F) {
  // Full reg2mem: demote both PHI nodes and any non-PHI instruction whose
  // uses cross a basic-block boundary.  FLA rewires the entire CFG into a
  // switch dispatch, so the old dominator tree is invalidated — every
  // cross-block SSA use would violate dominance in the new CFG.
  //
  // Process PHIs first (they must be demoted before the instructions that
  // use their results, otherwise DemoteRegToStack trips on a PHI user).
  std::vector<PHINode *> Phis;
  for (auto &BB : F)
    for (auto &I : BB)
      if (auto *Phi = dyn_cast<PHINode>(&I))
        Phis.push_back(Phi);
  for (auto *Phi : Phis)
    DemotePHIToStack(Phi);

  // Now demote non-PHI instructions with cross-block uses.
  // Skip: terminators, instructions with no uses, allocas (already memory),
  // and any instruction in the entry block whose only users are in the same
  // block (avoids demoting entry-block stores/loads that reference args).
  std::vector<Instruction *> ToSpill;
  for (auto &BB : F) {
    for (auto &I : BB) {
      if (isa<PHINode>(I) || I.isTerminator() || I.use_empty())
        continue;
      // Never demote alloca instructions — they are already memory references.
      if (isa<AllocaInst>(I))
        continue;
      for (auto *U : I.users()) {
        auto *UI = dyn_cast<Instruction>(U);
        if (UI && UI->getParent() != &BB) {
          ToSpill.push_back(&I);
          break;
        }
      }
    }
  }
  for (auto *I : ToSpill)
    DemoteRegToStack(*I, /*VolatileLoads=*/false);
}

std::vector<BasicBlock *> getBlocks(Function &F) {
  std::vector<BasicBlock *> Blocks;
  for (auto &BB : F)
    Blocks.push_back(&BB);
  return Blocks;
}

Function *getOrDeclare(Module &M, StringRef Name, FunctionType *FTy) {
  if (auto *F = M.getFunction(Name))
    return F;
  return Function::Create(FTy, Function::ExternalLinkage, Name, M);
}

Function *createCtorFunction(Module &M, const Twine &Name) {
  LLVMContext &Ctx = M.getContext();
  auto *FTy = FunctionType::get(Type::getVoidTy(Ctx), /*isVarArg=*/false);
  auto *F = Function::Create(FTy, Function::InternalLinkage, Name, M);
  BasicBlock::Create(Ctx, "entry", F);
  return F;
}

// ---- Global-variable use analysis ----

bool hasOnlyGuardableUses(const GlobalVariable *GV) {
  for (const User *U : GV->users()) {
    if (isa<PHINode>(U))
      return false;
    if (isa<Instruction>(U))
      continue;
    if (isa<ConstantExpr>(U)) {
      for (const User *Nested : U->users()) {
        if (!isa<Instruction>(Nested) || isa<PHINode>(Nested))
          return false;
      }
      continue;
    }
    return false;
  }
  return true;
}

// ---- Lazy-decrypt guard ----

void emitLazyGuard(Instruction *InsertBefore, GlobalVariable *FlagGV,
                   Function *DecryptStub, StringRef BBPrefix) {
  Function *ParentF = InsertBefore->getFunction();
  LLVMContext &Ctx  = ParentF->getContext();
  auto *Int8Ty      = Type::getInt8Ty(Ctx);

  // Split at InsertBefore so we get
  //   CheckBB --(flag == 0)--> DecryptBB --> MergeBB
  //           --(flag != 0)-------------> MergeBB
  BasicBlock *CheckBB = InsertBefore->getParent();
  BasicBlock *MergeBB =
      CheckBB->splitBasicBlock(InsertBefore, BBPrefix + ".merge");
  BasicBlock *DecryptBB =
      BasicBlock::Create(Ctx, BBPrefix + ".decrypt", ParentF, MergeBB);

  // splitBasicBlock leaves an unconditional branch behind; replace it with the
  // flag test.
  CheckBB->getTerminator()->eraseFromParent();

  IRBuilder<> B(CheckBB);
  Value *Flag   = B.CreateLoad(Int8Ty, FlagGV, BBPrefix + ".flag");
  Value *IsZero = B.CreateICmpEQ(Flag, ConstantInt::get(Int8Ty, 0));
  B.CreateCondBr(IsZero, DecryptBB, MergeBB);

  IRBuilder<> DB(DecryptBB);
  DB.CreateCall(DecryptStub);
  DB.CreateStore(ConstantInt::get(Int8Ty, 1), FlagGV);
  DB.CreateBr(MergeBB);
}

// ---- Call rewriting ----

CallInst *replaceCalleeWith(CallInst *CI, FunctionType *FTy, Value *NewCallee) {
  SmallVector<Value *, 8> Args(CI->args());
  SmallVector<OperandBundleDef, 2> Bundles;
  CI->getOperandBundlesAsDefs(Bundles);

  IRBuilder<> B(CI);
  CallInst *NewCI = B.CreateCall(FTy, NewCallee, Args, Bundles);

  NewCI->setCallingConv(CI->getCallingConv());
  NewCI->setAttributes(CI->getAttributes());
  NewCI->setTailCallKind(CI->getTailCallKind());
  NewCI->setDebugLoc(CI->getDebugLoc());
  // Only meaningful on floating-point calls, but harmless otherwise — and
  // omitting it is precisely the drift this helper exists to prevent.
  if (isa<FPMathOperator>(NewCI))
    NewCI->copyFastMathFlags(CI);

  CI->replaceAllUsesWith(NewCI);
  CI->eraseFromParent();
  return NewCI;
}

void replaceAllUsesExcept(Value *Old, Instruction *New) {
  Old->replaceUsesWithIf(New, [&](Use &U) { return U.getUser() != New; });
}

// ---- String global collection ----

std::vector<GlobalVariable *> collectStringGlobals(Module &M,
                                                    bool StrictLinkage) {
  std::vector<GlobalVariable *> Result;
  for (auto &GV : M.globals()) {
    if (!GV.isConstant() || !GV.hasInitializer())
      continue;
    if (StrictLinkage &&
        GV.getLinkage() != GlobalValue::PrivateLinkage &&
        GV.getLinkage() != GlobalValue::InternalLinkage)
      continue;
    auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
    if (!CDA || !CDA->isString())
      continue;
    StringRef S = CDA->getAsString();
    if (S.size() < 4)
      continue;
    if (S.contains('%') || S.trim().empty())
      continue;
    bool UsedInFunction = false;
    for (auto *U : GV.users()) {
      if (isa<Instruction>(U) ||
          (isa<ConstantExpr>(U) && !cast<ConstantExpr>(U)->user_empty())) {
        UsedInFunction = true;
        break;
      }
    }
    if (UsedInFunction)
      Result.push_back(&GV);
  }
  return Result;
}

// ---- Constant builders ----

Constant *buildByteArrayConstant(LLVMContext &Ctx, ArrayRef<uint8_t> Data) {
  auto *Int8Ty = Type::getInt8Ty(Ctx);
  auto *ArrTy  = ArrayType::get(Int8Ty, Data.size());
  std::vector<Constant *> Bytes;
  Bytes.reserve(Data.size());
  for (uint8_t B : Data)
    Bytes.push_back(ConstantInt::get(Int8Ty, B));
  return ConstantArray::get(ArrTy, Bytes);
}

GlobalVariable *createPrivateByteGlobal(Module &M, ArrayRef<uint8_t> Data,
                                         StringRef Name, bool IsConstant) {
  LLVMContext &Ctx = M.getContext();
  auto *Init = buildByteArrayConstant(Ctx, Data);
  return new GlobalVariable(M, Init->getType(), IsConstant,
                            GlobalValue::PrivateLinkage, Init, Name);
}

void fillRandomBytes(uint8_t *Out, size_t Len) {
  PRNG &RNG = getModulePRNG();
  for (size_t I = 0; I < Len; I += 8) {
    uint64_t V = RNG.next();
    size_t N = std::min(static_cast<size_t>(8), Len - I);
    for (size_t J = 0; J < N; ++J)
      Out[I + J] = static_cast<uint8_t>((V >> (J * 8)) & 0xFF);
  }
}

} // namespace kagura
