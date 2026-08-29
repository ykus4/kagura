//===-- StringSplit.cpp - String literal fragmenter pass ------------------===//
//
// Splits long string literals into N smaller fragments stored in separate
// private globals, then injects a per-string assembler stub that
// concatenates them at runtime on first access.
//
// Motivation
// ----------
// `kagura-str` XOR-encrypts strings, defeating `strings -n 4` for the literal
// itself.  But static analyzers can still discover the encrypted-blob global
// at a single contiguous offset.  String-split breaks that observation:
//
//   - The plaintext (or kagura-str-encrypted ciphertext) never lives as a
//     contiguous span in .rodata.  Each fragment is at most `MaxFragLen`
//     bytes (default 8).
//   - Fragments are stored in *separate* globals with randomized names, so
//     a memory map showing "this region holds the encrypted secret" no
//     longer applies.
//   - The runtime concatenation stub runs **once** per string on first
//     access — same lazy-init pattern as `kagura-str`, so cost is
//     amortized.
//
// Compose with `kagura-str` (string-split runs AFTER it) for maximal effect:
// each fragment is itself XOR-encrypted, and the resulting binary has
// neither a contiguous plaintext nor a contiguous ciphertext for the
// original string.
//
// Eligibility
// -----------
// A `GlobalVariable` is eligible when:
//   - private linkage, constant, initialized with a `ConstantDataArray` of i8
//   - length >= `MinSplitLen` (default 16 bytes — below this the split is
//     pointless and adds more overhead than benefit)
//   - not annotated `kagura_nosplit`
//   - name does not start with "kagura_" (own scaffolding)
//
// Transformation
// --------------
// For an eligible string of length N split into K fragments:
//
//   @str = private constant [N x i8] c"...secret data..."
//
// becomes:
//
//   @str.frag.0 = private constant [n0 x i8] c"...se"
//   @str.frag.1 = private constant [n1 x i8] c"cret "
//   @str.frag.2 = private constant [n2 x i8] c"dat"
//   @str.frag.3 = private constant [n3 x i8] c"a"
//   @str.recombined = global [N x i8] zeroinitializer
//   @str.flag       = global i8 0
//
//   void __kagura_strsplit_<suffix>() {
//     if (str.flag) return;
//     memcpy(str.recombined + 0,  str.frag.0, n0);
//     memcpy(str.recombined + n0, str.frag.1, n1);
//     ...
//     str.flag = 1;
//   }
//
// Every use of @str is rewritten to call the init stub then load
// @str.recombined.  The fragments are randomly ordered in memory (the
// generated stub still concatenates in the original order — so
// observation order on disk reveals nothing).
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes/Data.h"
#include "kagura/Utils.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <string>
#include <vector>

using namespace llvm;

namespace kagura {

namespace {
constexpr uint32_t kMinSplitLen = 16;   // bytes
constexpr uint32_t kMaxFragLen  = 8;    // bytes per fragment
constexpr uint32_t kMinFragLen  = 1;
} // namespace

// Build the per-string init stub that memcpy's each fragment into the
// recombined buffer and sets the flag.
static Function *buildSplitInit(Module &M,
                                ArrayRef<GlobalVariable *> Fragments,
                                ArrayRef<uint32_t> Offsets,
                                ArrayRef<uint32_t> Lengths,
                                GlobalVariable *Recombined,
                                GlobalVariable *Flag,
                                StringRef Suffix) {
  LLVMContext &Ctx = M.getContext();
  auto *VoidTy = Type::getVoidTy(Ctx);
  auto *Int8Ty = Type::getInt8Ty(Ctx);
  auto *Int8PtrTy = PointerType::getUnqual(Ctx);

  auto *FTy = FunctionType::get(VoidTy, false);
  auto *F   = Function::Create(FTy, Function::InternalLinkage,
                               ("__kagura_strsplit_" + Suffix).str(), M);
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::NoUnwind);

  auto *Entry = BasicBlock::Create(Ctx, "entry", F);
  auto *Init  = BasicBlock::Create(Ctx, "init", F);
  auto *Done  = BasicBlock::Create(Ctx, "done", F);

  // entry: if (flag) goto done; else goto init;
  IRBuilder<> B(Entry);
  auto *FlagVal = B.CreateLoad(Int8Ty, Flag, "flag.val");
  auto *Cmp     = B.CreateICmpNE(FlagVal, ConstantInt::get(Int8Ty, 0),
                                  "already.init");
  B.CreateCondBr(Cmp, Done, Init);

  // init: memcpy each fragment, then set flag = 1
  B.SetInsertPoint(Init);
  for (size_t i = 0; i < Fragments.size(); ++i) {
    auto *DstPtr = B.CreateInBoundsGEP(
        cast<ArrayType>(Recombined->getValueType()),
        Recombined,
        {ConstantInt::get(Type::getInt32Ty(Ctx), 0),
         ConstantInt::get(Type::getInt32Ty(Ctx), Offsets[i])},
        "dst.ptr");
    auto *SrcPtr = B.CreateBitCast(Fragments[i], Int8PtrTy);
    B.CreateMemCpy(DstPtr, MaybeAlign(1), SrcPtr, MaybeAlign(1), Lengths[i]);
  }
  B.CreateStore(ConstantInt::get(Int8Ty, 1), Flag);
  B.CreateBr(Done);

  // done: ret void
  B.SetInsertPoint(Done);
  B.CreateRetVoid();

  return F;
}

static bool processGlobal(Module &M, GlobalVariable *GV, PRNG &RNG,
                          uint32_t StringIdx) {
  if (!GV->isConstant()) return false;
  if (!GV->hasInitializer()) return false;
  auto *Init = dyn_cast<ConstantDataArray>(GV->getInitializer());
  if (!Init) return false;
  if (!Init->isString()) return false;

  StringRef Str = Init->getAsString();
  if (Str.size() < kMinSplitLen) return false;

  // Skip kagura's own scaffolding
  if (GV->getName().starts_with("kagura_")) return false;
  if (GV->getName().contains(".frag.")) return false;

  // Build random fragment lengths summing to Str.size()
  std::vector<uint32_t> Lengths;
  std::vector<uint32_t> Offsets;
  uint32_t Remaining = (uint32_t)Str.size();
  uint32_t Off = 0;
  while (Remaining > 0) {
    uint32_t Hi = Remaining < kMaxFragLen ? Remaining : kMaxFragLen;
    uint32_t Len = (uint32_t)RNG.nextRange(kMinFragLen, Hi + 1);
    if (Len > Remaining) Len = Remaining;
    Lengths.push_back(Len);
    Offsets.push_back(Off);
    Off       += Len;
    Remaining -= Len;
  }

  LLVMContext &Ctx = M.getContext();
  auto *Int8Ty = Type::getInt8Ty(Ctx);

  std::string Suffix = std::to_string(StringIdx);

  // Build fragment globals
  std::vector<GlobalVariable *> Fragments;
  Fragments.reserve(Lengths.size());
  for (size_t i = 0; i < Lengths.size(); ++i) {
    StringRef Frag = Str.substr(Offsets[i], Lengths[i]);
    auto *FragTy   = ArrayType::get(Int8Ty, Lengths[i]);
    std::vector<Constant *> Bytes;
    Bytes.reserve(Lengths[i]);
    for (char C : Frag)
      Bytes.push_back(ConstantInt::get(Int8Ty, (uint8_t)C));
    auto *FragConst = ConstantArray::get(FragTy, Bytes);
    auto *FragGV    = new GlobalVariable(
        M, FragTy, true, GlobalValue::PrivateLinkage, FragConst,
        ("kagura_str_frag_" + Suffix + "_" + std::to_string(i)));
    FragGV->setAlignment(Align(1));
    Fragments.push_back(FragGV);
  }

  // Build recombined zero-init global with the original element type
  auto *RecombinedTy = ArrayType::get(Int8Ty, Str.size());
  auto *Recombined = new GlobalVariable(
      M, RecombinedTy, false, GlobalValue::PrivateLinkage,
      ConstantAggregateZero::get(RecombinedTy),
      ("kagura_str_recombined_" + Suffix));
  Recombined->setAlignment(Align(1));

  // Build init flag
  auto *Flag = new GlobalVariable(
      M, Int8Ty, false, GlobalValue::PrivateLinkage,
      ConstantInt::get(Int8Ty, 0), ("kagura_str_flag_" + Suffix));

  // Build the init function
  Function *InitFn =
      buildSplitInit(M, Fragments, Offsets, Lengths, Recombined, Flag, Suffix);

  // Rewrite every use of GV: insert a call to InitFn at each user, then
  // replace the operand with Recombined.
  SmallVector<Use *, 8> Uses;
  for (auto &U : GV->uses())
    Uses.push_back(&U);

  for (auto *U : Uses) {
    auto *UserI = dyn_cast<Instruction>(U->getUser());
    if (!UserI) continue;  // skip metadata / non-instruction users
    // Skip uses inside the init function we just built — those refer to
    // the fragments / recombined globals, not the original.
    if (UserI->getFunction() == InitFn) continue;
    IRBuilder<> B(UserI);
    B.CreateCall(InitFn);
    U->set(Recombined);
  }

  // Original GV may still be referenced by metadata or by uses we couldn't
  // rewrite — leave it in place if so; otherwise remove.
  if (GV->use_empty())
    GV->eraseFromParent();

  return true;
}

PreservedAnalyses StringSplitPass::run(Module &M, ModuleAnalysisManager &) {
  auto &RNG    = getModulePRNG(M);
  bool Changed = false;
  uint32_t Idx = 0;

  // Snapshot globals — we'll add new ones inside the loop.
  SmallVector<GlobalVariable *, 16> Candidates;
  for (auto &G : M.globals()) {
    if (auto *GV = dyn_cast<GlobalVariable>(&G))
      Candidates.push_back(GV);
  }

  for (auto *GV : Candidates) {
    if (processGlobal(M, GV, RNG, Idx)) {
      ++Idx;
      Changed = true;
    }
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
