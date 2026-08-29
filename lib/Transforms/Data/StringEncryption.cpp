//===-- StringEncryption.cpp - Compile-time string encryption -------------===//
//
// For every GlobalVariable that is a string constant referenced from a
// function, this pass:
//   1. Encrypts the bytes with XOR using a per-string random key.
//   2. Replaces the global with an encrypted version.
//   3. Injects a runtime decryption stub that decrypts on first use.
//
// 4.2.4: Lazy decryption — each string is guarded by a private i8 flag.
//   The decryption stub is only executed the first time the string is
//   accessed at runtime:
//
//     if (!kagura_flag_<suffix>) {
//       kagura_decrypt_<suffix>();
//       kagura_flag_<suffix> = 1;
//     }
//
// 4.2.12: API key / network endpoint protection — the pass also encrypts
//   longer string globals that are skipped by collectStringGlobals() due
//   to heuristics (format specifiers, length thresholds).  URL/key-like
//   strings are opt-in via the "kagura_apikey" annotation or automatically
//   detected when the string starts with "https://", "http://", "Bearer ",
//   "sk-", or "AIza" (common API key prefixes).
//
// The decryption stub itself is later obfuscated by the other passes.
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
#include "llvm/ADT/STLExtras.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <vector>

using namespace llvm;

namespace kagura {

// Build an LLVM function that decrypts Encrypted in-place using key Key.
// uint8_t Key[KeyLen] is XOR'd over the buffer cyclically.
// The generated function signature: void kagura_decrypt_<suffix>(void)
// It is marked NoInline so other passes can still obfuscate it independently.
static Function *buildDecryptStub(Module &M, GlobalVariable *Encrypted,
                                   ArrayRef<uint8_t> Key, StringRef Suffix) {
  LLVMContext &Ctx = M.getContext();
  IRBuilder<> B(Ctx);

  auto *VoidTy  = Type::getVoidTy(Ctx);
  auto *Int8Ty  = Type::getInt8Ty(Ctx);
  auto *Int32Ty = Type::getInt32Ty(Ctx);
  auto *Int64Ty = Type::getInt64Ty(Ctx);

  // void kagura_decrypt_<suffix>()
  auto *FTy = FunctionType::get(VoidTy, false);
  auto *F   = Function::Create(FTy, Function::InternalLinkage,
                               "kagura_decrypt_" + Suffix, M);
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::NoUnwind);

  // Build key constant
  std::vector<Constant *> KeyBytes;
  for (uint8_t B : Key)
    KeyBytes.push_back(ConstantInt::get(Int8Ty, B));
  auto *KeyArrTy = ArrayType::get(Int8Ty, Key.size());
  auto *KeyConst = ConstantArray::get(KeyArrTy, KeyBytes);
  auto *KeyGV    = new GlobalVariable(M, KeyArrTy, true,
                                       GlobalValue::PrivateLinkage, KeyConst,
                                       "kagura_key_" + Suffix);

  // Entry block
  auto *Entry = BasicBlock::Create(Ctx, "entry", F);
  // Loop block
  auto *Loop  = BasicBlock::Create(Ctx, "loop", F);
  // Exit block
  auto *Exit  = BasicBlock::Create(Ctx, "exit", F);

  // Get the encrypted buffer length
  auto *EncTy   = cast<ArrayType>(Encrypted->getValueType());
  uint64_t Len  = EncTy->getNumElements();
  uint64_t KLen = Key.size();

  // entry: idx = 0; br loop_header
  B.SetInsertPoint(Entry);
  auto *IdxAlloc = B.CreateAlloca(Int64Ty, nullptr, "idx");
  B.CreateStore(ConstantInt::get(Int64Ty, 0), IdxAlloc);
  B.CreateBr(Loop);

  // loop_header: if idx < Len goto body else goto exit
  B.SetInsertPoint(Loop);
  auto *Idx      = B.CreateLoad(Int64Ty, IdxAlloc, "i");
  auto *InBounds = B.CreateICmpULT(Idx, ConstantInt::get(Int64Ty, Len));
  // Temporary: will be fixed after creating LoopBody
  auto *HeaderBr = B.CreateCondBr(InBounds, Exit, Exit); // placeholders

  // body block
  auto *LoopBody = BasicBlock::Create(Ctx, "body", F);
  HeaderBr->setSuccessor(0, LoopBody);

  B.SetInsertPoint(LoopBody);
  // key index = idx % KLen  (use i64 throughout, GEP accepts i64)
  auto *KIdxFull = B.CreateURem(Idx, ConstantInt::get(Int64Ty, KLen), "kidx");

  // Load key byte: KeyGV[0][kidx]
  auto *KPtr  = B.CreateInBoundsGEP(KeyArrTy, KeyGV,
                                     {ConstantInt::get(Int64Ty, 0), KIdxFull});
  auto *KByte = B.CreateLoad(Int8Ty, KPtr, "kb");

  // Load encrypted byte: Encrypted[0][idx]
  auto *EPtr  = B.CreateInBoundsGEP(EncTy, Encrypted,
                                     {ConstantInt::get(Int64Ty, 0), Idx});
  auto *EByte = B.CreateLoad(Int8Ty, EPtr, "eb");

  // XOR and store back
  auto *Plain = B.CreateXor(EByte, KByte, "plain");
  B.CreateStore(Plain, EPtr);

  // idx++; br loop_header
  auto *Next = B.CreateAdd(Idx, ConstantInt::get(Int64Ty, 1), "next");
  B.CreateStore(Next, IdxAlloc);
  B.CreateBr(Loop);

  // exit block
  B.SetInsertPoint(Exit);
  B.CreateRetVoid();

  return F;
}

// ---- 4.2.12: API key / network endpoint detection -------------------------

/// Returns true if Raw looks like a network endpoint, bearer token, or API key
/// that should be force-encrypted regardless of the collectStringGlobals()
/// heuristics (e.g., even if it contains '%' or is otherwise filtered).
static bool looksLikeApiKey(StringRef Raw) {
  // Common URL schemes
  if (Raw.starts_with("https://") || Raw.starts_with("http://"))
    return true;
  // Common API key prefixes
  if (Raw.starts_with("Bearer ") || Raw.starts_with("Authorization:"))
    return true;
  if (Raw.starts_with("sk-"))          // OpenAI / Stripe style keys
    return true;
  if (Raw.starts_with("AIza"))         // Google API keys
    return true;
  if (Raw.starts_with("AAAA") && Raw.size() >= 40) // Firebase / FCM tokens
    return true;
  return false;
}

/// Collect string globals that should be encrypted by the STR pass.
/// Extends collectStringGlobals() to also capture API key / URL globals.
static std::vector<GlobalVariable *> collectEncryptionTargets(Module &M) {
  // Standard collection (strips format strings etc.)
  auto Result = kagura::collectStringGlobals(M);

  // 4.2.12: Additionally scan for API key / URL-like strings that were
  // rejected by the standard heuristics (e.g. contain '%' from URL encoding).
  for (auto &GV : M.globals()) {
    if (!GV.isConstant() || !GV.hasInitializer())
      continue;
    if (GV.getName().starts_with("kagura_"))
      continue;
    auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
    if (!CDA || !CDA->isString())
      continue;
    StringRef S = CDA->getAsString();
    if (S.size() < 8)
      continue;
    if (!looksLikeApiKey(S))
      continue;
    // Avoid duplicates with the standard list
    if (!llvm::is_contained(Result, &GV))
      Result.push_back(&GV);
  }
  return Result;
}

// ---- Pass entry point ------------------------------------------------------

PreservedAnalyses StringEncryptionPass::run(Module &M,
                                             ModuleAnalysisManager &) {
  auto Strings = collectEncryptionTargets(M);
  if (Strings.empty())
    return PreservedAnalyses::all();

  LLVMContext &Ctx = M.getContext();
  auto &RNG        = getModulePRNG(M);
  bool Changed     = false;

  auto *Int8Ty = Type::getInt8Ty(Ctx);

  for (auto *GV : Strings) {
    if (!hasOnlyGuardableUses(GV))
      continue;

    auto *CDA = dyn_cast<ConstantDataArray>(GV->getInitializer());
    if (!CDA)
      continue;
    StringRef Raw = CDA->getRawDataValues();
    uint64_t Len  = Raw.size();

    // Generate random XOR key (8 bytes, cyclic)
    constexpr size_t KeyLen = 8;
    uint8_t Key[KeyLen];
    uint64_t RandKey = RNG.next();
    for (size_t I = 0; I < KeyLen; ++I)
      Key[I] = static_cast<uint8_t>((RandKey >> (I * 8)) & 0xFF);

    // Encrypt the string bytes
    std::vector<uint8_t> Encrypted(Len);
    for (uint64_t I = 0; I < Len; ++I)
      Encrypted[I] = static_cast<uint8_t>(Raw[I]) ^ Key[I % KeyLen];

    // Build encrypted global (mutable, private)
    auto *ArrTy    = ArrayType::get(Int8Ty, Len);
    std::vector<Constant *> EncBytes;
    EncBytes.reserve(Len);
    for (uint8_t B : Encrypted)
      EncBytes.push_back(ConstantInt::get(Int8Ty, B));
    auto *EncConst = ConstantArray::get(ArrTy, EncBytes);

    std::string Suffix = std::to_string(RNG.next32());
    auto *EncGV = new GlobalVariable(M, ArrTy, /*isConstant=*/false,
                                     GlobalValue::PrivateLinkage, EncConst,
                                     "kagura_enc_" + Suffix);
    EncGV->setAlignment(GV->getAlign());

    // 4.2.4: Per-string decrypted flag (i8, init=0).
    auto *FlagGV = new GlobalVariable(M, Int8Ty, /*isConstant=*/false,
                                      GlobalValue::PrivateLinkage,
                                      ConstantInt::get(Int8Ty, 0),
                                      "kagura_flag_" + Suffix);
    FlagGV->setAlignment(Align(1));

    // Build decryption stub
    ArrayRef<uint8_t> KeyRef(Key, KeyLen);
    auto *Stub = buildDecryptStub(M, EncGV, KeyRef, Suffix);

    // Replace uses: inject lazy guard before each instruction that uses GV,
    // then redirect the operand to EncGV.
    SmallVector<User *, 8> Users(GV->users());
    for (auto *U : Users) {
      if (auto *CE = dyn_cast<ConstantExpr>(U)) {
        SmallVector<User *, 8> CEUsers(CE->users());
        for (auto *CU : CEUsers) {
          auto *Inst = dyn_cast<Instruction>(CU);
          if (!Inst || isa<PHINode>(Inst))
            continue;

          emitLazyGuard(Inst, FlagGV, Stub);

          Value *Replacement = EncGV;
          IRBuilder<> IB(Inst);
          if (CE->getType() != EncGV->getType())
            Replacement = IB.CreateBitCast(EncGV, CE->getType());
          Inst->replaceUsesOfWith(CE, Replacement);
        }
        continue;
      }
      if (auto *Inst = dyn_cast<Instruction>(U)) {
        // PHI nodes cannot be split-points: splitBasicBlock at a PHI leaves
        // the PHI in the wrong block with stale predecessor lists.  Skip PHI
        // uses here; they are reached from a non-PHI use site where the guard
        // will be inserted, or they are covered by the ConstantExpr path above.
        if (isa<PHINode>(Inst)) {
          continue;
        }

        // 4.2.4: emit lazy guard — splits the block, so must come before
        // any operand replacement.
        emitLazyGuard(Inst, FlagGV, Stub);

        for (unsigned I = 0; I < Inst->getNumOperands(); ++I) {
          if (Inst->getOperand(I)->stripPointerCasts() == GV)
            Inst->setOperand(I, EncGV);
        }
      }
    }

    if (GV->use_empty())
      GV->eraseFromParent();

    Changed = true;
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace kagura
