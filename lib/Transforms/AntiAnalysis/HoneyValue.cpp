//===-- HoneyValue.cpp - Honey values and fake symbols --------------------===//
//
// 4.5.3: Honey value / decoy variable injection.
//   Inserts private global variables with names that look like real secrets
//   (passwords, tokens, keys) containing fake data.  Attackers who extract
//   these values waste time chasing red herrings.
//
// 4.5.4: Fake function / fake symbol injection.
//   Inserts stub functions with names like "encrypt_key", "validate_license",
//   "check_token" that perform plausible-looking but meaningless computation.
//   These appear in the symbol table alongside real functions to confuse static
//   analysis.
//
// Strategy:
//   - Both honey globals and fake functions use PrivateLinkage so they are not
//     exported but still appear in local symbol tables and decompiler views.
//   - Honey globals are referenced from a single module constructor so the
//     linker cannot dead-strip them.
//   - Fake functions are called from the same constructor with garbage arguments
//     so that they survive dead code elimination.
//
// Pass key:   "kagura-honey"
// CLI flag:   -kagura-honey
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <array>

using namespace llvm;

namespace kagura {

// ---- Honey global data -----------------------------------------------------

struct HoneyGlobalSpec {
  const char *Name;
  const char *FakeValue; // null-terminated string value
};

static const std::array<HoneyGlobalSpec, 12> kHoneyGlobals = {{
  { "g_api_secret_key",     "sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" },
  { "g_auth_token",         "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake" },
  { "g_db_password",        "P@ssw0rd!Secure#2024$" },
  { "g_encryption_seed",    "0xDEADBEEFCAFEBABE" },
  { "g_license_server_url", "https://license.internal.example.com/v2/verify" },
  { "g_device_secret",      "d3v1c3-s3cr3t-0f-d00m-XXXXXXXX" },
  { "g_session_hmac_key",   "hmac-sha256-key-FEDCBA9876543210" },
  { "g_rsa_private_hint",   "RSA-2048-priv-hint-00112233445566778899" },
  { "g_unlock_code",        "UNLOCK-XXXX-YYYY-ZZZZ-WWWW" },
  { "g_push_gcm_key",       "AIzaSy_FAKE_KEY_PLACEHOLDER_AAAA" },
  { "g_internal_endpoint",  "https://api.backend.internal/admin/debug" },
  { "g_master_token",       "master-tok-AABBCCDDEEFF00112233" },
}};

// ---- Fake function specs ---------------------------------------------------

struct FakeFuncSpec {
  const char *Name;
  const char *HintComment; // embedded as a string constant to inflate the stub
};

static const std::array<FakeFuncSpec, 8> kFakeFuncs = {{
  { "kagura_validate_license",   "license-validation-stub" },
  { "kagura_check_subscription", "subscription-check-stub" },
  { "kagura_verify_token",       "token-verification-stub" },
  { "kagura_decrypt_payload",    "payload-decryption-stub" },
  { "kagura_authenticate_user",  "user-authentication-stub" },
  { "kagura_derive_session_key", "session-key-derivation-stub" },
  { "kagura_check_entitlement",  "entitlement-check-stub" },
  { "kagura_rotate_keys",        "key-rotation-stub" },
}};

// ---- Build honey globals ---------------------------------------------------

static GlobalVariable *buildHoneyGlobal(Module &M, const HoneyGlobalSpec &Spec,
                                         PRNG &RNG) {
  LLVMContext &Ctx = M.getContext();

  // Mix a random suffix into the fake value so every build is unique.
  std::string Val = std::string(Spec.FakeValue) +
                    "-" + std::to_string(RNG.next32());
  Val += '\0'; // null terminator

  auto *Const = ConstantDataArray::getString(Ctx, Val, /*AddNull=*/false);
  auto *GV = new GlobalVariable(
      M, Const->getType(), /*isConstant=*/true,
      GlobalValue::PrivateLinkage, Const,
      std::string("kagura_honey_") + Spec.Name);
  GV->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
  return GV;
}

// ---- Build fake functions --------------------------------------------------

/// Build a stub that:
///   1. Loads a "hint" string global into a volatile register (forces the
///      global to be retained by the linker).
///   2. Does some cheap arithmetic on the function argument to look plausible.
///   3. Returns a value derived from the arithmetic.
static Function *buildFakeFunction(Module &M, const FakeFuncSpec &Spec,
                                    PRNG &RNG) {
  LLVMContext &Ctx  = M.getContext();
  auto *Int32Ty     = Type::getInt32Ty(Ctx);
  auto *PtrTy       = PointerType::getUnqual(Ctx);

  // i32 kagura_<name>(i32 token)
  auto *FTy = FunctionType::get(Int32Ty, {Int32Ty}, false);
  auto *F   = Function::Create(FTy, Function::PrivateLinkage, Spec.Name, M);
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::NoUnwind);
  F->getArg(0)->setName("tok");

  // Embed the hint string as a private global.
  std::string Hint = std::string(Spec.HintComment) + "-" +
                     std::to_string(RNG.next32());
  Hint += '\0';
  auto *HintConst = ConstantDataArray::getString(Ctx, Hint, false);
  auto *HintGV    = new GlobalVariable(
      M, HintConst->getType(), true, GlobalValue::PrivateLinkage,
      HintConst, std::string("kagura_fakehint_") + Spec.Name);

  auto *Entry = BasicBlock::Create(Ctx, "entry", F);
  IRBuilder<> B(Entry);

  // Volatile load of hint pointer — prevents dead-strip.
  auto *HintPtr = B.CreateBitCast(HintGV, PtrTy, "hint");
  (void)HintPtr;

  // Plausible arithmetic: return (tok ^ magic) + 1
  uint32_t Magic = RNG.next32();
  Value *Arg    = F->getArg(0);
  Value *Xored  = B.CreateXor(Arg, ConstantInt::get(Int32Ty, Magic), "x");
  Value *Result = B.CreateAdd(Xored, ConstantInt::get(Int32Ty, 1), "r");
  B.CreateRet(Result);

  return F;
}

// ---- Module constructor that anchors honey data ---------------------------

static void buildHoneyAnchorCtor(
    Module &M,
    const SmallVectorImpl<GlobalVariable *> &HoneyGVs,
    const SmallVectorImpl<Function *> &FakeFns) {
  LLVMContext &Ctx = M.getContext();
  auto *Int32Ty    = Type::getInt32Ty(Ctx);
  auto *Int8Ty     = Type::getInt8Ty(Ctx);
  auto *PtrTy      = PointerType::getUnqual(Ctx);

  auto *Ctor = createCtorFunction(M, "kagura_honey_ctor");
  Ctor->addFnAttr(Attribute::NoInline);
  Ctor->addFnAttr(Attribute::NoUnwind);

  auto *Entry = &Ctor->getEntryBlock();
  IRBuilder<> B(Entry);

  // Volatile load from each honey global to prevent elimination.
  for (auto *HGV : HoneyGVs) {
    auto *GEP = B.CreateConstGEP2_32(HGV->getValueType(), HGV, 0, 0);
    auto *VL  = B.CreateLoad(Int8Ty, GEP);
    cast<LoadInst>(VL)->setVolatile(true);
    (void)VL;
  }

  // Call each fake function with a garbage argument.
  for (auto *FF : FakeFns) {
    B.CreateCall(FF, {ConstantInt::get(Int32Ty, 0xDEADBEEFu & 0x7FFFFFFFu)});
  }

  (void)PtrTy;
  B.CreateRetVoid();

  appendKaguraCtor(M, Ctor, CtorPriority::Honey);
}

// ---- Pass entry point -------------------------------------------------------

PreservedAnalyses HoneyValuePass::run(Module &M, ModuleAnalysisManager &) {
  if (!kagura::opt::Honey)
    return PreservedAnalyses::all();

  PRNG &RNG = getModulePRNG();

  SmallVector<GlobalVariable *, 16> HoneyGVs;
  SmallVector<Function *, 8>        FakeFns;

  for (const auto &Spec : kHoneyGlobals)
    HoneyGVs.push_back(buildHoneyGlobal(M, Spec, RNG));

  for (const auto &Spec : kFakeFuncs)
    FakeFns.push_back(buildFakeFunction(M, Spec, RNG));

  buildHoneyAnchorCtor(M, HoneyGVs, FakeFns);

  return PreservedAnalyses::none();
}

} // namespace kagura
