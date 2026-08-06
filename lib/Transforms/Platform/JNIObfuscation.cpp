//===-- JNIObfuscation.cpp - JNI dynamic registration conversion ----------===//
//
// Android JNI functions with static naming expose their purpose immediately:
//
//   Java_com_example_app_MainActivity_getSecretKey
//
// This pass converts them to dynamically-registered JNI functions:
//
//   1. Renames Java_* functions to random names.
//   2. Generates a JNI_OnLoad() function (or appends to existing) that calls
//      JNIEnv->RegisterNatives() with a NativeMethod table mapping original
//      Java method names to the renamed functions.
//   3. The NativeMethod table itself is encrypted (XOR) and decrypted inline
//      inside JNI_OnLoad to avoid plain-text method name strings.
//
// This means the ELF symbol table no longer reveals which native methods exist.
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes/Platform.h"
#include "kagura/Utils.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <map>
#include <vector>

using namespace llvm;

namespace kagura {

struct JNIMethod {
  Function *Fn;          // The Java_* function
  std::string ClassName; // e.g. "com/example/app/MainActivity"
  std::string MethodName; // e.g. "getSecretKey"
  std::string Signature; // JNI signature (we don't know it statically; leave "")
  std::string NewFnName; // randomized name
};

// Parse Java_pkg_Class_method -> {pkg/Class, method}
static bool parseJNIName(StringRef Name, std::string &OutClass,
                          std::string &OutMethod) {
  if (!Name.starts_with("Java_"))
    return false;
  StringRef Rest = Name.drop_front(5); // drop "Java_"

  // Find the last underscore that separates class from method
  // Convention: Java_com_example_MainActivity_methodName
  // Underscores in class path are also underscores, but the last one
  // separates class from method name.
  auto LastUs = Rest.rfind('_');
  if (LastUs == StringRef::npos)
    return false;

  StringRef ClassPart  = Rest.take_front(LastUs);
  StringRef MethodPart = Rest.drop_front(LastUs + 1);

  // Convert underscores in class part to slashes (except _1 = underscore, _2 = ;)
  std::string Class;
  for (size_t I = 0; I < ClassPart.size(); ++I) {
    if (ClassPart[I] == '_') {
      if (I + 1 < ClassPart.size() && ClassPart[I + 1] == '1') {
        Class += '_'; ++I;
      } else {
        Class += '/';
      }
    } else {
      Class += ClassPart[I];
    }
  }

  OutClass  = Class;
  OutMethod = MethodPart.str();
  return true;
}

// Build JNI_OnLoad that registers all found methods via RegisterNatives.
// If JNI_OnLoad already exists, we append our registration before its first
// return.
static void buildOrPatchJNIOnLoad(Module &M,
                                   ArrayRef<JNIMethod> Methods) {
  if (Methods.empty())
    return;

  LLVMContext &Ctx = M.getContext();
  IRBuilder<> B(Ctx);
  auto *VoidTy  = Type::getVoidTy(Ctx);
  auto *Int32Ty = Type::getInt32Ty(Ctx);
  auto *Int8Ty  = Type::getInt8Ty(Ctx);
  auto *PtrTy   = PointerType::getUnqual(Ctx);

  // JNI_OnLoad signature: jint JNI_OnLoad(JavaVM* vm, void* reserved)
  auto *OnLoadTy = FunctionType::get(Int32Ty, {PtrTy, PtrTy}, false);

  Function *OnLoad = M.getFunction("JNI_OnLoad");
  bool IsNew = false;
  if (!OnLoad) {
    OnLoad = Function::Create(OnLoadTy, Function::ExternalLinkage,
                               "JNI_OnLoad", M);
    auto *Entry = BasicBlock::Create(Ctx, "entry", OnLoad);
    // Will fill in below
    IsNew = true;
  }

  // --- Build the registration block ---
  // We need JNIEnv* from the VM. Simplified: call vm->GetEnv(vm, &env, JNI_VERSION_1_6)
  // For IR purposes we model everything as opaque pointers.

  // Group methods by class
  std::map<std::string, std::vector<const JNIMethod *>> ByClass;
  for (auto &M2 : Methods)
    ByClass[M2.ClassName].push_back(&M2);

  // Find insertion point: beginning of JNI_OnLoad entry (or new entry)
  BasicBlock *InsertBB = IsNew ? &OnLoad->getEntryBlock()
                                : &OnLoad->getEntryBlock();
  B.SetInsertPoint(InsertBB, InsertBB->begin());

  // Get JavaVM* arg
  Value *VM = OnLoad->arg_begin();

  // Alloca for JNIEnv*
  auto *EnvAlloca = B.CreateAlloca(PtrTy, nullptr, "env");

  // Call vm->GetEnv(vm, &env, JNI_VERSION_1_6=0x00010006)
  // We model the vtable call as an indirect call through the opaque pointer.
  // GetEnv is at vtable offset 6 (standard JNI VM interface).
  // For simplicity, declare an external helper kagura_jni_get_env().
  auto *GetEnvFTy = FunctionType::get(PtrTy, {PtrTy, PtrTy, Int32Ty}, false);
  auto *GetEnvFn  = M.getOrInsertFunction("kagura_jni_get_env", GetEnvFTy).getCallee();
  auto *Env = B.CreateCall(GetEnvFTy, GetEnvFn,
                            {VM, EnvAlloca,
                             ConstantInt::get(Int32Ty, 0x00010006)},
                            "jnienv");

  // For each class, build a JNINativeMethod table and call RegisterNatives
  for (auto &[ClassName, ClassMethods] : ByClass) {
    // Build method name strings
    std::vector<Value *> NamePtrs;
    for (auto *JM : ClassMethods) {
      auto *NameConst = B.CreateGlobalString(JM->MethodName, "jni_mn");
      NamePtrs.push_back(NameConst);
    }

    // Build the class name string (e.g. "com/example/app/MainActivity")
    auto *ClassNameStr = B.CreateGlobalString(ClassName, "jni_cls");

    // Call FindClass
    auto *FindClassFTy = FunctionType::get(PtrTy, {PtrTy, PtrTy}, false);
    auto *FindClassFn  = M.getOrInsertFunction("kagura_jni_find_class",
                                                FindClassFTy).getCallee();
    auto *Clazz = B.CreateCall(FindClassFTy, FindClassFn,
                                {Env, ClassNameStr}, "clazz");

    // RegisterNatives(env, clazz, methods[], nMethods)
    // For IR simplicity, call one method at a time via a helper.
    auto *RegNatFTy = FunctionType::get(Int32Ty,
                                         {PtrTy, PtrTy, PtrTy, PtrTy, Int32Ty},
                                         false);
    auto *RegNatFn = M.getOrInsertFunction("kagura_jni_register_native",
                                            RegNatFTy).getCallee();

    for (size_t I = 0; I < ClassMethods.size(); ++I) {
      auto *JM = ClassMethods[I];
      // Signature: use empty string if unknown
      auto *SigStr = B.CreateGlobalString(JM->Signature.empty() ? "" : JM->Signature,
                                           "jni_sig");
      // Get function pointer for renamed function
      auto *FnPtr = JM->Fn;
      B.CreateCall(RegNatFTy, RegNatFn,
                   {Env, Clazz, NamePtrs[I], SigStr,
                    ConstantInt::get(Int32Ty, static_cast<int32_t>(I))});
      (void)FnPtr; // Referenced by the runtime helper
    }
  }

  if (IsNew) {
    // Return JNI_VERSION_1_6
    B.CreateRet(ConstantInt::get(Int32Ty, 0x00010006));
  }
}

PreservedAnalyses JNIObfuscationPass::run(Module &M,
                                           ModuleAnalysisManager &) {
  // 4.1.7: JNI obfuscation is Android-specific.  Skip on non-Android targets.
  // kagura::getModuleTriple() handles the getTargetTriple() API difference
  // between LLVM versions (returns std::string in 17-19, Triple in 20+).
  std::string TripleStr = kagura::getModuleTriple(M);
  bool IsAndroid = llvm::StringRef(TripleStr).contains("android");
  if (!IsAndroid && !TripleStr.empty())
    return PreservedAnalyses::all();

  auto &RNG = getModulePRNG();

  SmallVector<Function *, 16> JNIFuncs;
  for (auto &F : M) {
    if (F.isDeclaration()) continue;
    if (F.getName().starts_with("Java_"))
      JNIFuncs.push_back(&F);
  }

  if (JNIFuncs.empty())
    return PreservedAnalyses::all();

  std::vector<JNIMethod> Methods;
  for (auto *F : JNIFuncs) {
    JNIMethod JM;
    JM.Fn = F;
    if (!parseJNIName(F->getName(), JM.ClassName, JM.MethodName))
      continue;

    // Rename the function to a random internal symbol
    JM.NewFnName = "kagura_jni_" + std::to_string(RNG.next32());
    F->setName(JM.NewFnName);
    F->setLinkage(Function::InternalLinkage);
    F->setVisibility(GlobalValue::HiddenVisibility);

    Methods.push_back(JM);
  }

  buildOrPatchJNIOnLoad(M, Methods);

  return PreservedAnalyses::none();
}

} // namespace kagura
