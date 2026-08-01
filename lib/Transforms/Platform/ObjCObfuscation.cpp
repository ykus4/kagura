//===-- ObjCObfuscation.cpp - Objective-C metadata obfuscation ------------===//
//
// 4.2.2 + 4.2.3: Obfuscates Objective-C selector, class, and method names
// that appear as GlobalVariable string literals in the following Mach-O
// sections:
//
//   __TEXT,__objc_methnames   (selector strings, e.g. "initWithFoo:bar:")
//   __TEXT,__objc_classnames  (class name strings, e.g. "MyViewController")
//   __TEXT,__objc_methname    (variant section name)
//   __TEXT,__objc_propnames   (property names, e.g. "title", "delegate")
//   __TEXT,__objc_ivar        (ivar name strings, e.g. "_myVar")
//
// 4.2.3 additions over 4.2.2:
//   - Property name obfuscation (__objc_prop_names / __objc_propnames):
//     property names are exposed by KVC/KVO and decompilers; obfuscating them
//     prevents automated class-hierarchy reconstruction.
//   - Ivar name obfuscation: instance variable names in the ivar list
//     section reveal internal implementation details.
//   - NSClassFromString / NSProtocolFromString redirect: a module constructor
//     (kagura_objc_remap_ctor) registers all obfuscated name mappings with
//     kagura_objc_register_remap() so that callers using string-based class
//     lookup still work correctly.
//
// Strategy:
//   1. Collect all GlobalVariables in the above sections.
//   2. For each name, generate a scrambled replacement (preserving ':'
//      for selector arity).
//   3. Update the GlobalVariable's initializer in-place.
//   4. Emit a null-terminated mapping table (kagura_objc_name_map).
//   5. Emit a module constructor that calls kagura_objc_register_remap() for
//      each original→obfuscated pair so runtime lookups are redirected.
//
//===----------------------------------------------------------------------===//

#include "kagura/Passes.h"
#include "kagura/Utils.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <map>
#include <string>

using namespace llvm;

namespace kagura {

// Returns true if GV is in an ObjC method/class/property/ivar name section
static bool isObjCNameSection(const GlobalVariable &GV) {
  if (!GV.hasSection())
    return false;
  StringRef Section = GV.getSection();
  return Section.contains("__objc_methname")  ||
         Section.contains("__objc_classname") ||
         Section.contains("__objc_methnames") ||
         Section.contains("__objc_prop_name") ||  // 4.2.3: property names
         Section.contains("__objc_propnames") ||  // 4.2.3: variant section
         Section.contains("__objc_ivar");          // 4.2.3: ivar names
}

// Generate a short alphanumeric obfuscated name
static std::string scrambleName(StringRef Original, PRNG &RNG) {
  static const char Chars[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  constexpr size_t CharsLen = sizeof(Chars) - 1;

  // Preserve selector colons so ObjC ABI stays intact:
  // "initWithFoo:bar:" -> "xK7m:q2R:"
  std::string Result;
  for (char C : Original) {
    if (C == ':') {
      Result += ':';
    } else {
      Result += Chars[RNG.nextRange(0, CharsLen)];
    }
  }
  return Result;
}

PreservedAnalyses ObjCObfuscationPass::run(Module &M,
                                            ModuleAnalysisManager &) {
  // 4.1.7: ObjC metadata is only meaningful on Apple targets (iOS, macOS,
  // tvOS, watchOS).  Skip on Android and Linux to avoid false-positive matches
  // on globals with similar section names in non-Apple toolchains.
  // kagura::getModuleTriple() handles the getTargetTriple() API difference
  // between LLVM versions (returns std::string in 17-19, Triple in 20+).
  std::string TripleStr = kagura::getModuleTriple(M);
  StringRef Triple(TripleStr);
  bool IsAppleTarget = Triple.contains("apple") || Triple.contains("darwin") ||
                       Triple.contains("ios") || Triple.contains("macos") ||
                       Triple.contains("macosx");
  if (!IsAppleTarget && !TripleStr.empty())
    return PreservedAnalyses::all();

  LLVMContext &Ctx = M.getContext();
  auto &RNG        = getModulePRNG();

  // name mapping: original -> obfuscated
  std::map<std::string, std::string> NameMap;

  SmallVector<GlobalVariable *, 32> Targets;
  for (auto &GV : M.globals()) {
    if (!GV.hasInitializer() || !isObjCNameSection(GV))
      continue;
    auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
    if (!CDA || !CDA->isString())
      continue;
    Targets.push_back(&GV);
  }

  if (Targets.empty())
    return PreservedAnalyses::all();

  auto *Int8Ty = Type::getInt8Ty(Ctx);

  for (auto *GV : Targets) {
    auto *CDA = cast<ConstantDataArray>(GV->getInitializer());
    std::string Original = CDA->getAsString().str();
    // Strip null terminator for processing
    if (!Original.empty() && Original.back() == '\0')
      Original.pop_back();

    std::string Obfuscated;
    auto It = NameMap.find(Original);
    if (It != NameMap.end()) {
      Obfuscated = It->second;
    } else {
      Obfuscated = scrambleName(Original, RNG);
      NameMap[Original] = Obfuscated;
    }

    // Build new ConstantDataArray with null terminator
    std::string ObfuscatedZ = Obfuscated + '\0';
    auto *NewConst = ConstantDataArray::getString(Ctx, ObfuscatedZ,
                                                   /*AddNull=*/false);
    auto *NewTy    = ArrayType::get(Int8Ty, ObfuscatedZ.size());

    // Replace the global's initializer with the obfuscated string
    // (same type size assumed; if different, create a new GV)
    if (NewConst->getType() == GV->getInitializer()->getType()) {
      GV->setInitializer(NewConst);
    } else {
      auto *NewGV = new GlobalVariable(
          M, NewTy, GV->isConstant(), GV->getLinkage(), NewConst,
          GV->getName(), GV, GV->getThreadLocalMode(),
          GV->getAddressSpace(), GV->isExternallyInitialized());
      NewGV->setSection(GV->getSection());
      NewGV->setAlignment(GV->getAlign());
      GV->replaceAllUsesWith(NewGV);
      GV->eraseFromParent();
    }
  }

  // Store the mapping table as a module-level global for the runtime
  // Format: null-terminated pairs: original\0obfuscated\0 ... \0
  if (!NameMap.empty()) {
    std::string MapData;
    for (auto &[Orig, Obf] : NameMap) {
      MapData += Orig;
      MapData += '\0';
      MapData += Obf;
      MapData += '\0';
    }
    MapData += '\0'; // double null = end of table

    auto *MapConst = ConstantDataArray::getString(Ctx, MapData, false);
    new GlobalVariable(M, MapConst->getType(), true,
                       GlobalValue::PrivateLinkage, MapConst,
                       "kagura_objc_name_map");

    // 4.2.3: Emit a module constructor that registers all name remappings
    // with the runtime so NSClassFromString / NSProtocolFromString and KVO
    // key-path lookups continue to work with obfuscated names.
    //
    // The constructor calls:
    //   void kagura_objc_register_remap(const char *original,
    //                                    const char *obfuscated);
    // for each pair in the mapping table.
    auto *VoidTy = Type::getVoidTy(Ctx);
    auto *I8PtrTy = PointerType::getUnqual(Ctx);
    auto *RemapFTy = FunctionType::get(VoidTy, {I8PtrTy, I8PtrTy}, false);
    FunctionCallee RemapFn =
        M.getOrInsertFunction("kagura_objc_register_remap", RemapFTy);

    auto *Ctor = createCtorFunction(M, "kagura_objc_remap_ctor");
    Ctor->addFnAttr(Attribute::NoInline);
    Ctor->addFnAttr(Attribute::NoUnwind);

    auto *Entry = &Ctor->getEntryBlock();
    IRBuilder<> B(Entry);

    for (auto &[Orig, Obf] : NameMap) {
      // Create private string globals for original and obfuscated names
      auto *OrigStr = B.CreateGlobalString(Orig, "kagura.remap.orig");
      auto *ObfStr  = B.CreateGlobalString(Obf,  "kagura.remap.obf");
      B.CreateCall(RemapFTy, RemapFn.getCallee(), {OrigStr, ObfStr});
    }
    B.CreateRetVoid();

    appendKaguraCtor(M, Ctor, CtorPriority::ObjCRemap);
  }

  return PreservedAnalyses::none();
}

} // namespace kagura
