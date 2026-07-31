//===-- tools/kagura-opt.cpp - Standalone bitcode optimizer ----------------===//
//
// 4.1.5: Bitcode input support — standalone tool to apply kagura passes to
// .bc / .ll files without a full clang invocation.
//
// Usage:
//   kagura-opt [options] <input.bc|input.ll> -o <output.bc|output.ll>
//
// Examples:
//   # Control flow flattening + substitution on bitcode
//   kagura-opt -kagura-fla -kagura-sub input.bc -o output.bc
//
//   # String encryption on LLVM IR text
//   kagura-opt -kagura-str input.ll -o output.ll -S
//
//   # All available passes with JSON config
//   kagura-opt -kagura-config policy.json input.bc -o output.bc
//
// Flags:
//   All -kagura-* flags defined in Options.cpp are accepted.
//   -S            Emit human-readable .ll instead of binary .bc
//   -o <path>     Output path (default: stdout)
//   -O<N>         Optimization level forwarded to PassBuilder (0-3, s, z)
//   -load-kagura  Path to libKaguraObfuscator plugin (default: auto-detect)
//
// Implementation note
// -------------------
// kagura-opt has two linkage modes, selected at configure time:
//
//   Shared (default).  The plugin is loaded at runtime via PassPlugin::Load().
//   This avoids the MODULE_LIBRARY linkage restriction and header-search-path
//   issues that arise when Plugin.cpp is compiled a second time in a different
//   target.  The plugin path is resolved from the same directory as the
//   kagura-opt executable (build/bin/../lib/).
//
//   Static (KAGURA_STATIC_PLUGIN).  The passes are linked into this binary and
//   registered by calling getKaguraPluginInfo() directly.  Required on
//   platforms where LLVM cannot build loadable modules — notably the
//   MSVC-targeted Windows toolchain, where LLVM_ENABLE_PLUGINS is OFF and
//   neither `-fpass-plugin` nor `opt --load-pass-plugin` is available.  On
//   those platforms kagura-opt is the supported way to run the passes.
//
//===----------------------------------------------------------------------===//

#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassInstrumentation.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/StandardInstrumentations.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif

#include <memory>

using namespace llvm;

#ifdef KAGURA_STATIC_PLUGIN
// Defined in lib/Transforms/Plugin.cpp, linked in from the static
// KaguraObfuscator library.  This is the same PassPluginLibraryInfo that
// llvmGetPassPluginInfo() returns to a dlopen()ing host; calling it directly
// is what lets the passes run without a loadable module.
llvm::PassPluginLibraryInfo getKaguraPluginInfo();
#endif

// ---- CLI options ------------------------------------------------------------

static cl::opt<std::string> InputFilename(
    cl::Positional, cl::desc("<input .bc or .ll>"), cl::Required);

static cl::opt<std::string> OutputFilename(
    "o", cl::desc("Output filename"), cl::value_desc("filename"),
    cl::init("-"));

static cl::opt<bool> OutputTextual(
    "S", cl::desc("Emit text IR (.ll) instead of bitcode (.bc)"),
    cl::init(false));

static cl::opt<char> OptLevel(
    "O", cl::desc("Optimization level (0-3, s, z)"),
    cl::Prefix, cl::init('2'));

static cl::opt<std::string> PluginPath(
    "load-kagura",
    cl::desc("Path to libKaguraObfuscator plugin (default: auto-detect; "
             "ignored in static builds)"),
    cl::init(""));

// ---- Plugin path auto-detection ---------------------------------------------
// Only needed in shared mode; a static build has the passes linked in and
// never looks for a module on disk.
#ifndef KAGURA_STATIC_PLUGIN

static std::string getExplicitPluginPath(int argc, char **argv) {
  StringRef Prefix("-load-kagura=");
  for (int I = 1; I < argc; ++I) {
    StringRef Arg(argv[I]);
    if (Arg.starts_with(Prefix))
      return Arg.drop_front(Prefix.size()).str();
    if (Arg == "-load-kagura" && I + 1 < argc)
      return std::string(argv[I + 1]);
  }
  return "";
}

// Return the first existing "<Dir>/<name>" for every known plugin filename,
// or "" if none of them exist in Dir.
static std::string findPluginInDir(StringRef Dir) {
  static const char *const Names[] = {
      "KaguraObfuscator.dylib", "libKaguraObfuscator.dylib",
      "KaguraObfuscator.so",    "libKaguraObfuscator.so",
      "KaguraObfuscator.dll",
  };
  for (const char *Name : Names) {
    SmallString<256> Candidate(Dir);
    sys::path::append(Candidate, Name);
    if (sys::fs::exists(Candidate))
      return std::string(Candidate);
  }
  return "";
}

static std::string findPlugin(const char *Argv0, StringRef ExplicitPath) {
  if (!ExplicitPath.empty())
    return ExplicitPath.str();

  SmallString<256> ExeDir(sys::path::parent_path(
      sys::fs::getMainExecutable(Argv0, nullptr)));

  // Search, in priority order: <exe_dir>/../lib, <exe_dir>/../lib/Transforms
  // (where CMake's add_llvm_pass_plugin drops the plugin in normal build
  // trees), and finally next to the executable itself.
  SmallString<256> LibDir(ExeDir);
  sys::path::append(LibDir, "..", "lib");

  SmallString<256> TransformDir(LibDir);
  sys::path::append(TransformDir, "Transforms");

  for (StringRef Dir : {StringRef(LibDir), StringRef(TransformDir),
                        StringRef(ExeDir)}) {
    if (std::string Found = findPluginInDir(Dir); !Found.empty())
      return Found;
  }
  return "";
}

#endif // !KAGURA_STATIC_PLUGIN

// ---- Main -------------------------------------------------------------------

int main(int argc, char **argv) {
  InitLLVM X(argc, argv);

#ifdef KAGURA_STATIC_PLUGIN
  // The passes are linked into this binary, so there is nothing to load and
  // the -kagura-* cl::opts are already registered by static initialisation.
  PassPluginLibraryInfo KaguraInfo = getKaguraPluginInfo();
#else
  // Load the kagura plugin before parsing command-line options.  The plugin
  // owns the -kagura-* cl::opts, so parsing first would reject those flags as
  // unknown.
  std::string Plugin = findPlugin(argv[0], getExplicitPluginPath(argc, argv));
  if (Plugin.empty()) {
    WithColor::error() << "Could not find libKaguraObfuscator plugin.\n"
                       << "Use -load-kagura=<path> to specify it explicitly.\n";
    return 1;
  }

  auto PluginOrErr = PassPlugin::Load(Plugin);
  if (!PluginOrErr) {
    WithColor::error() << "Failed to load plugin " << Plugin << ": "
                       << toString(PluginOrErr.takeError()) << '\n';
    return 1;
  }
#endif

  cl::ParseCommandLineOptions(argc, argv,
                               "kagura-opt -- apply kagura obfuscation passes\n");

#ifdef KAGURA_STATIC_PLUGIN
  if (!PluginPath.empty())
    WithColor::warning() << "-load-kagura is ignored: the passes are linked "
                            "into this binary.\n";
#endif

  // Load the input module
  LLVMContext Ctx;
  SMDiagnostic Err;
  std::unique_ptr<Module> M = parseIRFile(InputFilename, Err, Ctx);
  if (!M) {
    Err.print(argv[0], errs());
    return 1;
  }

  // Build optimization level
  OptimizationLevel OL = OptimizationLevel::O2;
  switch (OptLevel) {
  case '0': OL = OptimizationLevel::O0; break;
  case '1': OL = OptimizationLevel::O1; break;
  case '2': OL = OptimizationLevel::O2; break;
  case '3': OL = OptimizationLevel::O3; break;
  case 's': OL = OptimizationLevel::Os; break;
  case 'z': OL = OptimizationLevel::Oz; break;
  default:  OL = OptimizationLevel::O2; break;
  }

  LoopAnalysisManager     LAM;
  FunctionAnalysisManager FAM;
  CGSCCAnalysisManager    CGAM;
  ModuleAnalysisManager   MAM;

  PassInstrumentationCallbacks PIC;
  StandardInstrumentations SI(Ctx, /*DebugLogging=*/false);
  SI.registerCallbacks(PIC, &MAM);
  LAM.registerPass([&] { return PassInstrumentationAnalysis(&PIC); });
  FAM.registerPass([&] { return PassInstrumentationAnalysis(&PIC); });
  CGAM.registerPass([&] { return PassInstrumentationAnalysis(&PIC); });
  MAM.registerPass([&] { return PassInstrumentationAnalysis(&PIC); });

  // Construct the pass pipeline with the kagura plugin registered.
  PassBuilder PB(nullptr, PipelineTuningOptions(), std::nullopt, &PIC);
#ifdef KAGURA_STATIC_PLUGIN
  KaguraInfo.RegisterPassBuilderCallbacks(PB);
#else
  PluginOrErr->registerPassBuilderCallbacks(PB);
#endif

  PB.registerModuleAnalyses(MAM);
  PB.registerCGSCCAnalyses(CGAM);
  PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM);
  PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

  ModulePassManager MPM = PB.buildPerModuleDefaultPipeline(OL);
  MPM.run(*M, MAM);

  // Write output
  std::error_code EC;
  sys::fs::OpenFlags OutFlags = sys::fs::OF_None;
  if (OutputTextual)
    OutFlags |= sys::fs::OF_Text;

  ToolOutputFile Out(OutputFilename, EC, OutFlags);
  if (EC) {
    WithColor::error() << EC.message() << '\n';
    return 1;
  }

  if (OutputTextual) {
    Out.os() << *M;
  } else {
    WriteBitcodeToFile(*M, Out.os());
  }

  Out.keep();
  return 0;
}
