//===-- Options.cpp - Kagura CLI option definitions ------------------------===//
//
// Single source of truth for all -kagura-* command-line flags.
// Include "kagura/Options.h" to access them from any pass.
//
// Per-pass enable flags and numeric tuning parameters are generated from
// kagura/PassRegistry.def so they cannot drift from the pass list. Only the
// infrastructure flags that have no registry row — string-valued options and
// pipeline switches that are not per-pass — are defined by hand below.
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"

using namespace llvm;

namespace kagura {
namespace opt {

// ---- Per-pass enable flags and tuning parameters (from PassRegistry.def) ----
// Each row of the registry expands to one cl::opt definition:
//   cl::opt<bool>     Flag(Cli, cl::desc("[Kagura] " Desc), cl::init(false));
//   cl::opt<uint32_t> Flag(Cli, cl::desc("[Kagura] " Desc), cl::init(Default));
#define KAGURA_BOOL_OPT(Flag, Cli, Desc)                                       \
  cl::opt<bool> Flag(Cli, cl::desc("[Kagura] " Desc), cl::init(false));

#define KAGURA_FN_PASS(Flag, Cli, Desc, Ctor)  KAGURA_BOOL_OPT(Flag, Cli, Desc)
#define KAGURA_MOD_PASS(Flag, Cli, Desc, Ctor) KAGURA_BOOL_OPT(Flag, Cli, Desc)
#define KAGURA_TUNING(Flag, Cli, Type, Default, Desc)                          \
  cl::opt<Type> Flag(Cli, cl::desc("[Kagura] " Desc), cl::init(Default));
#include "kagura/PassRegistry.def"
#undef KAGURA_BOOL_OPT

// ---- Infrastructure / pipeline-control flags ----

cl::opt<bool> Metrics("kagura-metrics",
                      cl::desc("[Kagura] Print obfuscation metrics"),
                      cl::init(false));

cl::opt<bool> LTOSafe(
    "kagura-lto-safe",
    cl::desc("[Kagura] Run obfuscation passes during LTO/ThinLTO pipeline"),
    cl::init(false));

cl::opt<bool> O0Protect(
    "kagura-o0-protect",
    cl::desc("[Kagura] Enable lightweight protection at -O0 (debug builds)"),
    cl::init(false));

cl::opt<std::string> DWARFMode(
    "kagura-dwarf",
    cl::desc("[Kagura] Debug info handling: keep (default), strip, obfuscate"),
    cl::init("keep"));

cl::opt<bool> VTP("kagura-vtp",
                  cl::desc("[Kagura] RTTI / vtable protection (C++ ABI)"),
                  cl::init(false));

// ---- Build-system / DX flags ----

cl::opt<bool> AutoSelect(
    "kagura-autoselect",
    cl::desc("[Kagura] Auto-select passes per function based on risk score"),
    cl::init(false));

cl::opt<std::string> ConfigFile(
    "kagura-config",
    cl::desc("[Kagura] Path to JSON policy configuration file"),
    cl::init(""));

cl::opt<bool> SymMap("kagura-symmap",
                     cl::desc("[Kagura] Emit symbol map JSON after obfuscation"),
                     cl::init(false));

cl::opt<std::string> SymMapOut(
    "kagura-symmap-out",
    cl::desc("[Kagura] Output path for symbol map (default: kagura_symbols.json)"),
    cl::init(""));

cl::opt<std::string> ProtectList(
    "kagura-protect",
    cl::desc("[Kagura] Comma-separated symbol patterns to force-protect"),
    cl::init(""));

cl::opt<std::string> DenyList(
    "kagura-deny",
    cl::desc("[Kagura] Comma-separated symbol/file patterns to exclude from obfuscation"),
    cl::init(""));

cl::opt<std::string> AllowList(
    "kagura-allow",
    cl::desc("[Kagura] Comma-separated allowlist; when set only matching symbols are obfuscated"),
    cl::init(""));

cl::opt<bool> AuditLog(
    "kagura-audit",
    cl::desc("[Kagura] Emit an audit log of all protected symbols"),
    cl::init(false));

cl::opt<std::string> AuditLogOut(
    "kagura-audit-out",
    cl::desc("[Kagura] Output path for audit log (default: kagura_audit.json)"),
    cl::init(""));

cl::opt<std::string> BuildID(
    "kagura-build-id",
    cl::desc("[Kagura] Build identifier mixed into PRNG seed for per-build key rotation"),
    cl::init(""));

} // namespace opt
} // namespace kagura
