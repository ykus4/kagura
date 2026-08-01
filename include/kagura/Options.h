#pragma once
//===-- Options.h - Kagura CLI flags (centralized declarations) -----------===//
//
// All command-line options are *defined* in Options.cpp and declared here so
// that any pass file can access them via `#include "kagura/Options.h"`.
//
//===----------------------------------------------------------------------===//

#include "llvm/Support/CommandLine.h"
#include <cstdint>

namespace kagura {
namespace opt {

// ---- Pass enable flags ----
extern llvm::cl::opt<bool> FLA;
extern llvm::cl::opt<bool> BCF;
extern llvm::cl::opt<bool> SUB;
extern llvm::cl::opt<bool> CSEBreak;
extern llvm::cl::opt<bool> STR;
extern llvm::cl::opt<bool> STRAES;
extern llvm::cl::opt<bool> STRSplit;
extern llvm::cl::opt<bool> AntiDebug;
extern llvm::cl::opt<bool> ObjC;
extern llvm::cl::opt<bool> JNI;
extern llvm::cl::opt<bool> CO;
extern llvm::cl::opt<bool> VM;
extern llvm::cl::opt<bool> Metrics;
extern llvm::cl::opt<bool> BBR;
extern llvm::cl::opt<bool> DCI;
extern llvm::cl::opt<bool> FSplit;
extern llvm::cl::opt<bool> BBS;
extern llvm::cl::opt<bool> SV;
extern llvm::cl::opt<bool> IBR;
extern llvm::cl::opt<bool> LT;
extern llvm::cl::opt<bool> Tamper;
extern llvm::cl::opt<bool> CI;
extern llvm::cl::opt<bool> PAC;
extern llvm::cl::opt<bool> GENC;

/// XOR-encrypt alloca'd pointer values to defeat memory dump analysis.
extern llvm::cl::opt<bool> PE;

/// Inject telemetry event calls at function entry.
extern llvm::cl::opt<bool> Telemetry;

/// Inject basic-block-level opcode checksum guards.
extern llvm::cl::opt<bool> BBCheck;
extern llvm::cl::opt<bool> VTP;
extern llvm::cl::opt<bool> ELT;

// ---- Pass tuning parameters ----
extern llvm::cl::opt<uint32_t> BCFProb;
extern llvm::cl::opt<uint32_t> BCFIter;
extern llvm::cl::opt<uint32_t> SUBIter;
extern llvm::cl::opt<uint32_t> DCIProb;
extern llvm::cl::opt<uint64_t> Seed;

// ---- Infrastructure flags ----

/// Enable protection during LTO/ThinLTO pipeline phases.
/// When false (default), kagura skips module passes that are unsafe to run
/// during link-time optimisation (e.g. passes that assume single-module IR).
extern llvm::cl::opt<bool> LTOSafe;

/// Enable a lightweight pass subset at -O0 (debug builds).
/// When false (default), all passes are skipped at O0 for build speed.
extern llvm::cl::opt<bool> O0Protect;

/// DWARF / debug-info handling mode.
///   "keep"  (default) — preserve all debug info unchanged.
///   "strip" — remove all debug metadata from functions touched by kagura.
///   "obfuscate" — remap source locations to synthetic coordinates.
extern llvm::cl::opt<std::string> DWARFMode;

// ---- Data-protection flags ----

/// Encrypt wide-character (wchar_t / char16_t / char32_t) string
/// literals and ObjC/CoreFoundation CFString backing buffers.
extern llvm::cl::opt<bool> WSTR;

// ---- Game / anti-cheat flags ----

/// In-memory integer variable XOR obfuscation.
extern llvm::cl::opt<bool> MVO;

/// Honey value / decoy variable and fake symbol injection.
extern llvm::cl::opt<bool> Honey;

// ---- Build-system / DX flags ----

/// Auto-select obfuscation passes per function based on risk score.
extern llvm::cl::opt<bool> AutoSelect;

/// Path to the JSON policy configuration file.
extern llvm::cl::opt<std::string> ConfigFile;

/// Comma-separated list of symbol name patterns to force-protect
/// (overrides per-function annotations; supports '*' glob suffix).
extern llvm::cl::opt<std::string> ProtectList;

/// Comma-separated list of symbol/file/module patterns to exclude
/// from all kagura passes.  Supports '*' glob suffix matching.
extern llvm::cl::opt<std::string> DenyList;

/// Comma-separated list of symbol/file/module patterns to explicitly
/// include (allowlist mode).  When non-empty, only matching symbols are
/// obfuscated (everything else is treated as denied).
extern llvm::cl::opt<std::string> AllowList;

/// Enable symbol map output.
extern llvm::cl::opt<bool> SymMap;

/// Output path for the symbol map JSON file.
extern llvm::cl::opt<std::string> SymMapOut;

/// Emit an audit log recording what was protected and how.
extern llvm::cl::opt<bool> AuditLog;

/// Output path for the audit log (default: kagura_audit.json).
extern llvm::cl::opt<std::string> AuditLogOut;

// ---- Additional flags ----

/// A build-time identifier string mixed into the PRNG seed so every
/// build produces different keys even with the same -kagura-seed value.
/// Typically set to a CI build number, git commit hash, or timestamp.
extern llvm::cl::opt<std::string> BuildID;

} // namespace opt

/// Apply -kagura-config=<file> to the opt:: flags above.
///
/// This MUST run before anything reads an opt:: flag to decide which passes to
/// build. It used to happen inside ConfigLoaderPass, i.e. at pipeline *run*
/// time, while Plugin.cpp reads the same flags at pipeline *construction*
/// time — so the JSON policy file never affected which passes were added and
/// `-kagura-config=policy.json` was silently a no-op.
///
/// Idempotent: the file is parsed at most once per process.
///
/// Flags the user passed explicitly on the command line win over the config
/// file, so `-kagura-config=p.json -kagura-fla=false` disables flattening even
/// if p.json asks for it.
void loadConfigFileIfSpecified();

} // namespace kagura
