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

// ---- Per-pass enable flags and tuning parameters ----
//
// Generated from the same registry Options.cpp defines them from, so the
// declarations cannot drift from the definitions. The list used to be written
// out by hand here while Options.cpp already generated its half.
#define KAGURA_FN_PASS(Flag, Cli, Desc, Ctor)  extern llvm::cl::opt<bool> Flag;
#define KAGURA_MOD_PASS(Flag, Cli, Desc, Ctor) extern llvm::cl::opt<bool> Flag;
#define KAGURA_TUNING(Flag, Cli, Type, Default, Desc)                          \
  extern llvm::cl::opt<Type> Flag;
#include "kagura/PassRegistry.def"

// ---- Infrastructure flags ----

/// Print per-function basic-block / instruction / complexity deltas.
extern llvm::cl::opt<bool> Metrics;

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

/// RTTI / vtable protection (C++ ABI). An infrastructure pass rather than a
/// registry row, because Plugin.cpp injects it at a fixed point in the
/// pipeline rather than in registry order.
extern llvm::cl::opt<bool> VTP;

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
