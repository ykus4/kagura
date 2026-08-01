//===-- ConfigLoader.cpp - JSON policy file loader -------------------------===//
//
// 4.6.1: Reads a JSON/YAML policy file and applies per-module and
// per-function protection settings, overriding command-line defaults.
//
// File format (JSON):
//
//   {
//     "profile": "BALANCED",          // FAST | BALANCED | STRONG (4.6.2)
//     "passes": {                      // override individual pass enables
//       "fla": true,
//       "bcf": false,
//       "str": true,
//       "str_aes": false,
//       "wstr": true,
//       "genc": true,
//       "mvo": true,
//       "honey": false,
//       "dwarf": "strip"
//     },
//     "tuning": {
//       "bcf_prob": 30,
//       "bcf_iter": 1,
//       "sub_iter": 2,
//       "dci_prob": 40
//     },
//     "allowlist": ["main", "JNI_OnLoad"],
//     "denylist":  ["test_*", "debug_*"]
//   }
//
// 4.6.2: Profile presets
//   FAST     — STR only; no CFG passes
//   BALANCED — STR + BCF(20%) + BBR + BBS + GENC
//   STRONG   — all passes at maximum settings
//
// The loader is NOT a pass. loadConfigFileIfSpecified() is called from
// Plugin.cpp while the pipeline is being constructed, because that is where
// the opt:: flags are read to decide which passes to add. Running it as a pass
// (as this file used to) is too late: by the time any pass executes, the
// pipeline is already fixed, so the policy file had no effect at all.
// ConfigLoaderPass remains only so `opt -passes=kagura-config` stays valid.
//
// Precedence: explicit command-line flag > flavor block > passes/tuning object
// > profile preset > built-in default.
//
// Pass key:   "kagura-config"
// CLI flag:   -kagura-config=<path>
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes.h"

#include "llvm/IR/Module.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>

using namespace llvm;

namespace kagura {

// ---- Profile presets (4.6.2) -----------------------------------------------

/// An option the user named explicitly on the command line outranks the config
/// file. Without this the config would silently clobber
/// `-kagura-config=p.json -kagura-fla=false`.
template <typename T> static bool setByUser(const cl::opt<T> &Flag) {
  return Flag.getNumOccurrences() > 0;
}

/// Assign a profile preset value, unless the user set that flag explicitly.
template <typename T, typename V> static void preset(cl::opt<T> &Flag, V Value) {
  if (!setByUser(Flag))
    Flag = static_cast<T>(Value);
}

static void applyProfile(StringRef Profile) {
  if (Profile.equals_insensitive("fast")) {
    preset(opt::STR, true);
    preset(opt::STRAES, false);
    preset(opt::WSTR, false);
    preset(opt::FLA, false);
    preset(opt::BCF, false);
    preset(opt::BBR, false);
    preset(opt::BBS, false);
    preset(opt::DCI, false);
    preset(opt::SUB, false);
    preset(opt::CO, false);
    preset(opt::GENC, false);
    preset(opt::MVO, false);
  } else if (Profile.equals_insensitive("balanced")) {
    preset(opt::STR, true);
    preset(opt::STRAES, false);
    preset(opt::WSTR, true);
    preset(opt::BCF, true);
    preset(opt::BCFProb, 20);
    preset(opt::BCFIter, 1);
    preset(opt::BBR, true);
    preset(opt::BBS, true);
    preset(opt::DCI, true);
    preset(opt::GENC, true);
    preset(opt::MVO, true);
    preset(opt::FLA, false);
    preset(opt::SUB, false);
    preset(opt::CO, false);
  } else if (Profile.equals_insensitive("strong")) {
    preset(opt::STR, true);
    preset(opt::STRAES, true);
    preset(opt::WSTR, true);
    preset(opt::FLA, true);
    preset(opt::BCF, true);
    preset(opt::BCFProb, 50);
    preset(opt::BCFIter, 2);
    preset(opt::BBR, true);
    preset(opt::BBS, true);
    preset(opt::DCI, true);
    preset(opt::SUB, true);
    preset(opt::SUBIter, 2);
    preset(opt::CO, true);
    preset(opt::GENC, true);
    preset(opt::MVO, true);
    preset(opt::Honey, true);
    preset(opt::LT, true);
    preset(opt::IBR, true);
    preset(opt::SV, true);
  }
  // "custom" or unknown: no-op (use individual CLI flags)
}

// ---- JSON policy loader ----------------------------------------------------

static void applyPassesObject(const json::Object &Passes) {
  auto getBool = [&](StringRef Key, cl::opt<bool> &Flag) {
    if (setByUser(Flag))
      return;
    if (auto V = Passes.getBoolean(Key))
      Flag = *V;
  };
  getBool("fla",    opt::FLA);
  getBool("bcf",    opt::BCF);
  getBool("sub",    opt::SUB);
  getBool("str",    opt::STR);
  getBool("str_aes",opt::STRAES);
  getBool("wstr",   opt::WSTR);
  getBool("co",     opt::CO);
  getBool("vm",     opt::VM);
  getBool("ibr",    opt::IBR);
  getBool("lt",     opt::LT);
  getBool("bbr",    opt::BBR);
  getBool("dci",    opt::DCI);
  getBool("bbs",    opt::BBS);
  getBool("fsplit", opt::FSplit);
  getBool("sv",     opt::SV);
  getBool("genc",   opt::GENC);
  getBool("mvo",    opt::MVO);
  getBool("honey",  opt::Honey);
  getBool("tamper", opt::Tamper);
  getBool("pac",    opt::PAC);
  getBool("ci",     opt::CI);
  getBool("anti_debug", opt::AntiDebug);
  getBool("objc",   opt::ObjC);
  getBool("jni",    opt::JNI);
  getBool("pe",     opt::PE);
  getBool("telemetry", opt::Telemetry);

  if (!setByUser(opt::DWARFMode))
    if (auto DwarfVal = Passes.getString("dwarf"))
      opt::DWARFMode = DwarfVal->str();
}

static void applyTuningObject(const json::Object &Tuning) {
  auto getU32 = [&](StringRef Key, cl::opt<uint32_t> &Flag) {
    if (setByUser(Flag))
      return;
    if (auto V = Tuning.getInteger(Key))
      Flag = static_cast<uint32_t>(*V);
  };
  getU32("bcf_prob", opt::BCFProb);
  getU32("bcf_iter", opt::BCFIter);
  getU32("sub_iter", opt::SUBIter);
  getU32("dci_prob", opt::DCIProb);

  if (!setByUser(opt::Seed))
    if (auto Seed = Tuning.getInteger("seed"))
      opt::Seed = static_cast<uint64_t>(*Seed);
}

// ---- Entry point ------------------------------------------------------------

void loadConfigFileIfSpecified() {
  // Parse at most once. Plugin.cpp calls this every time it builds a pipeline,
  // and re-applying would undo any flag a later caller had adjusted.
  static bool Loaded = false;
  if (Loaded)
    return;
  Loaded = true;

  StringRef ConfigPath = kagura::opt::ConfigFile;
  if (ConfigPath.empty())
    return;

  // Load file
  auto BufOrErr = MemoryBuffer::getFile(ConfigPath);
  if (!BufOrErr) {
    errs() << "[kagura] ConfigLoader: cannot open " << ConfigPath
           << ": " << BufOrErr.getError().message() << "\n";
    return;
  }

  // Parse JSON
  auto JsonOrErr = json::parse((*BufOrErr)->getBuffer());
  if (!JsonOrErr) {
    errs() << "[kagura] ConfigLoader: JSON parse error in " << ConfigPath
           << ": " << toString(JsonOrErr.takeError()) << "\n";
    return;
  }

  auto *Root = JsonOrErr->getAsObject();
  if (!Root) {
    errs() << "[kagura] ConfigLoader: root must be a JSON object\n";
    return;
  }

  // 4.6.9: Multi-flavor support — select a flavor-specific config block if
  // the KAGURA_FLAVOR environment variable is set and the config file has a
  // "flavors" object whose key matches the env var value.
  //
  // Example config:
  //   {
  //     "profile": "BALANCED",
  //     "flavors": {
  //       "staging":    { "profile": "FAST" },
  //       "production": { "profile": "STRONG", "passes": { "vm": true } }
  //     }
  //   }
  //
  // When KAGURA_FLAVOR=production, the production flavor overrides the base
  // config values.
  const char *FlavorEnv = std::getenv("KAGURA_FLAVOR");
  const json::Object *FlavorRoot = nullptr;
  if (FlavorEnv && *FlavorEnv) {
    if (auto *FlavorsObj = Root->getObject("flavors"))
      FlavorRoot = FlavorsObj->getObject(FlavorEnv);
  }

  // 4.6.2: Apply base profile preset
  if (auto Profile = Root->getString("profile"))
    applyProfile(*Profile);

  // 4.6.1: Apply base pass enables / disables
  if (auto *PassesObj = Root->getObject("passes"))
    applyPassesObject(*PassesObj);

  // 4.6.1: Apply base tuning parameters
  if (auto *TuningObj = Root->getObject("tuning"))
    applyTuningObject(*TuningObj);

  // 4.6.3/4.6.4: Load allowlist / denylist / protect from JSON
  auto concatArray = [&](const json::Object *Obj, StringRef Key,
                         cl::opt<std::string> &Flag) {
    auto *Arr = Obj ? Obj->getArray(Key) : nullptr;
    if (!Arr) return;
    std::string Combined;
    for (const auto &V : *Arr) {
      if (auto S = V.getAsString()) {
        if (!Combined.empty()) Combined += ',';
        Combined += S->str();
      }
    }
    if (!Combined.empty()) Flag = Combined;
  };
  concatArray(Root, "allowlist", opt::AllowList);
  concatArray(Root, "denylist",  opt::DenyList);
  concatArray(Root, "protect",   opt::ProtectList);

  // 4.6.10: Audit log path from JSON
  if (auto AuditOut = Root->getString("audit_out"))
    opt::AuditLogOut = AuditOut->str();

  // 4.6.9: Apply flavor-specific overrides (after base config)
  if (FlavorRoot) {
    if (auto Profile = FlavorRoot->getString("profile"))
      applyProfile(*Profile);
    if (auto *PassesObj = FlavorRoot->getObject("passes"))
      applyPassesObject(*PassesObj);
    if (auto *TuningObj = FlavorRoot->getObject("tuning"))
      applyTuningObject(*TuningObj);
    concatArray(FlavorRoot, "allowlist", opt::AllowList);
    concatArray(FlavorRoot, "denylist",  opt::DenyList);
    concatArray(FlavorRoot, "protect",   opt::ProtectList);
  }
}

// ---- Pass entry point -------------------------------------------------------

/// Kept so `opt -passes=kagura-config` stays valid. The real work happens in
/// loadConfigFileIfSpecified(), which Plugin.cpp calls before it builds the
/// pipeline; by the time a pass runs it is far too late to influence which
/// passes were added.
PreservedAnalyses ConfigLoaderPass::run(Module &, ModuleAnalysisManager &) {
  loadConfigFileIfSpecified();
  return PreservedAnalyses::all(); // flags only, no IR modification
}

} // namespace kagura
