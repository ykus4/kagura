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
// The one deliberate exception is the symbol filter lists ("allowlist",
// "denylist", "protect"): those *merge* with an explicit command-line list
// rather than losing to it, because every entry in such a list is a symbol the
// user asked to be treated specially and dropping either source silently
// re-obfuscates it. See concatArray() below.
//
// Keys may be spelled with hyphens or underscores ("str-aes" == "str_aes");
// see canonicalKey().
//
// Pass key:   "kagura-config"
// CLI flag:   -kagura-config=<path>
//             -kagura-config-strict  (unknown keys become errors)
//
//===----------------------------------------------------------------------===//

#include "kagura/Options.h"
#include "kagura/Passes/Infrastructure.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

using namespace llvm;

namespace kagura {

/// Turn the unknown-key diagnostic below into a build failure. Defined here
/// rather than in Options.cpp because nothing outside this file consults it;
/// it exists so a CI job can refuse to ship a policy file that has quietly
/// stopped meaning anything.
static cl::opt<bool> ConfigStrict(
    "kagura-config-strict",
    cl::desc("[Kagura] Treat unknown keys in the -kagura-config policy file as "
             "errors instead of warnings"),
    cl::init(false));

// ---- Shared helpers --------------------------------------------------------

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

/// Fold a policy-file key to its canonical spelling by replacing '-' with '_'.
///
/// The registry names passes with hyphens ("kagura-str-aes") and the policy
/// schema derives its keys by swapping in underscores ("str_aes"). Every
/// hand-written example in docs/ used the hyphen form instead, which no lookup
/// matched — and unknown keys used to be dropped without a word, so those
/// policy files silently protected nothing. The worst of them told an SDK
/// vendor to write `"anti-debug": false` for a soft-response build and then
/// shipped one that aborts on detection. Accepting both spellings on read
/// makes that entire class of bug impossible.
static std::string canonicalKey(StringRef Key) {
  std::string Out = Key.str();
  std::replace(Out.begin(), Out.end(), '-', '_');
  return Out;
}

/// Map a registry CLI name to its JSON policy key: "kagura-str-aes" ->
/// "str_aes". Deriving the key means the policy schema cannot drift from the
/// pass list.
static std::string jsonKeyFor(StringRef Cli) {
  return canonicalKey(Cli.drop_front(StringRef("kagura-").size()));
}

/// Canonical keys the "passes" object accepts, generated from the registry.
static std::vector<std::string> validPassKeys() {
  std::vector<std::string> Keys;
#define KAGURA_FN_PASS(Flag, Cli, Desc, Ctor)  Keys.push_back(jsonKeyFor(Cli));
#define KAGURA_MOD_PASS(Flag, Cli, Desc, Ctor) Keys.push_back(jsonKeyFor(Cli));
#include "kagura/PassRegistry.def"
  Keys.push_back("dwarf"); // string-valued, no registry row
  return Keys;
}

/// Canonical keys the "tuning" object accepts, generated from the registry.
static std::vector<std::string> validTuningKeys() {
  std::vector<std::string> Keys;
#define KAGURA_TUNING(Flag, Cli, Type, Default, Desc)                          \
  Keys.push_back(jsonKeyFor(Cli));
#include "kagura/PassRegistry.def"
  return Keys;
}

/// Kagura options that exist, but only on the command line: they have no
/// PassRegistry.def row, so the "passes"/"tuning" reader below cannot see them
/// however they are spelled. Returns the flag to use instead, or nullptr.
///
/// docs/configuration.md promises you can "control every pass setting in one
/// place", and these are the exceptions; saying so at the point of failure is
/// cheaper than making the reader find the caveat in the docs.
static const char *commandLineOnlyFlagFor(StringRef CanonKey) {
  static const struct { const char *Key, *Flag; } Table[] = {
      {"vtp",        "-kagura-vtp"},
      {"metrics",    "-kagura-metrics"},
      {"autoselect", "-kagura-autoselect"},
      {"lto_safe",   "-kagura-lto-safe"},
      {"o0_protect", "-kagura-o0-protect"},
      {"symmap",     "-kagura-symmap"},
      {"symmap_out", "-kagura-symmap-out"},
      {"build_id",   "-kagura-build-id"},
      {"audit",      "-kagura-audit"},
  };
  for (const auto &Row : Table)
    if (CanonKey == Row.Key)
      return Row.Flag;
  return nullptr;
}

namespace {

/// One "passes" or "tuning" object of a policy file, indexed by canonical key.
///
/// Two problems are solved here at once:
///   * hyphen/underscore tolerance (see canonicalKey), and
///   * unknown-key detection. Every lookup this class serves is generated from
///     PassRegistry.def, so any entry that no lookup ever claimed is a key the
///     loader physically cannot act on. Reporting those closes TODO D.1. The
///     comment in applyPassesObject() below already records four keys that were
///     lost exactly this way: the cause was fixed at the time, the symptom
///     class — silent acceptance — was not.
class PolicyObject {
  struct Entry {
    std::string Spelling;      ///< as written in the file, to quote back
    const json::Value *Value = nullptr;
    bool Claimed = false;
  };

  StringRef ObjectName;
  StringMap<Entry> Entries;

  const json::Value *find(StringRef CanonKey) {
    auto It = Entries.find(CanonKey);
    if (It == Entries.end())
      return nullptr;
    It->second.Claimed = true;
    return It->second.Value;
  }

public:
  PolicyObject(const json::Object &Obj, StringRef ObjectName)
      : ObjectName(ObjectName) {
    for (const auto &KV : Obj)
      Entries[canonicalKey(KV.first)] =
          Entry{StringRef(KV.first).str(), &KV.second, false};
  }

  std::optional<bool> getBoolean(StringRef Key) {
    const json::Value *V = find(Key);
    return V ? V->getAsBoolean() : std::nullopt;
  }
  std::optional<int64_t> getInteger(StringRef Key) {
    const json::Value *V = find(Key);
    return V ? V->getAsInteger() : std::nullopt;
  }
  std::optional<StringRef> getString(StringRef Key) {
    const json::Value *V = find(Key);
    return V ? V->getAsString() : std::nullopt;
  }

  /// Diagnose every key no registry row claimed. Returns true if there was at
  /// least one, so the caller can fail the build under -kagura-config-strict.
  bool reportUnclaimed(ArrayRef<std::string> Valid) const {
    bool Any = false;
    for (const auto &KV : Entries) {
      if (KV.second.Claimed)
        continue;
      Any = true;

      StringRef Written(KV.second.Spelling);
      std::string Canon = canonicalKey(Written);

      errs() << "[kagura] " << (ConfigStrict ? "error" : "warning")
             << ": unknown key \"" << Written << "\" in the \"" << ObjectName
             << "\" object of the policy file — it is ignored, so this "
                "setting has no effect";

      // A real flag that simply has no policy-file representation is a
      // different mistake from a typo, and telling the two apart is the
      // difference between "fix your spelling" and "this cannot be expressed
      // here at all, move it to the command line".
      if (const char *Flag = commandLineOnlyFlagFor(Canon)) {
        errs() << ". It is a command-line-only option: pass " << Flag
               << " instead.\n";
        continue;
      }

      // Otherwise a typo is by far the likeliest cause, so point at the
      // nearest real key — but only when the match is close enough that the
      // suggestion is more help than noise.
      StringRef Closest;
      unsigned BestDistance = ~0u;
      for (const std::string &Candidate : Valid) {
        unsigned D = StringRef(Canon).edit_distance(Candidate,
                                                    /*AllowReplacements=*/true);
        if (D < BestDistance) {
          BestDistance = D;
          Closest = Candidate;
        }
      }
      unsigned Threshold = std::max<unsigned>(1, Canon.size() / 3);
      if (!Closest.empty() && BestDistance <= Threshold)
        errs() << "; did you mean \"" << Closest << "\"?\n";
      else
        errs() << ".\n";
    }
    return Any;
  }
};

} // namespace

// ---- Profile presets -------------------------------------------------------

/// Apply the FAST / BALANCED / STRONG preset named by Profile.
///
/// The table lives in Profiles.def, which is also what generates
/// integration/profiles/*.json, so a hand-written `{"profile": "BALANCED"}`
/// and the shipped balanced.json now describe the same binary. They did not:
/// the JSON enabled sv, anti_debug and tamper and this function did not.
static void applyProfile(StringRef Profile) {
  bool Known = false;

#define KAGURA_PROFILE_PASS(Prof, Flag, Value)                                 \
  if (Profile.equals_insensitive(#Prof)) {                                     \
    preset(opt::Flag, Value);                                                  \
    Known = true;                                                              \
  }
#define KAGURA_PROFILE_TUNING(Prof, Flag, Value)                               \
  KAGURA_PROFILE_PASS(Prof, Flag, Value)
#include "../Profiles.def"

  // "custom" means "I am listing the passes myself" and is not a typo. Any
  // other unrecognised name silently produced an unprotected build.
  if (!Known && !Profile.equals_insensitive("custom"))
    errs() << "[kagura] warning: unknown profile \"" << Profile
           << "\" — expected FAST, BALANCED, STRONG or CUSTOM. No preset "
              "applied; only the \"passes\" and \"tuning\" objects take "
              "effect.\n";
}

// ---- JSON policy loader ----------------------------------------------------

/// Returns true if the object contained a key the loader cannot act on.
static bool applyPassesObject(const json::Object &PassesJson) {
  PolicyObject Passes(PassesJson, "passes");

  // Note the lookup happens even when the flag is set by the user: the key is
  // still a *known* key, and skipping the lookup would make it show up in the
  // unknown-key diagnostic.
  auto getBool = [&](StringRef Cli, cl::opt<bool> &Flag) {
    auto V = Passes.getBoolean(jsonKeyFor(Cli));
    if (V && !setByUser(Flag))
      Flag = *V;
  };

  // Generated from the registry rather than written out by hand. The hand
  // written table this replaces had already lost cse_break, string_split,
  // bbcheck and elt — those keys were simply ignored in policy files, with no
  // diagnostic. reportUnclaimed() below is what makes the next such loss loud.
#define KAGURA_FN_PASS(Flag, Cli, Desc, Ctor)  getBool(Cli, opt::Flag);
#define KAGURA_MOD_PASS(Flag, Cli, Desc, Ctor) getBool(Cli, opt::Flag);
#include "kagura/PassRegistry.def"

  if (auto DwarfVal = Passes.getString("dwarf"))
    if (!setByUser(opt::DWARFMode))
      opt::DWARFMode = DwarfVal->str();

  return Passes.reportUnclaimed(validPassKeys());
}

/// Read one numeric tuning key, keyed off the registry row so the JSON schema
/// stays derived from the flag set. This used to hold its own copy of the
/// key-to-flag mapping.
template <typename T>
static void readTuning(PolicyObject &Tuning, StringRef Cli, cl::opt<T> &Flag) {
  auto V = Tuning.getInteger(jsonKeyFor(Cli));
  if (V && !setByUser(Flag))
    Flag = static_cast<T>(*V);
}

/// Returns true if the object contained a key the loader cannot act on.
static bool applyTuningObject(const json::Object &TuningJson) {
  PolicyObject Tuning(TuningJson, "tuning");
#define KAGURA_TUNING(Flag, Cli, Type, Default, Desc)                          \
  readTuning(Tuning, Cli, opt::Flag);
#include "kagura/PassRegistry.def"
  return Tuning.reportUnclaimed(validTuningKeys());
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

  bool UnknownKeys = false;

  // 4.6.2: Apply base profile preset
  if (auto Profile = Root->getString("profile"))
    applyProfile(*Profile);

  // 4.6.1: Apply base pass enables / disables
  if (auto *PassesObj = Root->getObject("passes"))
    UnknownKeys |= applyPassesObject(*PassesObj);

  // 4.6.1: Apply base tuning parameters
  if (auto *TuningObj = Root->getObject("tuning"))
    UnknownKeys |= applyTuningObject(*TuningObj);

  // 4.6.3/4.6.4: Load allowlist / denylist / protect from JSON.
  //
  // These MERGE with an explicit command-line list instead of replacing it.
  // A JSON "denylist" used to clobber -kagura-deny=vendor_* outright, which
  // both contradicted the precedence rule docs/configuration.md publishes
  // ("an explicit -kagura-* flag wins") and re-obfuscated the very symbols the
  // user had just excluded. Losing to the flag would be no better: every entry
  // in a filter list is a symbol somebody deliberately singled out, so the only
  // answer that cannot silently drop one is the union of both sources.
  auto concatArray = [&](const json::Object *Obj, StringRef Key,
                         cl::opt<std::string> &Flag) {
    auto *Arr = Obj ? Obj->getArray(Key) : nullptr;
    if (!Arr) return;
    // Seed with the command-line value, if any, so it survives the assignment.
    std::string Combined = setByUser(Flag) ? Flag.getValue() : std::string();
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

  // 4.6.10: Audit log path from JSON. Scalar, so the ordinary precedence rule
  // applies: -kagura-audit-out on the command line wins.
  if (!setByUser(opt::AuditLogOut))
    if (auto AuditOut = Root->getString("audit_out"))
      opt::AuditLogOut = AuditOut->str();

  // 4.6.9: Apply flavor-specific overrides (after base config)
  if (FlavorRoot) {
    if (auto Profile = FlavorRoot->getString("profile"))
      applyProfile(*Profile);
    if (auto *PassesObj = FlavorRoot->getObject("passes"))
      UnknownKeys |= applyPassesObject(*PassesObj);
    if (auto *TuningObj = FlavorRoot->getObject("tuning"))
      UnknownKeys |= applyTuningObject(*TuningObj);
    concatArray(FlavorRoot, "allowlist", opt::AllowList);
    concatArray(FlavorRoot, "denylist",  opt::DenyList);
    concatArray(FlavorRoot, "protect",   opt::ProtectList);
  }

  // A policy file that no longer means what it says is a silent downgrade of
  // the shipped binary, so let a build opt into failing on one.
  if (UnknownKeys && ConfigStrict)
    report_fatal_error("[kagura] -kagura-config-strict: the policy file "
                       "contains keys the loader does not understand",
                       /*gen_crash_diag=*/false);
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
