# Changelog

All notable changes to Kagura are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

A repair release. Several documented flags did nothing at all; a few produced
binaries that could not link or crashed the compiler. In every case the reason
it went unnoticed was a hole in the test suite, so the suite was rebuilt too.

### ⚠️ Read this before upgrading

**Passes that previously did nothing now do something.** If you build with any
of the flags below, expect your output to change — larger binaries, longer
compile times, and possibly newly-exposed problems in code that was never
actually obfuscated before. Re-measure size and performance before shipping.

| Flag | Behaviour before | Behaviour now |
|:-----|:-----------------|:--------------|
| `-kagura-config=<file>` | ignored entirely | selects passes as documented |
| `-kagura-co` | no-op at every seed | replaces constants with MBA expressions |
| `-kagura-autoselect` | no-op | narrows protection per function by risk score |
| `-kagura-lt`, `-kagura-fsplit` | crashed clang | apply their transforms |
| `opt -passes=kagura-{bbs,bbr,dci,ibr,lt,fsplit,bbcheck,telemetry,pe,elt,mvo}` | silently inert | apply their transforms |

The `-kagura-config` change is the largest. A policy file requesting
`"profile": "STRONG"` previously enabled **no** passes; it now enables around
fourteen.

Precedence is also now defined, where before it was undefined: an explicit
command-line flag beats the config file, so
`-kagura-config=p.json -kagura-str=false` disables string encryption rather
than having the profile preset silently overwrite it.

### Fixed

#### Features that did not work

- **`-kagura-config` was a complete no-op.** `ConfigLoader` ran as a pipeline
  pass, mutating the `opt::` flags at pipeline *run* time, while `Plugin.cpp`
  reads those same flags at pipeline *construction* time to decide which
  passes to add. The policy file therefore always arrived after the decision
  it was meant to inform. The loader now runs before the pipeline is built.
- **`-kagura-co` never obfuscated a constant, at any seed.** Every MBA
  identity is built from a `ConstantInt` operand, and the default
  `IRBuilder<>` carries a `ConstantFolder` that evaluated `(V ^ R) ^ R`
  straight back to `V` — so the pass stored the value that was already there.
  Now uses `IRBuilder<NoFolder>`.
- **`-kagura-vm` produced binaries that hung before their first line of
  output.** The interpreter was fine; the pass emitted bytecode that did not
  mean anything. `virtualize()` handled binops, icmp, br, ret, load, store and
  three casts — PHI nodes, calls, GEPs, allocas, selects and switches all fell
  through to "emit NOP and carry on", and an operand it could not materialise
  made it `continue` out of the middle of an instruction. `canVirtualize()`
  accepted those functions regardless, so at `-O1` every function with a loop
  became bytecode that computed nothing: the loop condition degenerated to a
  literal 0 and the VM took the same edge forever.

  Measured across the test subjects with inlining disabled, **all 16 cases
  where the old pass virtualized anything hung, segfaulted or aborted**; the 10
  that appeared to pass had virtualized nothing at all.

  The pass is now all-or-nothing: any shape it cannot express leaves the
  function untouched. PHIs lower to stack-based parallel copies, allocas to
  arena offsets, calls through a relocation pool. Two further defects fixed
  along the way — the bytecode blob was a *mutable* global decrypted in place,
  so a second call to a virtualized function re-encrypted it; and the
  trampoline kept the attributes inferred from the original body, advertising
  `memory(none)` while calling the interpreter.

  Verified: output identical to an unobfuscated build for every subject at
  -O0/-O1/-O2, across three PRNG seeds, on LLVM 21 and 22 — and repeated calls
  into the same virtualized function now return the same result.
  `integration_vm_correctness` guards it, and was confirmed to fail against the
  old code.

- **`-kagura-lt` and `-kagura-fsplit` crashed clang.** Both emitted IR that
  fails LLVM's verifier: PHI nodes left ungrouped at the top of a block, and
  values erased while still in use (the freed slots were recycled, so
  surviving operands pointed at unrelated values of unrelated types).
  `FunctionSplit` now threads live-out values through allocas.
- **Eleven passes were inert under `opt -passes=`.** Each re-checked its own
  `-kagura-*` enable flag inside the pass body, but that flag is only set by
  the `-fpass-plugin` entry point. Whether a pass runs is now decided once,
  when the pipeline is built.
- **`-kagura-autoselect` was dead three ways over**: never injected into the
  pipeline, wrote metadata nothing read, and emitted only force-*enable*
  annotations, which merely restate the default for a pass already in the
  pipeline.
- **`-kagura-anti-debug`, `-kagura-bbcheck` and `-kagura-telemetry` could not
  link** — `kagura_check_tracer_pid` existed only under `#ifdef __linux__`
  while being emitted unconditionally, and `kagura_bb_check` and
  `kagura_telemetry_event` were never defined at all.
- **`-kagura-str-aes` could not link on Windows.** `core/blob_integrity.c`
  needs only `<stdint.h>` yet sat in the `if(NOT WIN32)` source group.
- **`KAGURA_UNITY_BUILD=ON` did not compile** — `hasOnlyGuardableUses` was
  defined identically in two files that share a unity group.
- Four JSON policy keys — `cse_break`, `string_split`, `bbcheck`, `elt` —
  were accepted and silently ignored. The key table is now generated from
  `PassRegistry.def`.

#### Correctness

- Two `APInt` width overflows in key generation, which aborted on any
  `i8`/`i16` alloca or global.
- A `VMObfuscation` register-map overflow. With assertions enabled it aborted;
  with them compiled out — which is what ships — it kept handing out
  increasing indices, so the emitted bytecode addressed past the end of
  `VMState::regs[]` and corrupted adjacent interpreter state at run time.
- `SymbolVisibility` set hidden visibility on `internal` functions, which LLVM
  rejects (`local linkage requires default visibility`) and which achieves
  nothing anyway. It now hides unkept *exported* definitions.
- **Nine runtime checks were silently disabled.** `device_attest.c`,
  `integrity_report.c` and `play_integrity.c` declared symbols
  `__attribute__((weak))` under names that do not exist, then null-tested
  them — so `kagura_appattest_local_check()` always returned 1 and
  `collect_violation_flags()` always returned 0.
- `kagura_soft_response_check` was exported with two incompatible signatures
  (POSIX vs Windows), so no portable caller could exist.
- `kagura_tamper_detected` lived in an iOS source file, so Android and Windows
  links that pulled `elf_integrity.o` but not `jailbreak_detection.o` got an
  undefined symbol. Both callback names now live in `core/tamper_response.c`.
- On Darwin, `extern` + `weak` does not produce a weak-undefined reference, so
  `crash_symbolication.c`'s three `__kagura_sym_*` declarations were hard
  undefined symbols — breaking any consumer that force-loads the archive.
- Frida port detection was trapped inside `#ifdef __linux__`, i.e. absent on
  the platforms Frida is most used against.

#### Build and packaging

- **SwiftPM could not build**: all 40 source paths still referenced the
  pre-reorganization flat `runtime/` layout. `Package.swift` is now at the
  repository root, where SwiftPM requires it.
- **Bazel built an empty library**: `glob(["../../runtime/*.c"])` matches
  nothing, and Bazel rejects uplevel references. A root `BUILD.bazel` declares
  the runtime from a package that actually contains it.
- **CocoaPods pulled Android and Windows sources into an iOS pod** — all eight
  `exclude_files` entries were stale — and pointed at a plugin path that does
  not exist.
- `paper/*.tex` and `refs.bib` were gitignored and untracked, so the source
  behind the README's Zenodo DOI existed on one machine only.

### Added

- **Link smoke tests** — 30 of them, generated from `PassRegistry.def`, each
  compiling and linking a real executable. No test had ever linked one, which
  is how three passes shipped referencing undefined symbols.
- **The lit suite now runs.** Its harness had four stacked faults and CI never
  installed `lit`, so 29 tests were skipped with a `STATUS` message while the
  build stayed green. CI now installs `lit` and fails if the suite is not
  registered.
- **An assertions-enabled CI job.** Every other job builds `Release`, so
  `assert()` is compiled out and the three assertion-firing bugs above could
  never have failed a CI run.
- Pass tests append `verify` to every pipeline and build subjects at `-O0` as
  well as `-O2`, since most of what these passes get wrong involves PHI nodes,
  which barely exist before `mem2reg`.
- `cmake/` module directory; all eight `KAGURA_*` options documented in one
  place. `KAGURA_BUILD_FUZZ` previously did not exist unless tests were also
  enabled.
- `install()`/`EXPORT` rules. Release bundles were assembled by hand-copying
  build-tree paths; staging is now `cmake --install`.
- `integration/profiles/{fast,balanced,strong}.json` — one definition of each
  profile, replacing five drifted copies across the integration directories.
- `runtime/internal.h`. `runtime/` had no headers at all; every cross-TU
  contract was a hand-written `extern`, `kagura_on_tamper_detected` alone
  appearing 19 times in three inconsistent forms.
- `docs/requirements.txt`, pinning the documentation toolchain.

### Changed

- `CMAKE_BUILD_TYPE` defaults to `RelWithDebInfo`. A bare `cmake -B build`
  previously produced an unoptimised build with no `NDEBUG`, matching neither
  what CI tests nor what releases ship.
- Duplication removed: FNV-1a (9 implementations → 1, with the constants
  pinned to canonical vectors on both the pass and runtime sides),
  `/proc/self/maps` scanning (9 → 1), `path_exists` (6 → 1), dyld image
  scanning (5 divergent pattern lists → 1 union), module constructor
  priorities (7 magic integers → `enum CtorPriority`).
- `runtime/CMakeLists.txt` splits sources per platform. Previously every
  `android/*.c` was compiled on macOS as an empty translation unit and every
  `ios/*.c` on Linux.

### Known issues

- **`clang -fpass-plugin=… -mllvm -kagura-…` does not work below LLVM 22.**
  Pre-existing, and it is the invocation the README leads with. clang parses
  `-mllvm` options before `-fpass-plugin` has loaded the plugin, so the
  `-kagura-*` options are not registered yet and clang exits with
  *"Unknown command line argument '-kagura-str'"*. Verified failing on LLVM 21
  with both this branch's plugin and `main`'s; accepted on 22.

  Working on every supported version: the shipped `kagura-opt`, or
  `opt --load-pass-plugin=<plugin> -kagura-… -passes=…`. The test suite uses
  the latter, which is why this went unnoticed — nothing exercised the
  documented path. The docs now carry the caveat; picking a real fix (register
  the options earlier, or make `kagura-opt` the documented entry point) is
  still open.
- **`-kagura-bbcheck` cannot detect binary patching.** Its checksum is
  computed over LLVM IR opcodes before code generation; the runtime has
  machine code and no way to recompute that value, and `block_id` restarts at
  1 in every function so it is not a unique key. `kagura_bb_check` is a
  documented always-pass stub. Fixing this requires the pass to emit
  post-codegen byte ranges instead.
- `LegacyPlugin.cpp` builds in no CI job and has drifted from
  `PassRegistry.def`. It targets LLVM ≤ 16 while the project advertises 17–22.

## [0.2.1] — 2026-07-31

### Added

- **Windows: a working way to run the passes.** `-fpass-plugin` is unavailable
  on Windows because the MSVC-targeted LLVM ships with
  `LLVM_ENABLE_PLUGINS=OFF`, and the static `KaguraObfuscator.lib` the build
  produced there had no consumer — the documented "link it into your driver
  tool" had no such tool. `kagura-opt` now links the passes in and registers
  them by calling `getKaguraPluginInfo()` directly, so building with
  `-DKAGURA_BITCODE_TOOLS=ON` gives Windows users an IR-level entry point.
- **`KAGURA_FORCE_STATIC_PLUGIN`** — selects the same static-linkage path on
  macOS and Linux, so the Windows build can be reproduced without a Windows
  machine. CI runs this configuration on Linux.

### Fixed

- **Windows CI verified nothing.** With no loadable module, the entire test
  suite short-circuited to a single `echo`, so a green Windows job only meant
  the sources compiled. The suite now drives the passes through `kagura-opt`
  on that platform.
- The static `KaguraObfuscator` archive no longer links the imported LLVM
  targets. It never needed to resolve those symbols itself, and inheriting
  their `INTERFACE` include directories as `-isystem` put the macOS SDK C
  headers ahead of libc++, breaking `<cstddef>`. Consumers link the components
  (`Core`, `Support`, `Analysis`, `TransformUtils`, `Passes`) instead.

## [0.2.0] — 2026-06-30

A wide-coverage release. Two new IR passes, three platform attestation
runtime stubs, a full documentation site with Japanese translations, a CI
fix for Windows / MSVC compatibility, two post-build CLI utilities, and a
single-source-of-truth refactor for the pass registry.

### Added

#### New passes

- **`-kagura-cse-break`** (Data) — Defeats decompiler CSE-recovery (Ghidra,
  IDA hex-rays, Binary Ninja MLIL) by duplicating shared SSA expressions so
  every user sees a fresh definition. Functionally identical, syntactically
  distinct — pattern-matching deobfuscators can no longer merge the
  expressions back into a single readable line.
- **`-kagura-string-split`** (Data) — Fragments long (≥16 byte) string
  literals across multiple smaller private globals; recombines them at
  runtime via a flag-guarded init stub on first access. Defeats
  `strings -n <large>` and contiguous-blob assumptions. Composes with
  `kagura-str` / `kagura-str-aes`: when both are enabled, neither plaintext
  nor ciphertext exists contiguously in the binary.

#### Platform attestation runtime stubs

- **`runtime/ios/device_attest.c`** — C bindings for Apple DeviceCheck
  (iOS 11+) and App Attest (iOS 14+, A10+). Availability gates, nonce
  generation (arc4random_buf + clock + atomic counter mix), and a fast
  local pre-screen that short-circuits the async Apple round-trip when the
  environment is obviously bad.
- **`runtime/windows/etw_detection.c`** — ETW provider enumeration to detect
  analysis-tool registration (Cheat Engine, Procmon, Process Hacker,
  ScyllaHide GUIDs). Stub-only by default; enable the full TDH path with
  `-DKAGURA_ETW_FULL=1` + `tdh.lib`.

Android Play Integrity (`runtime/android/play_integrity.c`) is part of the
0.1.x history and is documented here for visibility.

#### Documentation site

- Full MkDocs site published at <https://ykus4.github.io/kagura>, deployed
  automatically from `main` via `.github/workflows/docs.yml`.
- Multi-section sidebar nav: Getting Started · Passes · Integration ·
  Cookbook · Security Model · Configuration · Runtime · Project.
- **Cookbook**: four recipe pages — Banking / FinTech, Mobile game /
  anti-cheat, SDK / library vendor, DRM / license enforcement. Each
  includes a threat model, complete policy JSON, build commands,
  source-side annotations, runtime hardening code, verification commands,
  and explicit "still on you" boundary callouts.
- **Security Model** (`docs/security-model.md`): STRIDE coverage matrix
  (strong / partial / out-of-scope), hard non-goals (plaintext secrets,
  side channels, determined adversaries), five load-bearing assumptions,
  self-evaluation tool matrix, recommended defense-in-depth layering.
- **Japanese localization** (`mkdocs-static-i18n`): English default at `/`,
  Japanese mirror at `/ja/`. 30 pages translated covering Home, Getting
  Started, every Passes page, Configuration, Runtime, Game Protection,
  Testing, Architecture, Contributing, Integration index, and per-system
  integration overviews. Cookbook + Security Model JA translations will
  follow in a subsequent release.

#### Tooling

- **`scripts/kagura-strip.py`** — Post-build hygiene CLI. Zeros out
  `LC_UUID` (Mach-O) / `.note.gnu.build-id` (ELF) so release binaries
  don't leak a rebuild fingerprint. Run after `strip`.
- **`scripts/kagura-diff.py`** — Section / symbol / string diff between
  baseline and obfuscated binaries. Text, HTML report, or JSON dump.
  Validates that a release build hid the symbols and encrypted the
  strings it was supposed to.

#### Community & DX

- GitHub Issue templates (`bug`, `feature`, `pass-proposal`) with required
  YAML fields, labels, and category dropdowns.
- PR template with type-of-change checklist, test plan, and new-pass
  checklist.
- `.github/ISSUE_TEMPLATE/config.yml` surfaces Discussions and the docs
  site, routing questions away from Issues.

### Changed

- **`refactor: table-driven pass registry`** — `lib/Transforms/PassRegistry.def`
  is now the single source of truth for every Kagura pass. Plugin.cpp
  shrinks from 378 → 197 lines; Options.cpp from 205 → 116 lines (net
  −250 lines). Adding a new pass is now a one-line edit in the registry
  table — no more synchronizing three separate if-chains across
  Plugin.cpp and Options.cpp.
- README slimmed to hero + threats table + docs links. Detailed content
  migrated into the docs site.
- MkDocs nav consolidated to collapsible left-sidebar groups (Home,
  Getting Started, Passes, Integration, Cookbook, Security Model,
  Configuration, Runtime, Project) instead of 10 cluttered top tabs.

### Fixed

- **Windows CI (`fix/ci-windows-llvm-bump`)** — `Build & Test (Windows,
  Clang-CL)` job was failing on `main` with `error STL1000: Unexpected
  compiler version, expected Clang 20 or newer` after a `windows-latest`
  runner image update. Bumped the LLVM tarball from 19.1.7 → 21.1.5 to
  satisfy the new MSVC STL requirement.

### PR list

PRs merged in this release:

- #36 — chore: add MkDocs (foundation)
- #37 — docs(mkdocs): collapsible left-sidebar nav with subsections
- #38 — ci(windows): bump LLVM 19.1.7 → 21.1.5 for MSVC STL requirement
- #39 — chore(batch-a): community templates, post-build CLIs, docs banner
- #40 — docs(batch-b): security model + cookbook recipes
- #41 — feat(batch-e): platform attestation stubs (iOS / Windows)
- #42 — docs(batch-c): i18n — Japanese translations with English default
- #43 — feat(batch-d1): kagura-cse-break — defeat decompiler CSE recovery
- #44 — feat(batch-d2): kagura-string-split — fragment string literals
- (this PR) — refactor: table-driven pass registry + CHANGELOG for v0.2.0

## [0.1.2] — 2026-05-24

See `git log v0.1.1..v0.1.2` for details. Highlights:

- Paper link added to Citation
- Zenodo DOI badge
- Documentation polish

## [0.1.1] — 2026-05-13

Initial public release iteration. See `git log v0.1.0..v0.1.1`.

## [0.1.0] — 2026-05-09

First public release of Kagura as MIT-licensed OSS.
