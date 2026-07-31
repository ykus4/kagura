# Changelog

All notable changes to Kagura are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
