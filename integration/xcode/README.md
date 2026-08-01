# kagura — Xcode Integration Guide

This document explains how to integrate the kagura LLVM obfuscator into an Xcode
project using the provided xcconfig and shell scripts.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [xcconfig Reference](#xcconfig-reference)
4. [Manual xcconfig Snippet](#manual-xcconfig-snippet)
5. [Per-File Selective Obfuscation](#per-file-selective-obfuscation)
6. [Build Phase Script](#build-phase-script)
7. [Swift and Objective-C Compatibility](#swift-and-objective-c-compatibility)
8. [Bitcode](#bitcode)
9. [Debug vs Release](#debug-vs-release)
10. [Code Signing](#code-signing)
11. [Performance Tuning](#performance-tuning)
12. [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| LLVM / clang | 17.0 | 22.0 |
| Xcode | 14.0 | 16.0+ |
| macOS SDK | 13.0 | 15.0+ |
| CMake | 3.20 | latest |

**Build kagura first.**  The Xcode integration references the compiled plugin at
`build/lib/Transforms/KaguraObfuscator.dylib`.  From the kagura repository root:

```sh
# macOS — Homebrew LLVM (recommended)
brew install llvm
bash build.sh
```

For a non-Homebrew LLVM installation, specify the LLVM CMake directory explicitly:

```sh
cmake -B build \
  -DLLVM_DIR=/path/to/llvm/lib/cmake/llvm \
  -DCMAKE_C_COMPILER=/path/to/llvm/bin/clang \
  -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++ \
  .
cmake --build build -- -j$(sysctl -n hw.logicalcpu)
```

Verify the build succeeded:

```sh
ls -lh build/lib/Transforms/KaguraObfuscator.dylib
```

---

## Quick Start

1. **Add `kagura.xcconfig` to your Xcode project.**
   Drag `integration/xcode/kagura.xcconfig` into the Project Navigator.
   Xcode will prompt you to add it; choose your app target.

2. **Assign the xcconfig to the Release configuration.**
   Select the project in the Project Navigator → Info tab →
   Configurations → Release → expand your target →
   set "Based on Configuration File" to `kagura`.

3. **Set `KAGURA_ROOT`.**
   In Build Settings, add a User-Defined Setting:

   | Key | Value |
   |-----|-------|
   | `KAGURA_ROOT` | `$(SRCROOT)/../kagura` |

   Adjust the relative path to match the location of the kagura checkout
   relative to your `.xcodeproj` file. `kagura-flags.sh` probes
   `$(KAGURA_ROOT)/build/lib/Transforms/KaguraObfuscator.{dylib,so,dll}`.
   Set `KAGURA_PLUGIN_PATH` to an absolute plugin path to skip the probe.

4. **Pick a profile.**
   `KAGURA_PROFILE = fast | balanced | strong | off` (default `balanced`),
   or an absolute path to your own JSON policy file.

5. **Add the validation build phase** (optional but recommended).
   See [Build Phase Script](#build-phase-script).

6. **Archive or build for Release.**

---

## xcconfig Reference

The following settings are available in `kagura.xcconfig`.

### Plugin location

```xcconfig
KAGURA_ROOT = $(SRCROOT)/../kagura
KAGURA_PLUGIN_PATH =            // optional: absolute path, skips the probe
```

`kagura-flags.sh` probes `$(KAGURA_ROOT)/build/lib/Transforms/` for
`KaguraObfuscator.dylib`, `.so` and `.dll`, in that order. Override
`KAGURA_PLUGIN_PATH` in a machine-local `.xcconfig` that you do not commit to
source control, or via a User-Defined build setting in the target.

### Profile

```xcconfig
KAGURA_PROFILE = balanced       // fast | balanced | strong | off | <path.json>
```

The pass set for each profile is **not** defined in this integration. It lives
in [`integration/profiles/<name>.json`](https://github.com/ykus4/kagura/tree/main/integration/profiles), the single
source of truth shared by all kagura integrations. `kagura-flags.sh` emits
both `-mllvm -kagura-config=<json>` and the flag list expanded from that same
JSON, so the build is configured identically whether or not the
`kagura-config` pass takes effect.

### Per-pass overrides

Every setting below is **empty by default** — the profile decides. Setting one
switches `kagura-flags.sh` to the explicit-flag path: the profile is still
expanded, your overrides are appended after it (last flag wins), and
`-kagura-config` is dropped so the `kagura-config` pass cannot clobber them.

| Setting | Pass |
|---------|------|
| `KAGURA_ENABLE_STR` | StringEncryption — XOR-encrypts string literals |
| `KAGURA_ENABLE_FLA` | ControlFlowFlattening — switch-based state machine |
| `KAGURA_ENABLE_BCF` | BogusControlFlow — MBA opaque predicates |
| `KAGURA_ENABLE_SUB` | Substitution — MBA arithmetic replacements |
| `KAGURA_ENABLE_CO` | ConstantObfuscation — replaces integer constants |
| `KAGURA_ENABLE_OBJC` | ObjCObfuscation — selector/class name obfuscation (Apple-only; in no profile, on by default here) |
| `KAGURA_ENABLE_ANTIDEB` | AntiDebug — ptrace/Frida/port-27042 checks |
| `KAGURA_ENABLE_METRICS` | ObfuscationMetrics — stderr diagnostic output |

### Tuning overrides

| Setting | Description |
|---------|-------------|
| `KAGURA_BCF_PROB` | Probability (0–100) of inserting bogus CF per BB |
| `KAGURA_BCF_ITER` | Number of BCF iterations |
| `KAGURA_SUB_ITER` | Number of substitution iterations |
| `KAGURA_SEED` | PRNG seed — set for reproducible obfuscation |

All four are empty by default and fall back to the profile's `"tuning"` block.

---

## Manual xcconfig Snippet

If you prefer not to use the provided `kagura.xcconfig` file you can paste the
following into your own xcconfig.  Replace `$(KAGURA_PLUGIN_PATH)` with the
literal path to `KaguraObfuscator.dylib` if the variable expansion does not
work in your environment.

```xcconfig
// ── kagura obfuscation flags ──────────────────────────────────────────────

// Load the pass plugin
// -fpass-plugin tells clang to load kagura into the New Pass Manager.
KAGURA_PLUGIN_FLAG = -fpass-plugin=$(KAGURA_PLUGIN_PATH)

// String encryption: XOR-encrypts all string literals at compile time.
// Strings are decrypted lazily on first access via a constructor stub.
KAGURA_STR_FLAG = -mllvm -kagura-str

// Control-flow flattening: replaces the CFG with a switch-based state machine.
// Best combined with -O1 or higher so dead code is eliminated first.
KAGURA_FLA_FLAG = -mllvm -kagura-fla

// Bogus control flow: injects dead basic blocks guarded by opaque predicates.
// Increase -kagura-bcf-prob to add more bogus branches (costs binary size).
KAGURA_BCF_FLAG = -mllvm -kagura-bcf -mllvm -kagura-bcf-prob=30 -mllvm -kagura-bcf-iter=1

// Instruction substitution: replaces arithmetic/bitwise ops with MBA equivalents.
KAGURA_SUB_FLAG = -mllvm -kagura-sub -mllvm -kagura-sub-iter=1

// Constant obfuscation: replaces integer constants with MBA expressions.
// Disabled by default — significantly increases binary size.
// KAGURA_CO_FLAG = -mllvm -kagura-co

// ObjC obfuscation: rewrites selector and class name metadata in LLVM IR.
// Does not affect Swift-only code; safe to enable for mixed targets.
KAGURA_OBJC_FLAG = -mllvm -kagura-objc

// Anti-debug / Anti-Frida: injects ptrace(PT_DENY_ATTACH), port-27042 probe,
// and /proc/maps detection. Requires kagura_runtime to be linked.
KAGURA_ANTIDEB_FLAG = -mllvm -kagura-anti-debug

// Assemble all active flags
OTHER_CFLAGS = $(inherited) $(KAGURA_PLUGIN_FLAG) $(KAGURA_STR_FLAG) $(KAGURA_FLA_FLAG) $(KAGURA_BCF_FLAG) $(KAGURA_SUB_FLAG) $(KAGURA_OBJC_FLAG) $(KAGURA_ANTIDEB_FLAG)
OTHER_CPLUSPLUSFLAGS = $(inherited) $(KAGURA_PLUGIN_FLAG) $(KAGURA_STR_FLAG) $(KAGURA_FLA_FLAG) $(KAGURA_BCF_FLAG) $(KAGURA_SUB_FLAG) $(KAGURA_OBJC_FLAG) $(KAGURA_ANTIDEB_FLAG)
```

---

## Per-File Selective Obfuscation

Some files (parsers, hot loops, generated code) may not benefit from or may be
harmed by obfuscation.  Xcode lets you override `OTHER_CFLAGS` on a per-file
basis in the "Compile Sources" build phase.

### Disabling obfuscation for a single file

1. Select the target → Build Phases → Compile Sources.
2. Find the source file, click the compiler flags column.
3. Enter the flags you want to **remove**, prefixed with `-Xclang -remove-option`
   — however, Xcode does not support removing inherited flags at the file level.
   The practical approach is to **set a replacement flag set** that omits kagura:

```
-fno-pass-plugin
```

Because `-fno-pass-plugin` is not a real flag, a simpler pattern is to compile
sensitive files without the plugin by assigning an explicit empty override:

```
OTHER_CFLAGS = $(inherited_except_kagura)
```

The recommended approach for large projects is to keep a secondary xcconfig
that enables only lightweight passes and assign it to files via a custom build
rule.

### Enabling extra passes for a single file

To apply the VM pass only to a specific `.c` or `.m` file, add these per-file
flags in Compile Sources:

```
-mllvm -kagura-vm
```

Note: `-kagura-vm` requires `libkagura_runtime.a` to be linked into the binary.

### Using source annotations (preferred)

For finer granularity, annotate individual functions in source code.  kagura
respects `__attribute__((annotate("kagura.*")))` markers:

```c
// Apply VM obfuscation to this function only
__attribute__((annotate("kagura.vm")))
int verify_license(const char *key) { ... }

// Exclude this function from all kagura passes
__attribute__((annotate("kagura.skip")))
void hot_render_loop(void) { ... }
```

Supported annotation strings:

| Annotation | Effect |
|------------|--------|
| `kagura.vm` | Force VMObfuscation on this function |
| `kagura.fla` | Force ControlFlowFlattening on this function |
| `kagura.bcf` | Force BogusControlFlow on this function |
| `kagura.skip` | Exclude function from all kagura passes |

---

## Build Phase Script

Add `kagura-build-phase.sh` as a Run Script phase **before** the Compile Sources
phase.  This script validates the plugin exists and prints the active
configuration to the build log.

1. Target → Build Phases → `+` → New Run Script Phase.
2. Drag the new phase above "Compile Sources".
3. Set **Shell** to `/bin/bash`.
4. Paste the script body:

```sh
${SRCROOT}/../kagura/integration/xcode/kagura-build-phase.sh
```

Or, if you prefer to embed the full path:

```sh
/absolute/path/to/kagura/integration/xcode/kagura-build-phase.sh
```

5. Uncheck "Based on dependency analysis" so the script runs on every build.

**What the script does:**

- Resolves `KAGURA_PLUGIN_PATH` (falls back to the relative default).
- Exits with code `0` (non-fatal) if the plugin is missing, printing a warning.
  This allows Debug builds (which typically skip the xcconfig) to succeed
  without the plugin being present.
- Prints a formatted summary of all active kagura settings to the build log for
  auditing purposes.

---

## Swift and Objective-C Compatibility

### Objective-C and Objective-C++

kagura is fully compatible with Objective-C and Objective-C++.  The
`-kagura-objc` pass additionally rewrites selector strings and class names
embedded in LLVM IR metadata, providing protection beyond what the C/C++ passes
offer.

Flags are passed via `OTHER_CFLAGS` / `OTHER_CPLUSPLUSFLAGS` which apply to
`.m` / `.mm` files automatically.

### Swift

Swift source is compiled by `swiftc`, not `clang`, so `OTHER_CFLAGS` does not
apply.  The `OTHER_SWIFT_FLAGS` setting in `kagura.xcconfig` forwards the
`-fpass-plugin` flag to `swiftc`; however:

- `-mllvm` flags are not forwarded to Swift's LLVM backend in the same way.
- `-kagura-objc` does not apply to Swift-generated LLVM IR.
- String literal protection via `-kagura-str` has limited effectiveness on Swift
  strings because Swift stores many strings in the Swift runtime, not as C
  `@llvm.globalobject` constants.

For Swift targets the recommended approach is:
1. Implement security-sensitive logic in Objective-C or C.
2. Call that logic from Swift via a bridging header.
3. Apply the full kagura flag set to the C/Objective-C translation units.

---

## Bitcode

**kagura requires bitcode to be disabled.**

Bitcode (`ENABLE_BITCODE = YES`) causes Xcode to embed LLVM bitcode in the
binary and re-optimize it server-side (App Store re-compilation).  This
re-compilation step does not load the kagura plugin and would strip or undo
the obfuscation.

Ensure your xcconfig or build settings include:

```xcconfig
ENABLE_BITCODE = NO
```

As of Xcode 14, bitcode submission is deprecated and disabled by default for
new projects.  If you are upgrading an older project, verify this setting is
explicitly set to `NO` in the Release configuration.

---

## Debug vs Release

It is strongly recommended to enable kagura passes **only in Release builds**.

- Obfuscation significantly increases compile time (typically 2–5× depending
  on the passes and iteration counts selected).
- Obfuscated binaries are harder to debug with LLDB because variable names,
  inline frames, and source locations may be obscured.
- The `kagura.xcconfig` file is intended to be assigned only to the Release
  configuration (see [Quick Start](#quick-start)).

To ensure kagura is inactive in Debug builds, confirm the xcconfig is **not**
assigned to the Debug configuration:

```
Project → Info → Configurations → Debug → <your target> → None
Project → Info → Configurations → Release → <your target> → kagura
```

For CI pipelines that run tests against Release builds, use
`KAGURA_PROFILE = fast`, which keeps string encryption active without the
compile-time-expensive CFG passes.

---

## Code Signing

kagura does not affect Mach-O load commands or code signature structures
directly, but the passes do modify function bodies, which changes the code hash
that codesign measures.

- Always sign **after** compilation (the default Xcode behaviour).
- Do **not** attempt to sign a binary, apply kagura post-link, then re-sign
  manually — use the standard Xcode archive workflow instead.
- If you use a custom post-link script that strips or modifies the binary,
  ensure it runs before the codesign step.
- `ENABLE_HARDENED_RUNTIME = YES` is compatible with kagura.  The AntiDebug
  pass injects `ptrace(PT_DENY_ATTACH, 0, 0, 0)` which is distinct from the
  Hardened Runtime debugger restriction and they do not conflict.

---

## Performance Tuning

The table below shows recommended flag combinations for three common scenarios.

The authoritative FAST / BALANCED / STRONG pass sets are the JSON files in
[`integration/profiles`](https://github.com/ykus4/kagura/tree/main/integration/profiles); read those rather than a table
here, which is how the six copies of this list drifted apart in the first
place. Select one with:

```xcconfig
KAGURA_PROFILE = strong
```

or point at your own policy file:

```xcconfig
KAGURA_PROFILE = $(SRCROOT)/kagura.json
```

```json
{ "profile": "BALANCED", "passes": { "vm": true } }
```

Rough compile-time overhead: `fast` ~1.1×, `balanced` ~2–3×, `strong` ~5–10×.

Notes:
- "selective" for `-kagura-vm` means applying it only to the highest-value
  functions via `__attribute__((annotate("kagura.vm")))`.
- VM obfuscation produces the largest binary size increase.  Virtualizing an
  entire app is not recommended.
- Setting `-kagura-seed=<N>` with a fixed value makes builds reproducible,
  which is useful for CI caching and binary diffing.

---

## Troubleshooting

### `error: unknown argument '-kagura-fla'`

**Cause:** clang is not picking up the kagura plugin.  The `-mllvm` flags
are only valid after `-fpass-plugin` loads the plugin that registers them.

**Fix:** Confirm `KAGURA_PLUGIN_PATH` points to the correct `.dylib` and that
the file exists.  Run the build phase script manually:

```sh
KAGURA_PLUGIN_PATH=/your/path/KaguraObfuscator.dylib \
  ./integration/xcode/kagura-flags.sh
```

(The script also works with `.so` and `.dll` plugins.)

The output should start with `-fpass-plugin=...`.

---

### `error: unknown command line argument '-kagura-fla'` (wrong LLVM path)

**Cause:** The system `clang` (Apple LLVM) is being used instead of the LLVM
clang that understands the New Pass Manager plugin interface.  Apple's clang
ships with a different LLVM version and does not support third-party pass
plugins loaded via `-fpass-plugin`.

**Fix:** Set `CC` and `CXX` to the Homebrew (or custom) LLVM clang in your
build settings:

```xcconfig
CC  = /opt/homebrew/opt/llvm/bin/clang
CXX = /opt/homebrew/opt/llvm/bin/clang++
```

On Intel Macs the Homebrew prefix is `/usr/local` rather than `/opt/homebrew`.

---

### `fatal error: pass plugin not loaded: KaguraObfuscator.dylib`

**Cause:** The dynamic library cannot be found or loaded.  This is typically a
missing dependency (LLVM dylibs) or a quarantine flag from macOS Gatekeeper.

**Fix 1 — Remove Gatekeeper quarantine:**

```sh
xattr -d com.apple.quarantine /path/to/KaguraObfuscator.dylib
```

**Fix 2 — Verify LLVM dylib linkage:**

```sh
otool -L /path/to/KaguraObfuscator.dylib
```

All `@rpath` entries must resolve.  If they do not, set `DYLD_LIBRARY_PATH`
to include the LLVM `lib` directory, or rebuild kagura with
`-DCMAKE_BUILD_RPATH=/opt/homebrew/opt/llvm/lib`.

---

### Crash in obfuscated code at runtime

**Cause:** Non-deterministic obfuscation (default `KAGURA_SEED=0`) can, in rare
cases involving complex CFG structures, produce code that crashes due to an
ordering bug in a pass.

**Fix 1 — Set a fixed seed to reproduce the crash:**

```xcconfig
KAGURA_SEED = 12345
```

Once the crash is reproducible with a fixed seed, bisect which pass is
responsible by disabling passes one at a time.

**Fix 2 — Exclude the crashing function:**

Add `__attribute__((annotate("kagura.skip")))` to the function that crashes and
file a bug report with the function's LLVM IR (`-emit-llvm -S`).

**Fix 3 — Reduce iteration counts:**

```xcconfig
KAGURA_BCF_ITER = 1
KAGURA_SUB_ITER = 1
```

Higher iteration counts increase the probability of exposing edge cases.

---

### Build is extremely slow

**Cause:** `-kagura-fla` and `-kagura-bcf` are O(n) in the number of basic
blocks and can be quadratic for very large functions (>1000 BB).

**Fix:** Annotate hot / large functions with `kagura.skip`, or reduce
`KAGURA_BCF_PROB` to 10–15.  See the [Performance Tuning](#performance-tuning)
table for a "Fastest build" configuration that still provides meaningful
protection.
