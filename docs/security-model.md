# Security Model

Kagura is one layer of a defense-in-depth strategy. This page is explicit about
**what it protects, what it does not, and what assumptions break it**, so you
can decide where Kagura fits in your threat model and where you still need
other controls.

---

## What Kagura is for

Kagura raises the cost of reverse engineering native code that ships to
adversarial environments — anti-cheat in games, key material in banking /
DRM apps, proprietary algorithms in SDKs. It does this entirely at the
**LLVM IR level**, before any architecture-specific code generation, so every
protection applies across iOS, Android, macOS, Windows, Linux, and WebAssembly
from a single build step.

## Threat model

The model below uses [STRIDE](https://en.wikipedia.org/wiki/STRIDE_model)
categories, but only the ones Kagura actually addresses. Tampering and
Information Disclosure are the primary categories; the others are out of scope
or partially covered.

| Category | Adversary capability | Kagura coverage |
|:---------|:---------------------|:----------------|
| **Information Disclosure** | Static binary analysis (strings, IDA, Ghidra, Binary Ninja) | ✅ Strong — string encryption, CFG flattening, MBA, symbol hiding, RTTI obfuscation, DWARF strip |
| **Information Disclosure** | Live memory inspection (Cheat Engine, GameGuardian, /proc/maps) | ✅ Strong — MVO/PE encrypt values at every store, `Protected<T>` adds shadow-copy detection |
| **Tampering** | Binary patching (NOP-ing checks, replacing instructions) | ⚠️ Partial — `kagura-tamper` hashes whole functions at startup. `kagura-bbcheck` is scaffolding only: it emits per-block call sites, but the shipped `kagura_bb_check` always returns "intact" — see [below](#binary-patching-what-kagura-bbcheck-actually-does) |
| **Tampering** | Loader hooking (Frida, Substrate, fishhook) | ✅ Medium — runtime detection probes for hook frameworks, suspicious dylib / .so scan |
| **Tampering** | Debugger attach (ptrace, lldb, WinDbg) | ✅ Medium — `kagura-anti-debug` covers ptrace, IsDebuggerPresent, PEB heap flags, Frida ports |
| **Information Disclosure** | Symbolic / concolic execution (angr, KLEE, S2E) | ⚠️ Partial — `kagura-fla` + `kagura-bcf` + `kagura-co` raise path explosion; see `tests/symbolic_exec/` for measurements |
| **Information Disclosure** | LLM-assisted decompilation | ⚠️ Partial — name stripping helps; MBA hurts readability but is not a hard barrier |
| **Repudiation** | Crash attribution / forensic logging | 🟡 Out of scope — use platform crash reporters, optionally enable `-kagura-symmap` for offline symbolication |
| **Denial of Service** | Targeted crashes | 🟡 Out of scope |
| **Elevation of Privilege** | Sandbox escape, kernel exploitation | 🟡 Out of scope |

✅ Strong = direct, well-tested coverage.
⚠️ Partial = raises cost; not a hard guarantee.
🟡 Out of scope = use other tooling.

---

## What Kagura does **not** protect

Be explicit about the boundaries — these are real and need other controls.

### Binary patching: what `kagura-bbcheck` actually does
`-kagura-bbcheck` emits a `kagura_bb_check(block_id, expected)` call at the top
of each basic block and branches to the tamper hook when it returns zero. The
shipped `kagura_bb_check` (`runtime/core/bb_check.c`) is a **weak,
always-passing stub**: it ignores both arguments and returns "intact". As
shipped, the pass detects no patching at all — you get the call sites and the
code-size cost, and nothing else.

The stub is honest rather than unfinished. `expected` is a hash of the block's
**LLVM IR opcodes**, computed before instruction selection, and IR opcodes have
no representation in the emitted binary; `block_id` restarts at 1 in every
function, so it is not a unique key. There is nothing at run time to verify
against. Making the pass real requires emitting post-codegen byte ranges into a
table the runtime can walk, which is not implemented.

For anti-patching today, use **`-kagura-tamper`**: it hashes loaded functions
and calls `kagura_runtime_hash_check` / `kagura_self_check`, which do work.
Note the assumption in [Pass order is
preserved](#2-the-pass-order-is-preserved) — checksums are taken at a specific
point in the pipeline.

### Plaintext server-side secrets
Anything decrypted at runtime is plaintext **in registers and memory** for the
duration of its use. Kagura minimizes the window (`kagura-str`'s decrypt-zero
loop) but cannot eliminate it. **Sensitive secrets that must survive a memory
dump belong server-side**, not in the client binary.

### Cryptographic primitives
Kagura encrypts string literals and values for **obscurity**, not
confidentiality against a determined adversary with debugger access. The AES
key used by `kagura-str-aes` is derived from build metadata; an attacker who
extracts the key once can decrypt all subsequent strings in the same build.
Use `-kagura-build-id=<sha>` to rotate keys per release, but recognize this
defeats *batch* extraction, not *single-binary* extraction.

### Side channels
Cache timing, EM emanation, power analysis, speculative execution, and
hardware-level attacks are **not** in scope. If you're shipping crypto on a
device adversaries physically control, use a hardware-backed keystore (SE,
StrongBox, Secure Enclave).

### Determined adversaries with unlimited time
Kagura raises the cost in **analyst-hours**. A well-resourced adversary will
eventually deobfuscate everything. The goal is to move the bar above your
target attacker's economic threshold — measured for your use case via
`scripts/eval/attacker_cost_model.py` and the angr / Ghidra / Frida resistance
suites under `tests/`.

### Side-effects from the operating system
- iOS Keychain reads / Android Keystore calls bypass IR-level protections —
  use the platform key store for keys that must persist.
- TrustZone / SGX / SEV protections are higher-assurance and orthogonal.
- The OS loader still sees your imports — `kagura-ci` helps, but cannot hide
  all `dlopen` / `LoadLibrary` calls.

---

## Assumptions Kagura relies on

These are the assumptions that, when violated, weaken Kagura's protections.

### 1. The plugin is loaded for every translation unit
If a single source file in the build is compiled without `-fpass-plugin=…`,
its strings and CFG are plaintext. Build-system integration matters — see
[Integration](integration/index.md) and audit the build with
`scripts/cli/kagura-cli.py audit-log` or `-kagura-audit`.

### 2. The pass order is preserved
`kagura-tamper` measures function checksums **before** CFG-mutating passes
run. If a third-party LLVM pass inserts itself between them, the checksums
become wrong. See [Pass Order](pass-order.md). Run `verify-reproducible.sh`
to confirm a fixed seed still produces identical IR.

### 3. The runtime library is linked
`kagura-str-aes`, `kagura-anti-debug`, `kagura-tamper`, `kagura-pac`,
`kagura-vm`, `kagura-ci`, `kagura-bbcheck`, `kagura-telemetry`, `kagura-objc`
and `kagura-jni` all call symbols they do not define — see [Runtime
Library](runtime.md) for the exact matrix. A missing link results in undefined
symbols at load time, which surfaces the problem early, but also means missing
the runtime means missing the protection.

Two of those symbols are weak no-ops on purpose (`kagura_bb_check`,
`kagura_telemetry_event`), so those two passes link *and* do nothing until you
supply an implementation. Linking successfully is not evidence that a
protection is active.

### 4. Reproducibility is honored
Setting `-kagura-seed=0` (entropy default) produces a different binary each
build. Forensically that's good (per-binary watermarking is implicit), but it
also means **per-build variant generation is on you** — use
`scripts/cli/variant_generator.py` if you ship per-customer variants.

### 5. Anti-tamper response is sensible
`kagura-tamper`'s default response is `abort()`, which gives a clean crash
attribution point. For shipping apps, replace with `setTamperCallback()` (see
[Game Protection](game-protection.md)) to do soft response — random delays,
poisoned data, or telemetry — making the detection point itself harder to
locate via differential debugging.

---

## How to evaluate coverage

Kagura ships measurement tools that let you quantify protection on your
binary, not just trust marketing claims.

| Tool | Question it answers |
|:-----|:--------------------|
| `scripts/eval/attacker_cost_model.py`  | "How many analyst-hours does this configuration cost an attacker?" |
| `tests/symbolic_exec/run_angr_eval.py` | "Does my binary survive 30-minute angr concolic execution?" |
| `tests/decompiler_eval/run_ghidra_eval.py` | "Does Ghidra reconstruct readable C from my binary?" |
| `tests/frida_resistance/` | "Are my hook / breakpoint / debugger probes catching the F1–F8 Frida vectors?" |
| `scripts/cli/review-risk-assessment.sh` | "Will the App Store / Play Store reject my binary for the protections I added?" |
| `scripts/cli/kagura-diff.py` | "Did my release build actually hide the symbols and encrypt the strings it was supposed to?" |

Run these on **your own representative builds**. The numbers in
[Performance & Size Impact](passes/performance.md) are illustrative; the only
numbers that matter for your project are the ones you measure on your code.

---

## Recommended layering

Kagura should be **one layer** in your stack. A realistic mobile / banking /
DRM deployment looks roughly like:

1. **Server-side authority** — anything that must not be tampered with
   (entitlements, currency totals, license validity) is authoritative on the
   server, not the client.
2. **Platform key stores** — Apple Keychain / Secure Enclave, Android
   Keystore / StrongBox for keys that must persist across runs.
3. **Platform attestation** — Apple DeviceCheck / App Attest, Android Play
   Integrity for "this device looks legit". (See
   [Integration](integration/index.md) for build-system wiring; SDK adapters
   live under `runtime/ios/` and `runtime/android/`.)
4. **Kagura compile-time obfuscation + runtime checks** — the layer this
   project covers.
5. **Application-level checks** — rate limits, anomaly detection, server-side
   replay protection.
6. **Operational telemetry** — `kagura-telemetry` events flowing to your SOC
   so you can react to detection signals at population scale.

Removing any one layer weakens the whole stack. Kagura by itself is not a
security product; it's a **building block** that makes the other layers
harder to attack.
