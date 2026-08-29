# Banking / FinTech

Protect transaction-signing keys, certificate pins, and authentication flows
against on-device analysis. The goal isn't perfect secrecy — that belongs
server-side — it's raising attacker cost above the economic threshold for
fraud-scale automation.

## Threat model

| Asset | Adversary | Capability |
|:------|:----------|:-----------|
| HMAC / signing keys | Mobile malware, rooted-device fraud rings | Static extraction, memory dump |
| Certificate pin list | MITM proxies (mitmproxy, Charles, Burp) | Static string search, runtime patching |
| Anti-fraud heuristics | Reverse engineers building bypass kits | Decompile + write a generator that mimics legitimate traffic |
| Session token handling | Frida / Substrate scripts | Hook the request signer to log tokens |

See [Security Model](../security-model.md) for what Kagura can and cannot do
in this scenario. Spoiler: this is **defense in depth** — Kagura is one layer.

## Policy file

```json title="kagura-bank.json"
{
  "profile": "STRONG",
  "passes": {
    "str_aes":    true,
    "wstr":       true,
    "mvo":        true,
    "pe":         true,
    "co":         true,
    "fla":        true,
    "bcf":        true,
    "sub":        true,
    "bbcheck":    true,
    "tamper":     true,
    "anti_debug": true,
    "ci":         true,
    "sv":         true,
    "honey":      true
  },
  "tuning": {
    "bcf_prob": 60,
    "seed":     0
  }
}
```

Why these choices:

- **`str_aes` + `wstr`** — encrypt all string literals (Swift `String`,
  Objective-C `@""`, Kotlin / Java string constants pulled into JNI) so
  `strings` returns nothing useful
- **`mvo` + `pe`** — on-stack key buffers and pointers stay XOR-encrypted at
  every store/load, even after the function uses them
- **`co` + `sub`** — break MBA pattern matchers (de4dot, FLOSS) on inline
  constants
- **`fla` + `bcf`** with `bcf_prob: 60` — defeats Ghidra's CFG view in
  decompiler-resistant builds
- **`tamper`** — catches binary patching by hashing the loaded text section
- **`bbcheck`** — emits a per-basic-block checksum call site. It only detects
  anything once you supply your own `kagura_bb_check`; the shipped one is a
  weak always-pass stub. See [Anti-Analysis
  Passes](../passes/anti-analysis.md).
- **`anti_debug`** — drops the obvious "Cheat Engine attached as debugger"
  attacks
- **`ci`** — hides imports from IDA's Import View
- **`sv`** — strips non-public symbols so the dynamic symtab doesn't leak
  internal names
- **`honey`** — injects decoy globals (`g_api_key_v2`, etc.) and fake stubs

## Build

```bash
# Per-release key rotation: a key extracted from v1 doesn't decrypt v2 strings
clang -fpass-plugin=KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura-bank.json \
      -mllvm -kagura-build-id=$(git rev-parse HEAD) \
      -mllvm -kagura-symmap \
      -mllvm -kagura-symmap-out=bank-symmap-$(git describe).json \
      -O2 -c bank_core.c -o bank_core.o
```

Keep the `bank-symmap-<release>.json` files **off-device** — they let you
symbolicate crash reports without shipping debug symbols.

## Source-side annotations

Mark the highest-value functions for VM virtualization:

```c
#include "kagura/runtime.h"

// Sign a transaction request. Worth the 10–50× VM overhead — called once per
// payment, but a 100% guarantee that this code is never readable as
// native instructions.
__attribute__((annotate("kagura_vm")))
int sign_transaction(const uint8_t *payload, size_t len, uint8_t out[64]) {
    // ... HMAC-SHA256 implementation
}

// Hot path — keep BALANCED-equivalent. Don't VM this.
__attribute__((annotate("kagura_nofla")))
int validate_amount(int64_t amount) { return amount > 0 && amount < 1e9; }
```

## Runtime hardening

In your application's startup path:

```c
#include "kagura/runtime.h"

int app_init(void) {
    // 1. Refuse to run on a tampered binary.
    //    kagura_macho_tampered() is the predicate. Its response-shaped sibling
    //    kagura_self_check() returns void and calls the tamper hook itself,
    //    which is the opposite of what we want here: we want to soft-respond
    //    so the detection point isn't a tombstone an attacker can grep for in
    //    /var/mobile/Library/Logs.
    if (kagura_macho_tampered()) {
        return -1;
    }

    // 2. Refuse to run with Frida / Substrate loaded
    if (kagura_suspicious_lib_loaded()) {
        return -1;
    }

    // 3. Refuse to run on jailbroken / rooted devices for payment flows.
    //    (Use feature-gated UX; do not crash the app for non-payment flows.)
#if defined(__APPLE__)
    if (kagura_jailbreak_detected()) {
#elif defined(__ANDROID__)
    if (kagura_magisk_present() || kagura_xposed_present()) {
#else
    if (0) {
#endif
        // Disable payment UI; show a "not supported on this device" screen.
    }

    return 0;
}
```

Every name above comes from `kagura/runtime.h`. Do not hand-write `extern`
declarations for them: a misspelling then links against nothing (or, if you
mark it weak, silently evaluates to false) and the guard disappears without a
word. `runtime/ios/device_attest.c` carries a comment about the time that
happened to four checks at once.

## Verification

Before shipping, run all of:

```bash
# 1. No plaintext API keys in the binary
strings YourApp.app/YourApp | grep -iE "api_key|hmac|secret"
# Should return nothing.

# 2. No readable signing logic
ghidra YourApp.app/YourApp     # then run the Ghidra eval suite
cd tests/decompiler_eval && python3 run_ghidra_eval.py \
    --binary YourApp.app/YourApp --ghidra /path/to/ghidra

# 3. Frida resistance
cd tests/frida_resistance
for s in probes/F*.js; do frida -l "$s" -f YourApp.app/YourApp; done

# 4. App Store review risk assessment
./scripts/cli/review-risk-assessment.sh YourApp.app/YourApp --platform ios

# 5. Confirm the release build actually obfuscated what you asked for
./scripts/cli/kagura-diff.py baseline.dylib release.dylib --html report.html
```

## What's still on you

Kagura cannot:

- Protect a key that **must** survive a memory dump — put it in the
  platform keystore (Keychain / Android Keystore / SE / StrongBox)
- Make rooted / jailbroken devices safe for high-value transactions —
  combine with Apple DeviceCheck / App Attest or Android Play Integrity
- Replace server-side fraud detection — Kagura raises client-side cost; the
  server still needs to detect anomalous patterns

See [Security Model](../security-model.md) for the full boundary.
