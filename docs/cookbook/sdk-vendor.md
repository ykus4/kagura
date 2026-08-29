# SDK / library vendor

Ship a `.a` / `.so` / `.dylib` that protects your proprietary algorithms from
extraction, **without requiring SDK consumers to change how they build their
app**. The integration must be transparent — your customer should still be
able to type `npm install` / `pod install` / `gradle build` and get a working
binary.

## Threat model

| Asset | Adversary | Capability |
|:------|:----------|:-----------|
| Proprietary algorithm (e.g. ML model weights, ranking logic, codec) | Competitor SDK vendors | Decompile your `.a` to extract the algorithm and re-implement |
| API authentication scheme | SDK consumers themselves | Strip your call-home, repackage as their own |
| License-key validation | End users of your customers' apps | Patch out the "is_licensed" check |
| Backdoor / debug paths | Security researchers | Find and publicly disclose internal debug entry points |

## Policy file

The SDK case is different from app cases: **you cannot crash on detection**
because your customer's app will crash. Soft responses only.

```json title="kagura-sdk-release.json"
{
  "profile": "STRONG",
  "passes": {
    "str_aes":    true,
    "wstr":       true,
    "co":         true,
    "fla":        true,
    "bcf":        true,
    "sub":        true,
    "mvo":        true,
    "pe":         true,
    "genc":       true,
    "sv":         true,
    "honey":      true,
    "ci":         true,
    "anti_debug": false,
    "tamper":     false,
    "bbcheck":    false
  },
  "tuning": {
    "bcf_prob": 60,
    "seed":     0
  }
}
```

The three `false` rows are the load-bearing part of this file, so spell them
`anti_debug` — with an underscore, matching the flag name `-kagura-anti-debug`
with `-` replaced by `_`. A key the loader does not recognise is ignored, and
`"profile": "STRONG"` turns AntiDebug **on**: an unnoticed typo here is how you
ship the aborting binary this whole page exists to avoid. Both spellings are
accepted since 0.3.0, and `-kagura-config-strict` fails the build on anything
the loader cannot act on — use it.

Disabled passes — and why:

- **`anti_debug` / `tamper`** — these can break legitimate consumer debugging
  workflows (Xcode debugger, Android Studio, crash reporters). Move those
  checks into a **user-opt-in** runtime API instead (see below).
- **`bbcheck`** — same reasoning; introduces aborts that your consumer can't
  predict.

## Build

`-kagura-vtp` has no policy-file key, so it goes on the command line:

```bash
# Compile your SDK with obfuscation; consumers link the result normally
clang -fpass-plugin=KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura-sdk-release.json \
      -mllvm -kagura-config-strict \
      -mllvm -kagura-vtp \
      -mllvm -kagura-sv \
      -mllvm -kagura-symmap \
      -mllvm -kagura-symmap-out=sdk-internal-symmap.json \
      -O2 -c sdk_core.c -o sdk_core.o

ar rcs libYourSDK.a sdk_core.o ...
# Or for shared library:
clang -shared -fpass-plugin=… -O2 sdk_core.c -o libYourSDK.dylib
```

Store `sdk-internal-symmap.json` **internally** — never ship it. Use it to
symbolicate customer-reported crash logs without giving the customer your
internal names.

## Symbol hygiene

`kagura-sv` hides everything that doesn't have explicit external linkage. Use
the export list pattern to make the public API tiny and explicit:

```c
// sdk_core.h — your public API
#if defined(_WIN32)
#  define YSDK_EXPORT __declspec(dllexport)
#else
#  define YSDK_EXPORT __attribute__((visibility("default")))
#endif

YSDK_EXPORT int  YSDK_Init(const char *license_key);
YSDK_EXPORT int  YSDK_Process(const uint8_t *in, size_t n, uint8_t **out);
YSDK_EXPORT void YSDK_Free(uint8_t *p);
```

Everything else (your ML weights, your ranking model, your codec internals)
is hidden.

## Soft anti-tamper API

Expose an **opt-in** integrity API so security-conscious consumers can choose
to enable it from their app:

```c
// public header
YSDK_EXPORT int YSDK_SelfCheck(void);   // returns 0 if intact, non-zero if tampered
```

```c
// in your SDK
#include "kagura/runtime.h"

int YSDK_SelfCheck(void) {
    if (kagura_suspicious_lib_loaded())                              return 1;
    if (kagura_check_sw_breakpoints() || kagura_check_hw_breakpoints()) return 2;
    if (kagura_check_inline_hooks()   || kagura_check_got_hooks())      return 3;
    return 0;
}
```

Call only the `int kagura_check_*()` **predicates** here. Their `void
kagura_*_check()` counterparts — `kagura_self_check()`,
`kagura_check_breakpoints()`, `kagura_check_hooks()` — invoke the tamper hook
themselves, which for an SDK means terminating inside your customer's app.
They also return nothing, so `if (kagura_self_check() != 0)` does not even
compile against `kagura/runtime.h`; it only appeared to work when the symbol
was declared by hand.

The consumer's app decides what to do with the result (refuse to issue
licensed operations, send telemetry, etc.) — your SDK does **not** crash.

If you want a graduated response rather than a boolean, the runtime ships one:
accumulate with `kagura_soft_response_add()` and read
`kagura_soft_response_level()` (`KAGURA_RESPONSE_OK` … `KAGURA_RESPONSE_KICK`).

## Per-customer variants

Use `scripts/cli/variant_generator.py` to produce a different XOR key set per
customer. If customer A's binary leaks, attackers can't reuse the key
extraction against customer B:

```bash
python3 scripts/cli/variant_generator.py \
    --config kagura-sdk-release.json \
    --customer-id ACME-CORP \
    --out kagura-acme.json

clang -fpass-plugin=KaguraObfuscator.dylib \
      -mllvm -kagura-config=kagura-acme.json \
      -O2 -c sdk_core.c -o sdk_core_acme.o
```

## Verification

```bash
# 1. Public API is the entire export set
nm -gU libYourSDK.dylib | grep ' T '
# Should show exactly the YSDK_* symbols, nothing else

# 2. No internal class names leak
strings libYourSDK.dylib | grep -E "MyRankingModel|InternalCodec|DebugMode"
# Should be empty

# 3. C++ RTTI is obfuscated (kagura-vtp)
strings libYourSDK.dylib | grep "_ZTS"
# Type names should be unreadable

# 4. Linkable from a clean consumer project
mkdir consumer-test && cd consumer-test
cat > main.c << 'EOF'
#include "sdk_core.h"
int main(void) { return YSDK_Init("test"); }
EOF
clang main.c ../libYourSDK.dylib -o test
./test
```

## What's still on you

- **Don't ship a free trial mode in the same binary** as the paid build.
  Per-tier feature flags compiled into one binary are trivial to flip with
  `kagura-honey`-defeating decompilers. Build separate binaries.
- **License validation that can't be patched** is impossible client-side —
  use a **server callback** that fails gracefully offline, not a pure
  client-side bit flip.
- **Customer can still wrap your SDK in another SDK and steal credit.**
  That's a legal / contractual problem; technical measures are limited.
