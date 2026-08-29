# DRM / license enforcement

Hide license-check logic so it's never readable as native code, even under
a debugger. This is the classic anti-piracy use case — your goal is to make
"crack the check" cost more than the price of a legitimate license.

## Threat model

| Asset | Adversary | Capability |
|:------|:----------|:-----------|
| License-validation function | Crackers | Decompile → find the `return 0` patch site |
| Trial-period timer | End users | Roll back the system clock, NOP the date check |
| Key-derivation function | Keygen authors | Reverse the algorithm, build a keygen |
| Server-callback URL | Re-distribution sites | Replace with a mock server that always returns "licensed" |

This is one of the **best-fit scenarios** for Kagura — license checks are
cold paths, called once or twice per session, so the 10–50× VM slowdown is
invisible to the user.

## Policy file

```json title="kagura-drm.json"
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
    "ci":         true,
    "sv":         true,
    "honey":      true,
    "bbcheck":    true,
    "tamper":     true,
    "anti_debug": true
  },
  "tuning": {
    "bcf_prob": 60,
    "seed":     0
  }
}
```

Everything STRONG plus `bbcheck` + `tamper` because:

- A DRM binary's most common attack is `bsdiff` patching ("set `eax, 0`")
- `tamper` catches whole-function modification at startup
- `bbcheck` puts a per-basic-block checksum call site next to every branch —
  but you have to write the `kagura_bb_check` that decides whether a checksum
  is correct. The shipped one is a weak always-passing stub, so until you
  override it this row costs you code size and detects nothing. See
  [Anti-Analysis Passes](../passes/anti-analysis.md).

## Virtualize the license check

This is the **key recipe** for DRM. Any function annotated with
`kagura_vm` is compiled to a custom stack-based VM bytecode and removed
from the binary as native code — the attacker sees an interpreter loop, not
your algorithm.

```c
#include "kagura/runtime.h"

// The crown jewel — compiled to VM bytecode. The attacker who decompiles
// the binary sees: opaque byte array + interpreter call.  They have to
// reverse the *interpreter* (not your function) before they can even start
// reversing your function.
__attribute__((annotate("kagura_vm")))
int verify_license(const char *key, time_t now, uint64_t *out_expiry) {
    // 1. Parse the license token format
    if (!key || !*key) return -1;

    // 2. HMAC the device fingerprint
    uint8_t digest[32];
    hmac_sha256(device_fingerprint(), 16, key, strlen(key), digest);

    // 3. Compare against the embedded public key signature
    if (!ed25519_verify(digest, signature_from(key), public_key)) {
        return -1;
    }

    // 4. Extract expiry, validate not-in-future-not-in-past
    uint64_t exp = expiry_from(key);
    if (now > exp) return -1;
    if (now < embedded_min_timestamp()) return -1;  // anti-rollback

    *out_expiry = exp;
    return 0;
}

// Also virtualize the trial-period check
__attribute__((annotate("kagura_vm")))
int check_trial_period(time_t install_date, time_t now) {
    return (now - install_date) < (30 * 86400) ? 0 : -1;
}
```

Other functions stay native (BALANCED+obfuscation only) — VM-virtualizing
hot paths kills performance.

## Anti-rollback for trial periods

System-clock manipulation is the easiest piracy method. Defenses (combine
several):

```c
// 1. Embed a monotonic "build timestamp" — the current time must be ≥ this
__attribute__((annotate("kagura_vm")))
time_t embedded_min_timestamp(void) {
    return BUILD_TIMESTAMP;  // injected at build time via -DBUILD_TIMESTAMP=…
}

// 2. Keep a hidden "last seen" file (write XOR-encrypted bytes to a path
//    the user doesn't easily find)
__attribute__((annotate("kagura_vm")))
time_t last_seen_timestamp(void) {
    // read from ~/Library/.cache/.system_state (macOS)
    // or  /var/data/data/<app>/cache/.sys (Android)
    // XOR-decrypted with a per-install key derived from device_fingerprint()
}

// 3. Detect rollback: now < max(last_seen, build_min)
if (now < max(last_seen_timestamp(), embedded_min_timestamp())) {
    return -1;  // clock rollback attempt
}
```

## Soft response

Crashing on detection is bad — users with corrupted disks / weird system
clocks file support tickets. Instead, **silently degrade**:

```c
#include "kagura/runtime.h"

int app_startup(void) {
    // Predicates, not the void kagura_*_check() responses: those invoke the
    // tamper hook themselves, and "crash on detection" is exactly what this
    // section is arguing against.
    //
    // The image-integrity check is per-loader-format, so it is per-platform:
    // macho_integrity.c only builds on Apple, elf_integrity.c only on
    // Linux/Android. Calling the wrong one is a link error, not a silent
    // no-op.
#if defined(__APPLE__)
    if (kagura_macho_tampered()) {
#elif defined(__unix__)
    if (kagura_elf_tampered()) {
#else
    if (0) {
#endif
        // Don't crash. Just go into "limited" mode:
        //   - Save to disk every 30s with a 50% chance of "I/O error"
        //   - Random 200ms hitches every 10s
        //   - Some menu items mysteriously do nothing
        g_app_mode = APP_MODE_LIMITED;
        return 0;
    }

    if (kagura_check_sw_breakpoints() || kagura_check_hw_breakpoints()) {
        // Debug-attached. Don't crash, but compute results from a poisoned
        // RNG so a cracker's "step through and see what happens" session
        // produces nondeterministic garbage.
        seed_rng_with_poison();
    }

    return 0;
}
```

## Verification

```bash
# 1. verify_license() is gone as native code
otool -tv YourApp | grep -A50 "_verify_license"
# Should be empty or just a thunk into the VM interpreter

# 2. No plaintext license format strings
strings YourApp | grep -iE "license|expired|trial"
# Should be empty

# 3. Patching the obvious "return 0" sites doesn't bypass anything
#    (Use the angr suite — it's the closest automated equivalent of a
#     determined cracker.)
cd tests/symbolic_exec && python3 run_angr_eval.py \
    --binary YourApp --timeout 600 --target verify_license

# 4. Frida script that tries to hook verify_license() finds nothing
cat > frida_hook.js << 'EOF'
Interceptor.attach(Module.findExportByName(null, "verify_license"), {
    onEnter(args) { console.log("verify_license called"); },
    onLeave(retval) { retval.replace(0); }  // force "licensed"
});
EOF
frida -l frida_hook.js -f YourApp
# Should print "Module.findExportByName: cannot find verify_license"
# because kagura-sv hid the symbol
```

## What's still on you

- **A skilled cracker with two weeks** will get through. The goal is **deter
  casual cracking** and **slow professional cracking enough that a release
  cycle ships before the crack does**.
- **Server-side license validation** is strictly better than client-side.
  Even one server callback per session (silently failing offline for legit
  users) breaks most pirate distribution.
- **DMCA / legal action** against re-distribution sites is the only
  enforcement that scales. Technical measures are deterrents, not stops.
- **No DRM is invisible.** If your app needs to load license-checked
  content, the content is loaded somewhere. Plan for that.
