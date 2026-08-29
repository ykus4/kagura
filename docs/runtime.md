# Runtime Library

Some passes emit calls to symbols they do not define. Those targets require
linking `libkagura_runtime.a` (built at `build/runtime/libkagura_runtime.a`):

| Pass | Flag | Symbols it calls but does not define |
|:-----|:-----|:-------------------------------------|
| StringEncryptionAES | `-kagura-str-aes` | `kagura_aes128_ctr_decrypt`, `kagura_check_blob_integrity` |
| VMObfuscation | `-kagura-vm` | `kagura_vm_execute` |
| AntiDebug | `-kagura-anti-debug` | `kagura_check_tracer_pid`, `kagura_check_inline_hooks`, `kagura_check_got_hooks`, `kagura_check_sw_breakpoints`, `kagura_check_hw_breakpoints`, `kagura_check_emulator` |
| AntiTamper | `-kagura-tamper` | `kagura_self_check`, `kagura_tamper_detected`, `kagura_runtime_hash_check` |
| BasicBlockChecksum | `-kagura-bbcheck` | `kagura_bb_check`, `kagura_on_tamper_detected` |
| Telemetry | `-kagura-telemetry` | `kagura_telemetry_event` |
| CallIndirection | `-kagura-ci` | `kagura_rtld_default_handle`, plus `dlsym` from the system |
| PointerAuth | `-kagura-pac` | `kagura_random_u64` |
| JNIObfuscation | `-kagura-jni` | `kagura_jni_get_env`, `kagura_jni_find_class`, `kagura_jni_register_native` |
| ObjCObfuscation | `-kagura-objc` | `kagura_objc_register_remap` |

Two names that look like they belong in that table do not, because the pass
**defines** them rather than importing them: `kagura_anti_debug_init` (the
module constructor AntiDebug builds) and `kagura_on_tamper_detected` (AntiDebug
emits a weak default that calls `abort()`; override it to choose your own
response). Every other pass — the string, control-flow and data passes —
generates self-contained code and needs no runtime at all.

```bash
clang your_file.c build/runtime/libkagura_runtime.a -o your_file
```

## Directly callable API

`include/kagura/runtime.h` is the public subset of the runtime: the detectors
you can call yourself, the hooks you can override, and the protected value
types.

```c
#include "kagura/runtime.h"

if (kagura_suspicious_lib_loaded())   { /* Frida gadget, Substrate, … */ }
if (kagura_check_tracer_pid())        { /* ptrace / debugger attached */ }
if (kagura_check_sw_breakpoints())    { /* int3 / BRK patched into code */ }
if (kagura_jailbreak_detected())      { /* Apple targets */ }
if (kagura_magisk_present())          { /* Android targets */ }
```

Use these from your `main()` (mobile apps) or your DLL `DllMain` (Windows) to
get the same defense without going through pass-injected init code — useful in
projects where you want explicit control over when checks fire.

### Predicates versus responses

Two shapes exist and they are not interchangeable:

| Shape | Returns | Behaviour |
|:------|:--------|:----------|
| `int kagura_check_*(void)` | nonzero == detected | Reports. Does nothing else. |
| `void kagura_*_check(void)` | nothing | Runs the predicates *and* invokes the tamper hook on a hit. |

`kagura_self_check()`, `kagura_check_hooks()` and `kagura_check_breakpoints()`
are in the second group despite their names, so `if (kagura_self_check() != 0)`
does not compile against this header. It used to appear to work when callers
hand-wrote their own `extern int` declaration — and then branched on a garbage
register. `runtime/ios/device_attest.c` documents the same failure hitting four
symbols at once, which is the reason this header exists.

Always `#include "kagura/runtime.h"` instead of declaring these by hand.

## Platform attestation API

Thin C bindings for the major platform attestation services. The C side
generates nonces and runs fast local pre-screens; the async signed-token
round-trip is wired up from your Swift / Kotlin code.

### Apple — DeviceCheck / App Attest (`runtime/ios/device_attest.c`)

```c
int kagura_devicecheck_available(void);     // iOS 11+, macOS 10.15+
int kagura_appattest_available(void);       // iOS 14+, A10+ hardware

int kagura_appattest_nonce(uint8_t *out, size_t len);
int kagura_appattest_local_check(void);     // fast (<5ms) env screen
```

Swift bridge example:

```swift
import DeviceCheck
let service = DCAppAttestService.shared
if service.isSupported && kagura_appattest_local_check() == 1 {
    var nonce = Data(count: 32)
    _ = nonce.withUnsafeMutableBytes { kagura_appattest_nonce($0.baseAddress, 32) }
    service.generateKey { keyId, err in /* server-side verification */ }
}
```

### Android — Play Integrity (`runtime/android/play_integrity.c`)

```c
void kagura_play_integrity_nonce(char *out_hex32, size_t len);
int  kagura_play_integrity_verdict_ok(const char *jwt_payload_b64url);
int  kagura_play_integrity_local_check(void);
```

The full JWT signature must be verified server-side — `verdict_ok` is a
**local fast-path**, not a security boundary. See the file header comment
for the Kotlin caller skeleton.

### Windows — ETW analysis-tool detection (`runtime/windows/etw_detection.c`)

```c
int kagura_etw_provider_present(const wchar_t *provider_guid);
int kagura_etw_analysis_tool_check(void);   // checks Cheat Engine / Procmon / etc.
```

This module ships as a **stub** by default. Build with `-DKAGURA_ETW_FULL=1`
and link `tdh.lib` to enable the real `TdhEnumerateProviders`-based
enumeration — see the file's header comment for the implementation outline.

## Source layout

```
runtime/
├── core/         AES, VM interpreter, crash symbolication, device key
├── anti_debug/   Cross-platform POSIX anti-debug / anti-Frida
├── android/      Root detection, attestation, /proc, syscall probes (Android + Linux)
├── ios/          Jailbreak detection, Mach-O integrity (iOS + macOS)
├── windows/      IsDebuggerPresent, NtQueryInformationProcess, PE integrity
└── game/         Anti-cheat, IL2CPP protection, telemetry
```
