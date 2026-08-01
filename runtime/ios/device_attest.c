/*===-- runtime/ios/device_attest.c - DeviceCheck / App Attest binding ----===
 *
 * Apple platform device-attestation bindings:
 *
 *   - DeviceCheck (iOS 11+): two persistent bits per device, set/read via
 *     Apple-signed RPC. Server-side counterpart can detect fresh-install
 *     fraud across reinstalls.
 *
 *   - App Attest (iOS 14+): hardware-backed attestation that **this app on
 *     this device** is genuine. The Secure Enclave generates a key pair;
 *     Apple signs the public key attestation; your server verifies it.
 *
 * This file exposes a thin C API so callers (Swift / ObjC / portable C code
 * driving the runtime) can request tokens. The async Foundation/CoreFoundation
 * round-trip is wrapped at the JNI-equivalent boundary in Swift/ObjC; the
 * C functions here are synchronous helpers used by the Swift bridge.
 *
 * Public API
 * ----------
 *   int  kagura_devicecheck_available(void);
 *       — 1 if running on a device that supports DeviceCheck (iOS 11+)
 *
 *   int  kagura_appattest_available(void);
 *       — 1 if running on a device that supports App Attest (iOS 14+, A10+)
 *
 *   int  kagura_appattest_nonce(uint8_t *out, size_t len);
 *       — generate a per-request challenge nonce (>=16 bytes recommended)
 *
 *   int  kagura_appattest_local_check(void);
 *       — fast environment pre-screen (jailbreak / debugger / TestFlight on
 *         a release build, etc.) — runs before the async App Attest request
 *
 * The Swift bridge (provided separately) calls these from:
 *
 *   import DeviceCheck
 *   let service = DCAppAttestService.shared
 *   if service.isSupported {
 *       var nonce = Data(count: 32)
 *       _ = nonce.withUnsafeMutableBytes { kagura_appattest_nonce($0.baseAddress, 32) }
 *       service.generateKey { keyId, err in ... }
 *       service.attestKey(keyId, clientDataHash: hash) { attestation, err in
 *           // POST attestation to your server for Apple verification
 *       }
 *   }
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#if defined(__APPLE__) && defined(__OBJC__)
/* When compiled as Objective-C, we can introspect the Foundation runtime. */
#  define KAGURA_APPLE_RUNTIME 1
#elif defined(__APPLE__)
#  define KAGURA_APPLE_RUNTIME 0
#endif

#ifdef __APPLE__

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <Availability.h>

/* ---- Availability ------------------------------------------------------- */

int kagura_devicecheck_available(void) {
    /* DeviceCheck is iOS 11+, macOS 10.15+, tvOS 11+, watchOS 9+ (no API
     * on Mac Catalyst before 13.4). Compile-time gate the obvious cases. */
#if defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && \
        __IPHONE_OS_VERSION_MIN_REQUIRED >= 110000
    return 1;
#elif defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && \
        __MAC_OS_X_VERSION_MIN_REQUIRED >= 101500
    return 1;
#else
    return 0;
#endif
}

int kagura_appattest_available(void) {
    /* App Attest is iOS 14+, requires A10 or newer hardware. The hardware
     * gate cannot be answered from C — caller must inspect
     * `DCAppAttestService.shared.isSupported` from Swift/ObjC and pass the
     * result down. The function below answers the API-availability gate. */
#if defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && \
        __IPHONE_OS_VERSION_MIN_REQUIRED >= 140000
    return 1;
#else
    return 0;
#endif
}

/* ---- Nonce generation --------------------------------------------------- */

/*
 * kagura_appattest_nonce — fill `out[0..len)` with a fresh challenge nonce.
 *
 * The nonce is used as the `clientDataHash` input to `attestKey:` /
 * `generateAssertion:`. Apple recommends a fresh, server-provided value per
 * request; this local-mix nonce is a fallback when offline.
 *
 * Returns: number of bytes written, or 0 on bad inputs.
 *
 * Sourcing: arc4random(3) + clock_gettime + a per-call counter.
 */
int kagura_appattest_nonce(uint8_t *out, size_t len) {
    if (!out || len == 0) return 0;
    if (len > 256) len = 256;

    /* Mix three sources so we don't depend on any one of them being random
     * enough. arc4random_buf is the standard libc CSPRNG on Apple platforms. */
    extern void arc4random_buf(void *, size_t);
    arc4random_buf(out, len);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    static uint64_t counter = 0;
    uint64_t mix = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    mix ^= __atomic_fetch_add(&counter, 1, __ATOMIC_RELAXED);
    mix ^= (uintptr_t)out;

    /* XOR the mix into the first 8 bytes so even if arc4random_buf were
     * pathological, callers still get *some* per-request entropy. */
    for (size_t i = 0; i < 8 && i < len; ++i) {
        out[i] ^= (uint8_t)(mix >> (i * 8));
    }
    return (int)len;
}

/* ---- Local pre-screen --------------------------------------------------- */

/*
 * kagura_appattest_local_check — fast (<5ms) environment screening that
 * runs before the async App Attest request.
 *
 * Returns 1 if the environment looks clean, 0 if suspicious. NOT a
 * replacement for App Attest — App Attest is the authoritative answer; this
 * is just a fast-path that lets the client refuse obviously bad environments
 * without waiting for the network round-trip.
 *
 * This function used to be dead code.  It called four symbols that were
 * declared weak here and never defined anywhere under those names:
 *
 *   kagura_check_loaded_libraries -> real name kagura_suspicious_lib_loaded
 *   kagura_testflight_detect      -> real name kagura_is_testflight
 *   kagura_macho_integrity_check  -> real name kagura_macho_tampered
 *   kagura_check_breakpoints      -> exists, but returns void and invokes
 *                                    the tamper hook itself
 *
 * Every weak pointer was therefore NULL, every guard short-circuited, and the
 * function unconditionally returned 1 - "environment is clean".  The names now
 * come from internal.h, so a future rename breaks the build instead of
 * silently disabling the screen.
 */
int kagura_appattest_local_check(void) {
    /* Frida / Substrate / fishhook injection */
    if (kagura_suspicious_lib_loaded())
        return 0;

    /* Hardware / software breakpoint surface.  Deliberately NOT
     * kagura_check_breakpoints(): that is the response path and terminates the
     * process, which is far too blunt for a pre-flight screen. */
    if (kagura_check_sw_breakpoints() || kagura_check_hw_breakpoints())
        return 0;

    /* TestFlight build masquerading as an App Store release?  Most apps want
     * to allow TestFlight here, so this stays informational and does not
     * fail the screen.  Callers that care should call kagura_is_testflight()
     * themselves. */
    (void)kagura_is_testflight();

    /* Mach-O integrity: a tampered binary should never get past App Attest
     * anyway, but rejecting here saves an Apple-side round-trip. */
    if (kagura_macho_tampered())
        return 0;

    return 1;
}

#endif /* __APPLE__ */
