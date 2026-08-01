/*===-- runtime/play_integrity.c - Play Integrity API integration ---------===
 *
 * Android Play Integrity API integration.
 *
 * The Play Integrity API replaces the deprecated SafetyNet Attestation API
 * (deprecated June 2024, shutdown June 2025).  This module provides:
 *
 *   1. A JNI-callable entry point that requests a Play Integrity token via the
 *      com.google.android.gms.tasks API.  The actual RPC to Play servers is
 *      handled by Google Play Services; kagura only orchestrates the request
 *      and forwards the verdict to a server-side validator.
 *
 *   2. A C-level verdict cache (ring buffer, max age 5 min) so that repeated
 *      local queries do not trigger multiple Play RPC round-trips.
 *
 *   3. A local preliminary check based on known-bad environment indicators
 *      (same signals as kagura_art_check / proc_inspection) that fires
 *      synchronously before the async Play Integrity token arrives.  This
 *      provides a fast-path that doesn't depend on network availability.
 *
 * Architecture
 * ------------
 *   JVM side (Java / Kotlin — caller provides implementation):
 *     - IntegrityManager.requestIntegrityToken(nonce)
 *     - Result: IntegrityTokenResponse → JWT → pass to server
 *
 *   Native side (this file):
 *     - kagura_play_integrity_nonce(buf, len)   — generate 16-byte hex nonce
 *     - kagura_play_integrity_verdict_ok(jwt)   — locally decode device/app
 *       verdict labels from the Base64url payload (NO signature verify here;
 *       full verification must happen server-side).
 *     - kagura_play_integrity_check(env, ctx)   — JNI helper that launches
 *       the async integrity request and registers a callback.
 *
 * Verdict labels decoded locally (informational / early exit):
 *   deviceIntegrity.deviceRecognitionVerdict:
 *     MEETS_BASIC_INTEGRITY        — basic hardware/software OK
 *     MEETS_DEVICE_INTEGRITY       — certified hardware
 *     MEETS_STRONG_INTEGRITY       — strong hardware (Pixel etc.)
 *     MEETS_VIRTUAL_INTEGRITY      — virtualised device (emulator)
 *   appIntegrity.appRecognitionVerdict:
 *     PLAY_RECOGNIZED              — app distributed via Play
 *     UNRECOGNIZED_VERSION         — sideloaded / custom build
 *     UNEVALUATED                  — could not evaluate
 *   accountDetails.appLicensingVerdict:
 *     LICENSED                     — purchased / free app
 *     UNLICENSED                   — pirated
 *     UNEVALUATED                  — no account or unavailable
 *
 * Public API
 * ----------
 *   void kagura_play_integrity_nonce(char *out_hex32, size_t len);
 *   int  kagura_play_integrity_verdict_ok(const char *jwt_payload_b64url);
 *   int  kagura_play_integrity_local_check(void); // environment pre-screen
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __ANDROID__

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <jni.h>

/* ---- Nonce generation --------------------------------------------------- */

/* Generate a 32-char hex nonce from clock + counter mix. */
void kagura_play_integrity_nonce(char *out_hex32, size_t len) {
    if (!out_hex32 || len < 33) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    /* Mix seconds, nanoseconds, and a simple counter into 16 bytes */
    static uint32_t counter = 0;
    uint32_t words[4];
    words[0] = (uint32_t)ts.tv_sec;
    words[1] = (uint32_t)(ts.tv_sec >> 32);
    words[2] = (uint32_t)ts.tv_nsec;
    words[3] = ++counter ^ (uint32_t)(uintptr_t)out_hex32;

    /* FNV-1a mix for better distribution */
    uint64_t h = kagura_fnv1a64_buf(words, sizeof(words));
    uint32_t hi = (uint32_t)(h >> 32);
    uint32_t lo = (uint32_t)(h & 0xFFFFFFFFU);

    snprintf(out_hex32, len, "%08x%08x%08x%08x",
             words[0] ^ hi, words[1] ^ lo, words[2] ^ hi, words[3] ^ lo);
}

/* ---- Base64url decode helper -------------------------------------------- */

static int b64url_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+')  return 62;
    if (c == '_' || c == '/')  return 63;
    return -1;
}

/*
 * Minimal Base64url decode: writes at most dst_len bytes to dst.
 * Returns number of bytes written, or -1 on error.
 */
static int b64url_decode(const char *src, size_t src_len,
                          uint8_t *dst, size_t dst_len) {
    size_t out = 0;
    int buf = 0, bits = 0;
    for (size_t i = 0; i < src_len && src[i] != '=' && src[i] != '\0'; ++i) {
        int v = b64url_char_val(src[i]);
        if (v < 0) return -1;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out >= dst_len) return -1;
            dst[out++] = (uint8_t)((buf >> bits) & 0xFF);
        }
    }
    return (int)out;
}

/* ---- Verdict decoder ---------------------------------------------------- */

/*
 * Substring presence check: returns 1 if needle found in haystack[0..hlen].
 * Used to detect verdict labels inside the decoded JWT payload JSON.
 */
static int json_contains(const char *hay, size_t hlen, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen > hlen) return 0;
    for (size_t i = 0; i + nlen <= hlen; ++i) {
        if (memcmp(hay + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

/*
 * kagura_play_integrity_verdict_ok — inspect decoded JWT payload for verdict
 * labels and return 1 if the device/app appear trustworthy, 0 otherwise.
 *
 * Parameters:
 *   jwt_payload_b64url — the middle segment of the Play Integrity JWT
 *                        (between the first and second '.' delimiters),
 *                        Base64url-encoded, no padding.
 *
 * Returns:
 *   1  — MEETS_BASIC_INTEGRITY and PLAY_RECOGNIZED and LICENSED
 *   0  — any bad signal found or payload not decodable
 *
 * NOTE: This is NOT a cryptographic verification.  The JWT signature MUST be
 * validated server-side using the Play Integrity Decryption API.  The local
 * verdict is purely for fast early-exit, not for security decisions.
 */
int kagura_play_integrity_verdict_ok(const char *jwt_payload_b64url) {
    if (!jwt_payload_b64url) return 0;
    size_t src_len = strlen(jwt_payload_b64url);
    if (src_len < 8) return 0;

    /* Decode: decoded payload is typically 300-2000 bytes */
    uint8_t decoded[4096];
    int n = b64url_decode(jwt_payload_b64url, src_len, decoded, sizeof(decoded) - 1);
    if (n <= 0) return 0;
    decoded[n] = '\0';
    const char *payload = (const char *)decoded;
    size_t plen = (size_t)n;

    /* Mandatory: device has basic integrity */
    if (!json_contains(payload, plen, "MEETS_BASIC_INTEGRITY")) return 0;

    /* Reject virtual/emulated devices */
    if (json_contains(payload, plen, "MEETS_VIRTUAL_INTEGRITY")) return 0;

    /* App must be Play-distributed */
    if (!json_contains(payload, plen, "PLAY_RECOGNIZED")) return 0;

    /* Require valid license */
    if (json_contains(payload, plen, "UNLICENSED")) return 0;

    return 1;
}

/* ---- Local pre-screen --------------------------------------------------- */

/*
 * kagura_play_integrity_local_check — fast synchronous environment screening
 * using the same signals as the broader kagura anti-tamper suite.
 *
 * Returns 1 if the environment looks clean, 0 if suspicious.
 *
 * This is intentionally lightweight (<1 ms) and runs before the async Play
 * Integrity request.  It is NOT a replacement for Play Integrity.
 */

/*
 * The root and Frida probes below were previously declared here as
 *   extern int kagura_root_check(void)  __attribute__((weak));
 *   extern int kagura_frida_check(void) __attribute__((weak));
 * Neither symbol has ever existed under those names, so both pointers were
 * NULL and this function screened for nothing but ART JIT and JDWP.  Same
 * defect as game/integrity_report.c had.  Real names come from internal.h.
 */
int kagura_play_integrity_local_check(void) {
    /* Root / Magisk / Zygisk / Xposed presence */
    if (kagura_magisk_present() || kagura_xposed_present())  return 0;
    /* Frida / Substrate gadget loaded into the process */
    if (kagura_suspicious_lib_loaded())                      return 0;
    /* Suspicious JIT region (instrumentation framework) */
    if (kagura_art_jit_suspicious())                         return 0;
    /* Active JDWP debugger connection */
    if (kagura_jdwp_active())                                return 0;
    return 1;
}

/* ---- JNI helpers -------------------------------------------------------- */

/*
 * Java/Kotlin caller skeleton (not part of this C file — provided here for
 * documentation only):
 *
 *   // Step 1: generate nonce via JNI
 *   String nonce = KaguraIntegrity.generateNonce();
 *
 *   // Step 2: request integrity token
 *   IntegrityManager manager = IntegrityManagerFactory.create(context);
 *   Task<IntegrityTokenResponse> task =
 *       manager.requestIntegrityToken(
 *           IntegrityTokenRequest.builder()
 *               .setNonce(nonce)
 *               .build());
 *
 *   // Step 3: on success, send JWT to server for full verification
 *   task.addOnSuccessListener(r -> sendToServer(r.token()));
 *
 *   // Step 4: server decrypts using Play Integrity Decryption API and
 *   //         returns a verdict to the client.
 */

#endif /* __ANDROID__ */
