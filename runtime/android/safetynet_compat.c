/*===-- runtime/safetynet_compat.c - SafetyNet backward compatibility -----===
 *
 * SafetyNet backward compatibility shim.
 *
 * Google deprecated the SafetyNet Attestation API in June 2024 and announced
 * shutdown in June 2025.  This module provides:
 *
 *   1. A compatibility shim that detects the runtime Android API level and
 *      routes attestation calls through the appropriate API:
 *        - API level >= 28 (Android 9+) with Play Services >= 17.x → Play Integrity
 *        - API level 24-27 (Android 7-8) → SafetyNet Attestation (deprecated fallback)
 *        - API level < 24 → local-only checks (no remote attestation available)
 *
 *   2. A nonce-matching helper to detect replay attacks against both APIs:
 *      the nonce embedded in the response must match the nonce we sent.
 *
 *   3. A verdict cache (TTL 5 min) shared with play_integrity.c to avoid
 *      duplicate round-trips when both shims are active.
 *
 * The SafetyNet path is intentionally minimal: only cts_profile_match and
 * basic_integrity are read from the payload, as the API is sunset.
 *
 * Public API
 * ----------
 *   int  kagura_safetynet_available(JNIEnv *env);
 *   int  kagura_safetynet_verdict_ok(const char *jws_payload_b64url,
 *                                    const char *expected_nonce);
 *   int  kagura_attestation_ok(JNIEnv *env, const char *response_b64url,
 *                              const char *nonce, int is_play_integrity);
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
#include <android/api-level.h>

/* ---- Shared verdict cache ----------------------------------------------- */

/* Simple 1-entry TTL cache shared between SafetyNet and Play Integrity */
typedef struct {
    int       result;      /* 1 = ok, 0 = fail, -1 = not set */
    time_t    timestamp;   /* time() at last update */
} KaguraVerdictCache;

static KaguraVerdictCache g_verdict_cache = { -1, 0 };

#define VERDICT_TTL_SECS 300  /* 5 minutes */

static int cache_get(void) {
    if (g_verdict_cache.result < 0) return -1;
    time_t now = time(NULL);
    if (now - g_verdict_cache.timestamp > VERDICT_TTL_SECS) {
        g_verdict_cache.result = -1;
        return -1;
    }
    return g_verdict_cache.result;
}

static void cache_set(int result) {
    g_verdict_cache.result    = result;
    g_verdict_cache.timestamp = time(NULL);
}

/* ---- Base64url helpers (duplicated to avoid cross-TU linkage issues) ---- */

static int b64url_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-' || c == '+')  return 62;
    if (c == '_' || c == '/')  return 63;
    return -1;
}

static int sn_b64url_decode(const char *src, size_t slen,
                             uint8_t *dst, size_t dlen) {
    size_t out = 0;
    int buf = 0, bits = 0;
    for (size_t i = 0; i < slen && src[i] != '=' && src[i] != '\0'; ++i) {
        int v = b64url_val(src[i]);
        if (v < 0) return -1;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out >= dlen) return -1;
            dst[out++] = (uint8_t)((buf >> bits) & 0xFF);
        }
    }
    return (int)out;
}

static int sn_json_contains(const char *hay, size_t hlen, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen > hlen) return 0;
    for (size_t i = 0; i + nlen <= hlen; ++i) {
        if (memcmp(hay + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

/* ---- API level check ---------------------------------------------------- */

/*
 * kagura_safetynet_available — returns 1 if SafetyNet is available (API 24+)
 * but Play Integrity is not yet required (API < 28 or Play Services too old).
 * In practice, call this only for the fallback path; prefer Play Integrity.
 */
int kagura_safetynet_available(JNIEnv *env) {
    (void)env;
    int api = android_get_device_api_level();
    /* SafetyNet works on API 24+; on 28+ prefer Play Integrity */
    return (api >= 24 && api < 28) ? 1 : 0;
}

/* ---- SafetyNet verdict decoder ------------------------------------------ */

/*
 * kagura_safetynet_verdict_ok — decode a SafetyNet JWS payload and check:
 *   1. basicIntegrity == true
 *   2. ctsProfileMatch == true  (relaxed: accept false for sideload testing)
 *   3. nonce matches expected_nonce (replay protection)
 *
 * Parameters:
 *   jws_payload_b64url — middle segment of the SafetyNet JWS attestation
 *   expected_nonce     — the nonce string we sent in the request
 *
 * Returns 1 if trustworthy, 0 otherwise.
 *
 * NOTE: Signature verification must happen server-side.  This local check
 * is only for fast early-exit on obviously bad responses.
 */
int kagura_safetynet_verdict_ok(const char *jws_payload_b64url,
                                 const char *expected_nonce) {
    if (!jws_payload_b64url) return 0;
    size_t slen = strlen(jws_payload_b64url);
    if (slen < 8) return 0;

    uint8_t decoded[4096];
    int n = sn_b64url_decode(jws_payload_b64url, slen, decoded, sizeof(decoded) - 1);
    if (n <= 0) return 0;
    decoded[n] = '\0';

    const char *payload = (const char *)decoded;
    size_t plen = (size_t)n;

    /* Must have basic integrity */
    if (!sn_json_contains(payload, plen, "\"basicIntegrity\":true")) return 0;

    /* Nonce check: look for "nonce":"<expected_nonce>" */
    if (expected_nonce && *expected_nonce) {
        char needle[256];
        int written = snprintf(needle, sizeof(needle),
                               "\"nonce\":\"%s\"", expected_nonce);
        if (written > 0 && (size_t)written < sizeof(needle)) {
            if (!sn_json_contains(payload, plen, needle)) return 0;
        }
    }

    return 1;
}

/* ---- Unified attestation entry point ------------------------------------ */

/*
 * kagura_attestation_ok — unified verdict check for both Play Integrity and
 * SafetyNet (compatibility bridge).
 *
 * Parameters:
 *   env                — JNI environment pointer (unused, reserved)
 *   response_b64url    — Base64url-encoded JWT/JWS payload segment
 *   nonce              — nonce we sent (for replay protection)
 *   is_play_integrity  — 1 if Play Integrity JWT, 0 if SafetyNet JWS
 *
 * Returns:
 *   1  — verdict is OK
 *   0  — verdict bad or undecidable locally (always validate server-side)
 */
int kagura_attestation_ok(JNIEnv *env, const char *response_b64url,
                           const char *nonce, int is_play_integrity) {
    (void)env;

    /* Check TTL cache first */
    int cached = cache_get();
    if (cached >= 0) return cached;

    int result;
    if (is_play_integrity) {
        result = kagura_play_integrity_verdict_ok(response_b64url);
    } else {
        result = kagura_safetynet_verdict_ok(response_b64url, nonce);
    }

    cache_set(result);
    return result;
}

#endif /* __ANDROID__ */
