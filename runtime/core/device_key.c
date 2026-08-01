/*===-- runtime/device_key.c - Device-bound key derivation ----------------===
 *
 * Derive encryption keys that are bound to the specific device,
 *        so that a string blob extracted from one device cannot be decrypted
 *        on a different device (e.g. by an attacker who dumped the APK/IPA).
 *
 * Strategy
 * --------
 * Derive a per-device 128-bit key by hashing stable hardware identifiers
 * using FNV-1a-64:
 *
 *   iOS:     kern.bootsessionuuid via sysctlbyname (proxy for device identity)
 *   Android: /proc/cpuinfo Serial field
 *   Fallback: /etc/machine-id or /var/lib/dbus/machine-id
 *
 * The derived key is XOR-mixed with the compile-time key so that neither the
 * device key alone nor the compile-time key alone can decrypt the data.
 *
 * Public API
 * ----------
 *   int  kagura_device_key(uint8_t out[16]);
 *     Returns 1 on success, 0 if a device identifier could not be obtained.
 *     out receives a 16-byte device-bound key.
 *
 *   void kagura_device_mix_key(uint8_t key[16]);
 *     XOR mixes the device-bound key INTO an existing 16-byte compile-time
 *     key in place.  Use before decrypting AES-encrypted data.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <TargetConditionals.h>
#if TARGET_OS_IOS && !TARGET_OS_SIMULATOR
#include <sys/sysctl.h>
#endif
#endif

/* ── Helper: read one line from a file ──────────────────────────────────── */

static int read_file_line(const char *path, char *out, size_t outsz) {
    if (!path || !out || outsz == 0) return 0;
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int ok = fgets(out, (int)outsz, f) != NULL;
    fclose(f);
    if (!ok) return 0;
    size_t len = strlen(out);
    while (len > 0 && (out[len-1] == '\n' || out[len-1] == '\r' ||
                        out[len-1] == ' '))
        out[--len] = '\0';
    return len > 0 ? 1 : 0;
}

/* ── FNV-1a-64 ──────────────────────────────────────────────────────────── */
/* Thin adapter over core/hash.c so the constants live in exactly one place. */

static void fnv1a64_bytes(uint64_t *h, const uint8_t *data, size_t len) {
    *h = kagura_fnv1a64_update(*h, data, len);
}

/* ── Public API ─────────────────────────────────────────────────────────── */

int kagura_device_key(uint8_t out[16]) {
    uint64_t h0 = 0xcbf29ce484222325ULL;
    uint64_t h1 = 0x517cc1b727220a95ULL;

    char buf[256] = {0};
    int  got_id   = 0;

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
    /* iOS: use boot session UUID as a per-device-boot proxy */
    {
        size_t sz = sizeof(buf) - 1;
        if (sysctlbyname("kern.bootsessionuuid", buf, &sz, NULL, 0) == 0 &&
                buf[0]) {
            fnv1a64_bytes(&h0, (uint8_t *)buf, strlen(buf));
            fnv1a64_bytes(&h1, (uint8_t *)buf, strlen(buf));
            got_id = 1;
        }
    }
#elif defined(__ANDROID__)
    /* Android: hash /proc/cpuinfo lines containing "Serial" */
    {
        FILE *f = fopen("/proc/cpuinfo", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "Serial", 6) == 0) {
                    fnv1a64_bytes(&h0, (uint8_t *)line, strlen(line));
                    got_id = 1;
                    break;
                }
            }
            fclose(f);
        }
    }
#endif

    /* Universal fallback */
    if (!got_id) {
        if (!read_file_line("/etc/machine-id", buf, sizeof(buf)))
            read_file_line("/var/lib/dbus/machine-id", buf, sizeof(buf));
        if (buf[0]) {
            fnv1a64_bytes(&h0, (uint8_t *)buf, strlen(buf));
            fnv1a64_bytes(&h1, (uint8_t *)buf, strlen(buf));
            got_id = 1;
        }
    }

    if (!got_id) return 0;

    memcpy(out,     &h0, 8);
    memcpy(out + 8, &h1, 8);
    return 1;
}

void kagura_device_mix_key(uint8_t key[16]) {
    uint8_t dev[16];
    if (!kagura_device_key(dev)) return;
    for (int i = 0; i < 16; ++i)
        key[i] ^= dev[i];
}
