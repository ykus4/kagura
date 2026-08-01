/*===-- runtime/proc_inspection.c - /proc filesystem hardening ------------===
 *
 * Harden /proc/self/{maps,status,mounts,fd} inspection.
 *
 * On Android, security researchers use /proc/self/maps to enumerate loaded
 * libraries, /proc/self/status to detect ptrace attachment, and
 * /proc/self/mounts to spot rootfs remounts.  This module:
 *
 *   1. Scans /proc/self/maps for suspicious library paths (Frida, Xposed,
 *      Magisk, custom injectors).
 *   2. Checks /proc/self/status for TracerPid > 0 (process is being ptraced).
 *   3. Scans /proc/self/mounts for suspicious bind-mounts introduced by
 *      Magisk's mirror mechanism.
 *
 * Public API
 * ----------
 *   int  kagura_proc_maps_suspicious(void);  // 1 = suspicious mapping found
 *   int  kagura_proc_traced(void);           // 1 = TracerPid non-zero
 *   int  kagura_proc_mounts_suspicious(void);// 1 = suspicious mount found
 *   void kagura_proc_check(void);            // combined; calls tamper cb
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#if defined(__linux__) || defined(__ANDROID__)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* ── Suspicious patterns in /proc/self/maps ─────────────────────────────── */

static const char *const kSuspiciousMaps[] = {
    "frida",
    "gadget",
    "substrate",
    "xposed",
    "lspd",
    "edxposed",
    "zygisk",
    "/data/adb/modules",
    "/dev/fd/",
    "magisk",
    NULL
};

int kagura_proc_maps_suspicious(void) {
    /* Android-specific artefacts (zygisk, /data/adb/modules, ...) plus the
     * shared injection-framework table.  Case folding now lives in
     * core/procfs.c instead of a per-line 512-byte lowercase copy here. */
    return kagura_maps_contain(kSuspiciousMaps) ||
           kagura_maps_contain(kagura_suspicious_image_patterns());
}

/* ── TracerPid detection via /proc/self/status ──────────────────────────── */

int kagura_proc_traced(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            long pid = strtol(line + 10, NULL, 10);
            fclose(f);
            return pid != 0 ? 1 : 0;
        }
    }
    fclose(f);
    return 0;
}

/* ── Suspicious mounts ──────────────────────────────────────────────────── */

static const char *const kSuspiciousMounts[] = {
    "/sbin/.magisk",
    "/data/adb",
    "/proc/1/ns",   /* Magisk mirror namespace bind */
    NULL
};

int kagura_proc_mounts_suspicious(void) {
    FILE *f = fopen("/proc/self/mounts", "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; kSuspiciousMounts[i]; ++i) {
            if (strstr(line, kSuspiciousMounts[i])) {
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

/* ── Combined check ─────────────────────────────────────────────────────── */

void kagura_proc_check(void) {
    if (kagura_proc_maps_suspicious() ||
        kagura_proc_traced() ||
        kagura_proc_mounts_suspicious())
        kagura_on_tamper_detected();
}

#endif /* __linux__ || __ANDROID__ */
