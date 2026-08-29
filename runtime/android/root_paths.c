/*===-- runtime/android/root_paths.c - Basic Android root detection -------===
 *
 * The four checks below - su binary, root-manager package directories,
 * build.prop test-keys, /system remounted rw - are the baseline root probes.
 * android/android_root_advanced.c complements them with the framework-specific
 * Magisk / Zygisk / Xposed indicators that survive MagiskHide.
 *
 * Why this file exists
 * --------------------
 * All four used to sit in ios/jailbreak_detection.c behind
 * `#if defined(__ANDROID__)`, inside a file that runtime/CMakeLists.txt only
 * ever feeds to an Apple compiler.  They were declared in runtime/internal.h,
 * referenced from the aggregate detector, and had never once been compiled by
 * anything.  The identical arrangement in android_root_advanced.c is what let a
 * call to `kaguramaps_contain` - a symbol that has never existed - sit in the
 * tree undetected: code that no configuration compiles is code no compiler can
 * check.
 *
 * Which is also why the bodies here are NOT wrapped in `#ifdef __ANDROID__`.
 * Nothing in them is Bionic-specific: they are path probes and two small text
 * parsers, so they compile as-is on desktop Linux, which is the configuration
 * CI actually builds.  The paths they look for (/system/bin/su,
 * /data/data/com.topjohnwu.magisk, /system/build.prop) simply do not exist
 * there, so they return 0 on a desktop the same way they return 0 on a clean
 * phone - a genuine negative, not a stub.  Keeping them compilable is the whole
 * point of the move; re-adding the guard would re-create the bug.
 *
 * The file stays in the Android/Linux source list rather than the portable one
 * because /proc/mounts has no Windows equivalent and the aggregate in
 * core/self_check.c only calls these under __ANDROID__.
 *
 * Public API
 * ----------
 *   int kagura_check_su_binary(void);
 *   int kagura_check_root_packages(void);
 *   int kagura_check_test_keys(void);
 *   int kagura_check_rw_system(void);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdio.h>
#include <string.h>

/* Shared probe from core/pathprobe.c.  The hardened variant asks stat, access
 * and open rather than stat alone: root hiders routinely hook exactly one of
 * the three. */
#define path_exists(p) kagura_path_exists_hardened(p)

/* --- Check 1: su binary in common system paths -------------------------- */

/**
 * kagura_check_su_binary
 *
 * Checks an exhaustive list of file-system locations where a superuser (su)
 * binary is typically installed by root management frameworks such as Magisk,
 * SuperSU, or KingRoot.
 *
 * Returns 1 if any su binary is found, 0 otherwise.
 */
int kagura_check_su_binary(void) {
    static const char *SuPaths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/system/sbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/app/Superuser.apk",
        "/system/etc/init.d/99SuperSUDaemon",
        NULL
    };

    for (int i = 0; SuPaths[i] != NULL; ++i) {
        if (path_exists(SuPaths[i]))
            return 1;
    }
    return 0;
}

/* --- Check 2: Known root management package data directories ------------ */

/**
 * kagura_check_root_packages
 *
 * Root management applications leave their data directories at well-known
 * locations under /data/data/.  Their presence is a strong indicator of a
 * rooted device.
 *
 * Returns 1 if any known root package directory exists, 0 otherwise.
 */
int kagura_check_root_packages(void) {
    static const char *RootPackages[] = {
        "/data/data/com.topjohnwu.magisk",       /* Magisk Manager */
        "/data/data/eu.chainfire.supersu",        /* SuperSU */
        "/data/data/com.noshufou.android.su",     /* Superuser (CyanogenMod) */
        "/data/data/com.koushikdutta.superuser",  /* ClockworkMod Superuser */
        "/data/data/com.zachspong.temprootremovejb",
        "/data/data/com.ramdroid.appquarantine",
        "/data/data/me.phh.superuser",            /* phh SuperUser */
        NULL
    };

    for (int i = 0; RootPackages[i] != NULL; ++i) {
        if (path_exists(RootPackages[i]))
            return 1;
    }
    return 0;
}

/* --- Check 3: Build property test-keys signature ----------------------- */

/**
 * kagura_check_test_keys
 *
 * Official production builds are signed with release keys; custom ROMs and
 * engineering builds typically use test-keys.  The tag is recorded in
 * /system/build.prop under the key "ro.build.tags".
 *
 * Returns 1 if "test-keys" is found in build.prop, 0 otherwise.
 */
int kagura_check_test_keys(void) {
    FILE *f = fopen("/system/build.prop", "r");
    if (!f)
        return 0;

    char line[256];
    while (fgets(line, (int)sizeof(line), f)) {
        /* Look for the tags property line. */
        if (strncmp(line, "ro.build.tags=", 14) == 0) {
            fclose(f);
            return (strstr(line, "test-keys") != NULL) ? 1 : 0;
        }
    }
    fclose(f);
    return 0;
}

/* --- Check 4: /system mounted read-write -------------------------------- */

/**
 * kagura_check_rw_system
 *
 * On a properly locked production device /system is a read-only partition.
 * Root access typically remounts it read-write.  We detect this by scanning
 * /proc/mounts for the /system entry and checking whether it is mounted "rw".
 *
 * Returns 1 if /system is mounted rw, 0 otherwise.
 */
int kagura_check_rw_system(void) {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f)
        return 0;

    char line[512];
    while (fgets(line, (int)sizeof(line), f)) {
        /* /proc/mounts columns: device mountpoint fstype options dump pass */
        char device[128], mountpoint[128], fstype[64], options[256];
        if (sscanf(line, "%127s %127s %63s %255s",
                   device, mountpoint, fstype, options) < 4)
            continue;
        if (strcmp(mountpoint, "/system") == 0) {
            int rw = 0;
            /* strtok_r, not strtok: strtok keeps its cursor in a single
             * process-wide static, so it silently corrupts any tokenisation
             * the caller had in progress - and this is a detection routine the
             * AntiTamper pass can schedule at the entry of arbitrary functions,
             * including ones already inside a strtok loop, on any thread.
             * strtok_r keeps the cursor in `save` and has no such hazard. */
            char *save = NULL;
            char *opt = strtok_r(options, ",", &save);
            while (opt) {
                if (strcmp(opt, "rw") == 0) {
                    rw = 1;
                    break;
                }
                opt = strtok_r(NULL, ",", &save);
            }
            fclose(f);
            return rw;
        }
    }
    fclose(f);
    return 0;
}
