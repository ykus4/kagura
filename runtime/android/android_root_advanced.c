/*===-- runtime/android_root_advanced.c - Magisk/Zygisk/Xposed detection --===
 *
 * Magisk and Zygisk detection.
 * Xposed / LSPosed detection.
 *
 * These checks complement the basic root detection in jailbreak_detection.c
 * with framework-specific indicators that survive Magisk Hide / DenyList and
 * LSPosed's module loading.
 *
 * Magisk detection strategy:
 *   1. File-system artifacts — Magisk leaves markers under /data/adb/ and
 *      /sbin/.magisk even with MagiskHide active when accessed from a
 *      native context (MagiskHide only patches /proc/self/mountinfo and
 *      bind-mount remappings, not direct path probes from native code).
 *   2. Zygisk presence — the Zygisk module injects into every Zygote process;
 *      its shared object is always loaded into the process from a path under
 *      /dev/fd or /data/adb/modules.
 *   3. /proc/self/maps scan for suspicious module paths.
 *
 * Xposed / LSPosed detection strategy:
 *   1. Known artifact paths: /data/data/de.robv.android.xposed.installer,
 *      /system/framework/XposedBridge.jar.
 *   2. /proc/self/maps scan for XposedBridge, lspd.
 *   3. Stack frame inspection: call-stack contamination by Xposed hooks leaves
 *      class names like "de.robv.android.xposed" in Java exception messages;
 *      from C we check via the /proc/self/maps approach since we have no JVM.
 *
 * Public API
 * ----------
 *   int  kagura_magisk_present(void);    // 1 = Magisk/Zygisk detected
 *   void kagura_magisk_check(void);
 *   int  kagura_xposed_present(void);    // 1 = Xposed/LSPosed detected
 *   void kagura_xposed_check(void);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __ANDROID__

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static int _path_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0) ? 1 : 0;
}

/* Scan /proc/self/maps for a path fragment.  Returns 1 if found. */
static int _maps_contain(const char *fragment) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return 0;
    char line[512];
    int found = 0;
    while (!found && fgets(line, (int)sizeof(line), f))
        if (strstr(line, fragment))
            found = 1;
    fclose(f);
    return found;
}

/* -------------------------------------------------------------------------
 * Magisk / Zygisk detection
 * ---------------------------------------------------------------------- */

/* Known Magisk artifact paths that survive MagiskHide at the native layer */
static const char *kMagiskPaths[] = {
    "/data/adb/magisk",
    "/data/adb/magisk.db",
    "/data/adb/magisk_simple",
    "/data/adb/modules",
    "/sbin/.magisk",
    "/sbin/magisk",
    "/sbin/magiskinit",
    "/sbin/magiskpolicy",
    "/debug_ramdisk/.magisk",   /* some GSI builds */
    "/data/magisk",             /* older Magisk versions */
    "/cache/magisk.log",
    NULL
};

int kagura_magisk_present(void) {
    /* Path probes */
    for (int i = 0; kMagiskPaths[i] != NULL; ++i)
        if (_path_exists(kMagiskPaths[i]))
            return 1;

    /* Zygisk injects its .so from /dev/fd or /data/adb paths */
    if (_maps_contain("/data/adb/"))
        return 1;
    if (_maps_contain("zygisk"))
        return 1;

    /* Magisk tmpfs mount: /sbin is usually not mounted on stock Android
     * (API 29+ doesn't have /sbin); if it exists and is a tmpfs it's Magisk */
    if (_path_exists("/sbin"))
        return 1;

    return 0;
}

void kagura_magisk_check(void) {
    if (kagura_magisk_present())
        kagura_tamper_detected();
}

/* -------------------------------------------------------------------------
 * Xposed / LSPosed detection
 * ---------------------------------------------------------------------- */

static const char *kXposedPaths[] = {
    "/data/data/de.robv.android.xposed.installer",
    "/data/data/org.lsposed.manager",       /* LSPosed manager */
    "/system/framework/XposedBridge.jar",
    "/system/bin/app_process_xposed",
    "/system/lib/libxposed_art.so",
    "/system/lib64/libxposed_art.so",
    "/data/adb/lspd",                        /* LSPosed daemon socket */
    NULL
};

int kagura_xposed_present(void) {
    /* Path probes */
    for (int i = 0; kXposedPaths[i] != NULL; ++i)
        if (_path_exists(kXposedPaths[i]))
            return 1;

    /* /proc/self/maps scan */
    if (_maps_contain("XposedBridge"))
        return 1;
    if (_maps_contain("de.robv.android.xposed"))
        return 1;
    if (_maps_contain("/lspd"))
        return 1;

    /* app_process replacement: if /proc/self/exe is not the stock path
     * and contains "xposed" it's a modified app_process */
    char exe[256] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0 && strstr(exe, "xposed"))
        return 1;

    return 0;
}

void kagura_xposed_check(void) {
    if (kagura_xposed_present())
        kagura_tamper_detected();
}

#else /* !__ANDROID__ */

int  kagura_magisk_present(void)  { return 0; }
void kagura_magisk_check(void)    { }
int  kagura_xposed_present(void)  { return 0; }
void kagura_xposed_check(void)    { }

#endif /* __ANDROID__ */
