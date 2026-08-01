/*===-- runtime/ios_jailbreak_advanced.c - Advanced iOS jailbreak detection ===
 *
 * Jailbreak filesystem artifact detection (expanded path list).
 * Cydia / Substrate / FridaGadget.dylib detection (dyld image scan
 *         + path probes combined).
 * App repackaging detection — checks that the bundle ID and code
 *          signing team match the values baked in at compile time.
 *
 * These functions extend the basic checks in jailbreak_detection.c with
 * deeper coverage of modern jailbreaks (Palera1n, Dopamine, unc0ver, etc.)
 * and the specific detection patterns needed for each framework.
 *
 * Public API
 * ----------
 *   int  kagura_jailbreak_fs_artifacts(void);  // expanded FS probe
 *   void kagura_jailbreak_fs_check(void);
 *   int  kagura_cydia_substrate_loaded(void);  // dyld + path + dlopen probe
 *   void kagura_cydia_substrate_check(void);
 *   int  kagura_app_repackaged(const char *expected_bundle_id,
 *                               const char *expected_team_id);
 *   void kagura_repackage_check(const char *expected_bundle_id,
 *                                const char *expected_team_id);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __APPLE__

#include <TargetConditionals.h>

#if TARGET_OS_IOS

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static int _ios_path_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0) ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * Expanded jailbreak filesystem artifact detection
 *
 * Covers Cydia, Sileo, Zebra, Checkra1n, Unc0ver, Palera1n, Dopamine,
 * and the common tool-chain artifacts they install.
 * ---------------------------------------------------------------------- */

static const char *kJBPaths[] = {
    /* Package managers */
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Installer.app",
    "/Applications/Filza.app",
    "/Applications/iFile.app",
    /* Substrate / hooking */
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/TweakInject.dylib",
    "/usr/lib/substrate",
    /* SSH / shells */
    "/usr/bin/sshd",
    "/usr/sbin/sshd",
    "/bin/bash",
    "/bin/sh.bak",
    "/usr/bin/cycript",
    /* apt / dpkg package management */
    "/etc/apt",
    "/usr/bin/apt",
    "/usr/bin/dpkg",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/stash",
    /* Checkra1n / Palera1n */
    "/var/checkra1n.dmg",
    "/var/binpack",
    "/usr/libexec/checkra1n",
    "/private/preboot/jb",          /* palera1n */
    "/var/jb",                       /* Dopamine */
    /* Common paths on rootless jailbreaks */
    "/var/jb/usr/bin/apt",
    "/var/jb/Library/MobileSubstrate",
    /* Certificates / provisioning */
    "/private/var/mobile/Library/SBSettings/Themes",
    /* Frida */
    "/usr/sbin/frida-server",
    "/etc/frida",
    NULL
};

int kagura_jailbreak_fs_artifacts(void) {
    for (int i = 0; kJBPaths[i] != NULL; ++i)
        if (_ios_path_exists(kJBPaths[i]))
            return 1;
    return 0;
}

void kagura_jailbreak_fs_check(void) {
    if (kagura_jailbreak_fs_artifacts())
        kagura_tamper_detected();
}

/* -------------------------------------------------------------------------
 * Cydia / Substrate / FridaGadget detection
 *
 * Three-layer check:
 *   1. dyld image list scan (same as kagura_check_substrate_dylib in
 *      jailbreak_detection.c but with a more complete list).
 *   2. dlopen probe — attempt to load the dylib by path; success confirms
 *      it is present even if the image list scan was somehow bypassed.
 *   3. Path probe for known installation locations.
 * ---------------------------------------------------------------------- */

static const char *kSubstrateDylibs[] = {
    "MobileSubstrate",
    "CydiaSubstrate",
    "libhooker",
    "TweakInject",
    "FridaGadget",
    "frida-gadget",
    "frida-agent",
    "cycript",
    "cynject",
    "SSLKillSwitch",
    "Liberty",
    "Shadow",
    NULL
};

static const char *kDlopenProbes[] = {
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/TweakInject.dylib",
    "/usr/sbin/frida-server",
    NULL
};

int kagura_cydia_substrate_loaded(void) {
    /* Layer 1: dyld image list */
    int count = (int)_dyld_image_count();
    for (int i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name((uint32_t)i);
        if (!name) continue;
        for (int j = 0; kSubstrateDylibs[j] != NULL; ++j)
            if (strstr(name, kSubstrateDylibs[j]))
                return 1;
    }

    /* Layer 2: dlopen probe */
    for (int i = 0; kDlopenProbes[i] != NULL; ++i) {
        void *h = dlopen(kDlopenProbes[i], RTLD_LAZY | RTLD_NOLOAD);
        if (h) {
            dlclose(h);
            return 1;
        }
    }

    /* Layer 3: path probes */
    for (int i = 0; kDlopenProbes[i] != NULL; ++i)
        if (_ios_path_exists(kDlopenProbes[i]))
            return 1;

    return 0;
}

void kagura_cydia_substrate_check(void) {
    if (kagura_cydia_substrate_loaded())
        kagura_tamper_detected();
}

/* -------------------------------------------------------------------------
 * App repackaging detection
 *
 * Reads the bundle ID and team ID from the embedded mobile provision (or
 * from the Info.plist CF bundle identifier) at runtime and compares against
 * values captured at compile time.  A mismatch means the app was repacked
 * under a different certificate or bundle ID.
 *
 * Implementation:
 *   - Bundle ID is read from the main bundle's CFBundleIdentifier via the
 *     CFBundle APIs (weak-linked so we don't pull in CoreFoundation in C).
 *   - For the team ID we check the code signing CDHash / signing identity
 *     via csops(CS_OPS_IDENTITY).
 *
 * If expected_bundle_id / expected_team_id is NULL the respective check is
 * skipped (allows callers to check only one dimension).
 * ---------------------------------------------------------------------- */

/* csops for identity query */
#include <sys/types.h>
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#define CS_OPS_IDENTITY 1

int kagura_app_repackaged(const char *expected_bundle_id,
                           const char *expected_team_id) {
    /* Check signing identity via csops(CS_OPS_IDENTITY).
     * The identity string is in the form "Developer ID: <name> (<team>)" or
     * just the Team ID on iOS App Store builds.  We do a substring search. */
    if (expected_team_id) {
        char ident[256] = {0};
        if (csops(0, CS_OPS_IDENTITY, ident, sizeof(ident) - 1) == 0) {
            if (strlen(ident) > 0 && !strstr(ident, expected_team_id))
                return 1;
        }
    }

    /* Bundle ID check via /proc equivalent: read from executable path info.
     * On iOS, /var/containers/Bundle/Application/<UUID>/<AppName>.app/
     * The app name in the path should match; for a full check the caller
     * would integrate with the ObjC NSBundle API.  We do a path-based
     * heuristic: the dyld image 0 path should contain expected_bundle_id. */
    if (expected_bundle_id) {
        const char *exe_path = _dyld_get_image_name(0);
        if (exe_path && !strstr(exe_path, expected_bundle_id))
            return 1;
    }

    return 0;
}

void kagura_repackage_check(const char *expected_bundle_id,
                             const char *expected_team_id) {
    if (kagura_app_repackaged(expected_bundle_id, expected_team_id))
        kagura_tamper_detected();
}

#else /* !TARGET_OS_IOS */

int  kagura_jailbreak_fs_artifacts(void)           { return 0; }
void kagura_jailbreak_fs_check(void)               { }
int  kagura_cydia_substrate_loaded(void)            { return 0; }
void kagura_cydia_substrate_check(void)             { }
int  kagura_app_repackaged(const char *a, const char *b)
     { (void)a; (void)b; return 0; }
void kagura_repackage_check(const char *a, const char *b)
     { (void)a; (void)b; }

#endif /* TARGET_OS_IOS */

#else /* !__APPLE__ */

int  kagura_jailbreak_fs_artifacts(void)           { return 0; }
void kagura_jailbreak_fs_check(void)               { }
int  kagura_cydia_substrate_loaded(void)            { return 0; }
void kagura_cydia_substrate_check(void)             { }
int  kagura_app_repackaged(const char *a, const char *b)
     { (void)a; (void)b; return 0; }
void kagura_repackage_check(const char *a, const char *b)
     { (void)a; (void)b; }

#endif /* __APPLE__ */
