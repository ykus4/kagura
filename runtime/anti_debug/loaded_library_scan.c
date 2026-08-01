/*===-- runtime/loaded_library_scan.c - Suspicious loaded module detection -===
 *
 * Scans the loaded dynamic libraries for known analysis / hooking
 *         framework names on both iOS (Mach-O dyld image list) and Android
 *         (ELF dl_iterate_phdr).
 *
 * Covers:
 *   Frida, FridaGadget, frida-agent, frida-server
 *   MobileSubstrate, CydiaSubstrate, libhooker, SubstrateLoader
 *   Xposed, LSPosed (Android)
 *   cycript, cynject
 *   SSLKillSwitch, SSLKillSwitch2
 *   Liberty Lite, Shadow
 *   dobby, whale (popular hooking libraries)
 *
 * Public API
 * ----------
 *   int  kagura_suspicious_lib_loaded(void);  // 1 = suspicious lib found
 *   void kagura_library_scan_check(void);     // calls tamper_detected on hit
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stddef.h>
#include <string.h>

/*
 * This file used to own both the pattern list and a per-platform image walk.
 * Both moved to core/imagelist.c, which merged this list with the four other
 * divergent copies and made the walk available to every caller (including
 * Windows, which previously had no equivalent).  Nothing was dropped: the
 * union is a strict superset of what this file matched.
 */
int kagura_suspicious_lib_loaded(void) {
    return kagura_image_list_contains(kagura_suspicious_image_patterns());
}

void kagura_library_scan_check(void) {
    if (kagura_suspicious_lib_loaded())
        kagura_tamper_detected();
}
