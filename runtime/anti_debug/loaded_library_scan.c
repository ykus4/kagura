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

static const char *kSuspiciousLibs[] = {
    /* Frida ecosystem */
    "frida",
    "FridaGadget",
    "frida-gadget",
    "frida-agent",
    "frida-server",
    /* Substrate / hooking frameworks */
    "MobileSubstrate",
    "CydiaSubstrate",
    "libhooker",
    "SubstrateLoader",
    "libsubstrate",
    "substrate",
    /* Debugger helpers */
    "cycript",
    "cynject",
    /* SSL pinning bypass */
    "SSLKillSwitch",
    /* Xposed / Android */
    "xposed",
    "XposedBridge",
    "lspd",             /* LSPosed daemon */
    /* Generic hooking libs */
    "dobby",
    "whale",
    /* Jailbreak helpers */
    "Liberty",
    "Shadow",
    NULL
};

static int _lib_name_suspicious(const char *name) {
    if (!name)
        return 0;
    for (int i = 0; kSuspiciousLibs[i] != NULL; ++i) {
        if (strstr(name, kSuspiciousLibs[i]))
            return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * iOS / macOS: scan dyld image list
 * ---------------------------------------------------------------------- */

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <stdint.h>

int kagura_suspicious_lib_loaded(void) {
    int count = (int)_dyld_image_count();
    for (int i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name((uint32_t)i);
        if (_lib_name_suspicious(name))
            return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * Android / Linux: scan dl_iterate_phdr
 * ---------------------------------------------------------------------- */

#elif defined(__linux__) || defined(__ANDROID__)
#include <link.h>

struct _kls_ctx { int found; };

static int _kls_phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct _kls_ctx *ctx = (struct _kls_ctx *)data;
    if (ctx->found) return 1;
    if (_lib_name_suspicious(info->dlpi_name)) {
        ctx->found = 1;
        return 1;
    }
    return 0;
}

int kagura_suspicious_lib_loaded(void) {
    struct _kls_ctx ctx = { 0 };
    dl_iterate_phdr(_kls_phdr_cb, &ctx);
    return ctx.found;
}

#else

int kagura_suspicious_lib_loaded(void) { return 0; }

#endif /* platform */

void kagura_library_scan_check(void) {
    if (kagura_suspicious_lib_loaded())
        kagura_tamper_detected();
}
