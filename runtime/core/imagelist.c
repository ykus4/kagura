/*===-- runtime/core/imagelist.c - Shared loaded-image scanning -----------===
 *
 * One scanner over "the list of images loaded into this process", plus the
 * unified table of injection-framework names to look for.
 *
 * There were five separate dyld walks (anti_debug/anti_debug.c,
 * anti_debug/loaded_library_scan.c, ios/jailbreak_detection.c,
 * ios/ios_jailbreak_advanced.c, ios/ios_platform.c, plus partial ones in
 * game/ue4_protection.c and game/il2cpp_protection.c), each with its own
 * pattern list.  The lists had diverged, so which frameworks got detected
 * depended on which entry point the application happened to call:
 *
 *   ios_platform.c only knew "substitute" and "jtool"
 *   ios_jailbreak_advanced.c only knew "TweakInject"
 *   loaded_library_scan.c only knew "dobby", "whale", "lspd", "frida-server"
 *   anti_debug.c knew six names and missed the other fifteen
 *
 * kagura_suspicious_image_patterns() is the union of all of them, so every
 * caller now gets every pattern - nothing was dropped in the merge.
 *
 * Game-engine-specific mod loaders and memory scanners (BepInEx, UE4SS,
 * GameGuardian, ...) are deliberately NOT in this table.  They stay with
 * game/il2cpp_protection.c and game/ue4_protection.c, which union them with
 * this table for their own checks.  Some of those patterns are short enough
 * to false-positive on unrelated libraries ("libgg" matches "libggml"), and a
 * false positive here terminates the process.
 *
 * Matching is case-insensitive.  ios_platform.c was the only caller that did
 * this; the others missed "FRIDAGadget"-style renames for free.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <string.h>

/* ---- The unified pattern table ------------------------------------------- */

static const char *const kSuspiciousImages[] = {
    /* Frida ecosystem */
    "frida",                /* subsumes FridaGadget / frida-gadget /
                             * frida-agent / frida-server case-insensitively */
    "FridaGadget",
    "frida-gadget",
    "frida-agent",
    "frida-server",

    /* Substrate family and other iOS tweak injectors */
    "MobileSubstrate",
    "CydiaSubstrate",
    "SubstrateLoader",
    "libsubstrate",
    "substrate",
    "substitute",
    "libhooker",
    "TweakInject",

    /* Cycript */
    "cycript",
    "libcycript",
    "cynject",

    /* TLS pinning bypass */
    "SSLKillSwitch",

    /* Xposed family (Android) */
    "xposed",
    "XposedBridge",
    "lspd",                 /* LSPosed daemon */

    /* Generic inline-hook libraries */
    "dobby",
    "libdobby",
    "whale",

    /* Jailbreak hiders and RE tooling */
    "Liberty",
    "Shadow",
    "jtool",

    NULL
};

const char *const *kagura_suspicious_image_patterns(void) {
    return kSuspiciousImages;
}

/* ---- Case-insensitive substring match ------------------------------------
 *
 * Exported (via internal.h) because core/procfs.c needs the same comparison:
 * android/proc_inspection.c was the only maps scanner that folded case, and
 * it did so by lowercasing each line into a second 512-byte stack buffer.
 */

static char lower_ascii(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

int kagura_contains_ci(const char *haystack, const char *needle) {
    size_t hlen, nlen;

    if (!haystack || !needle) return 0;
    hlen = strlen(haystack);
    nlen = strlen(needle);
    if (nlen == 0 || hlen < nlen) return 0;

    for (size_t i = 0; i + nlen <= hlen; ++i) {
        size_t j = 0;
        while (j < nlen && lower_ascii(haystack[i + j]) == lower_ascii(needle[j]))
            ++j;
        if (j == nlen) return 1;
    }
    return 0;
}

int kagura_name_matches_any(const char *name, const char *const *patterns) {
    if (!name || !patterns) return 0;
    for (int i = 0; patterns[i] != NULL; ++i)
        if (kagura_contains_ci(name, patterns[i]))
            return 1;
    return 0;
}

/* ---- Platform backends ---------------------------------------------------- */

#if defined(__APPLE__)

#include <mach-o/dyld.h>

int kagura_image_list_contains(const char *const *patterns) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (kagura_name_matches_any(name, patterns))
            return 1;
    }
    return 0;
}

#elif defined(__linux__) || defined(__ANDROID__)

#include <link.h>

struct image_scan_ctx {
    const char *const *patterns;
    int found;
};

static int image_scan_cb(struct dl_phdr_info *info, size_t size, void *data) {
    struct image_scan_ctx *ctx = (struct image_scan_ctx *)data;
    (void)size;
    if (ctx->found)
        return 1;
    if (kagura_name_matches_any(info->dlpi_name, ctx->patterns)) {
        ctx->found = 1;
        return 1;
    }
    return 0;
}

int kagura_image_list_contains(const char *const *patterns) {
    struct image_scan_ctx ctx;
    ctx.patterns = patterns;
    ctx.found = 0;
    dl_iterate_phdr(image_scan_cb, &ctx);
    if (ctx.found)
        return 1;
    /* dl_iterate_phdr reports an empty name for the main executable and can
     * miss images mapped by a raw mmap, so fall back to the mapping table. */
    return kagura_maps_contain(patterns);
}

#elif defined(_WIN32)

/* WIN32_LEAN_AND_MEAN hides the tlhelp32 declarations, and the build defines
 * it globally, so undo it here the way windows/anti_debug.c does. */
#ifdef WIN32_LEAN_AND_MEAN
#undef WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>

/* Module32FirstW/Module32NextW are used explicitly rather than the
 * UNICODE-dependent macros, so the element type is always wchar_t.  The
 * pattern table is ASCII, hence the widening comparison below. */
static int wname_matches(const wchar_t *name, const char *const *patterns) {
    if (!name || !patterns) return 0;

    for (int p = 0; patterns[p] != NULL; ++p) {
        const char *pat = patterns[p];
        size_t nlen = wcslen(name);
        size_t plen = strlen(pat);
        if (plen == 0 || nlen < plen) continue;

        for (size_t i = 0; i + plen <= nlen; ++i) {
            size_t j = 0;
            while (j < plen) {
                wchar_t nc = name[i + j];
                char    pc = pat[j];
                if (nc >= L'A' && nc <= L'Z') nc = (wchar_t)(nc + 32);
                if (pc >= 'A' && pc <= 'Z')   pc = (char)(pc + 32);
                if (nc != (wchar_t)(unsigned char)pc) break;
                ++j;
            }
            if (j == plen) return 1;
        }
    }
    return 0;
}

int kagura_image_list_contains(const char *const *patterns) {
    MODULEENTRY32W me;
    HANDLE snap;
    int found = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me)) {
        do {
            if (wname_matches(me.szModule, patterns)) {
                found = 1;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

#else

int kagura_image_list_contains(const char *const *patterns) {
    (void)patterns;
    return 0;
}

#endif
