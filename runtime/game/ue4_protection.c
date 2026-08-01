/*===-- runtime/game/ue4_protection.c - Unreal Engine 4/5 runtime protection
 *
 * Provides integrity and anti-hook protection for Unreal Engine 4 and 5
 * (UE4/UE5) native binaries:
 *   Android : libUE4.so / libUnreal.so
 *   iOS     : UnrealGame (Mach-O executable)
 *   macOS   : GameName.app/Contents/MacOS/GameName
 *
 * Public API
 * ----------
 *   int  kagura_ue4_check_symbol_redirect(void);
 *   int  kagura_ue4_check_pak_integrity(const char *pak_path);
 *   void kagura_ue4_protect_function_table(void *vtable, size_t count);
 *   int  kagura_ue4_anti_memory_scan(void);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* ── Internal helpers ────────────────────────────────────────────────────── */

#define KAGURA_FNV1A_OFFSET_BASIS UINT32_C(0x811c9dc5)
#define KAGURA_FNV1A_PRIME        UINT32_C(0x01000193)

static uint32_t _ue4_fnv1a32(const void *data, size_t len) {
    const uint8_t *p    = (const uint8_t *)data;
    uint32_t       hash = KAGURA_FNV1A_OFFSET_BASIS;
    for (size_t i = 0; i < len; ++i) {
        hash ^= (uint32_t)p[i];
        hash *= KAGURA_FNV1A_PRIME;
    }
    return hash;
}

/*
 * UE4 .pak file magic: little-endian u32 at the end-of-central-directory
 * record.  UE4 paks end with the 4-byte magic 0x5A6F12E1.
 */
#define UE4_PAK_MAGIC UINT32_C(0x5A6F12E1)

/*
 * UE5 pak magic (introduced with UE 5.0).
 */
#define UE5_PAK_MAGIC UINT32_C(0x5A6F12E2)

/* =========================================================================
 * 1. kagura_ue4_check_symbol_redirect
 *
 * Uses dladdr(3) to verify that critical UE4/UE5 engine symbols resolve to
 * the same shared library image.  Hooking frameworks (Frida, Dobby) targeting
 * UE4 commonly intercept:
 *   FMemory::Malloc      — memory allocator (heap monitoring / cheats)
 *   UObject::ProcessEvent — Blueprints event dispatcher (mod loaders)
 *   GEngine              — global engine pointer (game state access)
 *
 * Returns 0 if all resolved symbols live in the same image (clean),
 * 1 if any symbol is missing or redirected to a different image.
 * ====================================================================== */

int kagura_ue4_check_symbol_redirect(void) {
    /*
     * UE4/UE5 exports these with C linkage in shipping builds when
     * WITH_ENGINE_EXPORT_SYMBOL is set, or as mangled C++ symbols otherwise.
     * We try both the common mangled forms and the C-linkage fallback names.
     */
    static const char *SymbolNames[] = {
        /* Memory subsystem */
        "_ZN7FMemory6MallocEmi",          /* FMemory::Malloc (GCC/Clang) */
        "FMemory_Malloc",                  /* C-linkage export fallback   */
        /* Blueprint event dispatch */
        "_ZN7UObject12ProcessEventEP10UFunctionPv", /* UObject::ProcessEvent */
        /* Global engine pointer — exported as a plain pointer */
        "GEngine",
        NULL
    };

    const char *reference_image = NULL;

    for (int i = 0; SymbolNames[i] != NULL; ++i) {
        void *sym = dlsym(RTLD_DEFAULT, SymbolNames[i]);
        if (!sym)
            continue; /* Symbol not present — non-UE binary or stripped build */

        Dl_info info;
        if (!dladdr(sym, &info) || !info.dli_fname)
            return 1; /* dladdr failure is suspicious */

        if (!reference_image) {
            reference_image = info.dli_fname;
        } else if (strcmp(reference_image, info.dli_fname) != 0) {
            return 1; /* Symbol resolved to a different image */
        }

        /* Check for known UE4 hook / mod framework names in the image path */
        static const char *SuspiciousLibs[] = {
            "frida", "dobby", "substrate", "xposed",
            "UE4SS",          /* UE4 Script System — popular mod loader */
            "MirrorHook",     /* Mirror Hook for UE4 */
            "LuaMachine",     /* Lua scripting bridge */
            "UnrealCheats",
            NULL
        };
        for (int j = 0; SuspiciousLibs[j] != NULL; ++j)
            if (strstr(info.dli_fname, SuspiciousLibs[j]))
                return 1;

        /* Inline hook check: resolved address should be very close to dli_saddr */
        if (info.dli_saddr) {
            uintptr_t delta = (uintptr_t)sym > (uintptr_t)info.dli_saddr
                              ? (uintptr_t)sym - (uintptr_t)info.dli_saddr
                              : (uintptr_t)info.dli_saddr - (uintptr_t)sym;
            if (delta > 32u)
                return 1;
        }
    }
    return 0;
}

/* =========================================================================
 * 2. kagura_ue4_check_pak_integrity
 *
 * Opens a UE4/UE5 .pak file and validates:
 *   a) The file ends with the correct 4-byte magic (0x5A6F12E1 or 0x5A6F12E2).
 *   b) The 4-byte version field at offset -8 from EOF is in the known valid
 *      range [3, 11] (UE4.0 through UE5.3 pak format versions).
 *
 * Returns 0 if the pak appears intact, 1 if tampered or unreadable.
 * ====================================================================== */

int kagura_ue4_check_pak_integrity(const char *pak_path) {
    if (!pak_path) return 1;

    FILE *f = fopen(pak_path, "rb");
    if (!f) return 1;

    /* Seek to last 8 bytes: [version u32][magic u32] */
    if (fseek(f, -8, SEEK_END) != 0) { fclose(f); return 1; }

    uint8_t footer[8];
    if (fread(footer, 1, sizeof(footer), f) != sizeof(footer)) {
        fclose(f);
        return 1;
    }
    fclose(f);

    /* Parse magic (bytes 4–7) and version (bytes 0–3) as little-endian */
    uint32_t version, magic;
    memcpy(&version, footer,     sizeof(version));
    memcpy(&magic,   footer + 4, sizeof(magic));

    if (magic != UE4_PAK_MAGIC && magic != UE5_PAK_MAGIC)
        return 1;

    /* Valid pak format versions: 3 (UE4.0) through 11 (UE5.3) */
    if (version < 3u || version > 11u)
        return 1;

    return 0;
}

/* =========================================================================
 * 3. kagura_ue4_protect_function_table
 *
 * XOR-encodes an array of function pointers (typically a UObject vtable or
 * a native function dispatch table) with a runtime-derived 64-bit key.
 *
 * Key derivation mirrors kagura_il2cpp_protect_method_table():
 *   key = UE4_TABLE_SEED ^ (uintptr_t)vtable ^ (count * golden_ratio)
 *
 * This is idempotent: calling it twice on the same table restores pointers.
 * ====================================================================== */

#ifndef KAGURA_UE4_TABLE_SEED
#  define KAGURA_UE4_TABLE_SEED UINT64_C(0xC0FFEE1234567890)
#endif

void kagura_ue4_protect_function_table(void *vtable, size_t count) {
    if (!vtable || count == 0) return;

    uintptr_t *table = (uintptr_t *)vtable;
    uint64_t   key   = (uint64_t)(KAGURA_UE4_TABLE_SEED)
                       ^ (uint64_t)(uintptr_t)vtable
                       ^ (uint64_t)(count * UINT64_C(0x9E3779B97F4A7C15));

    unsigned shift = (unsigned)(count & 0x3Fu);
    key = (key << shift) | (key >> (64u - shift));

    for (size_t i = 0; i < count; ++i) {
        uint64_t entry_key = key ^ (uint64_t)(i * UINT64_C(0x517CC1B727220A95));
        table[i] ^= (uintptr_t)entry_key;
    }
}

/* =========================================================================
 * 4. kagura_ue4_anti_memory_scan
 *
 * Checks for known UE4 cheat / mod tools active in the process:
 *   Android/Linux: /proc/self/maps scan
 *   iOS/macOS    : loaded dylib scan via _dyld_get_image_name
 * ====================================================================== */

#if defined(__ANDROID__) || defined(__linux__)

static int _ue4_check_maps(void) {
    static const char *Patterns[] = {
        /* General hook frameworks */
        "frida-agent", "frida-gadget", "libsubstrate", "libdobby",
        /* UE4-specific mod loaders and cheat tools */
        "UE4SS",
        "MirrorHook",
        "UnrealCheats",
        "libUEHook",
        /* Memory scanner / cheat engine */
        "libGameGuardian", "GameGuardian",
        NULL
    };

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    while (fgets(line, (int)sizeof(line), f)) {
        for (int i = 0; Patterns[i] != NULL; ++i) {
            if (strstr(line, Patterns[i])) { fclose(f); return 1; }
        }
    }
    fclose(f);
    return 0;
}

#endif /* __ANDROID__ || __linux__ */

int kagura_ue4_anti_memory_scan(void) {
#if defined(__ANDROID__) || defined(__linux__)
    if (_ue4_check_maps()) return 1;
#endif

#if defined(__APPLE__)
    {
        extern int          _dyld_image_count(void)
            __attribute__((weak_import));
        extern const char * _dyld_get_image_name(unsigned int)
            __attribute__((weak_import));

        static const char *SuspiciousLibs[] = {
            "frida", "dobby", "substrate",
            "UE4SS", "MirrorHook", "UnrealCheats",
            NULL
        };

        if (_dyld_image_count && _dyld_get_image_name) {
            int n = _dyld_image_count();
            for (int i = 0; i < n; ++i) {
                const char *name = _dyld_get_image_name((unsigned int)i);
                if (!name) continue;
                for (int j = 0; SuspiciousLibs[j] != NULL; ++j)
                    if (strstr(name, SuspiciousLibs[j])) return 1;
            }
        }
    }
#endif

    return 0;
}
