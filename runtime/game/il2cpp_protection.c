/*===-- runtime/il2cpp_protection.c - Unity IL2CPP runtime protection ------===
 *
 * Provides integrity and anti-hook protection for Unity IL2CPP binaries
 * (libil2cpp.so on Android, GameAssembly.dylib on iOS/macOS).
 *
 * Public API
 * ----------
 *   int  kagura_il2cpp_check_metadata_integrity(void);
 *   int  kagura_il2cpp_check_symbol_redirect(void);
 *   void kagura_il2cpp_protect_method_table(void *method_table, size_t count);
 *   int  kagura_protect_global_metadata(const char *metadata_path);
 *   int  kagura_il2cpp_anti_memory_scan(void);
 *
 * Platform support
 * ----------------
 *   Android : __ANDROID__ guard, /proc/self/maps scan
 *   iOS     : __APPLE__ / TARGET_OS_IOS, substrate dylib scan
 *   Linux   : __linux__ (host CI / stub builds)
 *
 * Compilation
 * -----------
 *   clang -std=c11 -Wall -Wextra -o il2cpp_protection.o \
 *         -c runtime/il2cpp_protection.c
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* No hand-rolled externs here: kagura_check_substrate_dylib and
 * kagura_tamper_detected both come from ../internal.h (see Rule 2 there).  The
 * dangling `#if defined(__APPLE__)` / `#endif` pair that used to bracket the
 * removed declarations went with them. */

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* FNV-1a-32 shared via core/hash.c — the constants used to be redeclared
 * here and in four other files. */
#define il2cpp_fnv1a32(data, len) kagura_fnv1a32_buf((data), (len))

/*
 * 64-bit left rotate that is defined for a zero rotate count.
 *
 * The obvious spelling, `(v << s) | (v >> (64 - s))`, is undefined behaviour
 * when s == 0: the right operand becomes 64, and C11 6.5.7p3 makes a shift by
 * the operand's width undefined.  That is not a theoretical concern here - the
 * caller derives s from `count & 0x3F`, and a method table whose entry count is
 * a multiple of 64 is the common case, so s == 0 happens routinely.  Whatever
 * the compiler decides to emit for the undefined shift changes the key, and
 * because the table protection is a self-inverse XOR the mismatch silently
 * corrupts a live function-pointer table on the way back out.
 */
static inline uint64_t rotl64(uint64_t v, unsigned s) {
    return (v << s) | (v >> ((64u - s) & 63u));
}

/*
 * IL2CPP global-metadata.dat magic bytes (little-endian u32 = 0xFAB11BAF).
 * Written at offset 0 of every valid metadata file.
 */
#define IL2CPP_METADATA_MAGIC UINT32_C(0xFAB11BAF)

/*
 * Number of bytes read from metadata for the hash integrity check.
 * Covers the file header and the first portion of the string literal pool.
 */
#define KAGURA_METADATA_HASH_WINDOW 4096u

/*
 * Expected global-metadata.dat size embedded at build time.
 * Override by defining KAGURA_EXPECTED_METADATA_SIZE on the compiler command
 * line; the default of 0 disables the size check.
 */
#ifndef KAGURA_EXPECTED_METADATA_SIZE
#  define KAGURA_EXPECTED_METADATA_SIZE 0ul
#endif

/*
 * XOR key seed used by kagura_il2cpp_protect_method_table().
 * The actual key is derived at runtime from the process start time xor'd
 * with this compile-time seed so that two builds of the runtime produce
 * different keys even if the seed is leaked by reverse-engineering.
 */
#ifndef KAGURA_METHOD_TABLE_SEED
#  define KAGURA_METHOD_TABLE_SEED UINT64_C(0xDEADBEEFCAFEBABE)
#endif

/* =========================================================================
 * 1. kagura_il2cpp_check_metadata_integrity
 * ====================================================================== */

/**
 * kagura_il2cpp_check_metadata_integrity
 *
 * Verifies that global-metadata.dat has not been tampered with by:
 *
 *   a) Checking the file size against KAGURA_EXPECTED_METADATA_SIZE (when
 *      non-zero).  A size mismatch indicates that data has been appended,
 *      truncated, or replaced.
 *
 *   b) Reading the first KAGURA_METADATA_HASH_WINDOW bytes and computing an
 *      FNV-1a hash.  The hash is compared against the value embedded at
 *      compile time via KAGURA_EXPECTED_METADATA_HASH.  If the macro is not
 *      defined (the default) the check is skipped and only the magic-byte
 *      and size checks apply.
 *
 * The metadata path is resolved in a platform-specific way:
 *   Android : next to the APK's lib/<abi>/ directory, typically accessible
 *             via /data/data/<package>/files/ or the assets/ path.  The path
 *             should be passed explicitly; this function probes a list of
 *             common locations when called with a NULL path.
 *   iOS     : embedded in the app bundle at <Bundle>/Data/Managed/Metadata/
 *             global-metadata.dat.
 *
 * Returns 0 if the metadata appears intact, 1 if tampering is detected.
 */
int kagura_il2cpp_check_metadata_integrity(void) {
    static const char *CandidatePaths[] = {
        /* Android APK extraction paths */
        "/data/app/il2cpp/Metadata/global-metadata.dat",
        /* iOS / macOS bundle-relative path (resolved at runtime via env) */
        "Data/Managed/Metadata/global-metadata.dat",
        NULL
    };

    /* Try each candidate until one opens. */
    FILE *f = NULL;
    for (int i = 0; CandidatePaths[i] != NULL && !f; ++i)
        f = fopen(CandidatePaths[i], "rb");

    if (!f)
        return 0; /* Cannot open — non-fatal on platforms without the file */

    /* ---- a) File size check ---- */
#if KAGURA_EXPECTED_METADATA_SIZE > 0
    {
        struct stat st;
        if (fstat(fileno(f), &st) == 0) {
            if ((unsigned long)st.st_size != (unsigned long)KAGURA_EXPECTED_METADATA_SIZE) {
                fclose(f);
                return 1;
            }
        }
    }
#endif

    /* ---- b) Magic bytes check ---- */
    uint8_t buf[KAGURA_METADATA_HASH_WINDOW];
    size_t  n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (n < 4)
        return 1; /* File too small — definitely tampered */

    /* Read magic as little-endian u32 without aliasing the uint8_t array */
    uint32_t magic;
    memcpy(&magic, buf, sizeof(magic));

    if (magic != IL2CPP_METADATA_MAGIC)
        return 1;

    /* ---- c) FNV-1a hash check (optional, requires build-time constant) ---- */
#ifdef KAGURA_EXPECTED_METADATA_HASH
    {
        uint32_t actual_hash = il2cpp_fnv1a32(buf, n);
        if (actual_hash != (uint32_t)(KAGURA_EXPECTED_METADATA_HASH))
            return 1;
    }
#endif

    return 0;
}

/* =========================================================================
 * 2. kagura_il2cpp_check_symbol_redirect
 * ====================================================================== */

/**
 * kagura_il2cpp_check_symbol_redirect
 *
 * Uses dladdr(3) to verify that the critical IL2CPP runtime symbols resolve
 * to addresses that lie within the same shared library image that originally
 * exported them.  A redirect (different dli_fname for two symbols that should
 * share the same image) indicates an inline-hook or import-table redirect
 * consistent with BepInEx, MelonLoader, or a Frida script targeting Unity.
 *
 * Checked symbols:
 *   il2cpp_init              — runtime initialiser; almost always hooked by
 *                              mod loaders to inject their own init code.
 *   il2cpp_object_new        — object allocator; hooked by memory monitors.
 *   il2cpp_method_get_name   — reflection helper; hooked by method patchers.
 *
 * Returns 0 if all symbols resolve to the same image (clean), 1 if any
 * symbol appears redirected or is unresolvable.
 */
int kagura_il2cpp_check_symbol_redirect(void) {
    static const char *SymbolNames[] = {
        "il2cpp_init",
        "il2cpp_object_new",
        "il2cpp_method_get_name",
        NULL
    };

    /* Resolve all symbols and collect their image paths. */
    const char *reference_image = NULL;

    for (int i = 0; SymbolNames[i] != NULL; ++i) {
        void *sym = dlsym(RTLD_DEFAULT, SymbolNames[i]);
        if (!sym) {
            /*
             * Symbol not found — either this is not an IL2CPP binary or the
             * library has not been loaded yet.  Treat as clean to avoid false
             * positives on non-Unity targets.
             */
            continue;
        }

        Dl_info info;
        if (!dladdr(sym, &info) || !info.dli_fname) {
            /* dladdr failed — this is suspicious. */
            return 1;
        }

        if (!reference_image) {
            reference_image = info.dli_fname;
        } else if (strcmp(reference_image, info.dli_fname) != 0) {
            /*
             * Two IL2CPP symbols resolve to different images.  One of them has
             * been redirected to an injected library.
             */
            return 1;
        }

        /*
         * Extra check: scan the resolved image name for known hook framework
         * strings.  A legitimate IL2CPP image should be named "libil2cpp.so"
         * (Android) or "GameAssembly.dylib" (iOS/macOS).
         */
        static const char *SuspiciousNames[] = {
            "BepInEx",
            "MelonLoader",
            "frida",
            "dobby",
            "substrate",
            "xposed",
            NULL
        };
        for (int j = 0; SuspiciousNames[j] != NULL; ++j) {
            if (strstr(info.dli_fname, SuspiciousNames[j]))
                return 1;
        }

        /*
         * Verify that the resolved symbol address is actually within the
         * bounds of the image by checking dli_fbase.  If dli_saddr differs
         * from sym by more than a reasonable trampoline size (32 bytes) on
         * ARM64 or x86-64, assume an inline hook is present.
         */
        if (info.dli_saddr) {
            uintptr_t sym_addr  = (uintptr_t)sym;
            uintptr_t saddr     = (uintptr_t)info.dli_saddr;
            uintptr_t delta     = (sym_addr > saddr) ? (sym_addr - saddr)
                                                     : (saddr - sym_addr);
            if (delta > 32u)
                return 1;
        }
    }

    return 0;
}

/* =========================================================================
 * 3. kagura_il2cpp_protect_method_table
 * ====================================================================== */

/**
 * kagura_il2cpp_protect_method_table
 *
 * XOR-encodes an array of method pointers with a runtime-generated 64-bit
 * key to prevent a static memory dump from revealing the full function
 * pointer table before execution.
 *
 * The key is derived from:
 *   key = KAGURA_METHOD_TABLE_SEED ^ (uintptr_t)method_table
 *
 * Using the table's own address as part of the key means that the encoded
 * values differ even if the same table content is copied to a new allocation,
 * which defeats simple dump-and-patch attacks.
 *
 * This function is idempotent: calling it twice on the same table restores
 * the original pointers (XOR encryption is self-inverse).  The call pattern
 * in generated code is therefore:
 *
 *   kagura_il2cpp_protect_method_table(table, count);   // encode at startup
 *   // ... protected region ...
 *   ptr = table[i] ^ key;                               // decode per-call (inlined)
 *
 * @method_table: Pointer to the first element of the method pointer array.
 *                Must be writable (not placed in a read-only segment).
 * @count:        Number of pointer-sized entries in the table.
 */
void kagura_il2cpp_protect_method_table(void *method_table, size_t count) {
    if (!method_table || count == 0)
        return;

    uintptr_t *table = (uintptr_t *)method_table;
    uint64_t   key   = (uint64_t)(KAGURA_METHOD_TABLE_SEED) ^
                       (uint64_t)(uintptr_t)method_table;

    /*
     * Rotate key by the lower 6 bits of the count to further diversify keys
     * across tables of different sizes that happen to share the same address
     * (e.g., after dlclose/dlopen recycling).
     */
    unsigned shift = (unsigned)(count & 0x3Fu);
    key = rotl64(key, shift);

    for (size_t i = 0; i < count; ++i) {
        /*
         * Mix index into the key so that adjacent entries are encoded with
         * different values, preventing pattern-based recovery of the table.
         */
        uint64_t entry_key = key ^ (uint64_t)(i * UINT64_C(0x9E3779B97F4A7C15));
        table[i] ^= (uintptr_t)entry_key;
    }
}

/* =========================================================================
 * 4. kagura_protect_global_metadata
 * ====================================================================== */

/**
 * kagura_protect_global_metadata
 *
 * Opens global-metadata.dat at the supplied path and performs a lightweight
 * integrity check:
 *
 *   1. Reads the first 4 bytes and verifies the IL2CPP magic (0xAF 0x1B 0xB1
 *      0xFA in file byte order, which is the little-endian representation of
 *      0xFAB11BAF).
 *   2. Reads the 4-byte file version at offset 4 and checks that it falls
 *      within the known valid range [24, 29] covering Unity 2019.x through
 *      Unity 6.
 *
 * @metadata_path: Path to global-metadata.dat.  Must not be NULL.
 *
 * Returns 0 if the file appears intact, 1 if it has been tampered with or
 * cannot be read.
 */
int kagura_protect_global_metadata(const char *metadata_path) {
    if (!metadata_path)
        return 1;

    FILE *f = fopen(metadata_path, "rb");
    if (!f)
        return 1;

    /*
     * Read the 8-byte header: 4 bytes magic + 4 bytes version.
     * Using a single fread avoids partial-read edge cases.
     */
    uint8_t header[8];
    if (fread(header, 1, sizeof(header), f) != sizeof(header)) {
        fclose(f);
        return 1;
    }
    fclose(f);

    /*
     * Magic check: file bytes [0..3] == 0xAF 0x1B 0xB1 0xFA
     * (IL2CPP_METADATA_MAGIC = 0xFAB11BAF in little-endian memory layout)
     */
    if (header[0] != 0xAFu || header[1] != 0x1Bu ||
        header[2] != 0xB1u || header[3] != 0xFAu) {
        return 1;
    }

    /*
     * Version check: bytes [4..7] hold the metadata format version as a
     * little-endian int32.  Valid values seen in the wild:
     *   24 — Unity 2019.3+
     *   27 — Unity 2020.x
     *   29 — Unity 2021.x / 2022.x / 2023.x / 6
     */
    int32_t version;
    memcpy(&version, header + 4, sizeof(version));

    if (version < 24 || version > 29)
        return 1;

    return 0;
}

/* =========================================================================
 * 5. kagura_il2cpp_anti_memory_scan
 * ====================================================================== */

/*
 * Unity-specific mod loaders and memory editors.  Kept local rather than
 * added to the shared table in core/imagelist.c because "libgg" is short
 * enough to match unrelated libraries (libggml), and a false positive here
 * terminates the process.  The generic frameworks this list used to repeat
 * ("frida-agent", "libsubstrate", "libdobby", ...) live in the shared table.
 */
static const char *const kUnityCheatTools[] = {
    "BepInEx",
    "MelonLoader",
    "Il2CppAssemblyUnhollower",
    "libil2cppdumper",
    "Il2CppInspector",
    "GameGuardian",
    "libGameGuardian",
    "libgg",
    NULL
};

/**
 * kagura_il2cpp_anti_memory_scan
 *
 * Checks for active memory scanners or code-injection frameworks targeting
 * the IL2CPP runtime.  Both layers are platform-independent now: the image
 * walk is dyld on Apple, dl_iterate_phdr plus /proc/self/maps on
 * Linux/Android, and the Toolhelp module list on Windows.
 *
 * Returns 1 if one is found, 0 otherwise.
 */
int kagura_il2cpp_anti_memory_scan(void) {
    /* Shared injection frameworks: dyld on Apple, dl_iterate_phdr plus
     * /proc/self/maps on Linux/Android, module list on Windows.  This
     * replaces the separate maps scan and the two hand-rolled dyld walks
     * (one of which just called kagura_check_substrate_dylib). */
    if (kagura_image_list_contains(kagura_suspicious_image_patterns()))
        return 1;

    /* Unity-specific tooling. */
    if (kagura_image_list_contains(kUnityCheatTools))
        return 1;
    if (kagura_maps_contain(kUnityCheatTools))
        return 1;

    return 0;
}
