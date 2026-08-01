/*===-- runtime/symbol_interposition.c - Symbol interposition detection ---===
 *
 * Detect LD_PRELOAD / DYLD_INSERT_LIBRARIES symbol interposition.
 *
 * When an attacker uses LD_PRELOAD (Linux/Android) or DYLD_INSERT_LIBRARIES
 * (Apple) to interpose symbols, the resolved address of a known function will
 * differ from its address inside its canonical shared library.
 *
 * Detection strategy
 * ------------------
 *   1. For a set of well-known libc/libdl functions, resolve the symbol via
 *      dlsym(RTLD_DEFAULT, name) and dlsym(RTLD_NEXT, name).
 *      If these return different addresses the symbol has been interposed.
 *
 *   2. On Linux/Android, RTLD_DEFAULT vs RTLD_NEXT comparison catches
 *      LD_PRELOAD interposition directly.
 *
 *   3. On Apple platforms, scan early dyld images for unexpected paths that
 *      are not under the system library prefixes.
 *
 * Public API
 * ----------
 *   int  kagura_symbol_interposed(void);   // 1 = interposition detected
 *   void kagura_interposition_check(void); // calls kagura_on_tamper_detected()
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#endif

/* ── Probe list: symbols that frameworks commonly interpose ─────────────── */
/* Only the dlsym-based Linux/Android path consults this; the Apple path below
 * inspects the dyld image list instead. */

#if defined(__linux__) || defined(__ANDROID__)
static const char *const kProbedSymbols[] = {
    "open",
    "fopen",
    "read",
    "write",
    "mmap",
    "dlopen",
    "dlsym",
    NULL
};
#endif

/* ── RTLD_DEFAULT vs RTLD_NEXT check ────────────────────────────────────── */

int kagura_symbol_interposed(void) {
#if defined(__linux__) || defined(__ANDROID__)
    for (int i = 0; kProbedSymbols[i] != NULL; ++i) {
        void *def  = dlsym(RTLD_DEFAULT, kProbedSymbols[i]);
        void *next = dlsym(RTLD_NEXT,    kProbedSymbols[i]);
        /* If RTLD_DEFAULT resolves differently from RTLD_NEXT the first
         * shared object in the search order is overriding the symbol. */
        if (def && next && def != next)
            return 1;
    }
#elif defined(__APPLE__)
    /* On Apple, check whether any early-loaded image comes from an unexpected
     * path (not under /usr/lib or /System/Library). */
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count && i < 64; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        /* Skip known good prefixes */
        if (strncmp(name, "/usr/lib",          8) == 0) continue;
        if (strncmp(name, "/System/",          8) == 0) continue;
        if (strncmp(name, "/private/",         9) == 0) continue;
        if (strncmp(name, "@rpath/",           7) == 0) continue;
        if (strncmp(name, "@executable_path", 16) == 0) continue;
        if (strncmp(name, "@loader_path",     12) == 0) continue;
        /* An unexpected image in the first few slots is suspicious */
        if (i < 3)
            return 1;
    }
#endif
    return 0;
}

void kagura_interposition_check(void) {
    if (kagura_symbol_interposed())
        kagura_on_tamper_detected();
}
