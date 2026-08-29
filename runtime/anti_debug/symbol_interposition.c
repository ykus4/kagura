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
 *   3. On Apple platforms, scan the dyld images loaded *after* the main
 *      executable but before its dependencies - the slots
 *      DYLD_INSERT_LIBRARIES occupies - for images that are neither
 *      system-provided nor shipped inside the app bundle.
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
    /* dyld maps the DYLD_INSERT_LIBRARIES images immediately after the main
     * executable and ahead of the executable's own dependencies, so a
     * third-party image in one of the first few slots is the footprint of an
     * insert.  A clean process has libSystem (or the app's own frameworks)
     * there instead.
     *
     * The loop starts at 1 on purpose.  Image 0 is the main executable, and
     * its path is wherever the user installed the app - /Users/..., /opt/...,
     * a build tree - so it matched none of the "known good" prefixes this
     * check used to list.  The result was that the very first iteration
     * returned 1 in every clean macOS process, and kagura_interposition_check()
     * below terminated every process that called it.  (On iOS the bundle sits
     * under /private/, which *was* in the list, so the check merely never
     * fired there instead of always firing.)
     */
    uint32_t count = _dyld_image_count();

    /* Everything the app itself ships is legitimate.  On macOS the embedded
     * frameworks of Foo.app live under Foo.app/Contents/Frameworks/ while the
     * executable is at Foo.app/Contents/MacOS/Foo, so the allowance is
     * anchored at the ".app/" component rather than at the executable's own
     * directory; on iOS the same anchor covers <bundle>/Frameworks/.  For a
     * bare (non-bundled) executable we fall back to its directory. */
    const char *exe = _dyld_get_image_name(0);
    size_t own_prefix = 0;
    if (exe) {
        const char *dot_app = strstr(exe, ".app/");
        if (dot_app) {
            own_prefix = (size_t)(dot_app - exe) + 5;  /* through ".app/" */
        } else {
            const char *slash = strrchr(exe, '/');
            if (slash) own_prefix = (size_t)(slash - exe) + 1;
        }
    }

    /* Only the slots dyld fills before it starts resolving dependencies carry
     * any signal; past that the list is dominated by ordinary transitive
     * dependencies of the app. */
    for (uint32_t i = 1; i < count && i < 8; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;

        /* System-provided.  On current macOS/iOS these images are served out
         * of the dyld shared cache but still report their install paths. */
        if (strncmp(name, "/usr/lib/",        9) == 0) continue;
        if (strncmp(name, "/System/",         8) == 0) continue;
        if (strncmp(name, "/Library/Apple/", 15) == 0) continue;

        /* Shipped inside the app bundle (or next to a bare executable). */
        if (own_prefix && strncmp(name, exe, own_prefix) == 0) continue;

        /* /usr/local and /opt are where Homebrew, MacPorts and every vendored
         * SDK install the dylibs an app links against legitimately.  Treating
         * them as hostile would fire on every Homebrew-linked binary, and a
         * false positive here kills the user's app, so they get the benefit of
         * the doubt: an injection framework living there is still caught by
         * name in anti_debug/loaded_library_scan.c. */
        if (strncmp(name, "/usr/local/",      11) == 0) continue;
        if (strncmp(name, "/opt/",             5) == 0) continue;

        /* An unresolved load path (@rpath/, @executable_path/, ...) tells us
         * nothing about where the image actually came from. */
        if (name[0] != '/') continue;

        return 1;
    }
#endif
    return 0;
}

void kagura_interposition_check(void) {
    if (kagura_symbol_interposed())
        kagura_on_tamper_detected();
}
