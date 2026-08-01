/*===-- runtime/core/procfs.c - Shared /proc substring scanning -----------===
 *
 * "open /proc/self/maps, read it line by line, strstr each line against a
 * NULL-terminated pattern table" appeared nine times across the runtime, each
 * copy with its own line buffer size and its own fclose-on-every-return
 * bookkeeping.
 *
 * Note that only the *substring* scans are consolidated here.  The other
 * /proc/self/maps readers - anti_debug/anti_dump.c, android/art_environment.c,
 * android/elf_integrity.c and android/load_order.c - parse the address and
 * permission fields rather than matching text, so they are a genuinely
 * different operation and keep their own parsers.
 *
 * On non-Linux targets there is no /proc; the functions return 0 so that
 * callers do not need their own platform guard.  Equivalent coverage on Apple
 * comes from core/imagelist.c.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#if defined(__linux__) || defined(__ANDROID__)

#include <stdio.h>

int kagura_procfs_contains(const char *path, const char *const *patterns) {
    char line[512];
    FILE *f;

    if (!path || !patterns)
        return 0;

    f = fopen(path, "r");
    if (!f)
        return 0;

    while (fgets(line, (int)sizeof(line), f)) {
        if (kagura_name_matches_any(line, patterns)) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

#else /* no procfs */

int kagura_procfs_contains(const char *path, const char *const *patterns) {
    (void)path;
    (void)patterns;
    return 0;
}

#endif

int kagura_maps_contain(const char *const *patterns) {
    return kagura_procfs_contains("/proc/self/maps", patterns);
}
