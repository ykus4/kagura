/*===-- runtime/core/pathprobe.c - Shared filesystem existence probes -----===
 *
 * The same three-line stat() wrapper existed six times under four names
 * (path_exists, _path_exists, _ios_path_exists, ...), three of them
 * byte-identical: ios/jailbreak_detection.c, ios/ios_jailbreak_advanced.c and
 * android/android_root_advanced.c.
 *
 * kagura_path_exists is that stat() probe.
 *
 * kagura_path_exists_hardened exists because a bare stat() is the single
 * easiest jailbreak check to defeat: hiders such as Shadow and Liberty Lite
 * hook exactly one of stat / access / open and let the others through, so
 * asking all three costs two extra syscalls and defeats the common bypass.
 * Detection code should prefer it.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

int kagura_path_exists(const char *path) {
    if (!path) return 0;
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES ? 1 : 0;
}

int kagura_path_exists_hardened(const char *path) {
    return kagura_path_exists(path);
}

#else /* POSIX */

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int kagura_path_exists(const char *path) {
    struct stat st;
    if (!path) return 0;
    return (stat(path, &st) == 0) ? 1 : 0;
}

int kagura_path_exists_hardened(const char *path) {
    struct stat st;
    int fd;

    if (!path) return 0;

    if (stat(path, &st) == 0)      return 1;
    if (access(path, F_OK) == 0)   return 1;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

#endif

/* Convenience: NULL-terminated path table, 1 if any entry exists. */
int kagura_any_path_exists(const char *const *paths) {
    if (!paths) return 0;
    for (int i = 0; paths[i] != NULL; ++i)
        if (kagura_path_exists_hardened(paths[i]))
            return 1;
    return 0;
}
