/*===-- runtime/core/random.c - Runtime entropy source --------------------===
 *
 * kagura_random_u64() is emitted by the PointerAuth pass
 * (lib/Transforms/AntiAnalysis/PointerAuth.cpp) into the software-PAC key
 * constructor:
 *
 *     kagura_pac_key = kagura_random_u64();
 *
 * The constructor runs at priority 65534, i.e. before main() and before most
 * library initialisation, so the implementation must not depend on anything
 * that is itself initialised by a constructor.
 *
 * The symbol is weak: an application with a vetted CSPRNG can override it.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <bcrypt.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#  include <stdlib.h>            /* arc4random_buf */
#elif defined(__linux__) || defined(__ANDROID__)
#  include <errno.h>
#  include <fcntl.h>
#  include <unistd.h>
#  if defined(__GLIBC__) || defined(__ANDROID__)
#    include <sys/random.h>      /* getrandom */
#  endif
#endif

#include <time.h>

/* Last-resort mixer: ASLR of the stack and of this function, plus the clock.
 * Not cryptographic, but it still differs on every run, which is all the
 * software-PAC tagging scheme needs from it. */
static uint64_t entropy_fallback(void) {
    volatile uint64_t stack_probe = 0;
    uint64_t z = (uint64_t)(uintptr_t)&stack_probe;
    z ^= (uint64_t)(uintptr_t)(void *)&entropy_fallback;
    z ^= (uint64_t)time(NULL);
#if defined(CLOCK_MONOTONIC)
    {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
            z ^= (uint64_t)ts.tv_nsec * UINT64_C(0x9e3779b97f4a7c15);
    }
#endif
    /* splitmix64 finaliser */
    z += UINT64_C(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

__attribute__((weak))
uint64_t kagura_random_u64(void) {
    uint64_t v = 0;

#if defined(_WIN32)
    if (BCryptGenRandom(NULL, (PUCHAR)&v, (ULONG)sizeof(v),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 && v)
        return v;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    arc4random_buf(&v, sizeof(v));
    if (v) return v;
#elif defined(__linux__) || defined(__ANDROID__)
#  if defined(__GLIBC__) || defined(__ANDROID__)
    {
        ssize_t n = getrandom(&v, sizeof(v), 0);
        if (n == (ssize_t)sizeof(v) && v)
            return v;
    }
#  endif
    {
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t n = read(fd, &v, sizeof(v));
            close(fd);
            if (n == (ssize_t)sizeof(v) && v)
                return v;
        }
    }
#endif

    /* Mix the fallback in rather than replacing, so a partially successful
     * OS read still contributes. */
    return v ^ entropy_fallback();
}
