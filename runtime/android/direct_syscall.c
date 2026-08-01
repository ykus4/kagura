/*===-- runtime/direct_syscall.c - Direct syscall invocation for hook bypass
 *
 * Issue security-sensitive syscalls directly (bypassing libc/libdl
 *         hooks) to ensure that hook-based countermeasures cannot suppress
 *         detection results.
 *
 * Hooking frameworks (Frida, Substrate) intercept libc wrappers like open(),
 * read(), and getpid().  By invoking the kernel directly via the syscall
 * instruction we bypass those hooks.
 *
 * Supported platforms
 * -------------------
 *   x86-64 Linux/Android  : syscall instruction, Linux ABI numbers
 *   AArch64 Linux/Android : svc #0,  AArch64 ABI numbers
 *   Apple (macOS/iOS)     : Not implemented — Apple SPI syscall numbers change
 *                           between OS releases; use Mach traps instead.
 *
 * Public API
 * ----------
 *   pid_t  kagura_syscall_getpid(void);
 *   int    kagura_syscall_open(const char *path, int flags);
 *   int    kagura_syscall_close(int fd);
 *   ssize_t kagura_syscall_read(int fd, void *buf, size_t count);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>
#include <stddef.h>

#if (defined(__linux__) || defined(__ANDROID__)) && \
    (defined(__x86_64__) || defined(__aarch64__))

#include <sys/types.h>
#include <fcntl.h>

/* ── x86-64 Linux syscall numbers ─────────────────────────────────────── */
#if defined(__x86_64__)
#define SYS_kagura_read    0
#define SYS_kagura_open    2
#define SYS_kagura_close   3
#define SYS_kagura_getpid  39

static inline long kagura_raw_syscall(long nr,
                                       long a0, long a1, long a2) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/* ── AArch64 Linux syscall numbers ─────────────────────────────────────── */
#elif defined(__aarch64__)
#define SYS_kagura_read    63
#define SYS_kagura_open    56   /* openat; use AT_FDCWD = -100 */
#define SYS_kagura_close   57
#define SYS_kagura_getpid  172

static inline long kagura_raw_syscall(long nr,
                                       long a0, long a1, long a2) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    __asm__ volatile (
        "svc #0"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2)
        : "memory"
    );
    return x0;
}
#endif /* arch */

pid_t kagura_syscall_getpid(void) {
    return (pid_t)kagura_raw_syscall(SYS_kagura_getpid, 0, 0, 0);
}

int kagura_syscall_open(const char *path, int flags) {
#if defined(__x86_64__)
    return (int)kagura_raw_syscall(SYS_kagura_open, (long)path, flags, 0);
#else
    /* AArch64: openat(AT_FDCWD, path, flags) */
    return (int)kagura_raw_syscall(SYS_kagura_open, -100, (long)path, flags);
#endif
}

int kagura_syscall_close(int fd) {
    return (int)kagura_raw_syscall(SYS_kagura_close, fd, 0, 0);
}

ssize_t kagura_syscall_read(int fd, void *buf, size_t count) {
    return (ssize_t)kagura_raw_syscall(SYS_kagura_read, fd, (long)buf,
                                       (long)count);
}

#else /* unsupported platform — fall back to libc */

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

pid_t   kagura_syscall_getpid(void)                       { return getpid(); }
int     kagura_syscall_open(const char *path, int flags)  { return open(path, flags); }
int     kagura_syscall_close(int fd)                      { return close(fd); }
ssize_t kagura_syscall_read(int fd, void *buf, size_t n)  { return read(fd, buf, n); }

#endif
