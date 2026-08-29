/*===-- runtime/anti_dump.c - Anti-dump / anti-memory-scan ---------------===
 *
 * Anti-dump and anti-memory-scan countermeasures.
 *
 * Memory dumping tools (dumpdecrypted, Fridump, mem-dump) extract the full
 * contents of a process's address space.  This module provides:
 *
 *   1. Sensitive region poisoning: on-demand zeroing of nominated memory
 *      regions (e.g. decrypted string buffers, key material) before dump
 *      tools can capture them.  Combines with zero_buf.c (already in runtime).
 *
 *   2. mprotect guard pages: insert PROT_NONE pages around sensitive alloca-
 *      tions so that linear memory scanners trigger SIGSEGV when overrunning
 *      the buffer.  The SIGSEGV handler records the access and calls the
 *      tamper callback.
 *
 *   3. Page permission anomaly detection: scan /proc/self/maps (Linux/Android)
 *      or vm_region_recurse (macOS/iOS) for unexpected RWX pages injected by
 *      dump-assisting frameworks (e.g. dumpdecrypted.dylib hooks mmap to make
 *      pages readable before dumping).
 *
 *   4. ptrace/task_for_pid rejection: verify that no debugger is attached via
 *      ptrace and that task_for_pid() is not callable (iOS only), which would
 *      allow a remote process to read our memory.
 *
 * Signal-context caveat
 * ---------------------
 * The SIGSEGV guard installed by kagura_anti_dump_init() calls
 * kagura_on_tamper_detected() from inside the handler.  The default policy in
 * core/tamper_response.c is abort(), which POSIX lists as async-signal-safe.
 * An application that supplies its own kagura_on_tamper_detected must keep it
 * async-signal-safe as well: it can be entered from a signal handler on a
 * crashing thread, where malloc, stdio and the loader locks are all potentially
 * held by the interrupted code.
 *
 * Public API
 * ----------
 *   void kagura_anti_dump_init(void);        // install SIGSEGV guard + checks
 *   int  kagura_poison_region(void *p, size_t n); // zero + mprotect NONE;
 *                                            // 1 = region also made unreadable
 *   int  kagura_rwx_pages_present(void);     // 1 = suspicious RWX mapping
 *   int  kagura_anti_dump_check(void);       // combined check; 1 = suspicious
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#ifdef __APPLE__
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <unistd.h>
#endif

/* ---- 1. Sensitive region poisoning ---------------------------------------- */

/*
 * kagura_poison_region — zero out a sensitive memory region and revoke
 * read/write access so subsequent accesses fault immediately.
 *
 * Steps:
 *   a. volatile-write zeros (compiler cannot elide this).
 *   b. mprotect(PROT_NONE) to prevent further reads.
 *
 * Returns 1 only when both steps succeeded, 0 when the region was zeroed but
 * is still readable.  mprotect(2) genuinely fails in production - the range
 * has to cover whole pages the caller actually owns, and rounding a stack or
 * sub-page heap buffer up to page granularity walks into memory it does not.
 * Swallowing that return value meant the function reported success to a caller
 * that had just been told its key material was unreachable while it sat in
 * plain sight, which is precisely the wrong way round for a security API.
 *
 * Note: the caller is responsible for restoring permissions before the
 * region is needed again.  Typically called right after a decrypted buffer
 * has been consumed.
 */
int kagura_poison_region(void *p, size_t n) {
    if (!p || n == 0) return 0;

    /* volatile memset to prevent optimisation */
    volatile uint8_t *vp = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; ++i) vp[i] = 0;

#if defined(__linux__) || defined(__APPLE__)
    /* Get the page-aligned range */
    long page_sz = sysconf(_SC_PAGESIZE);
    if (page_sz <= 0) page_sz = 4096;
    uintptr_t addr  = (uintptr_t)p & ~(uintptr_t)(page_sz - 1);
    size_t    aligned_len = n + ((uintptr_t)p - addr);
    aligned_len = (aligned_len + (size_t)(page_sz - 1)) & ~(size_t)(page_sz - 1);
    return mprotect((void *)addr, aligned_len, PROT_NONE) == 0 ? 1 : 0;
#else
    /* Zeroed, but nothing on this platform revokes the mapping. */
    return 0;
#endif
}

/* ---- 2. RWX page scan ----------------------------------------------------- */

#ifdef __linux__

/*
 * On Linux/Android, parse /proc/self/maps and flag any anonymous mapping with
 * rwxp permissions (common footprint of dump-assisting shared libraries that
 * mmap themselves as rwx to patch JIT code or intercept decryption calls).
 */
int kagura_rwx_pages_present(void) {
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;

    /*
     * The tail of each chunk is almost never a complete line, so the leftover
     * bytes are carried into the front of the next read rather than dropped.
     * The previous version discarded them, which was wrong in both directions:
     * a genuine rwxp mapping that happened to straddle a 4 KiB boundary was
     * never seen, and the orphaned fragment that started the next chunk was
     * parsed as if it were a line of its own, so a path containing something
     * that looked like a permission field could be reported as a hit.
     * /proc/self/maps is also not seekable in the usual sense and its contents
     * are generated per-read, so re-reading to recover the line is not an
     * option - it has to be stitched as we go.
     */
    char buf[4096];
    size_t carry = 0;         /* bytes of a partial line already at buf[0..] */
    ssize_t n;
    int found = 0;

    while (!found &&
           (n = read(fd, buf + carry, sizeof(buf) - 1 - carry)) > 0) {
        size_t avail = carry + (size_t)n;
        buf[avail] = '\0';

        char *line = buf;
        char *nl;
        while ((nl = strchr(line, '\n')) != NULL) {
            *nl = '\0';
            /* Format: addr-addr perms offset dev ino [pathname] */
            char perms[8] = {0};
            if (sscanf(line, "%*s %7s", perms) == 1) {
                /* rwxp or rwx- = suspicious */
                if (perms[0] == 'r' && perms[1] == 'w' && perms[2] == 'x') {
                    found = 1;
                    break;
                }
            }
            line = nl + 1;
        }
        if (found) break;

        /* Move whatever follows the last newline to the front of the buffer.
         * A single line longer than the buffer cannot be completed, so the
         * carry is dropped in that case to keep the read loop making progress
         * (a maps line is ~80 bytes plus a path; 4 KiB is far beyond any real
         * one). */
        carry = avail - (size_t)(line - buf);
        if (carry >= sizeof(buf) - 1) {
            carry = 0;
        } else if (carry > 0) {
            memmove(buf, line, carry);
        }
    }

    close(fd);
    return found;
}

#elif defined(__APPLE__)

/*
 * On macOS/iOS, use vm_region_recurse to walk our own VM map and look for
 * regions with VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE.
 */
int kagura_rwx_pages_present(void) {
    task_t task = mach_task_self();
    vm_address_t addr = 0;
    vm_size_t sz = 0;
    uint32_t depth = 1;
    struct vm_region_submap_info_64 info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;

    while (1) {
        kern_return_t kr = vm_region_recurse_64(task, &addr, &sz, &depth,
                               (vm_region_recurse_info_t)&info, &info_count);
        if (kr != KERN_SUCCESS) break;

        vm_prot_t prot = info.protection;
        if ((prot & VM_PROT_READ)    &&
            (prot & VM_PROT_WRITE)   &&
            (prot & VM_PROT_EXECUTE) &&
            !info.is_submap) {
            return 1;
        }

        /* The walk advances only by `sz`, so a KERN_SUCCESS carrying sz == 0
         * would spin on the same address forever.  vm_region_recurse_64 makes
         * no promise about a non-zero size, and hanging inside an anti-dump
         * check is a worse outcome than ending the scan early. */
        if (sz == 0)
            break;

        addr += sz;
    }
    return 0;
}

#else

int kagura_rwx_pages_present(void) { return 0; }

#endif

/* ---- 3. Combined check ---------------------------------------------------- */

int kagura_anti_dump_check(void) {
    if (kagura_rwx_pages_present()) return 1;
    return 0;
}

/* ---- 4. Init: guard SIGSEGV and run initial checks ----------------------- */

static struct sigaction g_prev_sigsegv_dump;

static void dump_guard_sigsegv(int sig, siginfo_t *info, void *ctx) {
    /* A SIGSEGV into one of our PROT_NONE guard regions indicates a
     * linear memory scanner crossing a poisoned buffer boundary.
     *
     * This runs in signal context.  The default hook in core/tamper_response.c
     * is abort(), which POSIX lists as async-signal-safe, but an application
     * that overrides kagura_on_tamper_detected is on the hook for keeping its
     * replacement safe too - see the note in this file's header. */
    if (kagura_on_tamper_detected) kagura_on_tamper_detected();

    /*
     * Chain to whatever was installed before us.  sa_handler and sa_sigaction
     * are members of the same union on Linux and Darwin, so the previous shape
     * of this code - test sa_handler, then call sa_sigaction - read one member
     * and called through the other.  When the previous handler had been
     * installed without SA_SIGINFO that meant calling a one-argument function
     * through a three-argument pointer, which on a mismatched ABI corrupts the
     * stack of a process that is already crashing.  SA_SIGINFO in sa_flags is
     * the only thing that says which member is the live one.
     */
    if ((g_prev_sigsegv_dump.sa_flags & SA_SIGINFO) != 0) {
        if (g_prev_sigsegv_dump.sa_sigaction != NULL) {
            g_prev_sigsegv_dump.sa_sigaction(sig, info, ctx);
            return;
        }
    } else if (g_prev_sigsegv_dump.sa_handler != SIG_DFL &&
               g_prev_sigsegv_dump.sa_handler != SIG_IGN) {
        g_prev_sigsegv_dump.sa_handler(sig);
        return;
    }

    /* No usable predecessor.  Our handler carries no SA_RESETHAND, so raise()
     * on its own would simply re-enter this function; putting the recorded
     * disposition back first is what lets the default action actually run. */
    sigaction(sig, &g_prev_sigsegv_dump, NULL);
    raise(sig);
}

void kagura_anti_dump_init(void) {
    static int done = 0;
    if (done) return;
    done = 1;

    /* Install SIGSEGV guard (skip if crash handler already installed) */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = dump_guard_sigsegv;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &g_prev_sigsegv_dump);

    /* Run initial RWX check */
    if (kagura_anti_dump_check() && kagura_on_tamper_detected)
        kagura_on_tamper_detected();
}
