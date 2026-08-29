/*===-- runtime/crash_symbolication.c - Crash symbolication support -------===
 *
 * Crash symbolication support (dSYM / tombstone).
 *
 * When kagura renames or moves functions/variables, stack traces in crash
 * reports become unreadable.  This module provides:
 *
 *   1. Runtime symbol table: a compact mapping from obfuscated runtime address
 *      range → original symbol name, populated at startup from the embedded
 *      kagura symbol map (injected as a module constructor by SymbolMapPass).
 *
 *   2. kagura_symbolicate(pc) — resolve a program-counter address to its
 *      original name using the embedded symbol table.  Falls back to dladdr()
 *      for symbols not in the table.
 *
 *   3. Crash handler wrapper: on SIGSEGV/SIGBUS/SIGABRT the wrapper captures
 *      the backtrace, resolves each frame against the embedded table, and
 *      appends a stack trace to the crash log.
 *
 *      How async-signal-safe this actually is
 *      -------------------------------------
 *      The handler body is: it formats integers by hand and emits them with
 *      write(2), and the log destination is resolved (getenv + open) at
 *      install time rather than from inside the handler.  It does NOT call
 *      snprintf, ctime, getenv, malloc or dladdr, and it does not touch the
 *      g_sym_buf static that kagura_symbolicate() shares with normal callers.
 *
 *      The one exception is backtrace(3), which is not async-signal-safe and
 *      has no safe replacement that still yields a stack.  It is kept
 *      deliberately, warmed up at install time so its lazy initialisation is
 *      already done, and called out here rather than hidden: a crash taken
 *      while backtrace's own locks are held can hang the handler.  It is also
 *      not available on every target (Bionic only declares it from API 33), in
 *      which case the log records the signal but carries no frames.
 *
 *      One capability was dropped rather than kept: the handler no longer
 *      falls back to dladdr(3) for frames that are absent from the embedded
 *      kagura table, so those now print as an address and "<unknown>" instead
 *      of a library symbol name.  dladdr takes the dynamic loader's lock, and
 *      a crash that happens while that lock is held - inside dlopen, or in a
 *      lazy-binding stub, both entirely plausible for the tampering this
 *      library is meant to catch - would deadlock the handler and produce no
 *      log at all.  Addresses plus a symbolicated build are enough to recover
 *      the names offline; a handler that hangs is not recoverable.
 *
 *      Log destination: KAGURA_CRASH_LOG_PATH, which must be an ABSOLUTE path
 *      and is ignored entirely in a setuid/setgid (AT_SECURE) process, since
 *      the handler also runs on SIGABRT - the signal kagura's own tamper
 *      response raises - and would otherwise be a remotely triggerable write
 *      primitive aimed wherever the environment says.  With no usable path
 *      configured the trace goes to stderr; there is no on-disk default.
 *
 *   4. Tombstone helper (Android): reads /data/tombstones/tombstone_* and
 *      applies the kagura symbol table to each frame line.
 *
 * Symbol table format (embedded by SymbolMapPass):
 *   struct kagura_sym_entry { uintptr_t start; uint32_t size; uint32_t name_off; };
 *   Entries are sorted by start address for binary search.
 *   String pool follows the entry array, pointed to by kagura_sym_pool.
 *
 * Thread safety: the symbol table is read-only after __kagura_sym_init().
 *                The crash log file is written with O_APPEND so concurrent
 *                writes from multiple threads are safe on POSIX systems.
 *
 * Public API
 * ----------
 *   void        kagura_sym_init(void);   // call once at startup; auto via ctor
 *   const char *kagura_symbolicate(uintptr_t pc);
 *   void        kagura_install_crash_handler(void);
 *   void        kagura_symbolicate_tombstone(const char *tombstone_path,
 *                                            const char *out_path);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <time.h>
#include <errno.h>

/*
 * backtrace(3) availability.
 *
 * Apple and glibc declare it in <execinfo.h> unconditionally.  Bionic marks it
 * __INTRODUCED_IN(33), so on an Android build with a lower minSdk the header
 * exists but the declaration is compiled out - and the call site below then
 * became an implicit declaration, which C99 makes an error.  This file
 * therefore did not build for Android at all below API 33.  Where the function
 * is unavailable the crash log still records the signal and timestamp; it just
 * has no frames under it.
 */
#ifdef __APPLE__
#include <execinfo.h>
#define KAGURA_HAVE_BACKTRACE 1
#endif

#ifdef __linux__
#if !defined(__ANDROID__) || (defined(__ANDROID_API__) && __ANDROID_API__ >= 33)
#include <execinfo.h>
#define KAGURA_HAVE_BACKTRACE 1
#endif
#include <sys/types.h>
#include <sys/stat.h>
/* getauxval(AT_SECURE) is the Linux answer to issetugid(2).  It is a glibc /
 * Bionic extension, so the include is guarded the same way its use is; musl
 * and anything else fall back to the uid/gid comparison in env_is_untrusted(). */
#if defined(__GLIBC__) || defined(__BIONIC__)
#include <sys/auxv.h>
#endif
#endif

/* Older Android and musl headers do not define O_NOFOLLOW/O_CLOEXEC in every
 * feature-test configuration.  Both are hardening, not correctness, so define
 * them away rather than fail the build. */
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* ---- Embedded symbol table (populated at link time by SymbolMapPass) ---- */

typedef struct {
    uintptr_t start;     /* runtime start address (filled in at __init) */
    uint32_t  size;      /* byte size of the symbol */
    uint32_t  name_off;  /* offset into kagura_sym_pool */
} kagura_sym_entry_t;

/*
 * Empty-table defaults, overridden by the strong definitions the kagura
 * symbol-map emitter provides when -kagura-symmap is active.
 *
 * These must be weak DEFINITIONS, not weak extern declarations.  They used to
 * be declared:
 *
 *     extern kagura_sym_entry_t __kagura_sym_table[] __attribute__((weak));
 *
 * with a comment claiming they "default to empty tables" if not overridden.
 * That is true on ELF, where extern+weak yields a weak-undefined reference
 * that resolves to 0, but NOT on Mach-O: Darwin turns all three into hard
 * undefined symbols, so anything that pulls this object out of the archive
 * fails to link.  No pass emits a call into this file, so the object is
 * normally never pulled and the breakage stayed hidden - but it hits any
 * application that calls the symbolication API directly, and any consumer
 * that force-loads the archive, which is what SwiftPM does.
 *
 * A weak definition is still overridden by a strong one at link time, so the
 * intended -kagura-symmap path is unaffected.
 */
__attribute__((weak)) kagura_sym_entry_t __kagura_sym_table[1] = {{0, 0, 0}};
__attribute__((weak)) uint32_t           __kagura_sym_count    = 0;
__attribute__((weak)) char               __kagura_sym_pool[1]  = {0};

static kagura_sym_entry_t *g_sym_table = NULL;
static uint32_t            g_sym_count = 0;
static const char         *g_sym_pool  = NULL;

/* ---- Symbol table init -------------------------------------------------- */

void kagura_sym_init(void) {
    /* No null guard: a weak definition always has an address, so the old
     * `&__kagura_sym_table != NULL` test was a tautology even before this
     * change.  The real "is there a table?" test is the count, which
     * find_sym() already applies. */
    g_sym_table = __kagura_sym_table;
    g_sym_count = __kagura_sym_count;
    g_sym_pool  = __kagura_sym_pool;
}

/* Module constructor: auto-init before main() */
__attribute__((constructor(200)))
static void __kagura_sym_ctor(void) { kagura_sym_init(); }

/* ---- Binary search over sorted sym table -------------------------------- */

static const kagura_sym_entry_t *find_sym(uintptr_t pc) {
    if (!g_sym_table || g_sym_count == 0) return NULL;
    uint32_t lo = 0, hi = g_sym_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        const kagura_sym_entry_t *e = &g_sym_table[mid];
        if (pc < e->start) {
            hi = mid;
        } else if (pc >= e->start + e->size) {
            lo = mid + 1;
        } else {
            return e;
        }
    }
    return NULL;
}

/* ---- Public symbolication API ------------------------------------------ */

static char g_sym_buf[256];

/*
 * kagura_symbolicate — returns the original symbol name for a PC address.
 * Returns NULL if the address is not in the kagura symbol table and not
 * resolvable via dladdr().
 *
 * The returned pointer is to a static buffer; not thread-safe for concurrent
 * calls, and NOT usable from a signal handler - snprintf and dladdr are both
 * async-signal-unsafe and g_sym_buf is shared with ordinary callers.  The
 * crash handler below uses sig_put_symbol() instead.
 */
const char *kagura_symbolicate(uintptr_t pc) {
    const kagura_sym_entry_t *e = find_sym(pc);
    if (e && g_sym_pool) {
        const char *name = g_sym_pool + e->name_off;
        snprintf(g_sym_buf, sizeof(g_sym_buf), "%s + 0x%lx",
                 name, (unsigned long)(pc - e->start));
        return g_sym_buf;
    }

    /* Fallback: dladdr */
    Dl_info info;
    if (dladdr((void *)pc, &info) && info.dli_sname) {
        snprintf(g_sym_buf, sizeof(g_sym_buf), "%s + 0x%lx",
                 info.dli_sname,
                 (unsigned long)(pc - (uintptr_t)info.dli_saddr));
        return g_sym_buf;
    }
    if (dladdr((void *)pc, &info) && info.dli_fname) {
        snprintf(g_sym_buf, sizeof(g_sym_buf), "%s [0x%lx]",
                 info.dli_fname, (unsigned long)pc);
        return g_sym_buf;
    }
    return NULL;
}

/* ---- Crash handler ------------------------------------------------------ */

#define KAGURA_BT_MAX 64

static struct sigaction g_prev_sigsegv;
static struct sigaction g_prev_sigbus;
static struct sigaction g_prev_sigabrt;

/* Destination for the crash log, resolved once at install time.  Doing the
 * getenv()/open() inside the handler was both unsafe (neither is on the POSIX
 * async-signal-safe list) and, because the handler also fires on SIGABRT and
 * kagura_on_tamper_detected() raises exactly that, an attacker-steerable file
 * write that could be triggered on demand from a tamper-protected binary. */
static int g_crash_fd = -1;

/* ---- Async-signal-safe formatting --------------------------------------- *
 *
 * Everything from here to kagura_install_crash_handler() may run inside a
 * signal handler, so it is restricted to the functions POSIX lists as
 * async-signal-safe: write(2), time(2), sigaction(2), raise(3), _exit(2).
 *
 * The previous implementation of the handler was labelled "signal-safe" but
 * used getenv(3), open(2) on a path derived from the environment, snprintf(3),
 * ctime(3) - which returns a pointer into a shared static the interrupted code
 * may itself have been using - and wrote its result into the file-scope
 * g_sym_buf that kagura_symbolicate() shares with ordinary callers.  Any of
 * those can deadlock or produce garbage when the crash interrupted the same
 * subsystem.  Hence the hand-rolled integer formatting below: it is not
 * elegant, but it is the part of the claim that has to be true.
 *
 * One capability is knowingly kept despite not being async-signal-safe:
 * backtrace(3).  There is no safe substitute that still produces a usable
 * stack, so it stays, and kagura_install_crash_handler() calls it once at
 * install time to get its lazy initialisation (and the loader work behind it)
 * out of the way while the process is still healthy.  The residual risk is a
 * crash that happens while backtrace's own locks are held; in that case the
 * handler hangs instead of writing a log.  This is stated in the file header
 * rather than papered over.
 */

/* Append a NUL-terminated string, truncating at the buffer end. */
static size_t sig_puts(char *dst, size_t cap, size_t off, const char *s) {
    if (!s) return off;
    while (*s && off + 1 < cap) dst[off++] = *s++;
    return off;
}

/* Append a signed decimal integer. */
static size_t sig_putd(char *dst, size_t cap, size_t off, long long v) {
    char tmp[24];
    size_t n = 0;
    unsigned long long u;
    if (v < 0) {
        if (off + 1 < cap) dst[off++] = '-';
        /* Negate through unsigned so LLONG_MIN does not overflow. */
        u = (unsigned long long)(-(v + 1)) + 1ULL;
    } else {
        u = (unsigned long long)v;
    }
    do { tmp[n++] = (char)('0' + (int)(u % 10ULL)); u /= 10ULL; } while (u);
    while (n > 0 && off + 1 < cap) dst[off++] = tmp[--n];
    return off;
}

/* Append lowercase hex, zero-padded to `width` digits (0 = no padding). */
static size_t sig_putx(char *dst, size_t cap, size_t off,
                       unsigned long long v, size_t width) {
    static const char kHex[] = "0123456789abcdef";
    char tmp[16];
    size_t n = 0;
    do { tmp[n++] = kHex[v & 0xFULL]; v >>= 4; } while (v && n < sizeof(tmp));
    while (n < width && n < sizeof(tmp)) tmp[n++] = '0';
    while (n > 0 && off + 1 < cap) dst[off++] = tmp[--n];
    return off;
}

/* write(2) with the short-write and EINTR loop POSIX requires. */
static void sig_write(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w > 0) { off += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        return;
    }
}

/*
 * Signal-context symbolication.
 *
 * kagura_symbolicate() cannot be used here: it formats with snprintf, parks
 * the result in the shared g_sym_buf, and falls back to dladdr(3), which takes
 * the dynamic loader's lock - if the crash happened while that lock was held
 * the handler deadlocks instead of producing the log it exists to produce.
 * The embedded table is read-only once kagura_sym_init() has run, so a lookup
 * in it is safe; that is all this does, and frames outside the table are
 * reported as <unknown> rather than resolved.
 */
static size_t sig_put_symbol(char *dst, size_t cap, size_t off, uintptr_t pc) {
    const kagura_sym_entry_t *e = find_sym(pc);
    if (!e || !g_sym_pool)
        return sig_puts(dst, cap, off, "<unknown>");
    off = sig_puts(dst, cap, off, g_sym_pool + e->name_off);
    off = sig_puts(dst, cap, off, " + 0x");
    return sig_putx(dst, cap, off, (unsigned long long)(pc - e->start), 0);
}

static void write_crash_log(int sig, const char *sig_name) {
    int fd = g_crash_fd;
    if (fd < 0) return;

    char line[512];
    size_t off = 0;

    /* time(2) is async-signal-safe; ctime(3) is not, so the log carries a raw
     * UNIX timestamp instead of a formatted date. */
    off = sig_puts(line, sizeof(line), off, "\n--- kagura crash: signal ");
    off = sig_putd(line, sizeof(line), off, sig);
    off = sig_puts(line, sizeof(line), off, " (");
    off = sig_puts(line, sizeof(line), off, sig_name);
    off = sig_puts(line, sizeof(line), off, ") at unix time ");
    off = sig_putd(line, sizeof(line), off, (long long)time(NULL));
    off = sig_puts(line, sizeof(line), off, " ---\n");
    sig_write(fd, line, off);

    /* Backtrace — see the async-signal-safety note above. */
    void *frames[KAGURA_BT_MAX];
    int nframes = 0;
#ifdef KAGURA_HAVE_BACKTRACE
    nframes = backtrace(frames, KAGURA_BT_MAX);
#endif

    for (int i = 0; i < nframes; ++i) {
        uintptr_t pc = (uintptr_t)frames[i];
        off = 0;
        off = sig_puts(line, sizeof(line), off, "  #");
        if (i < 10) off = sig_puts(line, sizeof(line), off, "0");
        off = sig_putd(line, sizeof(line), off, i);
        off = sig_puts(line, sizeof(line), off, " 0x");
        off = sig_putx(line, sizeof(line), off, (unsigned long long)pc, 16);
        off = sig_puts(line, sizeof(line), off, "  ");
        off = sig_put_symbol(line, sizeof(line), off, pc);
        off = sig_puts(line, sizeof(line), off, "\n");
        sig_write(fd, line, off);
    }
}

static void kagura_crash_handler(int sig, siginfo_t *info, void *ctx) {
    /* A handler must leave errno as it found it: the interrupted code may be
     * between a failing call and its errno check. */
    int saved_errno = errno;

    const char *sig_name = "UNKNOWN";
    if (sig == SIGSEGV) sig_name = "SIGSEGV";
    else if (sig == SIGBUS)  sig_name = "SIGBUS";
    else if (sig == SIGABRT) sig_name = "SIGABRT";

    write_crash_log(sig, sig_name);
    errno = saved_errno;

    /* Re-raise to previous handler so the process terminates normally */
    struct sigaction *prev = NULL;
    if (sig == SIGSEGV) prev = &g_prev_sigsegv;
    else if (sig == SIGBUS)  prev = &g_prev_sigbus;
    else if (sig == SIGABRT) prev = &g_prev_sigabrt;

    /*
     * sa_handler and sa_sigaction are two members of the same union on Linux
     * and Darwin.  Testing sa_handler and then calling sa_sigaction, as this
     * used to, reads one member and calls through the other: if the previous
     * handler was installed without SA_SIGINFO it is a one-argument function
     * being called through a three-argument pointer.  SA_SIGINFO in sa_flags
     * is the only thing that says which member holds the live pointer.
     */
    if (prev) {
        if ((prev->sa_flags & SA_SIGINFO) != 0) {
            if (prev->sa_sigaction != NULL) {
                prev->sa_sigaction(sig, info, ctx);
                return;
            }
        } else if (prev->sa_handler != SIG_DFL &&
                   prev->sa_handler != SIG_IGN) {
            prev->sa_handler(sig);
            return;
        }
    }

    /* SA_RESETHAND put the default disposition back before this handler was
     * entered, so raising the signal again runs the default action. */
    raise(sig);
}

/*
 * Is the environment untrustworthy for choosing a file to write?
 *
 * A setuid/setgid (or otherwise AT_SECURE) process inherits its environment
 * from whoever launched it, so honouring KAGURA_CRASH_LOG_PATH there hands
 * that caller a write primitive with our elevated credentials, triggerable by
 * making the process crash.
 */
static int env_is_untrusted(void) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__) || defined(__DragonFly__)
    return issetugid() != 0;
#elif defined(__linux__) && (defined(__GLIBC__) || defined(__BIONIC__))
    return getauxval(AT_SECURE) != 0;
#else
    return getuid() != geteuid() || getgid() != getegid();
#endif
}

/*
 * Resolve and open the crash log once, before any signal can arrive.
 *
 * The path must be absolute.  A relative path - which is what the old default
 * of "kagura_crash.log" was - resolves against whatever the working directory
 * happens to be when the process crashes, which is neither predictable nor
 * necessarily writable, and in a directory an attacker controls it is a file
 * they choose.  With no usable path configured we fall back to stderr rather
 * than inventing a location on disk.
 */
static void open_crash_log(void) {
    const char *log_path = env_is_untrusted()
                               ? NULL
                               : getenv("KAGURA_CRASH_LOG_PATH");

    if (!log_path || log_path[0] != '/') {
        g_crash_fd = STDERR_FILENO;
        return;
    }

    /* O_NOFOLLOW refuses a symlink as the final component, so the classic
     * "point the log at /etc/something and let the crash append to it" trick
     * needs write access to the containing directory as well.  O_CLOEXEC keeps
     * the descriptor out of anything the process execs. */
    int fd = open(log_path,
                  O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    g_crash_fd = (fd >= 0) ? fd : STDERR_FILENO;
}

/*
 * kagura_install_crash_handler — install signal handlers for SIGSEGV/SIGBUS/
 * SIGABRT that append a symbolicated stack trace to the crash log.
 *
 * Safe to call multiple times; subsequent calls are no-ops.
 */
void kagura_install_crash_handler(void) {
    static int installed = 0;
    if (installed) return;
    installed = 1;

    /* Everything the handler needs is resolved here, while it is still legal
     * to call getenv(3) and open(2). */
    open_crash_log();

#ifdef KAGURA_HAVE_BACKTRACE
    /* Force backtrace(3)'s one-time initialisation now: the first call may
     * allocate and pull in the unwinder, neither of which we want to be doing
     * for the first time from a crashing thread. */
    {
        void *warmup[2];
        (void)backtrace(warmup, 2);
    }
#endif

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = kagura_crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, &g_prev_sigsegv);
    sigaction(SIGBUS,  &sa, &g_prev_sigbus);
    sigaction(SIGABRT, &sa, &g_prev_sigabrt);
}

/* ---- Tombstone symbolication (Android) ---------------------------------- */

/*
 * kagura_symbolicate_tombstone — read an Android tombstone file, replace any
 * obfuscated symbol names found in the kagura symbol table with their original
 * names, and write the result to out_path.
 *
 * Tombstone frame lines look like:
 *   #00 pc 0000abcd  /data/app/.../lib/arm64/libnative.so (_Z9obfname+24)
 *
 * We look for the hex PC and run it through kagura_symbolicate().  If a match
 * is found, the original name replaces the mangled/obfuscated one.
 */
void kagura_symbolicate_tombstone(const char *tombstone_path,
                                   const char *out_path) {
    if (!tombstone_path || !out_path) return;

    FILE *fin = fopen(tombstone_path, "r");
    if (!fin) return;
    FILE *fout = fopen(out_path, "w");
    if (!fout) { fclose(fin); return; }

    char line[1024];
    while (fgets(line, sizeof(line), fin)) {
        /*
         * Look for tombstone frame lines: "  #NN pc XXXXXXXX  <path> (<sym>)"
         * Extract the PC (hex), try to symbolicate, and replace if found.
         */
        const char *pc_prefix = " pc ";
        char *pc_pos = strstr(line, pc_prefix);
        if (pc_pos) {
            uintptr_t pc = (uintptr_t)strtoull(pc_pos + 4, NULL, 16);
            if (pc) {
                const char *sym = kagura_symbolicate(pc);
                if (sym) {
                    /* Find the paren-enclosed symbol name and replace it */
                    char *lp = strrchr(line, '(');
                    char *rp = strrchr(line, ')');
                    if (lp && rp && rp > lp) {
                        /* Write up to and including the '(' */
                        char prefix_buf[1024];
                        size_t prefix_len = (size_t)(lp - line) + 1;
                        if (prefix_len < sizeof(prefix_buf)) {
                            memcpy(prefix_buf, line, prefix_len);
                            prefix_buf[prefix_len] = '\0';
                            fprintf(fout, "%s%s)\n", prefix_buf, sym);
                            continue;
                        }
                    }
                }
            }
        }
        fputs(line, fout);
    }

    fclose(fin);
    fclose(fout);
}
