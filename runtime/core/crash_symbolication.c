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
 *   3. Signal-safe crash handler wrapper: on SIGSEGV/SIGBUS/SIGABRT the
 *      wrapper captures the backtrace (via backtrace()/unwind), symbolicates
 *      each frame, and appends a human-readable stack trace to a kagura crash
 *      log file at KAGURA_CRASH_LOG_PATH (default: kagura_crash.log).
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

#ifdef __APPLE__
#include <execinfo.h>
#endif

#ifdef __linux__
#include <execinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

/* ---- Embedded symbol table (populated at link time by SymbolMapPass) ---- */

typedef struct {
    uintptr_t start;     /* runtime start address (filled in at __init) */
    uint32_t  size;      /* byte size of the symbol */
    uint32_t  name_off;  /* offset into kagura_sym_pool */
} kagura_sym_entry_t;

/*
 * These weak symbols are overridden by the kagura linker when -kagura-symmap
 * is active.  If not overridden they default to empty tables.
 */
extern kagura_sym_entry_t __kagura_sym_table[] __attribute__((weak));
extern uint32_t            __kagura_sym_count   __attribute__((weak));
extern char                __kagura_sym_pool[]  __attribute__((weak));

static kagura_sym_entry_t *g_sym_table = NULL;
static uint32_t            g_sym_count = 0;
static const char         *g_sym_pool  = NULL;

/* ---- Symbol table init -------------------------------------------------- */

void kagura_sym_init(void) {
    if (&__kagura_sym_table != NULL && &__kagura_sym_count != NULL &&
        &__kagura_sym_pool  != NULL) {
        g_sym_table = __kagura_sym_table;
        g_sym_count = __kagura_sym_count;
        g_sym_pool  = __kagura_sym_pool;
    }
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
 * calls.  Crash handlers should use a local buffer.
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

/* ---- Signal-safe crash handler ----------------------------------------- */

#define KAGURA_CRASH_LOG_PATH "kagura_crash.log"
#define KAGURA_BT_MAX         64

static struct sigaction g_prev_sigsegv;
static struct sigaction g_prev_sigbus;
static struct sigaction g_prev_sigabrt;

static void write_crash_log(int sig, const char *sig_name) {
    const char *log_path = getenv("KAGURA_CRASH_LOG_PATH");
    if (!log_path || !*log_path) log_path = KAGURA_CRASH_LOG_PATH;

    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;

    /* Timestamp */
    time_t now = time(NULL);
    char line[512];
    int n = snprintf(line, sizeof(line), "\n--- kagura crash: signal %d (%s) at %s",
                     sig, sig_name, ctime(&now));
    if (n > 0) write(fd, line, (size_t)n);

    /* Backtrace */
    void *frames[KAGURA_BT_MAX];
    int nframes = 0;
#if defined(__APPLE__) || defined(__linux__)
    nframes = backtrace(frames, KAGURA_BT_MAX);
#endif

    for (int i = 0; i < nframes; ++i) {
        uintptr_t pc = (uintptr_t)frames[i];
        const char *sym = kagura_symbolicate(pc);
        if (sym) {
            n = snprintf(line, sizeof(line), "  #%02d 0x%016lx  %s\n",
                         i, (unsigned long)pc, sym);
        } else {
            n = snprintf(line, sizeof(line), "  #%02d 0x%016lx  <unknown>\n",
                         i, (unsigned long)pc);
        }
        if (n > 0) write(fd, line, (size_t)n);
    }
    close(fd);
}

static void kagura_crash_handler(int sig, siginfo_t *info, void *ctx) {
    (void)info; (void)ctx;
    const char *sig_name = "UNKNOWN";
    if (sig == SIGSEGV) sig_name = "SIGSEGV";
    else if (sig == SIGBUS)  sig_name = "SIGBUS";
    else if (sig == SIGABRT) sig_name = "SIGABRT";

    write_crash_log(sig, sig_name);

    /* Re-raise to previous handler so the process terminates normally */
    struct sigaction *prev = NULL;
    if (sig == SIGSEGV) prev = &g_prev_sigsegv;
    else if (sig == SIGBUS)  prev = &g_prev_sigbus;
    else if (sig == SIGABRT) prev = &g_prev_sigabrt;

    if (prev && prev->sa_handler != SIG_DFL && prev->sa_handler != SIG_IGN)
        prev->sa_sigaction(sig, info, ctx);
    else
        raise(sig);
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
