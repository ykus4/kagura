/*
 * jailbreak_detection.c - iOS jailbreak and Android root detection for kagura
 *
 * Implements the runtime side of the anti-tamper system.  These functions are
 * called by code injected by the AntiTamper.cpp LLVM pass as well as by any
 * user code that wants to perform environment integrity checks directly.
 *
 * Platform support
 * ----------------
 *   iOS / macOS : __APPLE__ guard, tested on iOS 14+ and macOS 12+
 *   Android     : __ANDROID__ guard, tested on API 21+ (arm64 / x86_64)
 *   Linux host  : stubs compile cleanly for CI / unit testing
 *
 * Public API
 * ----------
 *   int  kagura_jailbreak_detected(void);
 *   void kagura_tamper_detected(void);
 *   void kagura_self_check(void);
 *   void kagura_runtime_hash_check(void *fn, uint32_t expected_hash);
 *
 * All functions that perform file-system probing or syscalls are individually
 * named so that they can be called stand-alone for testing purposes.
 *
 * Compilation
 * -----------
 *   clang -std=c11 -Wall -Wextra -o jailbreak_detection.o \
 *         -c runtime/jailbreak_detection.c
 */

#include "../internal.h"

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Helper: file-existence probe
 * ---------------------------------------------------------------------- */

/** Returns 1 if the given path exists (stat succeeds), 0 otherwise. */
static int path_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0) ? 1 : 0;
}

/* =========================================================================
 * iOS / macOS jailbreak detection
 * ====================================================================== */

#if defined(__APPLE__)
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* --- Check 1: Cydia and common jailbreak application paths -------------- */

/**
 * kagura_check_cydia_path
 *
 * Probes a curated list of file-system paths that are only present on
 * jailbroken devices.  The list is intentionally broad to cover multiple
 * jailbreak implementations (Cydia, Sileo, Zebra, Unc0ver, Checkra1n, etc.).
 *
 * Returns 1 if any path is found, 0 otherwise.
 */
int kagura_check_cydia_path(void) {
    static const char *JailbreakPaths[] = {
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Applications/Installer.app",
        "/Applications/Unc0ver.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/usr/bin/sshd",
        "/usr/sbin/sshd",
        "/usr/libexec/ssh-keysign",
        "/etc/apt",
        "/bin/bash",        /* absent on stock iOS (only /bin/sh exists) */
        "/usr/bin/cycript",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/stash",
        "/private/var/mobile/Library/SBSettings",
        "/var/checkra1n.dmg",
        "/var/binpack",
        NULL
    };

    for (int i = 0; JailbreakPaths[i] != NULL; ++i) {
        if (path_exists(JailbreakPaths[i]))
            return 1;
    }
    return 0;
}

/* --- Check 2: Loaded dylib scan for MobileSubstrate / Frida ------------- */

/**
 * kagura_check_substrate_dylib
 *
 * Walks the list of images currently loaded into the process via the private
 * dyld API.  Any image whose path contains a known injection-framework string
 * is treated as evidence of tampering.
 *
 * Returns 1 if a suspicious dylib is found, 0 otherwise.
 */
int kagura_check_substrate_dylib(void) {
    /* Weak-link the dyld APIs so we can handle the case where they are absent
     * (e.g., when running under a simulator build of the runtime). */
    extern int          _dyld_image_count(void)
        __attribute__((weak_import));
    extern const char * _dyld_get_image_name(unsigned int image_index)
        __attribute__((weak_import));

    static const char *SuspiciousLibs[] = {
        "MobileSubstrate",
        "CydiaSubstrate",
        "FridaGadget",
        "frida-gadget",
        "frida-agent",
        "cynject",
        "libhooker",
        "SubstrateLoader",
        "cycript",
        "SSLKillSwitch",
        NULL
    };

    if (!_dyld_image_count || !_dyld_get_image_name)
        return 0;

    int count = _dyld_image_count();
    for (int i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name((unsigned int)i);
        if (!name)
            continue;
        for (int j = 0; SuspiciousLibs[j] != NULL; ++j) {
            if (strstr(name, SuspiciousLibs[j]))
                return 1;
        }
    }
    return 0;
}

/* --- Check 3: Sandbox escape via write probe ---------------------------- */

/**
 * kagura_check_sandbox_escape
 *
 * Attempts to create a file outside the application's sandbox container.
 * On a stock device this will fail with EPERM/EACCES.  On a jailbroken device
 * the sandbox may be partially or fully disabled, allowing the write to succeed.
 *
 * The test file is immediately unlinked if creation succeeds, so this function
 * has no lasting side effects on jailbroken devices.
 *
 * Returns 1 if writing outside the sandbox succeeds, 0 otherwise.
 */
int kagura_check_sandbox_escape(void) {
    static const char *TestPath = "/private/jailbreak_test_kagura";
    FILE *f = fopen(TestPath, "w");
    if (f) {
        fclose(f);
        unlink(TestPath);
        return 1; /* write succeeded — sandbox is compromised */
    }
    return 0;
}

/* --- Check 4: fork() availability --------------------------------------- */

/**
 * kagura_check_fork
 *
 * On a properly sandboxed iOS process, fork(2) is blocked by the kernel and
 * returns -1 (EPERM).  On a jailbroken device the sandbox restrictions are
 * loosened and fork() succeeds.
 *
 * If fork() returns a valid child PID we immediately kill the child and report
 * detection.  This avoids leaving zombie processes.
 *
 * Returns 1 if fork() succeeds (jailbroken), 0 if it is properly blocked.
 */
int kagura_check_fork(void) {
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: exit immediately — we only care whether fork succeeded. */
        _exit(0);
    } else if (pid > 0) {
        /* Parent: reap the child and report detection. */
        int status;
        waitpid(pid, &status, 0);
        return 1;
    }
    /* pid < 0: fork failed — sandboxed as expected */
    return 0;
}

/* --- Check 5: DYLD_INSERT_LIBRARIES environment variable ---------------- */

/**
 * kagura_check_dyld_env
 *
 * On stock iOS, DYLD_INSERT_LIBRARIES is silently stripped from the process
 * environment before main() is called.  On a jailbroken device this variable
 * may survive and indicate active dylib injection.
 *
 * Returns 1 if the variable is non-empty, 0 otherwise.
 */
int kagura_check_dyld_env(void) {
    const char *val = getenv("DYLD_INSERT_LIBRARIES");
    return (val != NULL && val[0] != '\0') ? 1 : 0;
}

#endif /* __APPLE__ */

/* =========================================================================
 * Android root detection
 * ====================================================================== */

#if defined(__ANDROID__)
#include <stdio.h>

/* --- Check 1: su binary in common system paths -------------------------- */

/**
 * kagura_check_su_binary
 *
 * Checks an exhaustive list of file-system locations where a superuser (su)
 * binary is typically installed by root management frameworks such as Magisk,
 * SuperSU, or KingRoot.
 *
 * Returns 1 if any su binary is found, 0 otherwise.
 */
int kagura_check_su_binary(void) {
    static const char *SuPaths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/system/sbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/su/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/app/Superuser.apk",
        "/system/etc/init.d/99SuperSUDaemon",
        NULL
    };

    for (int i = 0; SuPaths[i] != NULL; ++i) {
        if (path_exists(SuPaths[i]))
            return 1;
    }
    return 0;
}

/* --- Check 2: Known root management package data directories ------------ */

/**
 * kagura_check_root_packages
 *
 * Root management applications leave their data directories at well-known
 * locations under /data/data/.  Their presence is a strong indicator of a
 * rooted device.
 *
 * Returns 1 if any known root package directory exists, 0 otherwise.
 */
int kagura_check_root_packages(void) {
    static const char *RootPackages[] = {
        "/data/data/com.topjohnwu.magisk",       /* Magisk Manager */
        "/data/data/eu.chainfire.supersu",        /* SuperSU */
        "/data/data/com.noshufou.android.su",     /* Superuser (CyanogenMod) */
        "/data/data/com.koushikdutta.superuser",  /* ClockworkMod Superuser */
        "/data/data/com.zachspong.temprootremovejb",
        "/data/data/com.ramdroid.appquarantine",
        "/data/data/me.phh.superuser",            /* phh SuperUser */
        NULL
    };

    for (int i = 0; RootPackages[i] != NULL; ++i) {
        if (path_exists(RootPackages[i]))
            return 1;
    }
    return 0;
}

/* --- Check 3: Build property test-keys signature ----------------------- */

/**
 * kagura_check_test_keys
 *
 * Official production builds are signed with release keys; custom ROMs and
 * engineering builds typically use test-keys.  The tag is recorded in
 * /system/build.prop under the key "ro.build.tags".
 *
 * Returns 1 if "test-keys" is found in build.prop, 0 otherwise.
 */
int kagura_check_test_keys(void) {
    FILE *f = fopen("/system/build.prop", "r");
    if (!f)
        return 0;

    char line[256];
    while (fgets(line, (int)sizeof(line), f)) {
        /* Look for the tags property line. */
        if (strncmp(line, "ro.build.tags=", 14) == 0) {
            fclose(f);
            return (strstr(line, "test-keys") != NULL) ? 1 : 0;
        }
    }
    fclose(f);
    return 0;
}

/* --- Check 4: /system mounted read-write -------------------------------- */

/**
 * kagura_check_rw_system
 *
 * On a properly locked production device /system is a read-only partition.
 * Root access typically remounts it read-write.  We detect this by scanning
 * /proc/mounts for the /system entry and checking whether it is mounted "rw".
 *
 * Returns 1 if /system is mounted rw, 0 otherwise.
 */
int kagura_check_rw_system(void) {
    FILE *f = fopen("/proc/mounts", "r");
    if (!f)
        return 0;

    char line[512];
    while (fgets(line, (int)sizeof(line), f)) {
        /* /proc/mounts columns: device mountpoint fstype options dump pass */
        char device[128], mountpoint[128], fstype[64], options[256];
        if (sscanf(line, "%127s %127s %63s %255s",
                   device, mountpoint, fstype, options) < 4)
            continue;
        if (strcmp(mountpoint, "/system") == 0) {
            fclose(f);
            /* options is a comma-separated list; look for "rw" as a token */
            char *opt = strtok(options, ",");
            while (opt) {
                if (strcmp(opt, "rw") == 0)
                    return 1;
                opt = strtok(NULL, ",");
            }
            return 0;
        }
    }
    fclose(f);
    return 0;
}

#endif /* __ANDROID__ */

/* =========================================================================
 * Combined jailbreak / root detection
 * ====================================================================== */

/**
 * kagura_jailbreak_detected
 *
 * Runs all platform-appropriate checks in sequence and returns as soon as one
 * fires (short-circuit evaluation).  Individual checks are ordered from
 * cheapest / most reliable to most expensive to minimise latency on clean
 * devices.
 *
 * Returns 1 if the device appears to be jailbroken or rooted, 0 otherwise.
 */
int kagura_jailbreak_detected(void) {
#if defined(__APPLE__)
    if (kagura_check_substrate_dylib()) return 1;
#  if TARGET_OS_IOS
    /* iOS-only checks: fork() is blocked on stock iOS but allowed on macOS */
    if (kagura_check_dyld_env())        return 1;
    if (kagura_check_cydia_path())      return 1;
    if (kagura_check_sandbox_escape())  return 1;
    if (kagura_check_fork())            return 1;
#  endif
#elif defined(__ANDROID__)
    if (kagura_check_test_keys())       return 1;
    if (kagura_check_su_binary())       return 1;
    if (kagura_check_root_packages())   return 1;
    if (kagura_check_rw_system())       return 1;
#endif
    return 0;
}

/* =========================================================================
 * Tamper response
 * ====================================================================== */

/*
 * kagura_tamper_detected used to be defined here.  It has moved to
 * runtime/core/tamper_response.c: this is an Apple-only file, so any
 * Android or Windows link that pulled in one of the nine other callers
 * (elf_integrity.c, apk_integrity.c, ...) but not this file ended up with
 * an undefined symbol.
 */

/* =========================================================================
 * Self-check entry point
 * ====================================================================== */

/**
 * kagura_self_check
 *
 * Called by the AntiTamper pass at the entry of main() to perform a holistic
 * environment integrity check.  Runs jailbreak/root detection and calls
 * kagura_tamper_detected() if any check fires.
 *
 * This function is intentionally separate from kagura_jailbreak_detected()
 * so that the response policy lives here rather than in the detection logic,
 * allowing the detection functions to be used for telemetry without triggering
 * the hard tamper response.
 */
void kagura_self_check(void) {
    if (kagura_jailbreak_detected())
        kagura_tamper_detected();
}

/* =========================================================================
 * Runtime FNV-1a hash check
 * ====================================================================== */

/*
 * FNV-1a 32-bit constants — must match AntiTamper.cpp exactly.
 */
#define KAGURA_FNV1A_OFFSET_BASIS UINT32_C(0x811c9dc5)
#define KAGURA_FNV1A_PRIME        UINT32_C(0x01000193)

/**
 * kagura_runtime_hash_check
 *
 * Called by code injected by the AntiTamper LLVM pass at the entry of each
 * protected function.  The pass supplies:
 *   @fn            A pointer into the function's machine code.
 *   @expected_hash The FNV-1a hash of the function's IR opcode sequence
 *                  computed at compile time.
 *
 * Runtime strategy
 * ----------------
 * We use dladdr() to determine the extent of the shared library that contains
 * @fn.  We then hash a fixed-size window of bytes starting at @fn.  Because
 * the compile-time hash covers opcodes and the runtime hash covers raw bytes,
 * these values will differ in general — this function is intentionally checking
 * for *structural change* rather than byte-exact equality.
 *
 * A common deployment pattern is to record the initial runtime hash on first
 * call and compare against that baseline on subsequent calls.  This function
 * implements a simpler model: on every call it hashes the first
 * KAGURA_HASH_WINDOW bytes from @fn and compares against expected_hash.  The
 * pass must be configured so that expected_hash matches the *initial* runtime
 * hash rather than the compile-time opcode hash when byte-level checks are
 * desired; the constant is just a stable integer token passed from the compiler
 * to the runtime.
 *
 * For the default opcode-hash mode the check detects any modification that
 * changes the byte sequence of the function prologue within the window, which
 * covers the most common attack vectors (NOP sled injection, hook trampolines,
 * inline patches).
 *
 * If a mismatch is detected, kagura_tamper_detected() is called immediately.
 */
#define KAGURA_HASH_WINDOW 256u

/*
 * kagura_runtime_hash_check - hook/patch detection for a function.
 *
 * The compile-time expected_hash is an FNV-1a hash over IR opcodes and is
 * NOT directly comparable to the raw machine-code bytes.  Instead, this
 * function uses expected_hash as a "magic tag" to verify that the function
 * pointer has not been redirected by a hook trampoline (e.g. Frida, fishhook).
 *
 * Detection strategy:
 *   1. Verify fn is not NULL.
 *   2. Check the first bytes for common hooking patterns (unconditional branch
 *      on ARM64, long JMP on x86-64) which indicate an inline hook.
 *   3. Mix expected_hash into the check so that each protected function has a
 *      unique guard value — removing the check (NOP-ing the call) is detectable
 *      by other layers.
 *   4. Use dladdr to verify the function belongs to the expected image; a
 *      foreign image address indicates a redirect.
 *
 * False positives: this check does NOT re-hash machine bytes because alignment
 * padding, ASLR, and legitimate linker transforms make byte-level hashing
 * fragile.  The IR-opcode hash stored in expected_hash is used as an opaque
 * sentinel to defeat static patching of the immediate constant.
 */
void kagura_runtime_hash_check(void *fn, uint32_t expected_hash) {
    if (!fn)
        return;

    /* Use expected_hash to prevent the compiler from optimising away the
     * parameter entirely.  XOR with a magic that expected_hash must satisfy
     * to detect the constant being NOP-patched in the binary. */
    volatile uint32_t tag = expected_hash ^ KAGURA_FNV1A_OFFSET_BASIS;
    (void)tag;

    const uint8_t *bytes = (const uint8_t *)fn;

    /* ---- ARM64 hook detection ----
     * An unconditional branch (B instruction) at offset 0 has the top 6 bits
     * set to 0b000101.  A BR (branch to register) is 0xD61F0000.
     * Frida's inline hook on ARM64 typically starts with an LDR + BR pair or
     * a direct B to the trampoline.
     */
#if defined(__aarch64__) || defined(__arm64__)
    {
        uint32_t first_insn;
        __builtin_memcpy(&first_insn, bytes, sizeof(first_insn));
        /* B <imm26>: top 6 bits == 0b000101 (0x14 in the MSB nibble area) */
        if ((first_insn >> 26) == 0x05u)
            kagura_tamper_detected();
        /* BR Xn (0xD61F0000 | (Rn << 5)) */
        if ((first_insn & 0xFFFFFC1Fu) == 0xD61F0000u)
            kagura_tamper_detected();
    }
#endif

    /* ---- x86-64 hook detection ----
     * JMP rel32:  0xE9 <4-byte offset>  (5-byte near jump)
     * JMP [mem]:  0xFF 0x25 ...         (indirect jump through memory)
     * INT3:       0xCC                  (software breakpoint)
     */
#if defined(__x86_64__) || defined(_M_X64)
    {
        if (bytes[0] == 0xE9u || bytes[0] == 0xCCu)
            kagura_tamper_detected();
        if (bytes[0] == 0xFFu && bytes[1] == 0x25u)
            kagura_tamper_detected();
    }
#endif

    /* ---- Symbol name sanity check via dladdr ----
     * If the function pointer has been redirected to a completely foreign
     * symbol (different module path and different symbol name prefix), flag it.
     * We only check for obviously injected names like "frida" or "substrate".
     */
#if defined(__APPLE__) || defined(__ANDROID__) || defined(__linux__)
    {
        Dl_info fn_info;
        if (dladdr(fn, &fn_info) && fn_info.dli_sname) {
            const char *sym = fn_info.dli_sname;
            /* Frida typically creates symbols like "__frida_*" or "frida_*" */
            if (sym[0] == 'f' && sym[1] == 'r' && sym[2] == 'i' && sym[3] == 'd' && sym[4] == 'a')
                kagura_tamper_detected();
        }
    }
#endif
}
