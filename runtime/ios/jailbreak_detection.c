/*
 * jailbreak_detection.c - iOS / macOS jailbreak path and sandbox probes
 *
 * Implements the Apple half of the anti-tamper system's environment checks.
 * These are called by the aggregate in core/self_check.c and by any user code
 * that wants to perform environment integrity checks directly.
 *
 * Scope
 * -----
 * Apple only.  runtime/CMakeLists.txt compiles this file inside `if(APPLE)`,
 * so everything here may assume dyld, the iOS sandbox and Mach semantics.
 *
 * Two groups of code used to live here and no longer do, because being in an
 * Apple-only file was actively wrong for them:
 *
 *   - kagura_self_check, kagura_jailbreak_detected and
 *     kagura_runtime_hash_check moved to core/self_check.c.  AntiTamper.cpp
 *     emits calls to them on every non-Wasm target, so a definition that only
 *     exists on Apple meant -kagura-anti-tamper could not link anywhere else.
 *
 *   - The four Android root checks (kagura_check_su_binary,
 *     kagura_check_root_packages, kagura_check_test_keys,
 *     kagura_check_rw_system) moved to android/root_paths.c.  They were behind
 *     `#if defined(__ANDROID__)` in a file only Apple compilers ever see, so
 *     no build had ever compiled them.
 *
 * Public API
 * ----------
 *   int  kagura_check_cydia_path(void);
 *   int  kagura_check_substrate_dylib(void);
 *   int  kagura_check_sandbox_escape(void);
 *   int  kagura_check_fork(void);
 *   int  kagura_check_dyld_env(void);
 *
 * All functions that perform file-system probing or syscalls are individually
 * named so that they can be called stand-alone for testing purposes.
 */

#include "../internal.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

/* -------------------------------------------------------------------------
 * Helper: file-existence probe
 * ---------------------------------------------------------------------- */

/* Shared probe from core/pathprobe.c.  The hardened variant asks stat, access
 * and open rather than stat alone: jailbreak hiders routinely hook exactly one
 * of the three. */
#define path_exists(p) kagura_path_exists_hardened(p)

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
    /* The ten-name local list is superseded by the union table in
     * core/imagelist.c, which also folds case. */
    return kagura_image_list_contains(kagura_suspicious_image_patterns());
}

/* --- Check 3: Sandbox escape via write probe ---------------------------- */

/**
 * kagura_check_sandbox_escape
 *
 * Asks whether the process is permitted to write into /private, which sits
 * outside the application's sandbox container.  On a stock device the sandbox
 * denies this with EPERM/EACCES; on a jailbroken device the restriction is
 * partially or fully lifted.
 *
 * This probes with access(2) rather than by creating a file.  The previous
 * implementation did fopen("/private/jailbreak_test_kagura", "w") and unlinked
 * the result without checking whether the unlink succeeded - and on exactly the
 * devices where the probe fires, the write side has already succeeded, so a
 * failing unlink was entirely possible.  What it left behind was a file whose
 * name contains the string "kagura", permanently, in a world-readable location:
 * a fingerprint that identifies the app as kagura-protected to anyone who looks,
 * which is the opposite of what an anti-tamper library should be doing.  A
 * detection probe must not leave evidence of itself.
 *
 * access(2) is subject to the same sandbox policy as the open would have been,
 * so the answer is unchanged; only the side effect is gone.
 *
 * Returns 1 if writing outside the sandbox is permitted, 0 otherwise.
 */
int kagura_check_sandbox_escape(void) {
    static const char *OutsideSandboxDir = "/private";
    return access(OutsideSandboxDir, W_OK) == 0 ? 1 : 0;
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
