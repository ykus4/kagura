/*
 * anti_debug.c - Runtime anti-debug helpers for kagura
 *
 * These are linked into the target application alongside the obfuscated code.
 * The LLVM pass (AntiDebug.cpp) generates calls to these functions inside
 * a module constructor that runs before any user code.
 *
 * Targets: iOS (Darwin) and Android (Linux)
 */

#include "../internal.h"

#include <stdlib.h>
#include <string.h>

// The tamper response hook lives in core/tamper_response.c.

// ---- TracerPid check (Android / Linux) ----

#ifdef __linux__
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int kagura_check_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            return pid != 0 ? 1 : 0;
        }
    }
    fclose(f);
    return 0;
}

// Check /proc/self/maps for known analysis framework strings
int kagura_check_maps(void) {
    static const char *Patterns[] = {
        "frida-agent",
        "frida-gadget",
        "libsubstrate",
        "libcycript",
        "xposed",
        NULL
    };

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; Patterns[i]; ++i) {
            if (strstr(line, Patterns[i])) {
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

// Check if Frida's default port (27042) is open on localhost
int kagura_check_frida_port(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = __builtin_bswap16(27042);
    addr.sin_addr.s_addr = 0x0100007F; // 127.0.0.1

    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    return result == 0 ? 1 : 0; // connected = Frida is running
}

#endif // __linux__

// ---- TracerPid check: non-Linux implementations ----
//
// AntiDebug.cpp emits an unconditional call to kagura_check_tracer_pid on
// every target, so the symbol must always exist.  Without this block the
// -kagura-anti-debug pass could not link anywhere except Linux.

#if !defined(__linux__)
#if defined(__APPLE__)

#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

// Darwin has no /proc.  The canonical equivalent is the P_TRACED flag in the
// kinfo_proc record returned by sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID).
int kagura_check_tracer_pid(void) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };

    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0)
        return 0; // query failed — assume clean rather than false-positive
    return (info.kp_proc.p_flag & P_TRACED) != 0 ? 1 : 0;
}

#else // neither Linux nor Apple

// Portable fallback so the symbol always resolves.  Windows has its own,
// much better checks in runtime/windows/anti_debug.c.
int kagura_check_tracer_pid(void) {
    return 0;
}

#endif
#endif // !__linux__

// ---- iOS / macOS checks ----

#ifdef __APPLE__
#include <dlfcn.h>

// Scan loaded dylibs for known injection frameworks
int kagura_check_loaded_dylibs(void) {
    // Use weak-linked dyld APIs to avoid hard dependency
    extern int _dyld_image_count(void) __attribute__((weak_import));
    extern const char *_dyld_get_image_name(unsigned) __attribute__((weak_import));

    static const char *Patterns[] = {
        "FridaGadget",
        "frida-gadget",
        "cynject",
        "libsubstrate",
        "cycript",
        "libhooker",
        NULL
    };

    if (!_dyld_image_count || !_dyld_get_image_name)
        return 0;

    int count = _dyld_image_count();
    for (int i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name((unsigned)i);
        if (!name) continue;
        for (int j = 0; Patterns[j]; ++j) {
            if (strstr(name, Patterns[j]))
                return 1;
        }
    }
    return 0;
}

#endif // __APPLE__

/* ---- RTLD_DEFAULT helper for CallIndirection pass ---- */

#include <dlfcn.h>

/**
 * kagura_rtld_default_handle
 *
 * Returns the platform-appropriate handle for dlsym() to search the default
 * symbol namespace.
 *
 *   macOS / iOS : RTLD_DEFAULT = ((void *) -2)
 *   Linux / Android : RTLD_DEFAULT = NULL
 *
 * This function exists so the CallIndirectionPass can emit a call to it
 * rather than embedding a platform-specific constant in the IR.
 */
void *kagura_rtld_default_handle(void) {
#if defined(__APPLE__)
    /* On Darwin, RTLD_DEFAULT is defined as ((void *) -2) in <dlfcn.h> */
    return RTLD_DEFAULT;
#else
    /* On Linux/Android, RTLD_DEFAULT is NULL */
    return RTLD_DEFAULT;
#endif
}
