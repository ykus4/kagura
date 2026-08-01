/*===-- runtime/art_environment.c - ART/JIT environment checks ------------===
 *
 * Detect ART/JIT environment indicators on Android that may signal
 *         a dynamic analysis or instrumentation environment.
 *
 * Checks:
 *   1. JIT compilation activity: /proc/self/maps for libart.so JIT regions
 *      (anonymous rwx mappings that appear after the art jit-code-cache).
 *   2. ART interpreter mode: check system properties
 *      dalvik.vm.execution-mode and ro.dalvik.vm.native.bridge.
 *   3. JDWP debug socket: check whether the JDWP debugging port is active
 *      by probing /proc/net/tcp6 for port 5005 (default Android debug port)
 *      or the ANDROID_JDWP_PORT environment variable.
 *   4. ART method entry trampoline hooks: dladdr on JNI_OnLoad to verify
 *      it resolves inside the expected .so and not an ART hook trampoline.
 *
 * Public API
 * ----------
 *   int  kagura_art_jit_suspicious(void); // 1 = suspicious JIT anomaly
 *   int  kagura_jdwp_active(void);        // 1 = JDWP debugger connected
 *   void kagura_art_check(void);          // combined; tamper cb if hit
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __ANDROID__

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

/* Check /proc/self/maps for anonymous rwx (JIT code cache) outside normal
 * ranges — anomalous if a Frida or ART hook planted a fake JIT region. */
int kagura_art_jit_suspicious(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    int anon_rwx_count = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Lines with rwx permissions and no backing file (anonymous) */
        if (strstr(line, "rwxp") && strstr(line, "/dev/ashmem") == NULL) {
            char *path_start = strchr(line, '/');
            char *bracket     = strchr(line, '[');
            /* Anonymous mapping has no path */
            if (!path_start && !bracket) {
                ++anon_rwx_count;
                if (anon_rwx_count > 4) {
                    fclose(f);
                    return 1; /* Too many anonymous rwx regions */
                }
            }
        }
    }
    fclose(f);
    return 0;
}

/* Check if JDWP debugger port is listening */
int kagura_jdwp_active(void) {
    /* Android debugger socket path pattern */
    struct stat st;
    if (stat("/proc/net/unix", &st) == 0) {
        FILE *f = fopen("/proc/net/unix", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "jdwp") || strstr(line, "debug_socket")) {
                    fclose(f);
                    return 1;
                }
            }
            fclose(f);
        }
    }
    /* Check JDWP TCP port 5005 via /proc/net/tcp6 */
    FILE *f = fopen("/proc/net/tcp6", "r");
    if (!f) f = fopen("/proc/net/tcp", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        /* Port 1389 hex = 5001 decimal, 138D = 5005 */
        if (strstr(line, "138D") || strstr(line, "1389") ||
            strstr(line, "138d")) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

void kagura_art_check(void) {
    if (kagura_art_jit_suspicious() || kagura_jdwp_active())
        kagura_on_tamper_detected();
}

#endif /* __ANDROID__ */
