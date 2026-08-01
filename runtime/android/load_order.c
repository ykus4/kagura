/*===-- runtime/load_order.c - Native library load order control ----------===
 *
 * Control native library load order on Android to ensure that
 *         kagura_runtime.so loads before third-party SDKs or game engines,
 *         and to verify that the expected set of libraries is present in the
 *         expected order.
 *
 * Strategy:
 *   1. At JNI_OnLoad time, record the Dl_info.dli_fname of the current
 *      library to know our own path and confirm we are loaded first.
 *   2. Scan /proc/self/maps to build a list of .so load addresses and
 *      order them by base address.  If any known security-relevant library
 *      (e.g. an injection shim) appears at a lower address than us, flag it.
 *   3. Provide kagura_assert_load_order() which the app can call in JNI_OnLoad
 *      to enforce that kagura was the first native library loaded.
 *
 * Public API
 * ----------
 *   void kagura_record_load_address(void);    // call from kagura JNI_OnLoad
 *   int  kagura_load_order_valid(void);       // 1 = we loaded first
 *   void kagura_load_order_check(void);       // tamper cb if order violated
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __ANDROID__

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static uintptr_t kOwnBaseAddress = 0;

/* Record our own shared library base address using a local symbol. */
static void kagura_anchor(void) {}

void kagura_record_load_address(void) {
    Dl_info info;
    if (dladdr((void *)kagura_anchor, &info))
        kOwnBaseAddress = (uintptr_t)info.dli_fbase;
}

/* Scan /proc/self/maps for .so with a lower base address than us.
 * Injection shims always map at a lower address because they are
 * preloaded via LD_PRELOAD or System.loadLibrary priority. */
int kagura_load_order_valid(void) {
    if (!kOwnBaseAddress) return 1; /* not recorded yet — skip */

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Only examine executable pages of .so files */
        if (!strstr(line, "r-xp") && !strstr(line, "r--p")) continue;
        if (!strstr(line, ".so")) continue;
        if (strstr(line, "kagura")) continue; /* skip ourselves */

        uintptr_t base = (uintptr_t)strtoull(line, NULL, 16);
        if (base < kOwnBaseAddress) {
            /* Found a .so loaded before us */
            /* Check if it's a system library (safe) */
            char *slash = strchr(line, '/');
            if (!slash) continue;
            if (strncmp(slash, "/system/lib", 11) == 0 ||
                strncmp(slash, "/apex/",        6) == 0 ||
                strncmp(slash, "/vendor/lib",  11) == 0 ||
                strncmp(slash, "/data/app",     9) != 0) continue;
            /* Non-system .so loaded before us — suspicious */
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return 1;
}

void kagura_load_order_check(void) {
    if (!kagura_load_order_valid())
        kagura_on_tamper_detected();
}

#endif /* __ANDROID__ */
