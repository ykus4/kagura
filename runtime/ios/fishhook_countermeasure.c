/*===-- runtime/fishhook_countermeasure.c - fishhook rebinding detection --===
 *
 * Detect fishhook-style GOT rebinding on Apple platforms.
 *
 * fishhook (and similar tools) walk the Mach-O __DATA,__got and
 * __DATA,__la_symbol_ptr sections and overwrite function pointer slots.
 * After rebinding, the slot no longer points into the original dylib text.
 *
 * Detection strategy
 * ------------------
 *   1. For a set of well-known libc/libSystem functions, record their expected
 *      addresses by calling dlsym(RTLD_DEFAULT, name) before any hooking
 *      can occur (from a +load or __attribute__((constructor)) context,
 *      or early in the runtime initialisation sequence).
 *
 *   2. On each check, use dlsym again and compare with the cached address.
 *      If the current address differs, fishhook has re-pointed the GOT slot
 *      after our initial snapshot.
 *
 *   3. Additionally, for each probed function, verify via dladdr() that the
 *      resolved address lives inside the expected shared library
 *      (/usr/lib/libSystem.B.dylib or /usr/lib/libc++.1.dylib).
 *
 * Public API
 * ----------
 *   void kagura_fishhook_snapshot(void);  // call early (constructor priority)
 *   int  kagura_fishhook_detected(void);  // 1 = rebinding detected
 *   void kagura_fishhook_check(void);     // calls kagura_on_tamper_detected()
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __APPLE__

#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

#define PROBE_COUNT 8

static const char *const kProbeNames[PROBE_COUNT] = {
    "open", "close", "read", "write",
    "mmap", "dlopen", "dlsym", "malloc"
};

static void *kProbeSnapshot[PROBE_COUNT];
static int   kSnapshotTaken = 0;

/* Call this once from a +load or constructor before the app runs */
__attribute__((constructor(101)))
void kagura_fishhook_snapshot(void) {
    for (int i = 0; i < PROBE_COUNT; ++i)
        kProbeSnapshot[i] = dlsym(RTLD_DEFAULT, kProbeNames[i]);
    kSnapshotTaken = 1;
}

int kagura_fishhook_detected(void) {
    if (!kSnapshotTaken)
        kagura_fishhook_snapshot();

    for (int i = 0; i < PROBE_COUNT; ++i) {
        void *current = dlsym(RTLD_DEFAULT, kProbeNames[i]);

        /* 1. Address changed since snapshot */
        if (current != kProbeSnapshot[i])
            return 1;

        /* 2. dladdr check — must be in a system library */
        Dl_info info;
        if (!current) continue;
        if (dladdr(current, &info) == 0)
            return 1;
        if (!info.dli_fname)
            return 1;
        if (strstr(info.dli_fname, "/usr/lib/") == NULL &&
            strstr(info.dli_fname, "/System/Library/") == NULL)
            return 1;
    }
    return 0;
}

void kagura_fishhook_check(void) {
    if (kagura_fishhook_detected())
        kagura_on_tamper_detected();
}

#endif /* __APPLE__ */
