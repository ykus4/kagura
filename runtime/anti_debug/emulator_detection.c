/*
 * emulator_detection.c - Emulator and virtual environment detection
 *
 * Detects Android emulators (AVD, Genymotion, BlueStacks, etc.) and iOS
 * simulators at runtime.  Multiple independent signals are combined: a single
 * positive signal is reported to reduce false positives.
 *
 * Android checks:
 *   - Build properties via __system_property_get (ro.hardware, ro.product.*)
 *   - Known emulator filesytem artifacts (/dev/socket/qemud, /dev/qemu_pipe …)
 *   - /proc/cpuinfo feature strings absent on real hardware
 *   - CPU timing: RDTSC / clock_gettime delta too low for real hardware
 *
 * iOS checks:
 *   - TARGET_OS_SIMULATOR compile-time guard (not a runtime check, but the
 *     binary produced for the simulator embeds this path)
 *   - Absence of typical hardware entitlements (weak check; compile-time)
 *
 * Public API:
 *   kagura_check_emulator()   - Returns 1 if running in an emulator/simulator
 *   kagura_assert_real_device() - Calls tamper callback if emulator detected
 */

#include "../internal.h"

#include <stdint.h>
#include <string.h>

/* ─── iOS simulator (compile-time) ─────────────────────────────────────── */

#if defined(__APPLE__)
#include <TargetConditionals.h>

static int kagura_is_ios_simulator(void) {
#if TARGET_OS_SIMULATOR
    return 1;
#else
    return 0;
#endif
}
#else
static int kagura_is_ios_simulator(void) { return 0; }
#endif

/* ─── Android emulator detection ────────────────────────────────────────── */

#if defined(__linux__) && defined(__ANDROID__)
#include <stdio.h>
#include <stdlib.h>
#include <sys/system_properties.h>

/* Check a system property against a list of known emulator values.
 * Returns 1 if any value matches (case-insensitive prefix). */
static int prop_matches(const char *key, const char **values) {
    char buf[PROP_VALUE_MAX];
    if (__system_property_get(key, buf) == 0)
        return 0;
    /* lowercase for comparison */
    for (int i = 0; buf[i]; ++i)
        if (buf[i] >= 'A' && buf[i] <= 'Z') buf[i] += 32;
    for (int i = 0; values[i]; ++i)
        if (strstr(buf, values[i]))
            return 1;
    return 0;
}

static int kagura_check_build_props(void) {
    /* ro.hardware */
    static const char *hw_emulators[] = {
        "goldfish", "ranchu", "vbox", "nox", "bluestacks",
        "genymotion", "andy", "droid4x", NULL
    };
    if (prop_matches("ro.hardware", hw_emulators)) return 1;

    /* ro.product.model */
    static const char *model_emulators[] = {
        "sdk", "android sdk", "emulator", "google_sdk", "droid4x",
        "nox", "bluestacks", NULL
    };
    if (prop_matches("ro.product.model", model_emulators)) return 1;

    /* ro.product.manufacturer */
    static const char *mfr_emulators[] = {
        "genymotion", "unknown", "andy", NULL
    };
    if (prop_matches("ro.product.manufacturer", mfr_emulators)) return 1;

    /* ro.kernel.qemu */
    {
        char buf[PROP_VALUE_MAX];
        if (__system_property_get("ro.kernel.qemu", buf) > 0 && buf[0] == '1')
            return 1;
    }

    return 0;
}

static int kagura_check_emulator_files(void) {
    static const char *artifacts[] = {
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/dev/socket/genyd",         /* Genymotion */
        "/dev/socket/baseband_genyd",
        NULL
    };
    for (int i = 0; artifacts[i]; ++i) {
        FILE *f = fopen(artifacts[i], "r");
        if (f) { fclose(f); return 1; }
    }
    return 0;
}

/* Check /proc/cpuinfo for goldfish/ranchu emulator markers */
static int kagura_check_cpuinfo(void) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;

    static const char *markers[] = {
        "goldfish", "ranchu", NULL
    };

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; line[i]; ++i)
            if (line[i] >= 'A' && line[i] <= 'Z') line[i] += 32;
        for (int i = 0; markers[i]; ++i) {
            if (strstr(line, markers[i])) {
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

static int kagura_check_android_emulator(void) {
    if (kagura_check_build_props())    return 1;
    if (kagura_check_emulator_files()) return 1;
    if (kagura_check_cpuinfo())        return 1;
    return 0;
}

#else

static int kagura_check_android_emulator(void) { return 0; }

#endif /* __ANDROID__ */

/* ─── Timing-based detection (x86/x86-64 only) ──────────────────────────── */

#if defined(__x86_64__) || defined(__i386__)
#include <time.h>

/* On real hardware, RDTSC increments at ~1–4 GHz.  In some emulators the
 * TSC is virtualised or runs orders of magnitude slower.  We measure how
 * many nanoseconds a tight RDTSC loop takes; on an emulator the ratio
 * (ns / tsc_delta) is much larger than on bare metal. */
static int kagura_timing_check(void) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    volatile uint64_t tsc0, tsc1;
    __asm__ volatile("rdtsc" : "=A"(tsc0));
    /* Tight loop */
    for (volatile int i = 0; i < 1000; ++i) {}
    __asm__ volatile("rdtsc" : "=A"(tsc1));

    clock_gettime(CLOCK_MONOTONIC, &t1);

    uint64_t elapsed_ns = (uint64_t)(t1.tv_sec  - t0.tv_sec)  * 1000000000ULL
                        + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    uint64_t tsc_delta  = tsc1 - tsc0;

    if (tsc_delta == 0) return 0;
    /* If ns/tick > 10, TSC is likely virtualised / very slow */
    return (elapsed_ns / tsc_delta) > 10u ? 1 : 0;
}
#else
static int kagura_timing_check(void) { return 0; }
#endif

/* ─── Combined public API ────────────────────────────────────────────────── */

int kagura_check_emulator(void) {
    if (kagura_is_ios_simulator())        return 1;
    if (kagura_check_android_emulator())  return 1;
    if (kagura_timing_check())            return 1;
    return 0;
}

void kagura_assert_real_device(void) {
    if (kagura_check_emulator())
        kagura_on_tamper_detected();
}
