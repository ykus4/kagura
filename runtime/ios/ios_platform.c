/*===-- runtime/ios_platform.c - iOS platform-specific protections --------===
 *
 * iOS simulator exclusion (TARGET_OS_SIMULATOR).
 * Entitlements verification (csops-based).
 * dyld image list runtime inspection.
 *
 * Public API
 * ----------
 *   int  kagura_is_simulator(void);          // 1 = running in simulator
 *   void kagura_simulator_check(void);       // calls tamper cb if in simulator
 *   int  kagura_entitlements_valid(void);    // 1 = expected entitlements present
 *   void kagura_entitlements_check(void);
 *   int  kagura_dyld_suspicious(void);       // 1 = unexpected dylib loaded
 *   void kagura_dyld_image_check(void);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#ifdef __APPLE__

#include <TargetConditionals.h>
#include <stdint.h>
#include <string.h>
#include <mach-o/dyld.h>

/* ── Simulator detection ─────────────────────────────────────────────── */

int kagura_is_simulator(void) {
#if TARGET_OS_SIMULATOR
    return 1;
#else
    return 0;
#endif
}

void kagura_simulator_check(void) {
    if (kagura_is_simulator())
        kagura_on_tamper_detected();
}

/* ── Entitlements verification ──────────────────────────────────────── */

#if TARGET_OS_IOS && !TARGET_OS_SIMULATOR

#include <sys/types.h>

/* csops flags — same as in ios_integrity.c */
#define CS_VALID       0x00000001u
#define CS_ENFORCEMENT 0x00001000u
#define CS_OPS_STATUS  0

extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

int kagura_entitlements_valid(void) {
    uint32_t flags = 0;
    if (csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != 0)
        return 0;
    /* A legitimate App Store / TestFlight build must have both VALID and
     * ENFORCEMENT flags.  A repackaged / jailbroken app running under a
     * developer certificate may have VALID but not ENFORCEMENT. */
    return (flags & (CS_VALID | CS_ENFORCEMENT)) ==
           (CS_VALID | CS_ENFORCEMENT) ? 1 : 0;
}

void kagura_entitlements_check(void) {
    if (!kagura_entitlements_valid())
        kagura_on_tamper_detected();
}

#else

int  kagura_entitlements_valid(void) { return 1; } /* non-iOS: always pass */
void kagura_entitlements_check(void) {}

#endif /* TARGET_OS_IOS */

/* ── dyld image list inspection ─────────────────────────────────────── */

/* The former kSuspiciousDylibs table is now part of the union in core/imagelist.c. */

int kagura_dyld_suspicious(void) {
    /* This function's hand-rolled case-insensitive matcher is now
     * kagura_contains_ci() in core/imagelist.c, and its eight-name list is
     * folded into the shared union table. */
    return kagura_image_list_contains(kagura_suspicious_image_patterns());
}

void kagura_dyld_image_check(void) {
    if (kagura_dyld_suspicious())
        kagura_on_tamper_detected();
}

#endif /* __APPLE__ */
