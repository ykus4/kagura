/*===-- runtime/state_integrity.c - Client-side state invariant checks ----===
 *
 * State integrity check — verify that game-critical values satisfy
 *        compile-time-defined invariants at runtime.
 *
 * This module provides a generic invariant-check framework.  The game
 * developer registers invariants (value ranges, relationships, checksums)
 * that must hold for critical game state (health, currency, score).
 *
 * If any registered invariant fails, kagura_on_tamper_detected() is called
 * to trigger the anti-cheat response.
 *
 * Design
 * ------
 * Each invariant is a user-provided predicate function with a context pointer.
 * Up to KAGURA_MAX_INVARIANTS invariants can be registered.
 *
 * Registration: call kagura_register_invariant(fn, ctx) at startup.
 * Verification: call kagura_check_invariants() periodically (e.g. game tick).
 *
 * Built-in helpers:
 *   kagura_invariant_range_i32(ctx) — ctx is kagura_range_i32_t*
 *     Checks: min <= *value <= max
 *   kagura_invariant_nonzero(ctx)  — ctx is int32_t*
 *     Checks: *value != 0
 *
 * Public API
 * ----------
 *   void kagura_register_invariant(int (*fn)(void*), void *ctx);
 *   void kagura_check_invariants(void);
 *   int  kagura_invariant_range_i32(void *ctx);
 *   int  kagura_invariant_nonzero(void *ctx);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>

#define KAGURA_MAX_INVARIANTS 32

typedef struct {
    int  (*fn)(void *ctx);
    void  *ctx;
} kagura_invariant_t;

static kagura_invariant_t kInvariants[KAGURA_MAX_INVARIANTS];
static int kInvariantCount = 0;

void kagura_register_invariant(int (*fn)(void *ctx), void *ctx) {
    if (kInvariantCount >= KAGURA_MAX_INVARIANTS) return;
    kInvariants[kInvariantCount].fn  = fn;
    kInvariants[kInvariantCount].ctx = ctx;
    ++kInvariantCount;
}

void kagura_check_invariants(void) {
    for (int i = 0; i < kInvariantCount; ++i) {
        if (kInvariants[i].fn && !kInvariants[i].fn(kInvariants[i].ctx))
            kagura_on_tamper_detected();
    }
}

/* ── Built-in invariant: value within [min, max] range ─────────────────── */

typedef struct {
    int32_t *value;
    int32_t  min;
    int32_t  max;
} kagura_range_i32_t;

int kagura_invariant_range_i32(void *ctx) {
    const kagura_range_i32_t *r = (const kagura_range_i32_t *)ctx;
    if (!r || !r->value) return 1; /* skip if null */
    return (*r->value >= r->min && *r->value <= r->max) ? 1 : 0;
}

/* ── Built-in invariant: value is non-zero ─────────────────────────────── */

int kagura_invariant_nonzero(void *ctx) {
    const int32_t *v = (const int32_t *)ctx;
    if (!v) return 1;
    return *v != 0 ? 1 : 0;
}
