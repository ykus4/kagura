/*===-- runtime/core/soft_response.c - Graduated tamper response ----------===
 *
 * Delayed and graduated response to detected tampering.
 *
 * An immediate crash or ban on first detection:
 *   1. Teaches the attacker exactly what triggers the protection.
 *   2. Turns any false positive into a hard failure for a legitimate user.
 *
 * A soft response instead accumulates a suspicion score over time and applies
 * a graduated reaction: ignore -> warn -> penalise -> kick.
 *
 * Public API
 * ----------
 *   void kagura_soft_response_add(int score);
 *   int  kagura_soft_response_level(void);   // KAGURA_RESPONSE_*
 *   void kagura_soft_response_check(void (*respond)(int level, void *ctx),
 *                                   void *ctx);
 *   void kagura_soft_response_reset(void);
 *
 * ---------------------------------------------------------------------------
 * This file replaces two incompatible implementations of the same exported
 * names:
 *
 *   anti_debug/soft_response.c   void kagura_soft_response_check(
 *                                        void (*)(int, void *), void *)
 *   windows/tamper_response.c    void kagura_soft_response_check(int threshold)
 *
 * Same symbol, different signatures, selected by which platform you happened
 * to build - undefined behaviour for any caller linked against the other one.
 * The callback form wins because it lets the application decide the reaction;
 * the Windows form's behaviour (terminate once the score is high enough) is
 * preserved as the null-callback default, see kagura_soft_response_check.
 *
 * Two further fixes carried over from those files:
 *   - The score is now atomic.  Detection hooks run from arbitrary threads and
 *     `kSuspicionScore += score` was a plain read-modify-write data race; the
 *     POSIX version could and did lose increments.
 *   - The "timing jitter" busy-wait is gone.  It spun on clock_gettime() for
 *     up to 49ms per call, burning a full core, and defended against nothing:
 *     the delay was inside the scoring call, so it was itself the timing
 *     signal it claimed to hide.  Callers that want a delayed reaction should
 *     schedule it from their own response callback.
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

/* Score thresholds for each response level. */
#ifndef KAGURA_THRESHOLD_WARN
#define KAGURA_THRESHOLD_WARN     10
#endif
#ifndef KAGURA_THRESHOLD_PENALISE
#define KAGURA_THRESHOLD_PENALISE 30
#endif
#ifndef KAGURA_THRESHOLD_KICK
#define KAGURA_THRESHOLD_KICK     60
#endif

/* ---- Atomic score cell ---------------------------------------------------
 *
 * C11 <stdatomic.h> where available.  MSVC does not ship it for C (and
 * __STDC_NO_ATOMICS__ covers any other freestanding-ish toolchain), so fall
 * back to the Interlocked intrinsics, which give the same seq_cst ordering.
 */

#if !defined(__STDC_NO_ATOMICS__) && \
    (!defined(_MSC_VER) || defined(__clang__))

#include <stdatomic.h>

static atomic_int kSuspicionScore;

static int score_add(int delta)  { return atomic_fetch_add(&kSuspicionScore, delta) + delta; }
static int score_load(void)      { return atomic_load(&kSuspicionScore); }
static void score_store(int v)   { atomic_store(&kSuspicionScore, v); }

#else /* MSVC C mode */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static volatile LONG kSuspicionScore = 0;

static int score_add(int delta)  { return (int)InterlockedAdd(&kSuspicionScore, (LONG)delta); }
static int score_load(void)      { return (int)InterlockedCompareExchange(&kSuspicionScore, 0, 0); }
static void score_store(int v)   { InterlockedExchange(&kSuspicionScore, (LONG)v); }

#endif

/* ---- API ----------------------------------------------------------------- */

void kagura_soft_response_add(int score) {
    (void)score_add(score);
}

int kagura_soft_response_level(void) {
    int s = score_load();
    if (s >= KAGURA_THRESHOLD_KICK)     return KAGURA_RESPONSE_KICK;
    if (s >= KAGURA_THRESHOLD_PENALISE) return KAGURA_RESPONSE_PENALISE;
    if (s >= KAGURA_THRESHOLD_WARN)     return KAGURA_RESPONSE_WARN;
    return KAGURA_RESPONSE_OK;
}

/*
 * Evaluate the current level and react.
 *
 *   respond != NULL — invoked with the level whenever it is above OK.  The
 *                     application owns the policy from there.
 *   respond == NULL — default policy, matching the old Windows build: nothing
 *                     happens below KICK, and reaching KICK runs the tamper
 *                     hook.  Without this the null case would silently do
 *                     nothing, which is how the Windows path would have
 *                     regressed.
 */
void kagura_soft_response_check(void (*respond)(int level, void *ctx),
                                void *ctx) {
    int level = kagura_soft_response_level();
    if (level <= KAGURA_RESPONSE_OK)
        return;

    if (respond) {
        respond(level, ctx);
        return;
    }

    if (level >= KAGURA_RESPONSE_KICK)
        kagura_on_tamper_detected();
}

void kagura_soft_response_reset(void) {
    score_store(0);
}
