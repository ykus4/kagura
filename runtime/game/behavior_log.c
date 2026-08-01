/*===-- runtime/behavior_log.c - Suspicious behavior logging --------------===
 *
 * Collect and report suspicious cheat-indicative behaviors.
 *
 * Rather than immediately banning on first detection, this module accumulates
 * suspicious event signals into a circular ring buffer.  The game can
 * periodically flush the log to a backend for analysis, or apply soft
 * responses (penalise, degrade experience) based on accumulated score.
 *
 * Event types
 * -----------
 *   KAGURA_EVENT_MEMORY_TAMPER  — value outside expected range
 *   KAGURA_EVENT_SPEED_HACK     — delta-time anomaly
 *   KAGURA_EVENT_HOOK_DETECTED  — runtime hook found
 *   KAGURA_EVENT_DEBUG_DETECTED — debugger or analysis tool
 *   KAGURA_EVENT_CUSTOM         — app-defined event (code in range [64,127])
 *
 * Public API
 * ----------
 *   void kagura_log_event(uint8_t type, uint32_t detail);
 *   int  kagura_event_count(uint8_t type);
 *   int  kagura_suspicion_score(void);   // weighted sum of all events
 *   void kagura_flush_events(void (*cb)(uint8_t type, uint32_t detail, void*),
 *                             void *userdata);
 *   void kagura_clear_events(void);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>
#include <string.h>

#define KAGURA_LOG_SIZE 128

/* ── Event type constants ────────────────────────────────────────────────── */
#define KAGURA_EVENT_MEMORY_TAMPER  0x01
#define KAGURA_EVENT_SPEED_HACK     0x02
#define KAGURA_EVENT_HOOK_DETECTED  0x03
#define KAGURA_EVENT_DEBUG_DETECTED 0x04
#define KAGURA_EVENT_REPACKAGED     0x05
#define KAGURA_EVENT_CUSTOM_BASE    0x40  /* app-defined: 0x40–0x7F */

typedef struct {
    uint8_t  type;
    uint32_t detail;
} kagura_event_t;

static kagura_event_t kEventBuf[KAGURA_LOG_SIZE];
static int kEventHead = 0;
static int kEventCount = 0;

void kagura_log_event(uint8_t type, uint32_t detail) {
    kEventBuf[kEventHead % KAGURA_LOG_SIZE].type   = type;
    kEventBuf[kEventHead % KAGURA_LOG_SIZE].detail = detail;
    ++kEventHead;
    if (kEventCount < KAGURA_LOG_SIZE) ++kEventCount;
}

int kagura_event_count(uint8_t type) {
    int count = 0;
    int start = (kEventHead - kEventCount + KAGURA_LOG_SIZE) % KAGURA_LOG_SIZE;
    for (int i = 0; i < kEventCount; ++i) {
        if (kEventBuf[(start + i) % KAGURA_LOG_SIZE].type == type)
            ++count;
    }
    return count;
}

/* Weighted suspicion score */
int kagura_suspicion_score(void) {
    int score = 0;
    score += kagura_event_count(KAGURA_EVENT_HOOK_DETECTED)  * 10;
    score += kagura_event_count(KAGURA_EVENT_DEBUG_DETECTED) * 10;
    score += kagura_event_count(KAGURA_EVENT_REPACKAGED)     * 15;
    score += kagura_event_count(KAGURA_EVENT_MEMORY_TAMPER)  *  5;
    score += kagura_event_count(KAGURA_EVENT_SPEED_HACK)     *  3;
    return score;
}

void kagura_flush_events(
        void (*cb)(uint8_t type, uint32_t detail, void *userdata),
        void *userdata) {
    int start = (kEventHead - kEventCount + KAGURA_LOG_SIZE) % KAGURA_LOG_SIZE;
    for (int i = 0; i < kEventCount; ++i) {
        kagura_event_t *e = &kEventBuf[(start + i) % KAGURA_LOG_SIZE];
        if (cb) cb(e->type, e->detail, userdata);
    }
}

void kagura_clear_events(void) {
    kEventHead  = 0;
    kEventCount = 0;
    memset(kEventBuf, 0, sizeof(kEventBuf));
}
