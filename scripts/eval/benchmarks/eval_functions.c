/*
 * eval_functions.c — Obfuscation target functions only (no main)
 *
 * Design constraints for obfuscation correctness:
 *   - No local integer loop counters (MVO XORs all alloca'd integers)
 *   - No struct byvalue args (FLA demote-PHI crashes on byval under FLA)
 *   - Pointer loops instead of indexed loops where possible
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))

/* ── 1. Score verification ────────────────────────────────────────────── */

#define SCORE_MAX   9999999u
#define SCORE_MAGIC 0xA5C3E1B7u

NOINLINE int eval_verify_score(uint32_t score, uint32_t prev,
                                uint32_t delta, uint32_t key)
{
    if (score > SCORE_MAX)       return 0;
    if (prev  > score)           return 0;
    if ((score - prev) != delta) return 0;
    uint32_t expected = (prev ^ SCORE_MAGIC) + delta * 0x9e3779b9u;
    expected ^= key;
    return (score == (expected & SCORE_MAX));
}

/* ── 2. Item acquisition validation ──────────────────────────────────── */

#define MAX_ITEM_ID  1024u
#define MAX_QUANTITY 999u

typedef struct { uint32_t item_id, quantity, checksum; } ItemGrant;

NOINLINE int eval_verify_item(const ItemGrant *g, uint32_t level)
{
    if (!g)                                              return 0;
    if (g->item_id == 0 || g->item_id > MAX_ITEM_ID)    return 0;
    if (g->quantity == 0 || g->quantity > MAX_QUANTITY)  return 0;
    if (g->item_id > 500u && level < 20u)                return 0;
    uint32_t h = 2166136261u;
    h ^= (g->item_id  & 0xFFu); h *= 16777619u;
    h ^= (g->item_id  >> 8);    h *= 16777619u;
    h ^= (g->quantity & 0xFFu); h *= 16777619u;
    h ^= (g->quantity >> 8);    h *= 16777619u;
    return (g->checksum == h);
}

/* ── 3. Movement / speed-hack detection ─────────────────────────────── */

#define MAX_SPEED_SQ  400
#define MAX_JUMP_DIST 10

typedef struct { int32_t x, y, z; } Vec3;

NOINLINE int eval_check_movement(const Vec3 *prev, const Vec3 *curr,
                                  uint32_t ticks)
{
    if (!prev || !curr || ticks == 0) return 0;
    int64_t dx = curr->x - prev->x;
    int64_t dy = curr->y - prev->y;
    int64_t dz = curr->z - prev->z;
    int64_t d2 = dx*dx + dy*dy + dz*dz;
    if (d2 > (int64_t)MAX_SPEED_SQ * ticks * ticks) return 0;
    if (dz > MAX_JUMP_DIST || dz < -(int64_t)MAX_JUMP_DIST * 3) return 0;
    return 1;
}

/* ── 4. Auth token check ─────────────────────────────────────────────── */

#define TOKEN_LEN 32

NOINLINE int eval_validate_token(const uint8_t *tok, uint64_t pid,
                                  uint64_t ts, uint64_t secret)
{
    if (!tok) return 0;
    uint64_t key = (pid ^ secret) * 6364136223846793005ULL + 1ULL;
    key ^= ts;
    uint64_t acc = key;
    /* pointer walk — avoid alloca'd indexed counter (MVO target) */
    const uint8_t *p   = tok;
    const uint8_t *end = tok + TOKEN_LEN;
    uint32_t       idx = 0;
    while (p < end) {
        acc ^= (uint64_t)(*p) << ((idx % 8u) * 8u);
        acc  = (acc << 13) | (acc >> 51);
        acc *= 0xbf58476d1ce4e5b9ULL;
        ++p; ++idx;
    }
    uint64_t mac;
    memcpy(&mac, tok + 24, sizeof mac);
    return (mac == (acc & 0xFFFFFFFFFFFFFF00ULL));
}
