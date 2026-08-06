/*
 * game_integrity_eval.c — Paper benchmark: game anti-cheat functions
 *
 * Design constraints for obfuscation correctness:
 *   - No local integer counters (MVO XORs all alloca'd integers)
 *   - No struct byvalue args (FLA demote-PHI crashes on arm64 byval)
 *   - Results written to static globals (MVO does not touch global ints)
 *   - Each function is __attribute__((noinline)) to survive -O1 inlining
 *
 * Functions:
 *   eval_verify_score()    — score tamper detection
 *   eval_verify_item()     — item acquisition validation
 *   eval_check_movement()  — speed hack / teleport detection
 *   eval_validate_token()  — auth token check
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define NOINLINE __attribute__((noinline))

/* ── 1. Score verification ────────────────────────────────────────────── */

#define SCORE_MAX   9999999u
#define SCORE_MAGIC 0xA5C3E1B7u

NOINLINE int eval_verify_score(uint32_t score, uint32_t prev,
                                uint32_t delta, uint32_t key)
{
    if (score > SCORE_MAX)             return 0;
    if (prev  > score)                 return 0;
    if ((score - prev) != delta)       return 0;
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
    if (!g)                                      return 0;
    if (g->item_id == 0 || g->item_id > MAX_ITEM_ID)   return 0;
    if (g->quantity == 0 || g->quantity > MAX_QUANTITY) return 0;
    if (g->item_id > 500u && level < 20u)        return 0;
    uint32_t h = 2166136261u;
    h ^= (g->item_id  & 0xFF); h *= 16777619u;
    h ^= (g->item_id  >> 8);   h *= 16777619u;
    h ^= (g->quantity & 0xFF); h *= 16777619u;
    h ^= (g->quantity >> 8);   h *= 16777619u;
    return (g->checksum == h);
}

/* ── 3. Movement / speed-hack detection (pointer args) ───────────────── */

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
    /* Use a pointer to iterate — avoid alloca'd loop counter for MVO safety */
    const uint8_t *p = tok;
    const uint8_t *end = tok + TOKEN_LEN;
    uint32_t i = 0;
    while (p < end) {
        acc ^= (uint64_t)(*p) << ((i % 8) * 8);
        acc  = (acc << 13) | (acc >> 51);
        acc *= 0xbf58476d1ce4e5b9ULL;
        p++; i++;
    }
    uint64_t mac;
    memcpy(&mac, tok + 24, sizeof mac);
    return (mac == (acc & 0xFFFFFFFFFFFFFF00ULL));
}

/* ── Results stored in statics (not touched by MVO) ─────────────────── */

static int R[7];   /* R[0..6]: one result per test */

/* ── main ────────────────────────────────────────────────────────────── */

int main(void)
{
    /* Test 0: score over max → reject */
    R[0] = (eval_verify_score(10000000u, 90u, 10u, 0u) == 0);

    /* Test 1: prev > score → reject */
    R[1] = (eval_verify_score(80u, 90u, 10u, 0u) == 0);

    /* Test 2: valid item grant */
    ItemGrant g;
    g.item_id  = 1u;
    g.quantity = 1u;
    {
        uint32_t h = 2166136261u;
        h ^= 1u; h *= 16777619u;
        h ^= 0u; h *= 16777619u;
        h ^= 1u; h *= 16777619u;
        h ^= 0u; h *= 16777619u;
        g.checksum = h;
    }
    R[2] = (eval_verify_item(&g, 1u) == 1);

    /* Test 3: null grant → reject */
    R[3] = (eval_verify_item(NULL, 1u) == 0);

    /* Test 4: movement within bounds */
    Vec3 a, b;
    a.x = 0; a.y = 0; a.z = 0;
    b.x = 3; b.y = 4; b.z = 0;   /* dist=5, within sqrt(400)=20 */
    R[4] = (eval_check_movement(&a, &b, 1u) == 1);

    /* Test 5: movement too fast → reject */
    Vec3 c;
    c.x = 100; c.y = 100; c.z = 0;
    R[5] = (eval_check_movement(&a, &c, 1u) == 0);

    /* Test 6: null token → reject */
    R[6] = (eval_validate_token(NULL, 0, 0, 0) == 0);

    /* Count and report — sum written to a single volatile to avoid MVO */
    volatile int n = R[0]+R[1]+R[2]+R[3]+R[4]+R[5]+R[6];
    printf("Self-test: %d/7 passed\n", (int)n);
    return (n == 7) ? 0 : 1;
}
