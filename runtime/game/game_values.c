/*===-- runtime/game_values.c - Game value protection helpers -------------===
 *
 * Speed/movement value protection.
 *   Protect speed, velocity, and position values from memory manipulation
 *   by storing them as XOR-obfuscated pairs (value ^ key, key) and
 *   detecting tampering on each access.
 *
 * Random seed protection.
 *   Wrap the game's PRNG seed in an XOR-encrypted struct that detects when
 *   the seed has been patched to produce predictable outcomes (e.g. loot
 *   manipulation, aim randomness reduction).
 *
 * Both features extend the memory value obfuscation concept from the
 * MemoryValueObfuscation pass to the runtime side for values that change
 * frequently and need efficient CPU-side protection.
 *
 * Public API
 * ----------
 * Speed protection:
 *   void    kagura_speed_init(kagura_speed_t *s, float value);
 *   float   kagura_speed_get(const kagura_speed_t *s);
 *   void    kagura_speed_set(kagura_speed_t *s, float value);
 *   int     kagura_speed_valid(const kagura_speed_t *s, float min, float max);
 *
 * Seed protection:
 *   void     kagura_seed_init(kagura_seed_t *s, uint64_t seed);
 *   uint64_t kagura_seed_get(const kagura_seed_t *s);
 *   void     kagura_seed_set(kagura_seed_t *s, uint64_t seed);
 *   int      kagura_seed_tampered(const kagura_seed_t *s);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>
#include <string.h>

/* ── Protected floating-point value (speed / position / velocity) ─────── */

/* kagura_speed_t is declared in runtime/internal.h. */

static uint32_t speed_fnv(uint32_t v) {
    uint8_t b[4];
    memcpy(b, &v, 4);
    uint32_t h = 0x811c9dc5u;
    for (int i = 0; i < 4; ++i) { h ^= b[i]; h *= 0x01000193u; }
    return h;
}

void kagura_speed_init(kagura_speed_t *s, float value) {
    uint32_t bits;
    memcpy(&bits, &value, 4);
    /* Use a simple compile-time-constant key mixed with the address */
    s->key   = (uint32_t)(uintptr_t)s ^ 0xDEADBEEFu;
    s->enc   = bits ^ s->key;
    s->check = speed_fnv(s->enc ^ s->key);
}

float kagura_speed_get(const kagura_speed_t *s) {
    uint32_t bits = s->enc ^ s->key;
    float v;
    memcpy(&v, &bits, 4);
    return v;
}

void kagura_speed_set(kagura_speed_t *s, float value) {
    uint32_t bits;
    memcpy(&bits, &value, 4);
    s->enc   = bits ^ s->key;
    s->check = speed_fnv(s->enc ^ s->key);
}

int kagura_speed_valid(const kagura_speed_t *s, float min, float max) {
    /* Verify integrity checksum */
    if (speed_fnv(s->enc ^ s->key) != s->check)
        return 0;
    float v = kagura_speed_get(s);
    return (v >= min && v <= max) ? 1 : 0;
}

/* ── Protected PRNG seed ─────────────────────────────────────────────── */

/* kagura_seed_t is declared in runtime/internal.h. */

static uint32_t seed_fnv(uint64_t v) {
    uint8_t b[8];
    memcpy(b, &v, 8);
    uint32_t h = 0x811c9dc5u;
    for (int i = 0; i < 8; ++i) { h ^= b[i]; h *= 0x01000193u; }
    return h;
}

void kagura_seed_init(kagura_seed_t *s, uint64_t seed) {
    s->key   = (uint64_t)(uintptr_t)s ^ 0x9E3779B97F4A7C15ULL;
    s->enc   = seed ^ s->key;
    s->check = seed_fnv(seed);
}

uint64_t kagura_seed_get(const kagura_seed_t *s) {
    return s->enc ^ s->key;
}

void kagura_seed_set(kagura_seed_t *s, uint64_t seed) {
    s->enc   = seed ^ s->key;
    s->check = seed_fnv(seed);
}

int kagura_seed_tampered(const kagura_seed_t *s) {
    return seed_fnv(s->enc ^ s->key) != s->check ? 1 : 0;
}
