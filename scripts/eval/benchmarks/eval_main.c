/*
 * eval_main.c — Self-test harness (not obfuscated)
 *
 * Links against eval_functions.o (which IS obfuscated).
 * Results stored in statics to survive MVO.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef struct { uint32_t item_id, quantity, checksum; } ItemGrant;
typedef struct { int32_t x, y, z; } Vec3;

extern int eval_verify_score(uint32_t, uint32_t, uint32_t, uint32_t);
extern int eval_verify_item(const ItemGrant *, uint32_t);
extern int eval_check_movement(const Vec3 *, const Vec3 *, uint32_t);
extern int eval_validate_token(const uint8_t *, uint64_t, uint64_t, uint64_t);

static int R[7];

int main(void)
{
    R[0] = (eval_verify_score(10000000u, 90u, 10u, 0u) == 0);
    R[1] = (eval_verify_score(80u, 90u, 10u, 0u) == 0);

    ItemGrant g; g.item_id = 1u; g.quantity = 1u;
    {
        uint32_t h = 2166136261u;
        h ^= 1u; h *= 16777619u; h ^= 0u; h *= 16777619u;
        h ^= 1u; h *= 16777619u; h ^= 0u; h *= 16777619u;
        g.checksum = h;
    }
    R[2] = (eval_verify_item(&g, 1u) == 1);
    R[3] = (eval_verify_item(NULL, 1u) == 0);

    Vec3 a, b, c;
    a.x = 0; a.y = 0; a.z = 0;
    b.x = 3; b.y = 4; b.z = 0;
    c.x = 100; c.y = 100; c.z = 0;
    R[4] = (eval_check_movement(&a, &b, 1u) == 1);
    R[5] = (eval_check_movement(&a, &c, 1u) == 0);

    R[6] = (eval_validate_token(NULL, 0, 0, 0) == 0);

    volatile int n = R[0]+R[1]+R[2]+R[3]+R[4]+R[5]+R[6];
    printf("Self-test: %d/7 passed\n", (int)n);
    return ((int)n == 7) ? 0 : 1;
}
