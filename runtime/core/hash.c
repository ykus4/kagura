/*===-- runtime/core/hash.c - Shared FNV-1a implementations ---------------===
 *
 * FNV-1a was open-coded eight times across the runtime (core/blob_integrity.c,
 * core/device_key.c, game/integrity_report.c, game/ue4_protection.c,
 * game/il2cpp_protection.c, game/game_values.c, ios/objc_name_remap.c,
 * windows/device_key.c), in both 32- and 64-bit forms, with four different
 * spellings of the same two constants.  Two of those copies had already
 * drifted into dead code.
 *
 * The 32-bit variant must stay bit-identical to fnv1a32_str() in
 * lib/Transforms/AntiAnalysis/Telemetry.cpp and to the hash in
 * lib/Transforms/AntiAnalysis/AntiTamper.cpp: the passes bake hashes into the
 * binary at compile time and the runtime re-checks them.  Changing a constant
 * here silently breaks kagura_runtime_hash_check and kagura_check_blob_integrity.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#define FNV1A32_OFFSET_BASIS UINT32_C(0x811c9dc5)
#define FNV1A32_PRIME        UINT32_C(0x01000193)
#define FNV1A64_OFFSET_BASIS UINT64_C(0xcbf29ce484222325)
#define FNV1A64_PRIME        UINT64_C(0x100000001b3)

/* Incremental forms.  core/device_key.c folds several entropy sources into two
 * differently-seeded running hashes, so it needs to continue a hash rather
 * than start one. */
uint32_t kagura_fnv1a32_update(uint32_t h, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    if (!p) return h;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= FNV1A32_PRIME;
    }
    return h;
}

uint64_t kagura_fnv1a64_update(uint64_t h, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    if (!p) return h;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= FNV1A64_PRIME;
    }
    return h;
}

uint32_t kagura_fnv1a32_buf(const void *data, size_t len) {
    return kagura_fnv1a32_update(FNV1A32_OFFSET_BASIS, data, len);
}

uint64_t kagura_fnv1a64_buf(const void *data, size_t len) {
    return kagura_fnv1a64_update(FNV1A64_OFFSET_BASIS, data, len);
}

uint32_t kagura_fnv1a32_str(const char *s) {
    uint32_t h = FNV1A32_OFFSET_BASIS;
    if (!s) return h;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= FNV1A32_PRIME;
    }
    return h;
}

uint64_t kagura_fnv1a64_str(const char *s) {
    uint64_t h = FNV1A64_OFFSET_BASIS;
    if (!s) return h;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= FNV1A64_PRIME;
    }
    return h;
}
