/*===-- runtime/blob_integrity.c - Checksum-guarded decryption ------------===
 *
 * Compute and verify FNV-1a-32 checksums over encrypted blobs before
 *         decryption to detect tampering with the binary at rest.
 *
 * If the checksum of the encrypted blob no longer matches the compile-time
 * constant embedded by the pass, the binary has been patched and decryption
 * must not proceed — kagura_on_tamper_detected() is called instead.
 *
 * Public API
 * ----------
 *   uint32_t kagura_fnv1a32(const uint8_t *data, uint32_t len);
 *   void     kagura_check_blob_integrity(const uint8_t *blob, uint32_t len,
 *                                         uint32_t expected);
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>

#define FNV_OFFSET_BASIS 0x811c9dc5u
#define FNV_PRIME        0x01000193u

uint32_t kagura_fnv1a32(const uint8_t *data, uint32_t len) {
    uint32_t hash = FNV_OFFSET_BASIS;
    for (uint32_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }
    return hash;
}

void kagura_check_blob_integrity(const uint8_t *blob, uint32_t len,
                                  uint32_t expected) {
    if (kagura_fnv1a32(blob, len) != expected)
        kagura_on_tamper_detected();
}
