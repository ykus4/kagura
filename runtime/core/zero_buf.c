/*===-- runtime/zero_buf.c - Volatile memory zeroing helper ---------------===
 *
 * Provides kagura_zero_buf(), called by decryption stubs injected by
 * the StringEncryptionAES LLVM pass to clear the decrypted plaintext buffer
 * immediately after use.
 *
 * The volatile write prevents the compiler from eliding the zeroing.
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>

void kagura_zero_buf(void *ptr, uint32_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  for (uint32_t i = 0; i < len; ++i)
    p[i] = 0;
}
