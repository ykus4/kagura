/*===-- runtime/aes.c - AES-128 CTR decrypt runtime helper ----------------===
 *
 * Implements kagura_aes128_ctr_decrypt(), called by the decryption stubs
 * injected by the StringEncryptionAES LLVM pass.
 *
 * AES-128, CTR mode (nonce || counter layout, big-endian counter).
 * Counter block: nonce[0..7] || counter[0..7]
 *
 * CTR mode is its own inverse, so this function is used for both encryption
 * (at compile time, in the pass) and decryption (at runtime, here).
 *
 *===----------------------------------------------------------------------===*/

#include "../internal.h"

#include <stdint.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Rijndael S-box
 * ---------------------------------------------------------------------- */
static const uint8_t SBox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

/* Round constants */
static const uint8_t Rcon[11] = {
  0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
};

/* -------------------------------------------------------------------------
 * GF(2^8) multiply (used for MixColumns)
 * ---------------------------------------------------------------------- */
static uint8_t gmul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  int i;
  for (i = 0; i < 8; ++i) {
    if (b & 1) p ^= a;
    {
      uint8_t hi = a & 0x80;
      a = (uint8_t)(a << 1);
      if (hi) a ^= 0x1b;
    }
    b >>= 1;
  }
  return p;
}

/* -------------------------------------------------------------------------
 * AES-128 key schedule
 * Produces 11 round keys of 16 bytes each (stored flat: rk[11][16]).
 * ---------------------------------------------------------------------- */
static void aes128_key_expand(const uint8_t key[16],
                               uint8_t rk[11][16]) {
  int r, c;
  memcpy(rk[0], key, 16);
  for (r = 1; r <= 10; ++r) {
    uint8_t t0 = SBox[rk[r-1][13]] ^ Rcon[r];
    uint8_t t1 = SBox[rk[r-1][14]];
    uint8_t t2 = SBox[rk[r-1][15]];
    uint8_t t3 = SBox[rk[r-1][12]];

    rk[r][0] = rk[r-1][0] ^ t0;
    rk[r][1] = rk[r-1][1] ^ t1;
    rk[r][2] = rk[r-1][2] ^ t2;
    rk[r][3] = rk[r-1][3] ^ t3;

    for (c = 1; c < 4; ++c) {
      rk[r][c*4+0] = rk[r-1][c*4+0] ^ rk[r][c*4-4];
      rk[r][c*4+1] = rk[r-1][c*4+1] ^ rk[r][c*4-3];
      rk[r][c*4+2] = rk[r-1][c*4+2] ^ rk[r][c*4-2];
      rk[r][c*4+3] = rk[r-1][c*4+3] ^ rk[r][c*4-1];
    }
  }
}

/* -------------------------------------------------------------------------
 * AES-128 forward cipher — single 16-byte block.
 * in and out may alias.
 * ---------------------------------------------------------------------- */
static void aes128_encrypt_block(const uint8_t in[16],
                                  const uint8_t rk[11][16],
                                  uint8_t out[16]) {
  uint8_t s[16];
  int i, r, c;
  uint8_t tmp;

  /* AddRoundKey — round 0 */
  for (i = 0; i < 16; ++i) s[i] = in[i] ^ rk[0][i];

  /* Rounds 1-9 */
  for (r = 1; r <= 9; ++r) {
    /* SubBytes */
    for (i = 0; i < 16; ++i) s[i] = SBox[s[i]];

    /* ShiftRows
     * State layout: s[col*4 + row]
     *   Row 0: no shift
     *   Row 1: shift left 1  (s[1]->s[5]->s[9]->s[13])
     *   Row 2: shift left 2  (s[2]<->s[10], s[6]<->s[14])
     *   Row 3: shift left 3  (s[15]->s[11]->s[7]->s[3])
     */
    tmp   = s[1];
    s[1]  = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;

    tmp   = s[2]; s[2]  = s[10]; s[10] = tmp;
    tmp   = s[6]; s[6]  = s[14]; s[14] = tmp;

    tmp   = s[15];
    s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = tmp;

    /* MixColumns */
    for (c = 0; c < 4; ++c) {
      uint8_t a0 = s[c*4+0], a1 = s[c*4+1];
      uint8_t a2 = s[c*4+2], a3 = s[c*4+3];
      s[c*4+0] = gmul(0x02,a0) ^ gmul(0x03,a1) ^ a2          ^ a3;
      s[c*4+1] = a0            ^ gmul(0x02,a1) ^ gmul(0x03,a2)^ a3;
      s[c*4+2] = a0            ^ a1            ^ gmul(0x02,a2)^ gmul(0x03,a3);
      s[c*4+3] = gmul(0x03,a0) ^ a1            ^ a2           ^ gmul(0x02,a3);
    }

    /* AddRoundKey */
    for (i = 0; i < 16; ++i) s[i] ^= rk[r][i];
  }

  /* Round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns) */
  for (i = 0; i < 16; ++i) s[i] = SBox[s[i]];

  tmp   = s[1];
  s[1]  = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = tmp;
  tmp   = s[2]; s[2]  = s[10]; s[10] = tmp;
  tmp   = s[6]; s[6]  = s[14]; s[14] = tmp;
  tmp   = s[15];
  s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = tmp;

  for (i = 0; i < 16; ++i) s[i] ^= rk[10][i];

  memcpy(out, s, 16);
}

/* -------------------------------------------------------------------------
 * kagura_aes128_ctr_decrypt
 *
 * Called by the per-string stubs injected by StringEncryptionAES.cpp.
 *
 *   enc   — pointer to the encrypted bytes (module global, length `len`)
 *   len   — number of bytes
 *   key   — 16-byte AES-128 key
 *   nonce — 8-byte nonce (upper 8 bytes of each 128-bit counter block)
 *   out   — caller-allocated output buffer (at least `len` bytes)
 *
 * Counter block layout: nonce[0..7] || counter[0..7] (big-endian 64-bit).
 * ---------------------------------------------------------------------- */
void kagura_aes128_ctr_decrypt(const uint8_t *enc,
                                uint32_t       len,
                                const uint8_t  key[16],
                                const uint8_t  nonce[8],
                                uint8_t       *out) {
  uint8_t rk[11][16];
  uint8_t ctr_block[16];
  uint8_t keystream[16];
  uint32_t offset;
  uint64_t counter;
  int i;

  aes128_key_expand(key, rk);

  for (offset = 0; offset < len; offset += 16) {
    uint32_t block_len;
    counter = (uint64_t)(offset / 16);

    /* Build counter block: nonce || counter (big-endian) */
    for (i = 0; i < 8; ++i)
      ctr_block[i] = nonce[i];
    for (i = 0; i < 8; ++i)
      ctr_block[8 + i] = (uint8_t)((counter >> ((7 - i) * 8)) & 0xFF);

    aes128_encrypt_block(ctr_block, (const uint8_t (*)[16])rk, keystream);

    block_len = (len - offset < 16) ? (len - offset) : 16;
    for (i = 0; i < (int)block_len; ++i)
      out[offset + i] = enc[offset + i] ^ keystream[i];
  }
}
