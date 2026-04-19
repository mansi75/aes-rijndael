/*
 * rijndael.c - Full AES (Rijndael) block cipher implementation.
 *
 * Supports AES-128, AES-256, and the Rijndael-512 extension.
 * Uses no third-party libraries and no hardware AES instructions.
 * Only the C standard library is used (stdlib.h, string.h).
 *
 * The AES state is always a 4x4 = 16-byte matrix stored in FIPS 197
 * column-major order: state[r + 4*c] holds row r, column c.
 * Bytes are loaded directly from / stored directly to the plaintext /
 * ciphertext buffer with no reordering (memcpy).
 *
 * References:
 *   FIPS PUB 197 - Advanced Encryption Standard
 *   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 */

#include "rijndael.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ===========================================================================
 * AES lookup tables
 * =========================================================================*/

/*
 * Forward S-box: S_BOX[i] = SubBytes(i).
 * Constructed from the multiplicative inverse in GF(2^8) followed by
 * the affine transformation defined in FIPS 197 §5.1.1.
 */
static const uint8_t S_BOX[256] = {
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/*
 * Inverse S-box: INV_S_BOX[i] = InvSubBytes(i).
 */
static const uint8_t INV_S_BOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/*
 * Round constants for key expansion.
 * RCON[i] = x^(i-1) in GF(2^8); we use 1-based indexing (RCON[0] unused).
 */
static const uint8_t RCON[11] = {
    0x00,  /* unused — key expansion starts at i=1 */
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* ===========================================================================
 * Block-size utilities  (from starter scaffold, kept verbatim in spirit)
 * =========================================================================*/

size_t block_size_to_bytes(aes_block_size_t block_size)
{
    switch (block_size) {
    case AES_BLOCK_128: return 16;
    case AES_BLOCK_256: return 32;
    case AES_BLOCK_512: return 64;
    default:
        fprintf(stderr, "Invalid block size %d\n", block_size);
        exit(1);
    }
}

/*
 * block_access - treat the byte array as a row-major 2-D matrix.
 * Used by main.c for pretty-printing; not used by the cipher itself.
 *   AES_BLOCK_128: 4 rows x 4 cols  (row_len = 4)
 *   AES_BLOCK_256: 4 rows x 8 cols  (row_len = 8)
 *   AES_BLOCK_512: 4 rows x 16 cols (row_len = 16)
 */
unsigned char block_access(unsigned char *block,
                           size_t row, size_t col,
                           aes_block_size_t block_size)
{
    int row_len;
    switch (block_size) {
    case AES_BLOCK_128: row_len = 4;  break;
    case AES_BLOCK_256: row_len = 8;  break;
    case AES_BLOCK_512: row_len = 16; break;
    default:
        fprintf(stderr, "Invalid block size for block_access: %d\n", block_size);
        exit(1);
    }
    return block[(row * row_len) + col];
}

/* ===========================================================================
 * Block-size parameters for the cipher
 * =========================================================================*/

/* Number of AES rounds for each block size. */
static inline int num_rounds(aes_block_size_t bs)
{
    switch (bs) {
    case AES_BLOCK_128: return 10;
    case AES_BLOCK_256: return 14;
    case AES_BLOCK_512: return 22;
    default:            return 10;
    }
}

/* Number of 32-bit words in the original key (Nk in FIPS 197). */
static inline int num_key_words(aes_block_size_t bs)
{
    switch (bs) {
    case AES_BLOCK_128: return 4;   /* 16 bytes / 4 */
    case AES_BLOCK_256: return 8;   /* 32 bytes / 4 */
    case AES_BLOCK_512: return 16;  /* 64 bytes / 4 */
    default:            return 4;
    }
}

/* Total bytes in the expanded key = (Nr+1) * 16. */
static inline int expanded_key_bytes(aes_block_size_t bs)
{
    return (num_rounds(bs) + 1) * 16;
}

/* ===========================================================================
 * GF(2^8) arithmetic
 * Irreducible polynomial: x^8 + x^4 + x^3 + x + 1  (0x11B)
 * =========================================================================*/

/* Multiply by 2 (xtime): left shift, XOR 0x1B if the high bit was set. */
static inline uint8_t gf_mul2(uint8_t a)
{
    return (a << 1) ^ ((a >> 7) ? 0x1b : 0x00);
}

/*
 * Multiply two bytes in GF(2^8) using the double-and-add algorithm.
 * The multiplier b is typically a small constant (2, 3, 9, 11, 13, 14).
 */
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
    uint8_t result = 0;
    uint8_t cur    = a;

    while (b) {
        if (b & 1)
            result ^= cur;
        cur  = gf_mul2(cur);
        b  >>= 1;
    }
    return result;
}

/* ===========================================================================
 * SubBytes / InvSubBytes
 *
 * The AES state is 16 bytes regardless of key size; ShiftRows and SubBytes
 * always operate on this 4x4 = 16-byte state.
 * The block_size parameter is accepted (to match the API) but ignored here.
 * =========================================================================*/

void sub_bytes(unsigned char *block, aes_block_size_t block_size)
{
    (void)block_size; /* state is always 16 bytes */
    for (int i = 0; i < 16; i++)
        block[i] = S_BOX[block[i]];
}

void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size)
{
    (void)block_size;
    for (int i = 0; i < 16; i++)
        block[i] = INV_S_BOX[block[i]];
}

/* ===========================================================================
 * ShiftRows / InvShiftRows
 *
 * FIPS 197 column-major state layout (index = row + 4*col):
 *
 *   state[0]  state[4]  state[8]  state[12]   <- row 0, no shift
 *   state[1]  state[5]  state[9]  state[13]   <- row 1, shift left 1
 *   state[2]  state[6]  state[10] state[14]   <- row 2, shift left 2
 *   state[3]  state[7]  state[11] state[15]   <- row 3, shift left 3
 *
 * Row r contains bytes at indices r, r+4, r+8, r+12.
 * =========================================================================*/

void shift_rows(unsigned char *block, aes_block_size_t block_size)
{
    (void)block_size;
    uint8_t tmp;

    /* Row 1: left shift by 1 */
    tmp        = block[1];
    block[1]   = block[5];
    block[5]   = block[9];
    block[9]   = block[13];
    block[13]  = tmp;

    /* Row 2: left shift by 2 (swap pairs) */
    tmp        = block[2];
    block[2]   = block[10];
    block[10]  = tmp;
    tmp        = block[6];
    block[6]   = block[14];
    block[14]  = tmp;

    /* Row 3: left shift by 3 == right shift by 1 */
    tmp        = block[15];
    block[15]  = block[11];
    block[11]  = block[7];
    block[7]   = block[3];
    block[3]   = tmp;
}

void invert_shift_rows(unsigned char *block, aes_block_size_t block_size)
{
    (void)block_size;
    uint8_t tmp;

    /* Row 1: right shift by 1 */
    tmp        = block[13];
    block[13]  = block[9];
    block[9]   = block[5];
    block[5]   = block[1];
    block[1]   = tmp;

    /* Row 2: right shift by 2 (swap pairs) */
    tmp        = block[2];
    block[2]   = block[10];
    block[10]  = tmp;
    tmp        = block[6];
    block[6]   = block[14];
    block[14]  = tmp;

    /* Row 3: right shift by 3 == left shift by 1 */
    tmp        = block[3];
    block[3]   = block[7];
    block[7]   = block[11];
    block[11]  = block[15];
    block[15]  = tmp;
}

/* ===========================================================================
 * MixColumns / InvMixColumns
 *
 * Each of the 4 columns is treated as a polynomial over GF(2^8) and
 * multiplied by a fixed MDS polynomial modulo x^4 + 1.
 *
 * In FIPS 197 column-major layout, column c occupies bytes:
 *   block[c*4+0], block[c*4+1], block[c*4+2], block[c*4+3]
 *
 * Forward matrix:
 *   [2 3 1 1]   [s0]
 *   [1 2 3 1] x [s1]
 *   [1 1 2 3]   [s2]
 *   [3 1 1 2]   [s3]
 *
 * Inverse matrix (used in decryption):
 *   [14 11 13  9]   [s0]
 *   [ 9 14 11 13] x [s1]
 *   [13  9 14 11]   [s2]
 *   [11 13  9 14]   [s3]
 * =========================================================================*/

void mix_columns(unsigned char *block, aes_block_size_t block_size)
{
    (void)block_size;

    for (int col = 0; col < 4; col++) {
        uint8_t s0 = block[col * 4 + 0];
        uint8_t s1 = block[col * 4 + 1];
        uint8_t s2 = block[col * 4 + 2];
        uint8_t s3 = block[col * 4 + 3];

        block[col * 4 + 0] = gf_mul(s0, 2) ^ gf_mul(s1, 3) ^ s2          ^ s3;
        block[col * 4 + 1] = s0            ^ gf_mul(s1, 2) ^ gf_mul(s2, 3) ^ s3;
        block[col * 4 + 2] = s0            ^ s1            ^ gf_mul(s2, 2) ^ gf_mul(s3, 3);
        block[col * 4 + 3] = gf_mul(s0, 3) ^ s1            ^ s2            ^ gf_mul(s3, 2);
    }
}

void invert_mix_columns(unsigned char *block, aes_block_size_t block_size)
{
    (void)block_size;

    for (int col = 0; col < 4; col++) {
        uint8_t s0 = block[col * 4 + 0];
        uint8_t s1 = block[col * 4 + 1];
        uint8_t s2 = block[col * 4 + 2];
        uint8_t s3 = block[col * 4 + 3];

        block[col * 4 + 0] = gf_mul(s0, 14) ^ gf_mul(s1, 11) ^ gf_mul(s2, 13) ^ gf_mul(s3,  9);
        block[col * 4 + 1] = gf_mul(s0,  9) ^ gf_mul(s1, 14) ^ gf_mul(s2, 11) ^ gf_mul(s3, 13);
        block[col * 4 + 2] = gf_mul(s0, 13) ^ gf_mul(s1,  9) ^ gf_mul(s2, 14) ^ gf_mul(s3, 11);
        block[col * 4 + 3] = gf_mul(s0, 11) ^ gf_mul(s1, 13) ^ gf_mul(s2,  9) ^ gf_mul(s3, 14);
    }
}





