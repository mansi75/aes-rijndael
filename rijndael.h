/*
 * rijndael.h - AES (Rijndael) block cipher library interface
 *
 * Implements AES for 128-bit, 256-bit, and 512-bit block/key sizes
 * as defined by the Rijndael specification extended beyond FIPS 197.
 *
 * Public API: aes_encrypt_block / aes_decrypt_block
 * Internal steps exposed for unit-testing via ctypes.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include <stddef.h>
#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Block-size enum (matches starter scaffold exactly)
 *   AES_BLOCK_128 -> 16 bytes, 10 rounds
 *   AES_BLOCK_256 -> 32 bytes, 14 rounds  (key = 32 bytes)
 *   AES_BLOCK_512 -> 64 bytes, 22 rounds  (key = 64 bytes, Rijndael extension)
 * --------------------------------------------------------------------------*/
typedef enum {
    AES_BLOCK_128,
    AES_BLOCK_256,
    AES_BLOCK_512
} aes_block_size_t;

/* ---------------------------------------------------------------------------
 * Helper: access the block as a 2-D row-major matrix (used by main.c for
 * pretty-printing).
 * --------------------------------------------------------------------------*/
unsigned char block_access(unsigned char *block,
                           size_t row, size_t col,
                           aes_block_size_t block_size);

/* Returns the number of bytes for a given block size enum. */
size_t block_size_to_bytes(aes_block_size_t block_size);

/* ---------------------------------------------------------------------------
 * Public encrypt / decrypt API
 * Both functions heap-allocate output; the caller must free() it.
 * --------------------------------------------------------------------------*/
unsigned char *aes_encrypt_block(unsigned char *plaintext,
                                 unsigned char *key,
                                 aes_block_size_t block_size);

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key,
                                 aes_block_size_t block_size);

/* ---------------------------------------------------------------------------
 * Internal cipher-step functions — exposed for ctypes unit-testing.
 * All operate on a 16-byte state buffer in FIPS 197 column-major order.
 * --------------------------------------------------------------------------*/
void sub_bytes(unsigned char *block, aes_block_size_t block_size);
void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size);
void shift_rows(unsigned char *block, aes_block_size_t block_size);
void invert_shift_rows(unsigned char *block, aes_block_size_t block_size);
void mix_columns(unsigned char *block, aes_block_size_t block_size);
void invert_mix_columns(unsigned char *block, aes_block_size_t block_size);
void add_round_key(unsigned char *block,
                   unsigned char *round_key,
                   aes_block_size_t block_size);

/*
 * expand_key — key schedule / key expansion.
 * Returns a heap-allocated array of all round keys concatenated:
 *   AES_BLOCK_128: 176 bytes  (11 x 16)
 *   AES_BLOCK_256: 240 bytes  (15 x 16)
 *   AES_BLOCK_512: 368 bytes  (23 x 16)
 * Caller must free() the returned pointer.
 */
unsigned char *expand_key(unsigned char *cipher_key,
                          aes_block_size_t block_size);

#endif /* RIJNDAEL_H */
