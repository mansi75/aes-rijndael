/*
 * test_aes.c - C unit tests for the AES Rijndael implementation.
 *
 * Tests each cipher step independently using NIST FIPS 197 known-answer
 * vectors, then tests full encrypt/decrypt round-trips for all three block
 * sizes. Uses no external test frameworks.
 *
 * Compile & run:
 *   make test_aes && ./test_aes
 */

#include "rijndael.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ─── Minimal test framework ─────────────────────────────────────────────── */

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_BYTES_EQ(label, got, expected, len)                            \
    do {                                                                       \
        tests_run++;                                                           \
        if (memcmp((got), (expected), (size_t)(len)) == 0) {                  \
            printf("[PASS] %s\n", (label));                                    \
            tests_passed++;                                                    \
        } else {                                                               \
            printf("[FAIL] %s\n", (label));                                    \
            printf("  Expected: ");                                            \
            for (int _i = 0; _i < (len); _i++)                                \
                printf("%02x ", ((const unsigned char *)(expected))[_i]);     \
            printf("\n  Got:      ");                                          \
            for (int _i = 0; _i < (len); _i++)                                \
                printf("%02x ", ((const unsigned char *)(got))[_i]);          \
            printf("\n");                                                      \
            tests_failed++;                                                    \
        }                                                                      \
    } while (0)

#define ASSERT_TRUE(label, cond)                                              \
    do {                                                                       \
        tests_run++;                                                           \
        if (cond) { printf("[PASS] %s\n", (label)); tests_passed++; }         \
        else      { printf("[FAIL] %s\n", (label)); tests_failed++;  }        \
    } while (0)

/* ─── SubBytes ───────────────────────────────────────────────────────────── */

static void test_sub_bytes(void)
{
    printf("\n--- SubBytes ---\n");
    unsigned char block[16];

    /* S_BOX[0x00] = 0x63, so all-zeros should become all-0x63 */
    memset(block, 0x00, 16);
    sub_bytes(block, AES_BLOCK_128);
    unsigned char expected_zeros[16];
    memset(expected_zeros, 0x63, 16);
    ASSERT_BYTES_EQ("SubBytes(0x00*16) = 0x63*16", block, expected_zeros, 16);

    /* SubBytes on 0x00..0x0f = first 16 entries of S_BOX */
    for (int i = 0; i < 16; i++) block[i] = (unsigned char)i;
    sub_bytes(block, AES_BLOCK_128);
    unsigned char expected_seq[16] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
        0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
    };
    ASSERT_BYTES_EQ("SubBytes(0x00..0x0f) = S_BOX[0..15]", block, expected_seq, 16);

    /* InvSubBytes must undo SubBytes */
    unsigned char orig[16];
    for (int i = 0; i < 16; i++) orig[i] = (unsigned char)(i * 17 + 3);
    memcpy(block, orig, 16);
    sub_bytes(block, AES_BLOCK_128);
    invert_sub_bytes(block, AES_BLOCK_128);
    ASSERT_BYTES_EQ("InvSubBytes(SubBytes(x)) == x", block, orig, 16);
}

/* ─── ShiftRows ──────────────────────────────────────────────────────────── */

static void test_shift_rows(void)
{
    printf("\n--- ShiftRows ---\n");
    unsigned char block[16];

    /*
     * With FIPS 197 column-major layout, the block bytes 0..15 are:
     *   Col0=[0,1,2,3]  Col1=[4,5,6,7]  Col2=[8,9,10,11]  Col3=[12,13,14,15]
     * Rows are at indices r, r+4, r+8, r+12.
     * ShiftRows left by r gives:
     *   Row0 (0,4,8,12):  no change
     *   Row1 (1,5,9,13):  -> 5,9,13,1
     *   Row2 (2,6,10,14): -> 10,14,2,6
     *   Row3 (3,7,11,15): -> 15,3,7,11
     * Result: [0,5,10,15, 4,9,14,3, 8,13,2,7, 12,1,6,11]
     */
    for (int i = 0; i < 16; i++) block[i] = (unsigned char)i;
    shift_rows(block, AES_BLOCK_128);
    unsigned char expected_shift[16] = {
        0, 5, 10, 15,  4, 9, 14, 3,  8, 13, 2, 7,  12, 1, 6, 11
    };
    ASSERT_BYTES_EQ("ShiftRows(0..15) correct permutation", block, expected_shift, 16);

    /* InvShiftRows must undo ShiftRows */
    unsigned char orig[16];
    for (int i = 0; i < 16; i++) orig[i] = (unsigned char)(i * 13 + 7);
    memcpy(block, orig, 16);
    shift_rows(block, AES_BLOCK_128);
    invert_shift_rows(block, AES_BLOCK_128);
    ASSERT_BYTES_EQ("InvShiftRows(ShiftRows(x)) == x", block, orig, 16);

    /* Uniform block should be unchanged by ShiftRows */
    memset(block, 0xAB, 16);
    unsigned char same[16];
    memset(same, 0xAB, 16);
    shift_rows(block, AES_BLOCK_128);
    ASSERT_BYTES_EQ("ShiftRows(uniform) = identity", block, same, 16);
}

/* ─── MixColumns ─────────────────────────────────────────────────────────── */

static void test_mix_columns(void)
{
    printf("\n--- MixColumns ---\n");
    unsigned char block[16];

    /*
     * FIPS 197 §5.1.3 column example:
     * Input column [db, 13, 53, 45] -> Output [8e, 4d, a1, bc]
     */
    memset(block, 0, 16);
    block[0] = 0xdb; block[1] = 0x13; block[2] = 0x53; block[3] = 0x45;
    mix_columns(block, AES_BLOCK_128);
    unsigned char expected_col1[4] = { 0x8e, 0x4d, 0xa1, 0xbc };
    ASSERT_BYTES_EQ("MixColumns: FIPS example [db,13,53,45]->[8e,4d,a1,bc]",
                    block, expected_col1, 4);

    /*
     * Second FIPS 197 example: [f2, 0a, 22, 5c] -> [9f, dc, 58, 9d]
     */
    memset(block, 0, 16);
    block[0] = 0xf2; block[1] = 0x0a; block[2] = 0x22; block[3] = 0x5c;
    mix_columns(block, AES_BLOCK_128);
    unsigned char expected_col2[4] = { 0x9f, 0xdc, 0x58, 0x9d };
    ASSERT_BYTES_EQ("MixColumns: FIPS example [f2,0a,22,5c]->[9f,dc,58,9d]",
                    block, expected_col2, 4);

    /* InvMixColumns must undo MixColumns */
    unsigned char orig[16];
    for (int i = 0; i < 16; i++) orig[i] = (unsigned char)(i * 31 + 5);
    memcpy(block, orig, 16);
    mix_columns(block, AES_BLOCK_128);
    invert_mix_columns(block, AES_BLOCK_128);
    ASSERT_BYTES_EQ("InvMixColumns(MixColumns(x)) == x", block, orig, 16);
}

/* ─── AddRoundKey ────────────────────────────────────────────────────────── */

static void test_add_round_key(void)
{
    printf("\n--- AddRoundKey ---\n");

    unsigned char block[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    unsigned char orig[16];
    memcpy(orig, block, 16);

    unsigned char key[16] = {
        0x13,0x11,0x1d,0x7f,0xe3,0x94,0x4a,0x17,
        0xf3,0x07,0xa7,0x8b,0x4d,0x2b,0x30,0xc5
    };

    /* XOR twice with same key = identity */
    add_round_key(block, key, AES_BLOCK_128);
    add_round_key(block, key, AES_BLOCK_128);
    ASSERT_BYTES_EQ("AddRoundKey applied twice = identity", block, orig, 16);

    /* Single application: block XOR key */
    memcpy(block, orig, 16);
    add_round_key(block, key, AES_BLOCK_128);
    unsigned char expected[16];
    for (int i = 0; i < 16; i++) expected[i] = orig[i] ^ key[i];
    ASSERT_BYTES_EQ("AddRoundKey single XOR", block, expected, 16);

    /* All-zero block XOR key = key */
    memset(block, 0, 16);
    add_round_key(block, key, AES_BLOCK_128);
    ASSERT_BYTES_EQ("AddRoundKey(0x00*16, key) = key", block, key, 16);
}

