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

/* ─── Key Expansion ──────────────────────────────────────────────────────── */

static void test_key_expansion(void)
{
    printf("\n--- Key Expansion ---\n");

    /*
     * FIPS 197 Appendix A.1: AES-128 key schedule
     * Key: 2b7e151628aed2a6abf7158809cf4f3c
     *
     * RK0 = original key
     * RK1 = a0fafe1788542cb123a339392a6c7605
     * RK2 = f2c295f27a96b9435935807a7359f67f
     * RK10= d014f9a8c9ee2589e13f0cc8b6630ca6  (verified)
     */
    unsigned char key128[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };

    unsigned char *ek128 = expand_key(key128, AES_BLOCK_128);
    ASSERT_TRUE("AES-128 expand_key returns non-NULL", ek128 != NULL);

    if (ek128) {
        ASSERT_BYTES_EQ("AES-128 RK0 = original key", ek128, key128, 16);

        unsigned char rk1[16] = {
            0xa0,0xfa,0xfe,0x17,0x88,0x54,0x2c,0xb1,
            0x23,0xa3,0x39,0x39,0x2a,0x6c,0x76,0x05
        };
        ASSERT_BYTES_EQ("AES-128 RK1 (FIPS A.1)", ek128 + 16, rk1, 16);

        unsigned char rk2[16] = {
            0xf2,0xc2,0x95,0xf2,0x7a,0x96,0xb9,0x43,
            0x59,0x35,0x80,0x7a,0x73,0x59,0xf6,0x7f
        };
        ASSERT_BYTES_EQ("AES-128 RK2 (FIPS A.1)", ek128 + 32, rk2, 16);

        /* RK10 — last round key, verified against Python cryptography library */
        unsigned char rk10[16] = {
            0xd0,0x14,0xf9,0xa8,0xc9,0xee,0x25,0x89,
            0xe1,0x3f,0x0c,0xc8,0xb6,0x63,0x0c,0xa6
        };
        ASSERT_BYTES_EQ("AES-128 RK10 (verified)", ek128 + 160, rk10, 16);

        free(ek128);
    }

    /*
     * AES-256: FIPS 197 Appendix A.3
     * Key: 603deb10...  RK0=key[0..15], RK1=key[16..31]
     */
    unsigned char key256[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    unsigned char *ek256 = expand_key(key256, AES_BLOCK_256);
    ASSERT_TRUE("AES-256 expand_key returns non-NULL", ek256 != NULL);
    if (ek256) {
        ASSERT_BYTES_EQ("AES-256 RK0 = key[0..15]",  ek256,      key256,      16);
        ASSERT_BYTES_EQ("AES-256 RK1 = key[16..31]", ek256 + 16, key256 + 16, 16);
        free(ek256);
    }
}

/* ─── FIPS 197 Known-Answer Vectors ─────────────────────────────────────── */

static void test_fips_vectors(void)
{
    printf("\n--- FIPS 197 Known-Answer Test Vectors ---\n");

    /* ── AES-128  (FIPS 197 Appendix B) ── */
    unsigned char pt128[16] = {
        0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
        0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34
    };
    unsigned char k128[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    unsigned char exp_ct128[16] = {
        0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
        0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32
    };

    unsigned char *ct128 = aes_encrypt_block(pt128, k128, AES_BLOCK_128);
    ASSERT_TRUE("AES-128 encrypt non-NULL", ct128 != NULL);
    if (ct128) {
        ASSERT_BYTES_EQ("AES-128 FIPS B ciphertext", ct128, exp_ct128, 16);
        unsigned char *dec128 = aes_decrypt_block(ct128, k128, AES_BLOCK_128);
        ASSERT_TRUE("AES-128 decrypt non-NULL", dec128 != NULL);
        if (dec128) {
            ASSERT_BYTES_EQ("AES-128 decrypt(encrypt(x)) == x", dec128, pt128, 16);
            free(dec128);
        }
        free(ct128);
    }

    /* ── AES-256  (FIPS 197 Appendix C.3) ── */
    unsigned char pt256[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    unsigned char k256[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    unsigned char exp_ct256[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
        0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89
    };

    unsigned char *ct256 = aes_encrypt_block(pt256, k256, AES_BLOCK_256);
    ASSERT_TRUE("AES-256 encrypt non-NULL", ct256 != NULL);
    if (ct256) {
        ASSERT_BYTES_EQ("AES-256 FIPS C.3 ciphertext", ct256, exp_ct256, 16);
        unsigned char *dec256 = aes_decrypt_block(ct256, k256, AES_BLOCK_256);
        ASSERT_TRUE("AES-256 decrypt non-NULL", dec256 != NULL);
        if (dec256) {
            ASSERT_BYTES_EQ("AES-256 decrypt(encrypt(x)) == x", dec256, pt256, 16);
            free(dec256);
        }
        free(ct256);
    }
}

/* ─── Random round-trips for all three block sizes ───────────────────────── */

static void fill_random(unsigned char *buf, int n)
{
    for (int i = 0; i < n; i++) buf[i] = (unsigned char)(rand() & 0xff);
}

static void test_random_roundtrips(void)
{
    printf("\n--- Random Round-Trip Tests ---\n");
    srand((unsigned)time(NULL));

    struct { aes_block_size_t bs; int klen; const char *name; } tests[] = {
        { AES_BLOCK_128, 16, "AES-128" },
        { AES_BLOCK_256, 32, "AES-256" },
        { AES_BLOCK_512, 64, "AES-512" },
    };

    for (int t = 0; t < 3; t++) {
        for (int trial = 1; trial <= 3; trial++) {
            unsigned char pt[16];
            unsigned char key[64];
            fill_random(pt,  16);
            fill_random(key, tests[t].klen);

            unsigned char *ct  = aes_encrypt_block(pt, key, tests[t].bs);
            unsigned char *rec = ct ? aes_decrypt_block(ct, key, tests[t].bs) : NULL;

            char label[64];
            snprintf(label, sizeof(label),
                     "%s random round-trip #%d", tests[t].name, trial);

            if (ct && rec) {
                ASSERT_BYTES_EQ(label, rec, pt, 16);
            } else {
                printf("[FAIL] %s — NULL pointer\n", label);
                tests_run++; tests_failed++;
            }
            free(ct);
            free(rec);
        }
    }
}

/* ─── Entry point ────────────────────────────────────────────────────────── */

int main(void)
{
    printf("=== AES Rijndael C Unit Tests ===\n");

    test_sub_bytes();
    test_shift_rows();
    test_mix_columns();
    test_add_round_key();
    test_key_expansion();
    test_fips_vectors();
    test_random_roundtrips();

    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed) printf(", %d FAILED", tests_failed);
    printf(" ===\n");

    return tests_failed ? EXIT_FAILURE : EXIT_SUCCESS;
}


