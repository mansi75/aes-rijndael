#!/usr/bin/env python3
"""
test_rijndael.py - Python ctypes test suite for the AES Rijndael C library.

Loads rijndael.so via ctypes and tests every cipher step against an inline
pure-Python reference implementation derived from the AES specification.
Where the boppreh/aes git submodule is present (at ./aes/), end-to-end
encrypt/decrypt calls are also cross-checked against that reference.

Run:
    python3 -m pytest test_rijndael.py -v
Prerequisites:
    make rijndael.so
"""

import ctypes
import os
import sys
import random
import unittest

# ── Load shared library ───────────────────────────────────────────────────────

_LIB = os.path.join(os.path.dirname(__file__), "rijndael.so")
try:
    rijndael = ctypes.CDLL(_LIB)
except OSError as e:
    print(f"[ERROR] Could not load {_LIB}: {e}\n  Run 'make rijndael.so' first.")
    sys.exit(1)

# ── ctypes function signatures ────────────────────────────────────────────────

# Block-size enum values (must match rijndael.h exactly)
AES_BLOCK_128 = 0
AES_BLOCK_256 = 1
AES_BLOCK_512 = 2

def _sig(fn, argtypes, restype=None):
    fn.argtypes = argtypes
    fn.restype  = restype

_sig(rijndael.sub_bytes,         [ctypes.c_char_p, ctypes.c_int])
_sig(rijndael.invert_sub_bytes,  [ctypes.c_char_p, ctypes.c_int])
_sig(rijndael.shift_rows,        [ctypes.c_char_p, ctypes.c_int])
_sig(rijndael.invert_shift_rows, [ctypes.c_char_p, ctypes.c_int])
_sig(rijndael.mix_columns,       [ctypes.c_char_p, ctypes.c_int])
_sig(rijndael.invert_mix_columns,[ctypes.c_char_p, ctypes.c_int])
_sig(rijndael.add_round_key,     [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int])
_sig(rijndael.expand_key,        [ctypes.c_char_p, ctypes.c_int], ctypes.c_void_p)
_sig(rijndael.aes_encrypt_block, [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int],
     ctypes.c_void_p)
_sig(rijndael.aes_decrypt_block, [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int],
     ctypes.c_void_p)

# ── ctypes helpers ────────────────────────────────────────────────────────────

def _buf(data: bytes, n: int = None) -> ctypes.Array:
    """Create a ctypes buffer of exactly n bytes (avoids null-terminator issues)."""
    size = n if n is not None else len(data)
    return ctypes.create_string_buffer(data, size)

def _call_inplace(fn, data: bytes, block_size: int) -> bytes:
    """Call an in-place C function on a 16-byte buffer; return result bytes."""
    buf = _buf(data, 16)
    fn(buf, block_size)
    return bytes(buf)

def c_sub_bytes(b):         return _call_inplace(rijndael.sub_bytes, b, AES_BLOCK_128)
def c_invert_sub_bytes(b):  return _call_inplace(rijndael.invert_sub_bytes, b, AES_BLOCK_128)
def c_shift_rows(b):        return _call_inplace(rijndael.shift_rows, b, AES_BLOCK_128)
def c_invert_shift_rows(b): return _call_inplace(rijndael.invert_shift_rows, b, AES_BLOCK_128)
def c_mix_columns(b):       return _call_inplace(rijndael.mix_columns, b, AES_BLOCK_128)
def c_invert_mix_columns(b):return _call_inplace(rijndael.invert_mix_columns, b, AES_BLOCK_128)

def c_encrypt(pt: bytes, key: bytes, block_size: int) -> bytes:
    ptr = rijndael.aes_encrypt_block(_buf(pt, 16), _buf(key, len(key)), block_size)
    return ctypes.string_at(ptr, 16) if ptr else None

def c_decrypt(ct: bytes, key: bytes, block_size: int) -> bytes:
    ptr = rijndael.aes_decrypt_block(_buf(ct, 16), _buf(key, len(key)), block_size)
    return ctypes.string_at(ptr, 16) if ptr else None

def rand_bytes(n: int) -> bytes:
    return bytes(random.randint(0, 255) for _ in range(n))

# ── Pure-Python AES reference (for step-level unit tests) ────────────────────

_SBOX = bytes([
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
])
_INV_SBOX = bytes([
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
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
])

def _gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8), polynomial 0x11B."""
    r = 0
    while b:
        if b & 1: r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi: a ^= 0x1b
        b >>= 1
    return r

def ref_sub_bytes(block: bytes) -> bytes:
    return bytes(_SBOX[b] for b in block)

def ref_invert_sub_bytes(block: bytes) -> bytes:
    return bytes(_INV_SBOX[b] for b in block)

def ref_shift_rows(state: bytes) -> bytes:
    """FIPS 197 column-major layout: row r is at indices r, r+4, r+8, r+12."""
    s = list(state)
    s[1], s[5], s[9],  s[13] = s[5],  s[9],  s[13], s[1]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2],  s[6]
    s[3], s[7], s[11], s[15] = s[15], s[3],  s[7],  s[11]
    return bytes(s)

def ref_invert_shift_rows(state: bytes) -> bytes:
    s = list(state)
    s[1], s[5], s[9],  s[13] = s[13], s[1],  s[5],  s[9]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2],  s[6]
    s[3], s[7], s[11], s[15] = s[7],  s[11], s[15], s[3]
    return bytes(s)

def ref_mix_columns(state: bytes) -> bytes:
    """Column c occupies bytes col*4 .. col*4+3."""
    s = bytearray(state)
    for c in range(4):
        s0, s1, s2, s3 = state[c*4], state[c*4+1], state[c*4+2], state[c*4+3]
        s[c*4]   = _gf_mul(s0,2) ^ _gf_mul(s1,3) ^ s2           ^ s3
        s[c*4+1] = s0            ^ _gf_mul(s1,2) ^ _gf_mul(s2,3) ^ s3
        s[c*4+2] = s0            ^ s1             ^ _gf_mul(s2,2) ^ _gf_mul(s3,3)
        s[c*4+3] = _gf_mul(s0,3) ^ s1             ^ s2            ^ _gf_mul(s3,2)
    return bytes(s)

def ref_invert_mix_columns(state: bytes) -> bytes:
    s = bytearray(state)
    for c in range(4):
        s0, s1, s2, s3 = state[c*4], state[c*4+1], state[c*4+2], state[c*4+3]
        s[c*4]   = _gf_mul(s0,14) ^ _gf_mul(s1,11) ^ _gf_mul(s2,13) ^ _gf_mul(s3, 9)
        s[c*4+1] = _gf_mul(s0, 9) ^ _gf_mul(s1,14) ^ _gf_mul(s2,11) ^ _gf_mul(s3,13)
        s[c*4+2] = _gf_mul(s0,13) ^ _gf_mul(s1, 9) ^ _gf_mul(s2,14) ^ _gf_mul(s3,11)
        s[c*4+3] = _gf_mul(s0,11) ^ _gf_mul(s1,13) ^ _gf_mul(s2, 9) ^ _gf_mul(s3,14)
    return bytes(s)

# ── Optional boppreh/aes cross-check ─────────────────────────────────────────

_have_ref = False
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "aes"))
    import aes as _ref_aes
    _have_ref = True
    print("[INFO] boppreh/aes submodule found — cross-check enabled.")
except ImportError:
    print("[INFO] boppreh/aes not found; NIST vectors used for end-to-end checks.")

def ref_encrypt(pt: bytes, key: bytes) -> bytes | None:
    if not _have_ref: return None
    return bytes(_ref_aes.AES(key).encrypt_block(list(pt)))

def ref_decrypt(ct: bytes, key: bytes) -> bytes | None:
    if not _have_ref: return None
    return bytes(_ref_aes.AES(key).decrypt_block(list(ct)))

# ── Test classes ──────────────────────────────────────────────────────────────

class TestSubBytes(unittest.TestCase):
    """sub_bytes and invert_sub_bytes vs. Python reference."""

    def _check_fwd(self, data: bytes):
        self.assertEqual(c_sub_bytes(data), ref_sub_bytes(data),
                         f"sub_bytes mismatch: {data.hex()}")

    def _check_inv(self, data: bytes):
        self.assertEqual(c_invert_sub_bytes(data), ref_invert_sub_bytes(data))

    def test_sub_all_zeros(self):      self._check_fwd(b'\x00' * 16)
    def test_sub_sequential(self):     self._check_fwd(bytes(range(16)))
    def test_sub_random_1(self):       self._check_fwd(rand_bytes(16))
    def test_sub_random_2(self):       self._check_fwd(rand_bytes(16))
    def test_sub_random_3(self):       self._check_fwd(rand_bytes(16))
    def test_inv_sub_random_1(self):   self._check_inv(rand_bytes(16))
    def test_inv_sub_random_2(self):   self._check_inv(rand_bytes(16))
    def test_inv_sub_random_3(self):   self._check_inv(rand_bytes(16))
    def test_sub_roundtrip(self):
        for _ in range(3):
            d = rand_bytes(16)
            self.assertEqual(c_invert_sub_bytes(c_sub_bytes(d)), d)


class TestShiftRows(unittest.TestCase):
    """shift_rows and invert_shift_rows vs. Python reference."""

    def _check_fwd(self, data: bytes):
        self.assertEqual(c_shift_rows(data), ref_shift_rows(data))

    def _check_inv(self, data: bytes):
        self.assertEqual(c_invert_shift_rows(data), ref_invert_shift_rows(data))

    def test_shift_sequential(self):   self._check_fwd(bytes(range(16)))
    def test_shift_random_1(self):     self._check_fwd(rand_bytes(16))
    def test_shift_random_2(self):     self._check_fwd(rand_bytes(16))
    def test_shift_random_3(self):     self._check_fwd(rand_bytes(16))
    def test_inv_shift_random_1(self): self._check_inv(rand_bytes(16))
    def test_inv_shift_random_2(self): self._check_inv(rand_bytes(16))
    def test_inv_shift_random_3(self): self._check_inv(rand_bytes(16))
    def test_shift_roundtrip(self):
        for _ in range(3):
            d = rand_bytes(16)
            self.assertEqual(c_invert_shift_rows(c_shift_rows(d)), d)
    def test_shift_uniform(self):
        d = b'\xAB' * 16
        self.assertEqual(c_shift_rows(d), d)


class TestMixColumns(unittest.TestCase):
    """mix_columns and invert_mix_columns vs. Python reference."""

    def _check_fwd(self, data: bytes):
        self.assertEqual(c_mix_columns(data), ref_mix_columns(data))

    def _check_inv(self, data: bytes):
        self.assertEqual(c_invert_mix_columns(data), ref_invert_mix_columns(data))

    def test_mix_zeros(self):          self._check_fwd(b'\x00' * 16)
    def test_mix_random_1(self):       self._check_fwd(rand_bytes(16))
    def test_mix_random_2(self):       self._check_fwd(rand_bytes(16))
    def test_mix_random_3(self):       self._check_fwd(rand_bytes(16))
    def test_inv_mix_random_1(self):   self._check_inv(rand_bytes(16))
    def test_inv_mix_random_2(self):   self._check_inv(rand_bytes(16))
    def test_inv_mix_random_3(self):   self._check_inv(rand_bytes(16))
    def test_mix_roundtrip(self):
        for _ in range(3):
            d = rand_bytes(16)
            self.assertEqual(c_invert_mix_columns(c_mix_columns(d)), d)
    def test_mix_fips_column(self):
        """FIPS 197 §5.1.3: [db,13,53,45] -> [8e,4d,a1,bc]"""
        inp = bytes([0xdb,0x13,0x53,0x45]) + b'\x00' * 12
        out = c_mix_columns(inp)
        self.assertEqual(out[:4], bytes([0x8e,0x4d,0xa1,0xbc]))


class TestNISTVectors(unittest.TestCase):
    """Full encrypt/decrypt against NIST FIPS 197 known-answer vectors."""

    def test_aes128_encrypt(self):
        pt  = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        self.assertEqual(c_encrypt(pt, key, AES_BLOCK_128),
                         bytes.fromhex("3925841d02dc09fbdc118597196a0b32"))

    def test_aes128_decrypt(self):
        ct  = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        self.assertEqual(c_decrypt(ct, key, AES_BLOCK_128),
                         bytes.fromhex("3243f6a8885a308d313198a2e0370734"))

    def test_aes256_encrypt(self):
        pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                            "101112131415161718191a1b1c1d1e1f")
        self.assertEqual(c_encrypt(pt, key, AES_BLOCK_256),
                         bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"))

    def test_aes256_decrypt(self):
        ct  = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f"
                            "101112131415161718191a1b1c1d1e1f")
        self.assertEqual(c_decrypt(ct, key, AES_BLOCK_256),
                         bytes.fromhex("00112233445566778899aabbccddeeff"))


class TestEndToEndRoundTrips(unittest.TestCase):
    """Random plaintext/key round-trips for all three block sizes."""

    def _roundtrip(self, block_size: int, key_len: int, label: str):
        for i in range(3):
            pt  = rand_bytes(16)
            key = rand_bytes(key_len)
            ct  = c_encrypt(pt, key, block_size)
            rec = c_decrypt(ct, key, block_size)
            self.assertIsNotNone(ct,  f"{label} #{i+1}: encrypt returned None")
            self.assertIsNotNone(rec, f"{label} #{i+1}: decrypt returned None")
            self.assertEqual(rec, pt, f"{label} #{i+1}: round-trip mismatch")
            if _have_ref and block_size == AES_BLOCK_128:
                self.assertEqual(ct, ref_encrypt(pt, key),
                                 f"{label} #{i+1}: mismatch vs reference")

    def test_aes128_roundtrips(self):  self._roundtrip(AES_BLOCK_128, 16, "AES-128")
    def test_aes256_roundtrips(self):  self._roundtrip(AES_BLOCK_256, 32, "AES-256")
    def test_aes512_roundtrips(self):  self._roundtrip(AES_BLOCK_512, 64, "AES-512")

    def test_ct_differs_from_pt(self):
        for _ in range(3):
            pt  = rand_bytes(16)
            key = rand_bytes(16)
            self.assertNotEqual(c_encrypt(pt, key, AES_BLOCK_128), pt)


if __name__ == "__main__":
    random.seed()
    unittest.main(verbosity=2)