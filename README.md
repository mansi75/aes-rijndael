
# AES Rijndael — C Library Implementation

A from-scratch implementation of the AES (Rijndael) block cipher written in C, built as part of the Secure Systems Development module. The library supports 128-bit, 256-bit, and 512-bit block sizes and implements the full encryption and decryption pipeline with no third-party dependencies and no hardware AES instructions.

---

## What This Is

AES (Advanced Encryption Standard) is the symmetric encryption algorithm used pretty much everywhere — TLS, disk encryption, Wi-Fi, VPNs, you name it. This project implements it from the ground up in C, following the FIPS 197 specification, without relying on any existing crypto libraries.

The goal was to genuinely understand how AES works internally — not just call a library function, but actually implement SubBytes, ShiftRows, MixColumns, the key schedule, and wire it all together correctly. Every step is unit tested individually against NIST known-answer vectors, and the full encrypt/decrypt pipeline is tested against the FIPS 197 Appendix B and C test vectors.

---

## Repository Structure

aes-rijndael/
├── .github/
│   └── workflows/
│       └── build.yml        # GitHub Actions CI pipeline
├── .clang-format            # Code formatting configuration (LLVM style)
├── .gitignore               # Ignores build artefacts
├── Makefile                 # Build rules for library, demo, and tests
├── main.c                   # Demo program — encrypts a sample block
├── rijndael.h               # Public API header
├── rijndael.c               # Full AES implementation (~500 lines)
├── test_aes.c               # C unit tests (37 assertions)
├── test_rijndael.py         # Python ctypes test suite (35 tests)
└── README.md

---

## Prerequisites

### macOS

```bash
brew install gcc make python3
pip3 install pytest
```

### Ubuntu / Debian / WSL

```bash
sudo apt-get update
sudo apt-get install -y gcc make python3 python3-pip
pip3 install pytest
```

### Verify everything is installed

```bash
gcc --version
make --version
python3 --version
pytest --version
```

---

## Building the Project

### Build the shared library and demo binary

```bash
make all
```

Expected output (no errors, no warnings):

cc -Wall -Wextra -pedantic -std=c11 -O2 -o rijndael.o -fPIC -c rijndael.c
cc -Wall -Wextra -pedantic -std=c11 -O2 -o main main.c rijndael.o
cc -o rijndael.so -shared rijndael.o

### Run the demo program

```bash
./main
```

This encrypts a sample 16-byte plaintext block using a fixed key, prints the ciphertext, then decrypts it back and shows the recovered plaintext — which must exactly match the original.

############ ORIGINAL PLAINTEXT ###########
1  2  3  4
5  6  7  8
9 10 11 12
13 14 15 16
################ CIPHERTEXT ###############
75149134147
180233196235
146179232105
175 64224206
########### RECOVERED PLAINTEXT ###########
1  2  3  4
5  6  7  8
9 10 11 12
13 14 15 16

### Clean build artefacts

```bash
make clean
```

---

## Running the Tests

### C unit tests

```bash
make test_aes
./test_aes
```

### Python test suite

```bash
python3 -m pytest test_rijndael.py -v
```

### Run everything with one command

```bash
make test
```

This runs the C tests followed by the Python tests in one shot.

---

## How AES Works

### The state matrix

AES always operates on a fixed 4×4 = 16-byte state matrix, regardless of key size. Input bytes are loaded into this matrix column by column, following the FIPS 197 specification. The key size determines how many rounds are performed and how the key schedule is derived — it does not change the size of the state.

### The four cipher steps

**SubBytes** replaces every byte in the state with its corresponding value in the AES S-box, a fixed 256-entry lookup table. The S-box is constructed from the multiplicative inverse in GF(2⁸) followed by an affine transformation. The result is a highly non-linear mapping with no fixed points — no byte maps to itself — which makes the cipher resistant to differential and linear cryptanalysis.

**ShiftRows** cyclically shifts each row of the state matrix to the left by its row index. Row 0 stays unchanged, row 1 shifts one position, row 2 shifts two, row 3 shifts three. This ensures that after ShiftRows, the bytes in each column come from four different columns of the previous state, spreading the influence of each byte across the whole block.

**MixColumns** treats each column of the state as a polynomial over GF(2⁸) and multiplies it by a fixed MDS matrix. All arithmetic is done in the Galois Field GF(2⁸) using the irreducible polynomial x⁸ + x⁴ + x³ + x + 1 (0x11B). This step provides the strongest diffusion in AES — a single byte change in the input affects all four output bytes of that column. Combined with ShiftRows, full avalanche is achieved after just two rounds.

**AddRoundKey** XORs the current state with a 16-byte round key derived from the key schedule. This is the only step where the secret key material enters the cipher. Because XOR is self-inverse, this step needs no separate decryption variant — applying it twice with the same key restores the original state.

### Key expansion

The key schedule takes the original cipher key and derives one 16-byte round key per round, plus one for the initial XOR before the first round. Each new word in the schedule is computed by XORing earlier words with a transformed version of the previous word. The transformation involves RotWord (cyclic rotation), SubWord (S-box substitution), and XOR with a round constant (Rcon). For AES-256, an extra SubWord step is added at the halfway point of each key-length block to increase non-linearity.

### Decryption

Decryption uses the same round key schedule as encryption but applies the round keys in reverse order. The inverse of each step is used: InvSubBytes (inverse S-box lookup), InvShiftRows (right shift instead of left), and InvMixColumns (inverse matrix multiplication in GF(2⁸)). AddRoundKey is its own inverse so it stays the same.

### Block sizes

| Variant       | Key size | Rounds |
|---------------|----------|--------|
| AES-128       | 16 bytes | 10     |
| AES-256       | 32 bytes | 14     |
| Rijndael-512  | 64 bytes | 22     |

---

## Public API

```c
// Encrypt one block. Returns heap-allocated ciphertext. Caller must free().
unsigned char *aes_encrypt_block(unsigned char *plaintext,
                                 unsigned char *key,
                                 aes_block_size_t block_size);

// Decrypt one block. Returns heap-allocated plaintext. Caller must free().
unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key,
                                 aes_block_size_t block_size);
```

Example usage:

```c
unsigned char plaintext[16] = { 1, 2, 3, 4, 5, 6, 7, 8,
                                 9, 10, 11, 12, 13, 14, 15, 16 };
unsigned char key[16] = { 50, 20, 46, 86, 67, 9, 70, 27,
                           75, 17, 51, 17, 4, 8, 6, 99 };

unsigned char *ciphertext = aes_encrypt_block(plaintext, key, AES_BLOCK_128);
unsigned char *recovered  = aes_decrypt_block(ciphertext, key, AES_BLOCK_128);

free(ciphertext);
free(recovered);
```

---

## Continuous Integration

Every push to this repository triggers a GitHub Actions workflow defined in `.github/workflows/build.yml`. The pipeline runs on Ubuntu and performs the following steps in order:

1. Checks out the repository including any submodules
2. Installs gcc, make, python3, pytest, and clang-format
3. Runs a clang-format check on the C source files
4. Builds the shared library and demo binary with `make all`
5. Compiles and runs the C unit tests
6. Runs the Python ctypes test suite

If any step fails, the workflow reports a failure and the commit is marked red. All 72 tests must pass for the build to go green.

---

## Limitations

This implementation encrypts and decrypts one block at a time (ECB mode). Real-world applications need a mode of operation on top of this — such as CBC, CTR, or GCM — to securely handle messages longer than 16 bytes. Mode of operation is outside the scope of this assignment.

The Rijndael-512 variant passes all round-trip tests but has no official NIST known-answer vectors, since it is an extension beyond the FIPS 197 AES standard.

---

## References

- NIST FIPS PUB 197 — Advanced Encryption Standard: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
- Daemen, J. and Rijmen, V. — AES Proposal: Rijndael (Version 2), 1999
- boppreh/aes — Pure Python AES reference implementation: https://github.com/boppreh/aes
- Python ctypes documentation: https://docs.python.org/3/library/ctypes.html
- GitHub Actions documentation: https://docs.github.com/en/actions

