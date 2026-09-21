-- Algorithm Reference Document for 256-bit Cryptography

{-
## 256-bit Algorithms Reference

This document provides detailed information about the 256-bit cryptographic algorithms
integrated into the Blackworm project via OpenSSL.

### Hash Functions (256-bit output)

#### 1. SHA-256 (Secure Hash Algorithm 2 - 256-bit)

**Overview**: Cryptographic hash function from the SHA-2 family
- Output size: 256 bits (32 bytes)
- Block size: 512 bits (64 bytes)
- State size: 256 bits
- Operations: 64 rounds with sigma and hashing functions

**Security Level**: 128-bit (collision resistance)
**RFC**: RFC 3174, FIPS 180-4

**Lean Implementation**:
```lean
def hash256 (data : ByteArray) : IO SHA256Hash
```

**Example**:
```lean
let msg := "The quick brown fox".toUTF8
let hash ← hash256 msg
-- Returns 32-byte SHA-256 hash
```

**Use Cases**:
- Message integrity verification
- Digital signatures (with RSA/ECDSA)
- Merkle trees and blockchain applications
- Password hashing (with salt)
- HMAC construction

**Performance**: ~100-200 MB/s on modern CPUs

---

#### 2. SHA3-256 (Secure Hash Algorithm 3 - 256-bit)

**Overview**: Sponge-based hash function from the SHA-3 family (Keccak)
- Output size: 256 bits (32 bytes)
- Capacity: 512 bits (implies security level 256)
- State: 1600-bit permutation
- Padding: Sponge construction

**Security Level**: 256-bit (post-quantum secure)
**FIPS**: FIPS 202

**Lean Implementation**:
```lean
def hash3_256 (data : ByteArray) : IO SHA3_256Hash
```

**Advantages over SHA-256**:
- More resistant to extension attacks
- Different security paradigm (sponge vs Merkle-Damgård)
- Better cryptanalysis confidence

---

### Symmetric Ciphers (256-bit keys)

#### 1. AES-256 (Advanced Encryption Standard - 256-bit key)

**Overview**: Block cipher using 256-bit keys with 10/12/14 rounds
- Key size: 256 bits (32 bytes)
- Block size: 128 bits (16 bytes)
- Rounds: 14 rounds for key expansion and encryption
- Mode-dependent security

**Modes Implemented**:

**A. AES-256-ECB (Electronic Codebook)** [Unauthenticated]
- Simplest mode: plaintext blocks encrypted independently
- Security: ONLY use for testing (reveals patterns)
- Each 16-byte block encrypted with same key produces same ciphertext

```lean
def encryptAES256ECB (key : AES256Key) (plaintext : ByteArray) : IO ByteArray
def decryptAES256ECB (key : AES256Key) (ciphertext : ByteArray) : IO ByteArray
```

**B. AES-256-CBC (Cipher Block Chaining)** [Unauthenticated]
- IV-dependent mode: each block XORed with previous ciphertext
- Security: IND-CPA secure with random IV
- Requires input padding to block size

```lean
def encryptAES256CBC (key : AES256Key) (iv : AES256IV) (plaintext : ByteArray) : IO ByteArray
def decryptAES256CBC (key : AES256Key) (iv : AES256IV) (ciphertext : ByteArray) : IO ByteArray
```

**C. AES-256-GCM (Galois/Counter Mode)** [Authenticated]
- IV: 96 bits (12 bytes) recommended for efficiency
- Tag: 128 bits (16 bytes) for authentication
- Provides: Confidentiality + Authenticity + Integrity
- Additional Authenticated Data (AAD) support

```lean
def encryptAES256GCM (key : AES256Key) (iv : AES256GCMIV)
                     (plaintext : ByteArray) (aad : ByteArray := #[]) : IO CipherGCMResult

def decryptAES256GCM (key : AES256Key) (iv : AES256GCMIV)
                     (ciphertext : ByteArray) (tag : ByteArray)
                     (aad : ByteArray := #[]) : IO (Option ByteArray)
```

**GCM Performance**: ~500-1000 MB/s (hardware-accelerated)
**NIST Recommendation**: Use GCM or authenticated encryption

---

#### 2. ChaCha20-Poly1305 (AEAD Stream Cipher)

**Overview**: Modern AEAD cipher combining stream cipher and MAC
- Key size: 256 bits (32 bytes)
- Nonce: 96 bits (12 bytes) standard (4-byte counter)
- State: 512-bit internal state
- Block counter: 64 bits (supports up to 2^64 blocks per key)

**Components**:
- **ChaCha20**: 20-round stream cipher (Bernstein)
- **Poly1305**: One-time MAC based on Wegman-Carter construction

**Advantages**:
- No S-box tables (timing attack resistant)
- Cache-timing safe
- Good performance on CPUs without AES-NI
- RFC 7539 standardized

```lean
def encryptChaCha20Poly1305 (key : AES256Key) (nonce : ChaCha20Poly1305Nonce)
                             (plaintext : ByteArray) (aad : ByteArray := #[]) : IO CipherGCMResult

def decryptChaCha20Poly1305 (key : AES256Key) (nonce : ChaCha20Poly1305Nonce)
                             (ciphertext : ByteArray) (tag : ByteArray)
                             (aad : ByteArray := #[]) : IO (Option ByteArray)
```

**Security**: AEAD - provides authentication tags for tamper detection
**Performance**: ~300-600 MB/s

---

### Key Derivation Functions

#### 1. HKDF (HMAC-based Key Derivation Function)

**Algorithm**:
- Extract step: HMAC(salt, IKM) → PRK
- Expand step: Multiple HMAC-iterations for output
- Output length: Arbitrary

**Parameters**:
- salt: Random or context salt
- IKM (Input Keying Material): Initial secret
- info: Context/domain information
- length: Desired output length

```lean
def hkdf (salt : ByteArray) (ikm : ByteArray) (info : ByteArray) (length : Nat) : IO ByteArray
```

**RFC**: RFC 5869
**Use Cases**:
- Master key derivation
- Session key generation
- TLS 1.3 key schedule

---

#### 2. PBKDF2 (Password-Based Key Derivation Function 2)

**Algorithm**:
- Applies HMAC-SHA256 iteratively over password and salt
- Resistant to brute-force attacks via iteration parameter
- Output length: Arbitrary

**Parameters**:
- password: User password
- salt: Random salt (≥16 bytes recommended)
- iterations: Number of HMAC iterations (≥100,000 recommended)
- keyLength: Desired output length

```lean
def pbkdf2 (password : ByteArray) (salt : ByteArray) (iterations : Nat) (keyLength : Nat) : IO ByteArray
```

**RFC**: RFC 2898
**Iteration Recommendation**:
- 2024 guidance: 600,000+ iterations for passwords
- Adjustable to CPU performance

**Use Cases**:
- Password-to-key conversion
- Key encryption key (KEK) derivation
- Password verification storage

---

## Security Levels

| Algorithm | Confidentiality | Integrity | Post-Quantum |
|-----------|----------------|-----------|-------------|
| SHA-256   | N/A (Hash)     | 128-bit   | No          |
| SHA3-256  | N/A (Hash)     | 256-bit   | Yes         |
| AES-256-ECB | 256-bit      | None      | No          |
| AES-256-CBC | 256-bit      | None      | No          |
| AES-256-GCM | 256-bit      | 128-bit   | No          |
| ChaCha20-Poly1305 | 256-bit | 128-bit  | No          |

---

## Implementation Security Notes

1. **Nonce/IV Management**:
   - GCM: Use 96-bit nonce with random generation per encryption
   - ChaCha20: Use 96-bit nonce, counter internally managed
   - Never reuse same (key, nonce) pair

2. **Authentication Tag Verification**:
   - Always verify Poly1305/GCM tags before processing ciphertext
   - Use constant-time comparison (implemented in OpenSSL)

3. **Key Size**:
   - 256-bit keys provide 128-bit post-collision security
   - Sufficient against quantum computers for symmetric operations
   - Use key derivation for password material

4. **Random Generation**:
   - Use `OpenSSL_random()` or `/dev/urandom` for keys/nonsense

---

## Performance Benchmarks (Modern CPU)

| Operation | Throughput |
|-----------|-----------|
| SHA-256 | ~100-200 MB/s |
| SHA3-256 | ~50-100 MB/s |
| AES-256-GCM | ~500-1000 MB/s |
| ChaCha20-Poly1305 | ~300-600 MB/s |
| PBKDF2 (100k iter) | ~1-2 MB/s |

---

## References

- FIPS 197: AES Specification
- FIPS 180-4: SHA-2 and SHA-3
- RFC 5116: AEAD Interface and Algorithms
- RFC 3394: AES Key Wrap Algorithm
- RFC 7539: ChaCha20 and Poly1305 AEAD
- RFC 5869: HKDF
- NIST SP 800-38D: GCM Mode
- NIST SP 800-132: PBKDF2 Usage

-}

-- This file serves as documentation for the 256-bit algorithms
-- Actual implementations are in the Lean modules:
-- - Blackworm.OpenSSLBindings (FFI declarations)
-- - Blackworm.CryptoInterface (High-level API)
-- - Blackworm.CryptoExamples (Usage examples)
