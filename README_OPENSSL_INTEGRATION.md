# OpenSSL 256-bit Cryptography Integration Guide

This document describes the integration of 256-bit ciphers and hash functions from OpenSSL into the Lean project.

## Overview

The Blackworm project now includes full support for:
- **Hash Functions (256-bit output)**:
  - SHA-256
  - SHA3-256
- **Symmetric Encryption (256-bit keys)**:
  - AES-256-ECB
  - AES-256-CBC
  - AES-256-GCM (Authenticated Encryption with Associated Data)
  - ChaCha20-Poly1305 (Authenticated Encryption)
- **Key Derivation Functions**:
  - HKDF (HMAC-based Key Derivation Function) with SHA-256
  - PBKDF2 with SHA-256

## Project Structure

```
blackworm/
├── lakefile.toml                    # Lake build configuration with OpenSSL
├── lean-toolchain                   # Lean version specification
├── CMakeLists.txt                   # Build configuration for C FFI
├── openssl_crypto.c                 # Native C FFI bindings to OpenSSL
├── Blackworm/
│   ├── Basic.lean                   # Original Feistel cipher implementation
│   ├── theorem.lean                 # Lean type definitions
│   ├── OpenSSLBindings.lean         # Low-level FFI declarations
│   ├── CryptoInterface.lean         # High-level Lean API
│   └── CryptoExamples.lean          # Usage examples
└── README_OPENSSL_INTEGRATION.md    # This file
```

## Installation & Build

### Prerequisites

1. **OpenSSL 3.0 or higher**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libssl-dev

   # macOS (Homebrew)
   brew install openssl@3

   # Fedora/RHEL
   sudo dnf install openssl-devel
   ```

2. **Lean 4.28.0-rc1** (automatically managed by Lake)

3. **CMake** (for building C FFI):
   ```bash
   sudo apt-get install cmake  # Ubuntu/Debian
   brew install cmake          # macOS
   ```

### Building

1. **Using Lake (Lean build system)**:
   ```bash
   lake build
   ```

2. **Building C FFI library separately** (if needed):
   ```bash
   mkdir build
   cd build
   cmake ..
   make
   sudo make install
   ```

## API Reference

### Module: `Crypto`

#### Hash Functions

```lean
def hash256 (data : ByteArray) : IO SHA256Hash
def hash3_256 (data : ByteArray) : IO SHA3_256Hash
```

**Example**:
```lean
let message := "Hello, World!".toUTF8
let hash ← hash256 message
let hexString := hash.bytes.toHex
```

#### Symmetric Encryption - AES-256-ECB

```lean
def encryptAES256ECB (key : AES256Key) (plaintext : ByteArray) : IO ByteArray
def decryptAES256ECB (key : AES256Key) (ciphertext : ByteArray) : IO ByteArray
```

**Constants**:
- `AES_256_KEY_SIZE` = 32 bytes (256 bits)
- `AES_256_BLOCK_SIZE` = 16 bytes

**Example**:
```lean
let key : AES256Key := { bytes := /* 32 bytes */ }
let plaintext := "Secret message".toUTF8
let ciphertext ← encryptAES256ECB key plaintext
let decrypted ← decryptAES256ECB key ciphertext
```

#### Symmetric Encryption - AES-256-CBC

```lean
def encryptAES256CBC (key : AES256Key) (iv : AES256IV) (plaintext : ByteArray) : IO ByteArray
def decryptAES256CBC (key : AES256Key) (iv : AES256IV) (ciphertext : ByteArray) : IO ByteArray
```

**Constants**:
- `AES_256_KEY_SIZE` = 32 bytes
- `AES_256_BLOCK_SIZE` = 16 bytes (for IV)

#### Authenticated Encryption - AES-256-GCM

```lean
def encryptAES256GCM (key : AES256Key) (iv : AES256GCMIV) (plaintext : ByteArray)
                     (aad : ByteArray := #[]) : IO CipherGCMResult

def decryptAES256GCM (key : AES256Key) (iv : AES256GCMIV) (ciphertext : ByteArray)
                     (tag : ByteArray) (aad : ByteArray := #[]) : IO (Option ByteArray)
```

**Types**:
- `CipherGCMResult`: Contains `ciphertext : ByteArray` and `tag : ByteArray`
- Returns `Option ByteArray`: `Some plaintext` on success, `none` on authentication failure

**Constants**:
- `AES_256_KEY_SIZE` = 32 bytes
- `AES_256_GCM_IV_SIZE` = 12 bytes (96-bit recommended)

**Example**:
```lean
let key : AES256Key := { bytes := /* 32 bytes */ }
let iv : AES256GCMIV := { bytes := /* 12 bytes */ }
let plaintext := "Sensitive data".toUTF8
let aad := "Associated data".toUTF8
let result ← encryptAES256GCM key iv plaintext aad
let decrypted ← decryptAES256GCM key iv result.ciphertext result.tag aad
match decrypted with
| none => IO.println "Authentication failed"
| some p => IO.println s!"Decrypted: {String.fromUTF8! p}"
```

#### Authenticated Encryption - ChaCha20-Poly1305

```lean
def encryptChaCha20Poly1305 (key : AES256Key) (nonce : ChaCha20Poly1305Nonce)
                             (plaintext : ByteArray) (aad : ByteArray := #[]) : IO CipherGCMResult

def decryptChaCha20Poly1305 (key : AES256Key) (nonce : ChaCha20Poly1305Nonce)
                             (ciphertext : ByteArray) (tag : ByteArray)
                             (aad : ByteArray := #[]) : IO (Option ByteArray)
```

**Constants**:
- `CHACHA20_POLY1305_KEY_SIZE` = 32 bytes
- `CHACHA20_POLY1305_NONCE_SIZE` = 12 bytes

#### Key Derivation Functions

**HKDF (HMAC-based Key Derivation Function)**:
```lean
def hkdf (salt : ByteArray) (ikm : ByteArray) (info : ByteArray) (length : Nat) : IO ByteArray
```

**PBKDF2 (Password-Based Key Derivation Function 2)**:
```lean
def pbkdf2 (password : ByteArray) (salt : ByteArray) (iterations : Nat) (keyLength : Nat) : IO ByteArray
```

**Example**:
```lean
-- Derive a 256-bit key from password
let password := "MySecurePassword".toUTF8
let salt := "random_salt_1234".toUTF8
let derivedKey ← pbkdf2 password salt 100000 32
```

## Security Considerations

1. **Key Management**:
   - Never hardcode keys in source code
   - Use secure random generation for keys and IVs
   - Rotate keys regularly

2. **IV/Nonce Requirements**:
   - Each encryption operation must use a unique IV/nonce
   - For GCM: 96-bit (12-byte) IVs are recommended
   - For ChaCha20: 96-bit (12-byte) nonces are required

3. **Authenticated Encryption**:
   - Prefer AES-256-GCM or ChaCha20-Poly1305 over unauthenticated modes
   - Always verify authentication tags before using decrypted data

4. **Key Derivation**:
   - Use PBKDF2 with ≥100,000 iterations for password-based keys
   - Use HKDF for deterministic key derivation from master keys

5. **Error Handling**:
   - Check `Option` return values from decryption functions
   - Handle IO exceptions appropriately

## Integration with Existing Code

The cryptographic functions integrate seamlessly with the existing Feistel cipher implementation in `Basic.lean`:

```lean
-- Use SHA-256 to generate round keys for Feistel cipher
def feistelRoundKeyFromPassword (password : String) (round : Nat) : IO (BitVec 256) := do
  let hash ← hash256 (password.toUTF8 ++ ByteArray.mk [round.toUInt8])
  return BitVec.ofByteArray hash.bytes
```

## Performance Characteristics

- **SHA-256**: ~100-200 MB/s on modern CPUs
- **AES-256-CBC**: ~1000+ MB/s (hardware accelerated)
- **AES-256-GCM**: ~500-1000 MB/s (depending on hardware)
- **ChaCha20-Poly1305**: ~300-600 MB/s
- **PBKDF2**: Configurable via iterations parameter

## Testing

Examples and tests are provided in `CryptoExamples.lean`. Run them with:

```bash
lake build Blackworm
```

## Troubleshooting

### OpenSSL not found
```bash
# Check if OpenSSL is installed
openssl version

# Add to environment if needed
export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
```

### CMake build issues
```bash
# Clear and rebuild
rm -rf build
mkdir build
cd build
cmake -DOPENSSL_DIR=/usr/local/opt/openssl@3 ..
make
```

### Lean compilation errors
```bash
# Update dependencies
lake update
lake clean
lake build
```

## References

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Lean FFI Documentation](https://lean-lang.org/papers/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [ChaCha20-Poly1305 RFC 7539](https://tools.ietf.org/html/rfc7539)

## License

This OpenSSL integration follows the same license as the Blackworm project.

## Contributing

To add new cryptographic functions:

1. Add OpenSSL C code to `openssl_crypto.c`
2. Create FFI declarations in `OpenSSLBindings.lean`
3. Add high-level wrappers to `CryptoInterface.lean`
4. Include examples in `CryptoExamples.lean`
5. Update this documentation

