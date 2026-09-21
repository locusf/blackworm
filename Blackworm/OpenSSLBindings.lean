-- OpenSSL FFI Bindings for 256-bit Ciphers and Hashes
import Lean

-- SHA-256 Hash
@[extern "openssl_sha256_hash"]
opaque sha256Hash (data : ByteArray) : IO ByteArray

-- SHA3-256 Hash
@[extern "openssl_sha3_256_hash"]
opaque sha3_256Hash (data : ByteArray) : IO ByteArray

-- AES-256-ECB Encrypt
@[extern "openssl_aes_256_ecb_encrypt"]
opaque aes256ECBEncrypt (key : ByteArray) (plaintext : ByteArray) : IO ByteArray

-- AES-256-ECB Decrypt
@[extern "openssl_aes_256_ecb_decrypt"]
opaque aes256ECBDecrypt (key : ByteArray) (ciphertext : ByteArray) : IO ByteArray

-- AES-256-CBC Encrypt
@[extern "openssl_aes_256_cbc_encrypt"]
opaque aes256CBCEncrypt (key : ByteArray) (iv : ByteArray) (plaintext : ByteArray) : IO ByteArray

-- AES-256-CBC Decrypt
@[extern "openssl_aes_256_cbc_decrypt"]
opaque aes256CBCDecrypt (key : ByteArray) (iv : ByteArray) (ciphertext : ByteArray) : IO ByteArray

-- AES-256-GCM Encrypt (returns (ciphertext, tag))
@[extern "openssl_aes_256_gcm_encrypt"]
opaque aes256GCMEncrypt (key : ByteArray) (iv : ByteArray) (plaintext : ByteArray) (aad : ByteArray) : IO (ByteArray × ByteArray)

-- AES-256-GCM Decrypt (returns Option ByteArray)
@[extern "openssl_aes_256_gcm_decrypt"]
opaque aes256GCMDecrypt (key : ByteArray) (iv : ByteArray) (ciphertext : ByteArray) (tag : ByteArray) (aad : ByteArray) : IO (Option ByteArray)

-- ChaCha20-Poly1305 Encrypt (returns (ciphertext, tag))
@[extern "openssl_chacha20_poly1305_encrypt"]
opaque chacha20Poly1305Encrypt (key : ByteArray) (nonce : ByteArray) (plaintext : ByteArray) (aad : ByteArray) : IO (ByteArray × ByteArray)

-- ChaCha20-Poly1305 Decrypt (returns Option ByteArray)
@[extern "openssl_chacha20_poly1305_decrypt"]
opaque chacha20Poly1305Decrypt (key : ByteArray) (nonce : ByteArray) (ciphertext : ByteArray) (tag : ByteArray) (aad : ByteArray) : IO (Option ByteArray)

-- HKDF (HMAC-based Key Derivation Function) with SHA-256
@[extern "openssl_hkdf_sha256"]
opaque hkdfSha256 (salt : ByteArray) (ikm : ByteArray) (info : ByteArray) (length : Nat) : IO ByteArray

-- PBKDF2 with SHA-256
@[extern "openssl_pbkdf2_sha256"]
opaque pbkdf2Sha256 (password : ByteArray) (salt : ByteArray) (iterations : Nat) (keyLength : Nat) : IO ByteArray

-- Cryptographic constants
def SHA256_DIGEST_SIZE : Nat := 32
def SHA3_256_DIGEST_SIZE : Nat := 32
def AES_256_KEY_SIZE : Nat := 32  -- 256 bits
def AES_256_BLOCK_SIZE : Nat := 16
def AES_256_GCM_IV_SIZE : Nat := 12  -- Recommended 96-bit IV
def CHACHA20_POLY1305_KEY_SIZE : Nat := 32
def CHACHA20_POLY1305_NONCE_SIZE : Nat := 12
