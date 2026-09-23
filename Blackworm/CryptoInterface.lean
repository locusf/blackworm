-- High-level OpenSSL Crypto Interface
import Blackworm.OpenSSLBindings

namespace Crypto

-- Wrapper types for better type safety
structure SHA256Hash where
  bytes : ByteArray
  deriving Inhabited

structure SHA3_256Hash where
  bytes : ByteArray
  deriving Inhabited

structure AES256Key where
  bytes : ByteArray
  deriving Inhabited

structure AES256IV where
  bytes : ByteArray
  deriving Inhabited

structure CipherGCMResult where
  ciphertext : ByteArray
  tag : ByteArray

-- Hash Functions

def hash256 (data : ByteArray) : IO SHA256Hash := do
  let hash ← sha256Hash data
  return { bytes := hash }

def hash3_256 (data : ByteArray) : IO SHA3_256Hash := do
  let hash ← sha3_256Hash data
  return { bytes := hash }

-- Symmetric Encryption - AES-256-ECB

def encryptAES256ECB (key : AES256Key) (plaintext : ByteArray) : IO ByteArray := do
  if key.bytes.size ≠ AES_256_KEY_SIZE then
    throw (IO.userError "Invalid AES-256 key size")
  aes256ECBEncrypt key.bytes plaintext

def decryptAES256ECB (key : AES256Key) (ciphertext : ByteArray) : IO ByteArray := do
  if key.bytes.size ≠ AES_256_KEY_SIZE then
    throw (IO.userError "Invalid AES-256 key size")
  aes256ECBDecrypt key.bytes ciphertext

-- AES-256-ECB decryption with PKCS#7 padding disabled: a keyed permutation
-- over exact multiples of the AES block size. Native failures throw IO errors
-- (there is no notion of "invalid ciphertext" to reject once padding is
-- off). Unlike `decryptAES256ECB`, this is safe to call on data that was
-- never actually encrypted -- e.g. to use AES decryption purely as a
-- one-way scrambling function, as legitimate a round function as AES
-- encryption used the same way.
def decryptAES256ECBNoPad (key : AES256Key) (data : ByteArray) : IO ByteArray := do
  if key.bytes.size ≠ AES_256_KEY_SIZE then
    throw (IO.userError "Invalid AES-256 key size")
  if data.size % AES_256_BLOCK_SIZE ≠ 0 then
    throw (IO.userError "AES-256-ECB (no padding): data size must be a multiple of the AES block size")
  aes256ECBDecryptNoPad key.bytes data

-- Symmetric Encryption - AES-256-CBC

def encryptAES256CBC (key : AES256Key) (iv : AES256IV) (plaintext : ByteArray) : IO ByteArray := do
  if key.bytes.size ≠ AES_256_KEY_SIZE then
    throw (IO.userError "Invalid AES-256 key size")
  if iv.bytes.size ≠ AES_256_BLOCK_SIZE then
    throw (IO.userError "Invalid AES-256 IV size")
  aes256CBCEncrypt key.bytes iv.bytes plaintext

def decryptAES256CBC (key : AES256Key) (iv : AES256IV) (ciphertext : ByteArray) : IO ByteArray := do
  if key.bytes.size ≠ AES_256_KEY_SIZE then
    throw (IO.userError "Invalid AES-256 key size")
  if iv.bytes.size ≠ AES_256_BLOCK_SIZE then
    throw (IO.userError "Invalid AES-256 IV size")
  aes256CBCDecrypt key.bytes iv.bytes ciphertext

-- AES-256-CBC decryption with PKCS#7 padding disabled. See
-- `decryptAES256ECBNoPad`.
def decryptAES256CBCNoPad (key : AES256Key) (iv : AES256IV) (data : ByteArray) : IO ByteArray := do
  if key.bytes.size ≠ AES_256_KEY_SIZE then
    throw (IO.userError "Invalid AES-256 key size")
  if iv.bytes.size ≠ AES_256_BLOCK_SIZE then
    throw (IO.userError "Invalid AES-256 IV size")
  if data.size % AES_256_BLOCK_SIZE ≠ 0 then
    throw (IO.userError "AES-256-CBC (no padding): data size must be a multiple of the AES block size")
  aes256CBCDecryptNoPad key.bytes iv.bytes data

-- Authenticated Encryption - AES-256-GCM

structure AES256GCMIV where
  bytes : ByteArray
  deriving Inhabited

def encryptAES256GCM (key : AES256Key) (iv : AES256GCMIV) (plaintext : ByteArray) (aad : ByteArray := ByteArray.mk #[]) : IO CipherGCMResult := do
  if key.bytes.size ≠ AES_256_KEY_SIZE then
    throw (IO.userError "Invalid AES-256 key size")
  let (ciphertext, tag) ← aes256GCMEncrypt key.bytes iv.bytes plaintext aad
  return { ciphertext := ciphertext, tag := tag }

def decryptAES256GCM (key : AES256Key) (iv : AES256GCMIV) (ciphertext : ByteArray) (tag : ByteArray) (aad : ByteArray := ByteArray.mk #[]) : IO (Option ByteArray) := do
  if key.bytes.size ≠ AES_256_KEY_SIZE then
    throw (IO.userError "Invalid AES-256 key size")
  aes256GCMDecrypt key.bytes iv.bytes ciphertext tag aad

-- Authenticated Encryption - ChaCha20-Poly1305

structure ChaCha20Poly1305Nonce where
  bytes : ByteArray
  deriving Inhabited

def encryptChaCha20Poly1305 (key : AES256Key) (nonce : ChaCha20Poly1305Nonce) (plaintext : ByteArray) (aad : ByteArray := ByteArray.mk #[]) : IO CipherGCMResult := do
  if key.bytes.size ≠ CHACHA20_POLY1305_KEY_SIZE then
    throw (IO.userError "Invalid ChaCha20-Poly1305 key size")
  if nonce.bytes.size ≠ CHACHA20_POLY1305_NONCE_SIZE then
    throw (IO.userError "Invalid ChaCha20-Poly1305 nonce size")
  let (ciphertext, tag) ← chacha20Poly1305Encrypt key.bytes nonce.bytes plaintext aad
  return { ciphertext := ciphertext, tag := tag }

def decryptChaCha20Poly1305 (key : AES256Key) (nonce : ChaCha20Poly1305Nonce) (ciphertext : ByteArray) (tag : ByteArray) (aad : ByteArray := ByteArray.mk #[]) : IO (Option ByteArray) := do
  if key.bytes.size ≠ CHACHA20_POLY1305_KEY_SIZE then
    throw (IO.userError "Invalid ChaCha20-Poly1305 key size")
  if nonce.bytes.size ≠ CHACHA20_POLY1305_NONCE_SIZE then
    throw (IO.userError "Invalid ChaCha20-Poly1305 nonce size")
  chacha20Poly1305Decrypt key.bytes nonce.bytes ciphertext tag aad

-- Key Derivation Functions

def hkdf (salt : ByteArray) (ikm : ByteArray) (info : ByteArray) (length : Nat) : IO ByteArray := do
  if length = 0 then
    throw (IO.userError "Key length must be greater than 0")
  hkdfSha256 salt ikm info length

def pbkdf2 (password : ByteArray) (salt : ByteArray) (iterations : Nat) (keyLength : Nat) : IO ByteArray := do
  if iterations = 0 then
    throw (IO.userError "Iterations must be greater than 0")
  if keyLength = 0 then
    throw (IO.userError "Key length must be greater than 0")
  pbkdf2Sha256 password salt iterations keyLength

-- Utility functions

def validateKeySize (key : AES256Key) : Bool :=
  key.bytes.size = AES_256_KEY_SIZE

def byteToHex (b : UInt8) : String :=
  let toHexDigit (n : Nat) : String :=
    match n with
    | 0 => "0" | 1 => "1" | 2 => "2" | 3 => "3" | 4 => "4"
    | 5 => "5" | 6 => "6" | 7 => "7" | 8 => "8" | 9 => "9"
    | 10 => "a" | 11 => "b" | 12 => "c" | 13 => "d" | 14 => "e" | 15 => "f" | _ => "0"
  toHexDigit (b.toNat / 16) ++ toHexDigit (b.toNat % 16)

def byteArrayToHex (ba : ByteArray) : String :=
  let rec goRec (i : Nat) (acc : String) : String :=
    if i >= ba.size then acc
    else
      let byte := ba.get! i
      let hex := byteToHex byte
      goRec (i + 1) (acc ++ hex)
  goRec 0 ""

def sha256ToString (h : SHA256Hash) : String :=
  byteArrayToHex h.bytes

def sha3_256ToString (h : SHA3_256Hash) : String :=
  byteArrayToHex h.bytes

end Crypto
