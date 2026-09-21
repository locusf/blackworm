-- Cryptographic Examples and Tests
import Blackworm.CryptoInterface

open Crypto

namespace CryptoExamples

-- Example: Hash a message with SHA-256
example : IO Unit := do
  let message := "Hello, Lean Cryptography!".toUTF8
  let hash ← hash256 message
  IO.println s!"SHA-256: {sha256ToString hash}"

-- Example: Hash with SHA3-256
example : IO Unit := do
  let message := "Testing SHA3-256".toUTF8
  let hash ← hash3_256 message
  IO.println s!"SHA3-256: {sha3_256ToString hash}"

-- Example: AES-256-ECB Encryption
example : IO Unit := do
  let key : AES256Key := { bytes := ByteArray.mk (List.range AES_256_KEY_SIZE
    |>.map fun i => (i % 256 : UInt8)) }
  let plaintext := "This is a secret message".toUTF8
  let ciphertext ← encryptAES256ECB key plaintext
  IO.println s!"AES-256-ECB Ciphertext length: {ciphertext.size}"
  let decrypted ← decryptAES256ECB key ciphertext
  IO.println s!"Decrypted: {String.fromUTF8! decrypted}"

-- Example: AES-256-CBC Encryption
example : IO Unit := do
  let key : AES256Key := { bytes := ByteArray.mk (List.range AES_256_KEY_SIZE
    |>.map fun i => (i % 256 : UInt8)) }
  let iv : AES256IV := { bytes := ByteArray.mk (List.range AES_256_BLOCK_SIZE
    |>.map fun i => (i * 7 % 256 : UInt8)) }
  let plaintext := "Secret data protected with AES-256-CBC".toUTF8
  let ciphertext ← encryptAES256CBC key iv plaintext
  IO.println s!"AES-256-CBC Ciphertext length: {ciphertext.size}"
  let decrypted ← decryptAES256CBC key iv ciphertext
  IO.println s!"Decrypted: {String.fromUTF8! decrypted}"

-- Example: AES-256-GCM Authenticated Encryption
example : IO Unit := do
  let key : AES256Key := { bytes := ByteArray.mk (List.range AES_256_KEY_SIZE
    |>.map fun i => (i % 256 : UInt8)) }
  let iv : AES256GCMIV := { bytes := ByteArray.mk (List.range AES_256_GCM_IV_SIZE
    |>.map fun i => (i * 3 % 256 : UInt8)) }
  let plaintext := "Authenticated encryption message".toUTF8
  let aad := "Additional authenticated data".toUTF8
  let result ← encryptAES256GCM key iv plaintext aad
  IO.println s!"AES-256-GCM Ciphertext length: {result.ciphertext.size}"
  IO.println s!"AES-256-GCM Tag length: {result.tag.size}"
  let decrypted ← decryptAES256GCM key iv result.ciphertext result.tag aad
  match decrypted with
  | none => IO.println "GCM Decryption failed: Tag verification failed"
  | some plain => IO.println s!"GCM Decrypted: {String.fromUTF8! plain}"

-- Example: ChaCha20-Poly1305 Authenticated Encryption
example : IO Unit := do
  let key : AES256Key := { bytes := ByteArray.mk (List.range CHACHA20_POLY1305_KEY_SIZE
    |>.map fun i => (i % 256 : UInt8)) }
  let nonce : ChaCha20Poly1305Nonce := { bytes := ByteArray.mk (List.range CHACHA20_POLY1305_NONCE_SIZE
    |>.map fun i => (i * 5 % 256 : UInt8)) }
  let plaintext := "ChaCha20-Poly1305 encrypted message".toUTF8
  let aad := "Additional data".toUTF8
  let result ← encryptChaCha20Poly1305 key nonce plaintext aad
  IO.println s!"ChaCha20-Poly1305 Ciphertext length: {result.ciphertext.size}"
  let decrypted ← decryptChaCha20Poly1305 key nonce result.ciphertext result.tag aad
  match decrypted with
  | none => IO.println "ChaCha20 Decryption failed"
  | some plain => IO.println s!"ChaCha20 Decrypted: {String.fromUTF8! plain}"

-- Example: HKDF Key Derivation
example : IO Unit := do
  let salt := "salt_value_16bytes".toUTF8
  let ikm := "input_key_material_here".toUTF8
  let info := "key_derivation_context".toUTF8
  let derived ← hkdf salt ikm info 32  -- Derive 32 bytes (256 bits)
  IO.println s!"HKDF Derived Key length: {derived.size}"
  IO.println s!"HKDF Derived Key (hex): {derived.toHex}"

-- Example: PBKDF2 Key Derivation
example : IO Unit := do
  let password := "my_secure_password".toUTF8
  let salt := "pbkdf2_salt_1234".toUTF8
  let derived ← pbkdf2 password salt 100000 32  -- 100k iterations, 32 bytes output
  IO.println s!"PBKDF2 Derived Key length: {derived.size}"
  IO.println s!"PBKDF2 Derived Key (hex): {derived.toHex}"

-- Utility: Demonstrate key validation
example : IO Unit := do
  let validKey : AES256Key := { bytes := ByteArray.mk (List.range AES_256_KEY_SIZE
    |>.map fun i => (i % 256 : UInt8)) }
  let invalidKey : AES256Key := { bytes := #[0x01, 0x02, 0x03] }  -- Too short
  if validateKeySize validKey then
    IO.println "Valid key size"
  else
    IO.println "Invalid key size"
  if validateKeySize invalidKey then
    IO.println "Invalid key size check failed"
  else
    IO.println "Invalid key correctly detected"

end CryptoExamples
