-- Feistel Cipher with OpenSSL Integration
import Blackworm.CryptoInterface

set_option eval.type true
--set_option trace.Meta.synthInstance true

def dim := 256

structure Block where
  left: ByteArray
  right: ByteArray

  deriving Inhabited

def swap (b : Block) : Block :=
  { left := b.right, right := b.left }

--#eval swap { left := 0x1234, right := 0xABCD } -- { left := 0xABCD, right := 0x1234

def xorByteArrays (a b : ByteArray) : ByteArray :=
  let n := min a.size b.size
  let result := ByteArray.mk (Array.range n |>.map fun i =>
    (a.get! i) ^^^ (b.get! i))
  result

def feistelRound (b : Block) (f : ByteArray → ByteArray) : Block :=
  { left := b.right,
    right := xorByteArrays b.left (f b.right) } -- XOR operation on byte arrays

--#eval feistelRound { left := 0x1234, right := 0xABCD } (fun x => x + 1)

def blockList (n : Nat) : List Block :=
  List.range n |>.map (fun _ => { left := ByteArray.mk #[], right := ByteArray.mk #[] }) -- Placeholder blocks with empty byte arrays

--#eval blockList 5

def feistelCipher (blocks : List Block) (f : ByteArray → ByteArray) : List Block :=
  blocks.map (fun b => feistelRound b f)

-- Test with a simple function that takes and returns ByteArray
--#eval feistelCipher (blockList 6) (fun x => x)

-- IO Monadic versions for crypto functions

def feistelRoundIO (b : Block) (f : ByteArray → IO ByteArray) : IO Block := do
  let fResult ← f b.right
  return { left := b.right, right := xorByteArrays b.left fResult }

def feistelCipherIO (blocks : List Block) (f : ByteArray → IO ByteArray) : IO (List Block) := do
  let results ← blocks.mapM (fun b => feistelRoundIO b f)
  return results

-- Wrapper functions for specific crypto operations

-- Hash256 as a Feistel function
def feistelWithHash256 (data : ByteArray) : IO ByteArray := do
  let hash ← Crypto.hash256 data
  return hash.bytes

-- Hash3-256 as a Feistel function
def feistelWithHash3_256 (data : ByteArray) : IO ByteArray := do
  let hash ← Crypto.hash3_256 data
  return hash.bytes

-- AES-256-ECB encryption with a fixed key
def feistelWithAES256ECB (key : Crypto.AES256Key) (data : ByteArray) : IO ByteArray := do
  Crypto.encryptAES256ECB key data

-- AES-256-CBC encryption with a fixed key and IV
def feistelWithAES256CBC (key : Crypto.AES256Key) (iv : Crypto.AES256IV) (data : ByteArray) : IO ByteArray := do
  Crypto.encryptAES256CBC key iv data

-- HKDF key derivation as a Feistel function
def feistelWithHKDF (salt : ByteArray) (info : ByteArray) (length : Nat) (data : ByteArray) : IO ByteArray := do
  Crypto.hkdf salt data info length

-- Example usage patterns:
--
-- def exampleCipherWithHash : IO (List Block) := do
--   feistelCipherIO (blockList 6) feistelWithHash256
--
-- def exampleCipherWithAES : IO (List Block) := do
--   let key : Crypto.AES256Key := { bytes := ByteArray.mk #[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31] }
--   feistelCipherIO (blockList 6) (feistelWithAES256ECB key)

