-- Feistel Cipher with OpenSSL Integration
import Blackworm.CryptoInterface

set_option eval.type true
--set_option trace.Meta.synthInstance true

-- The cipher operates on 512-bit blocks. Each block is split into two
-- 256-bit halves, and every round-function pair encrypts exactly one
-- 256-bit half per round (its output is fitted to 256 bits before the
-- XOR, so the halves never grow or shrink).
--
-- Sizes are specified in bits; the `*_SIZE` constants are the corresponding
-- byte lengths of the `ByteArray`s that carry them (a 256-bit half is
-- exactly one SHA-256 digest, 32 bytes).
def HALF_BLOCK_BITS : Nat := 256
def BLOCK_BITS : Nat := 2 * HALF_BLOCK_BITS -- 512 bits
def HALF_BLOCK_SIZE : Nat := HALF_BLOCK_BITS / 8 -- 32 bytes
def BLOCK_SIZE : Nat := BLOCK_BITS / 8 -- 64 bytes

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

-- Fit `data` to exactly `n` bytes by cycling (repeating) its bytes, or
-- zero-filling if it is empty. This is how a round function whose natural
-- output size differs from a half block (e.g. a 48-byte PKCS#7-padded AES
-- ciphertext, or an HKDF output of arbitrary length) is stretched/truncated
-- to encrypt exactly one 256-bit (32-byte) half. A 32-byte SHA-256/SHA3-256
-- digest already fits and passes through unchanged. It is deterministic, so
-- encryption and decryption fit the same round-function output identically
-- and the XOR still cancels.
def fitTo (n : Nat) (data : ByteArray) : ByteArray :=
  if data.size == 0 then ByteArray.mk (Array.replicate n 0)
  else ByteArray.mk (Array.range n |>.map fun i => data.get! (i % data.size))

-- A zero-filled 256-bit half block.
def emptyHalf : ByteArray := ByteArray.mk (Array.replicate HALF_BLOCK_SIZE 0)

-- Split a 512-bit (64-byte) buffer into a Block of two 256-bit halves.
def Block.ofBits512 (data : ByteArray) : IO Block := do
  if data.size ≠ BLOCK_SIZE then
    throw (IO.userError s!"Block.ofBits512: expected {BLOCK_BITS} bits ({BLOCK_SIZE} bytes), got {data.size} bytes")
  return { left := data.extract 0 HALF_BLOCK_SIZE,
           right := data.extract HALF_BLOCK_SIZE BLOCK_SIZE }

-- Reassemble the 512-bit buffer from a block's two 256-bit halves.
def Block.toBytes (b : Block) : ByteArray :=
  b.left ++ b.right

-- One Feistel round on a 512-bit block: the round-function pair `f`
-- encrypts the 256-bit right half, its output is fitted to 256 bits, and
-- the result is XORed into the 256-bit left half. Halves keep their size.
def feistelRound (b : Block) (f : ByteArray → ByteArray) : Block :=
  { left := b.right,
    right := xorByteArrays b.left (fitTo b.left.size (f b.right)) } -- XOR operation on byte arrays

--#eval feistelRound { left := 0x1234, right := 0xABCD } (fun x => x + 1)

def blockList (n : Nat) : List Block :=
  List.range n |>.map (fun _ => { left := emptyHalf, right := emptyHalf }) -- Placeholder 512-bit blocks (two zeroed 256-bit halves)

--#eval blockList 5

def feistelCipher (blocks : List Block) (f : ByteArray → ByteArray) : List Block :=
  blocks.map (fun b => feistelRound b f)

-- Test with a simple function that takes and returns ByteArray
--#eval feistelCipher (blockList 6) (fun x => x)

-- IO Monadic versions for crypto functions

def feistelRoundIO (b : Block) (f : ByteArray → IO ByteArray) : IO Block := do
  let fResult ← f b.right
  return { left := b.right, right := xorByteArrays b.left (fitTo b.left.size fResult) }

def feistelCipherIO (blocks : List Block) (f : ByteArray → IO ByteArray) : IO (List Block) := do
  let results ← blocks.mapM (fun b => feistelRoundIO b f)
  return results

-- Inverse of a single Feistel round: undoes `feistelRoundIO` for the same
-- `f`. The round-function output is fitted to 256 bits exactly as during
-- encryption, so the XOR cancels and the original 256-bit halves return.
def feistelRoundInvIO (b : Block) (f : ByteArray → IO ByteArray) : IO Block := do
  let fResult ← f b.left
  return { left := xorByteArrays b.right (fitTo b.right.size fResult), right := b.left }

-- A dynamically generated cipher *chain*: run a 512-bit block through a
-- sequence of rounds where each round may use a *different* function (its
-- own cipher set), each pair encrypting one 256-bit half per round.
-- `specs` is applied left-to-right, one function per round/block.
def feistelChainIO (specs : List (ByteArray → IO ByteArray)) (b : Block) : IO Block :=
  specs.foldlM (fun b f => feistelRoundIO b f) b

-- Invert `feistelChainIO`: the round applied *first* during encryption must
-- be undone *last* during decryption, so decryption walks the **transpose**
-- (reverse) of the function-set list used to encrypt, undoing each round in
-- turn with `feistelRoundInvIO`.
def feistelDechainIO (specs : List (ByteArray → IO ByteArray)) (b : Block) : IO Block :=
  specs.reverse.foldlM (fun b f => feistelRoundInvIO b f) b

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
--
-- def exampleChainWithMixedCipherSets : IO Block := do
--   let key : Crypto.AES256Key := { bytes := ByteArray.mk #[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31] }
--   let block : Block := { left := emptyHalf, right := emptyHalf } -- 512-bit block
--   -- Each entry is a different cipher set/round function -- a dynamically
--   -- generated chain across multiple blocks/rounds.
--   let specs : List (ByteArray → IO ByteArray) :=
--     [feistelWithHash256, feistelWithAES256ECB key, feistelWithHash3_256]
--   let ciphertext ← feistelChainIO specs block
--   -- Decryption requires the *transpose* (reverse) of `specs`.
--   feistelDechainIO specs ciphertext

