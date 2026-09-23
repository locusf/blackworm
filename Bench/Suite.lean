-- Benchmark case definitions for the Blackworm dynamically generated
-- Feistel cipher and its underlying OpenSSL-backed round functions.
--
-- Each `BenchCase` bundles a human-readable name, the payload size (in
-- bytes) that one invocation of `op` processes (used for throughput
-- reporting), and the `IO Unit` action to time. `defaultCases` wires up a
-- representative set of microbenchmarks: raw OpenSSL primitives (including
-- both "real" and padding-disabled/one-way AES decrypt), single Feistel
-- rounds (encrypt-, decrypt-, and one-way-side), multi-block ciphers, and a
-- mixed-cipher-set chain in both the forward (`feistelChainIO`) and
-- transpose/decrypt (`feistelDechainIO`) directions.
import Blackworm.Basic
import Bench.Timing

namespace Bench

structure BenchCase where
  name        : String
  bytesPerOp  : Nat
  op          : IO Unit

/-- Deterministic, non-constant filler data so timed primitives are not
handed a suspiciously degenerate (all-zero) input. -/
def patternBytes (n : Nat) (seed : UInt8 := 0x5A) : ByteArray :=
  ByteArray.mk (Array.range n |>.map fun i => seed ^^^ (UInt8.ofNat (i % 256)))

/-- Run `warmup` untimed iterations of `c.op` followed by `iters` timed
iterations, returning the collected duration samples. -/
def runCase (warmup iters : Nat) (c : BenchCase) : IO Stats := do
  for _ in [0:warmup] do
    c.op
  let mut durations : Array Nat := #[]
  for _ in [0:iters] do
    let d ← timeIO' c.op
    durations := durations.push d
  return computeStats durations

/-- Build the default benchmark suite.
`blockCount` controls how many 512-bit blocks the multi-block cipher
cases process per invocation. -/
def defaultCases (blockCount : Nat := 64) : IO (Array BenchCase) := do
  let payload512 := patternBytes BLOCK_SIZE
  let payloadHalf := patternBytes HALF_BLOCK_SIZE
  let aesKey : Crypto.AES256Key :=
    { bytes := patternBytes AES_256_KEY_SIZE 0x11 }
  let aesIV : Crypto.AES256IV :=
    { bytes := patternBytes AES_256_BLOCK_SIZE 0x22 }
  let hkdfSalt := patternBytes 16 0x33
  let hkdfInfo := patternBytes 16 0x44
  let block : Block := { left := payloadHalf, right := payloadHalf }
  let blocks := blockList blockCount |>.map (fun _ => block)

  -- Decryption fixtures: genuine ciphertext computed once, up front, so the
  -- decrypt cases below time only the decrypt call itself. Unlike the
  -- encrypt-side round functions, AES decrypt must never be handed
  -- arbitrary/unrelated data (see the caveat on `feistelWithAES256ECBDecrypt`
  -- in `Blackworm/Basic.lean`), so these fixtures are real ciphertext
  -- produced by the matching encrypt primitive under the same key/IV.
  let aesECBCiphertext512 ← Crypto.encryptAES256ECB aesKey payload512
  let aesCBCCiphertext512 ← Crypto.encryptAES256CBC aesKey aesIV payload512
  let aesECBCipherHalf ← feistelWithAES256ECB aesKey payloadHalf
  let aesCBCCipherHalf ← feistelWithAES256CBC aesKey aesIV payloadHalf
  let aesECBCipherBlock : Block := { left := payloadHalf, right := aesECBCipherHalf }
  let aesCBCCipherBlock : Block := { left := payloadHalf, right := aesCBCCipherHalf }

  -- The mixed cipher-set chain, reused both to demonstrate forward chaining
  -- (encrypt) and, in transpose/reverse order, dechaining (decrypt) -- see
  -- docs/cipher-visualization.md §4. Every wrapper from `Blackworm/Basic.lean`
  -- appears as a link, including AES decrypt: the *padded* decrypt wrappers
  -- (`feistelWithAES256ECBDecrypt`/`CBCDecrypt`) are still excluded, since a
  -- forward chain link never sees genuine ciphertext -- it only ever sees
  -- the previous link's output XORed into the other half -- so a bare
  -- padded-decrypt link could fail with an invalid-padding IO error
  -- (this is also how the C++ `feistelizer` project, `src/derive/variants.h`,
  -- sidesteps the issue: its `decipher` reuses the forward-encrypt round
  -- functions in reverse rather than calling an AES decrypt primitive at
  -- all). Here, though, AES decrypt *is* used directly as an ordinary
  -- one-way link -- via `feistelWithAES256ECBDecryptNoPad`/
  -- `CBCDecryptNoPad`, which disable PKCS#7 padding and so are total,
  -- permutations defined on arbitrary chain state (native failures still
  -- throw IO errors). The
  -- chain's decryption direction below (`feistelDechainIO`,
  -- `feistelRoundInvIO`) undoes every link -- including these one-way AES
  -- decrypt links -- by reapplying the same forward functions in reverse,
  -- which is how a Feistel network decrypts without needing an inverse
  -- round function.
  let chainSpecs : List CipherPair :=
    [feistelWithHash256,
     feistelWithAES256ECB aesKey,
     feistelWithAES256ECBDecryptNoPad aesKey,
     feistelWithAES256CBC aesKey aesIV,
     feistelWithAES256CBCDecryptNoPad aesKey aesIV,
     feistelWithHKDF hkdfSalt hkdfInfo HALF_BLOCK_SIZE,
     feistelWithHash3_256].map CipherPair.ofFeistel
  let chainCiphertext ← feistelChainIO chainSpecs block

  return #[
    -- Raw OpenSSL primitives, no Feistel wrapping: a baseline for how much
    -- of the round's cost is the cryptographic primitive itself.
    { name := "raw SHA-256 (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (Crypto.hash256 payload512) },
    { name := "raw SHA3-256 (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (Crypto.hash3_256 payload512) },
    { name := "raw AES-256-ECB encrypt (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (Crypto.encryptAES256ECB aesKey payload512) },
    { name := "raw AES-256-CBC encrypt (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (Crypto.encryptAES256CBC aesKey aesIV payload512) },
    { name := "raw AES-256-ECB decrypt (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (Crypto.decryptAES256ECB aesKey aesECBCiphertext512) },
    { name := "raw AES-256-CBC decrypt (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (Crypto.decryptAES256CBC aesKey aesIV aesCBCCiphertext512) },
    -- No-padding decrypt on arbitrary (non-ciphertext) data: this doesn't
    -- crash the way `decryptAES256ECB`/`decryptAES256CBC` on arbitrary data
    -- would, because there's no PKCS#7 padding to (fail to) validate --
    -- see `Crypto.decryptAES256ECBNoPad`.
    { name := "raw AES-256-ECB decrypt, no padding (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (Crypto.decryptAES256ECBNoPad aesKey payload512) },
    { name := "raw AES-256-CBC decrypt, no padding (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (Crypto.decryptAES256CBCNoPad aesKey aesIV payload512) },
    { name := "raw HKDF-SHA256 derive (32B)"
      bytesPerOp := 32
      op := discard (Crypto.hkdf hkdfSalt payloadHalf hkdfInfo 32) },

    -- Pure Feistel-round mechanics (allocation/copy/XOR overhead), with an
    -- identity round function so the primitive's own cost is excluded.
    { name := "feistelRound, identity F (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (pure (feistelRound block id) : IO Block) },
    { name := "xorByteArrays (256-bit halves)"
      bytesPerOp := HALF_BLOCK_SIZE
      op := discard (pure (xorByteArrays payloadHalf payloadHalf) : IO ByteArray) },

    -- One Feistel round per real round function.
    { name := "feistelRoundIO + SHA-256 (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (feistelRoundIO block feistelWithHash256) },
    { name := "feistelRoundIO + SHA3-256 (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (feistelRoundIO block feistelWithHash3_256) },
    { name := "feistelRoundIO + AES-256-ECB (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (feistelRoundIO block (feistelWithAES256ECB aesKey)) },
    { name := "feistelRoundIO + AES-256-CBC (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (feistelRoundIO block (feistelWithAES256CBC aesKey aesIV)) },

    -- Decrypt-side round functions: same round mechanics, but the round
    -- function undoes real AES ciphertext (the `aesECBCipherBlock`/
    -- `aesCBCCipherBlock` fixtures above) rather than encrypting arbitrary
    -- data.
    { name := "feistelRoundIO + AES-256-ECB decrypt (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (feistelRoundIO aesECBCipherBlock (feistelWithAES256ECBDecrypt aesKey)) },
    { name := "feistelRoundIO + AES-256-CBC decrypt (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (feistelRoundIO aesCBCCipherBlock (feistelWithAES256CBCDecrypt aesKey aesIV)) },

    -- One-way round functions: AES decrypt with padding disabled, used as
    -- an ordinary round function directly on `block` (the same arbitrary,
    -- non-ciphertext data every encrypt/hash round function above runs on)
    -- -- no ciphertext fixture required, since it's a total permutation.
    { name := "feistelRoundIO + AES-256-ECB decrypt, no padding (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (feistelRoundIO block (feistelWithAES256ECBDecryptNoPad aesKey)) },
    { name := "feistelRoundIO + AES-256-CBC decrypt, no padding (512-bit)"
      bytesPerOp := BLOCK_SIZE
      op := discard (feistelRoundIO block (feistelWithAES256CBCDecryptNoPad aesKey aesIV)) },

    -- Multi-block cipher throughput: `blockCount` blocks run through one
    -- round each with the same round function.
    { name := s!"feistelCipherIO x{blockCount} + SHA-256"
      bytesPerOp := blockCount * BLOCK_SIZE
      op := discard (feistelCipherIO blocks feistelWithHash256) },
    { name := s!"feistelCipherIO x{blockCount} + AES-256-ECB"
      bytesPerOp := blockCount * BLOCK_SIZE
      op := discard (feistelCipherIO blocks (feistelWithAES256ECB aesKey)) },

    -- A dynamically generated cipher chain: one block through seven
    -- different cipher sets (every wrapper from `Blackworm/Basic.lean`,
    -- including AES decrypt used as a one-way link via
    -- `feistelWithAES256ECBDecryptNoPad`/`CBCDecryptNoPad`), mirroring the
    -- chain construction described in docs/cipher-visualization.md.
    { name := "feistelChainIO [SHA-256, AES-256-ECB, AES-256-ECB decrypt (no pad), AES-256-CBC, AES-256-CBC decrypt (no pad), HKDF, SHA3-256] (512-bit)"
      bytesPerOp := 7 * BLOCK_SIZE
      op := discard (feistelChainIO chainSpecs block) },

    -- Decryption of the chain: `feistelDechainIO` walks `chainSpecs.reverse`
    -- (the transpose, docs/cipher-visualization.md §4), undoing each link
    -- with `feistelRoundInvIO` -- reusing every forward function (including
    -- both one-way AES decrypt links) in reverse order rather than calling
    -- an inverse round function -- to recover the original block from
    -- `chainCiphertext`.
    { name := "feistelDechainIO [SHA-256, AES-256-ECB, AES-256-ECB decrypt (no pad), AES-256-CBC, AES-256-CBC decrypt (no pad), HKDF, SHA3-256] (512-bit)"
      bytesPerOp := 7 * BLOCK_SIZE
      op := discard (feistelDechainIO chainSpecs chainCiphertext) },

    -- Full round trip: encrypt the chain then decrypt it back, timing both
    -- the encryption and decryption (including all four AES links) as one
    -- unit of work.
    { name := "feistelChainIO+feistelDechainIO round trip [SHA-256, AES-256-ECB, AES-256-ECB decrypt (no pad), AES-256-CBC, AES-256-CBC decrypt (no pad), HKDF, SHA3-256] (512-bit)"
      bytesPerOp := 7 * BLOCK_SIZE
      op := discard (do
        let ciphertext ← feistelChainIO chainSpecs block
        feistelDechainIO chainSpecs ciphertext) }
  ]

end Bench
