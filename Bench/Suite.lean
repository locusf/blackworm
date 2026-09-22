-- Benchmark case definitions for the Blackworm dynamically generated
-- Feistel cipher and its underlying OpenSSL-backed round functions.
--
-- Each `BenchCase` bundles a human-readable name, the payload size (in
-- bytes) that one invocation of `op` processes (used for throughput
-- reporting), and the `IO Unit` action to time. `defaultCases` wires up a
-- representative set of microbenchmarks: raw OpenSSL primitives, single
-- Feistel rounds, multi-block ciphers, and a mixed-cipher-set chain.
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

    -- Multi-block cipher throughput: `blockCount` blocks run through one
    -- round each with the same round function.
    { name := s!"feistelCipherIO x{blockCount} + SHA-256"
      bytesPerOp := blockCount * BLOCK_SIZE
      op := discard (feistelCipherIO blocks feistelWithHash256) },
    { name := s!"feistelCipherIO x{blockCount} + AES-256-ECB"
      bytesPerOp := blockCount * BLOCK_SIZE
      op := discard (feistelCipherIO blocks (feistelWithAES256ECB aesKey)) },

    -- A dynamically generated cipher chain: one block through three
    -- different cipher sets, mirroring the chain construction described in
    -- docs/cipher-visualization.md.
    { name := "feistelChainIO [SHA-256, AES-256-ECB, SHA3-256] (512-bit)"
      bytesPerOp := 3 * BLOCK_SIZE
      op := discard (feistelChainIO
        [feistelWithHash256, feistelWithAES256ECB aesKey, feistelWithHash3_256] block) }
  ]

end Bench
