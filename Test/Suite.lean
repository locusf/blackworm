-- Correctness tests for the Blackworm dynamically generated Feistel cipher
-- chain, focused on the mixed-cipher-set chain methodology used in
-- `Bench/Suite.lean`: `feistelChainIO`/`feistelDechainIO` round trips
-- through hashes, AES-256-ECB/CBC encryption, HKDF, and -- new in this
-- session -- AES-256-ECB/CBC decryption used as an ordinary *one-way* round
-- function via the padding-disabled `feistelWithAES256ECBDecryptNoPad`/
-- `CBCDecryptNoPad` wrappers (see the caveats/comments in
-- `Blackworm/Basic.lean`).
--
-- This is a plain correctness suite, not a benchmark: each `TestCase` is an
-- `IO Bool` that returns whether the check passed. `main` runs every case,
-- reports PASS/FAIL for each, and exits with a nonzero code if any failed
-- (so `lake exe test` is CI-friendly).
import Blackworm.Basic

namespace Test

structure TestCase where
  name : String
  run  : IO Bool

/-- Deterministic, non-constant filler data, matching the convention in
`Bench/Suite.lean`, so test inputs aren't a suspiciously degenerate
all-zero block. -/
def patternBytes (n : Nat) (seed : UInt8 := 0x5A) : ByteArray :=
  ByteArray.mk (Array.range n |>.map fun i => seed ^^^ (UInt8.ofNat (i % 256)))

/-- Assert two `ByteArray`s are equal, printing a short diagnostic (sizes
and a hex prefix) on mismatch. -/
def checkEq (label : String) (expected actual : ByteArray) : IO Bool := do
  if expected == actual then
    return true
  else
    IO.eprintln s!"  {label}: expected {Crypto.byteArrayToHex expected} (size {expected.size}), got {Crypto.byteArrayToHex actual} (size {actual.size})"
    return false

/-- Assert two `Block`s are equal (both halves), printing a short
diagnostic on mismatch. -/
def checkBlockEq (label : String) (expected actual : Block) : IO Bool := do
  let leftOk ← checkEq s!"{label} (left)" expected.left actual.left
  let rightOk ← checkEq s!"{label} (right)" expected.right actual.right
  return leftOk && rightOk

/-- Assert that `act` throws (any `IO` error), returning whether it did. -/
def expectThrows {α : Type} (act : IO α) : IO Bool := do
  try
    discard act
    return false
  catch _ =>
    return true

/-- Build the default test suite. -/
def defaultCases : IO (Array TestCase) := do
  let aesKey : Crypto.AES256Key :=
    { bytes := patternBytes AES_256_KEY_SIZE 0x11 }
  let aesIV : Crypto.AES256IV :=
    { bytes := patternBytes AES_256_BLOCK_SIZE 0x22 }
  let hkdfSalt := patternBytes 16 0x33
  let hkdfInfo := patternBytes 16 0x44
  let payloadHalf := patternBytes HALF_BLOCK_SIZE
  let block : Block := { left := payloadHalf, right := payloadHalf }

  -- Several distinct test blocks (all-zero, all-0xFF, and two differently
  -- patterned blocks) so the round-trip checks below aren't only exercised
  -- on one degenerate input.
  let testBlocks : List Block :=
    [ { left := ByteArray.mk (Array.replicate HALF_BLOCK_SIZE 0),
        right := ByteArray.mk (Array.replicate HALF_BLOCK_SIZE 0) },
      { left := ByteArray.mk (Array.replicate HALF_BLOCK_SIZE 0xFF),
        right := ByteArray.mk (Array.replicate HALF_BLOCK_SIZE 0xFF) },
      { left := patternBytes HALF_BLOCK_SIZE 0x5A, right := patternBytes HALF_BLOCK_SIZE 0xA5 },
      { left := patternBytes HALF_BLOCK_SIZE 0x01, right := patternBytes HALF_BLOCK_SIZE 0x7E } ]

  -- The mixed cipher-set chain exercised by `Bench/Suite.lean`: every
  -- forward wrapper from `Blackworm/Basic.lean`, including AES decrypt used
  -- as an ordinary one-way link via the padding-disabled wrappers.
  let chainSpecs : List CipherPair :=
    [feistelWithHash256,
     feistelWithAES256ECB aesKey,
     feistelWithAES256ECBDecryptNoPad aesKey,
     feistelWithAES256CBC aesKey aesIV,
     feistelWithAES256CBCDecryptNoPad aesKey aesIV,
     feistelWithHKDF hkdfSalt hkdfInfo HALF_BLOCK_SIZE,
     feistelWithHash3_256].map CipherPair.ofFeistel

  -- Individual round functions to check `feistelRoundIO`/`feistelRoundInvIO`
  -- round-trip correctness for, one at a time.
  let roundFunctions : List (String × (ByteArray → IO ByteArray)) :=
    [("SHA-256", feistelWithHash256),
     ("SHA3-256", feistelWithHash3_256),
     ("AES-256-ECB", feistelWithAES256ECB aesKey),
     ("AES-256-CBC", feistelWithAES256CBC aesKey aesIV),
     ("AES-256-ECB decrypt, no padding", feistelWithAES256ECBDecryptNoPad aesKey),
     ("AES-256-CBC decrypt, no padding", feistelWithAES256CBCDecryptNoPad aesKey aesIV),
     ("HKDF", feistelWithHKDF hkdfSalt hkdfInfo HALF_BLOCK_SIZE)]

  return #[
    { name := "empty cipher-pair chain is identity in both directions"
      run := do
        let encrypted ← feistelChainIO [] block
        let decrypted ← feistelDechainIO [] block
        let forwardOk ← checkBlockEq "empty forward" block encrypted
        let inverseOk ← checkBlockEq "empty inverse" block decrypted
        return forwardOk && inverseOk },

    { name := "custom block pairs use distinct inverses in reverse order"
      run := do
        let calls ← IO.mkRef ([] : List String)
        let shift : CipherPair :=
          { forward := fun b => do
              calls.modify (· ++ ["shift forward"])
              return { b with left := ByteArray.mk (b.left.data.map (· + 1)) }
            inverse := fun b => do
              calls.modify (· ++ ["shift inverse"])
              return { b with left := ByteArray.mk (b.left.data.map (· - 1)) } }
        let exchange : CipherPair :=
          { forward := fun b => do
              calls.modify (· ++ ["swap forward"])
              return swap b
            inverse := fun b => do
              calls.modify (· ++ ["swap inverse"])
              return swap b }
        let specs := [shift, exchange]
        let ciphertext ← feistelChainIO specs block
        let expected := swap { block with left := ByteArray.mk (block.left.data.map (· + 1)) }
        let forwardOk ← checkBlockEq "custom forward" expected ciphertext
        let recovered ← feistelDechainIO specs ciphertext
        let inverseOk ← checkBlockEq "custom inverse" block recovered
        let actualCalls ← calls.get
        let orderOk := actualCalls == ["shift forward", "swap forward", "swap inverse", "shift inverse"]
        if !orderOk then
          IO.eprintln s!"  unexpected pair invocation order: {actualCalls}"
        let reverseCiphertext ← feistelDechainIO specs block
        let reverseRecovered ← feistelChainIO specs reverseCiphertext
        let reverseOk ← checkBlockEq "custom encrypt after decrypt" block reverseRecovered
        return forwardOk && inverseOk && orderOk && reverseOk },

    { name := "cipher-pair chain propagates forward and inverse errors"
      run := do
        let failing : CipherPair :=
          { forward := fun _ => throw (IO.userError "forward failure")
            inverse := fun _ => throw (IO.userError "inverse failure") }
        let forwardOk ← expectThrows (feistelChainIO [failing] block)
        let inverseOk ← expectThrows (feistelDechainIO [failing] block)
        if !forwardOk || !inverseOk then
          IO.eprintln "  cipher-pair chain did not propagate an error"
        return forwardOk && inverseOk },

    -- One Feistel round, then its inverse, must recover the original block
    -- -- for every round function used in the chain, including both
    -- one-way AES decrypt wrappers. This holds regardless of whether `f`
    -- is "really" invertible (SHA-256/SHA3-256/HKDF aren't), which is the
    -- whole point of the Feistel construction: `feistelRoundInvIO` reapplies
    -- the *same* forward `f`, it never needs an inverse of `f` itself.
    { name := "feistelRoundIO/feistelRoundInvIO round trip per round function"
      run := do
        let mut allOk := true
        for (label, f) in roundFunctions do
          let ciphertext ← feistelRoundIO block f
          let recovered ← feistelRoundInvIO ciphertext f
          let ok ← checkBlockEq s!"round trip ({label})" block recovered
          allOk := allOk && ok
        return allOk },

    -- The full 7-link mixed chain (as used in `Bench/Suite.lean`) must
    -- round-trip via `feistelChainIO` (encrypt) then `feistelDechainIO`
    -- (decrypt, the transpose/reverse order per
    -- docs/cipher-visualization.md §4), across several distinct blocks.
    { name := "feistelChainIO/feistelDechainIO round trip (7-link mixed chain)"
      run := do
        let mut allOk := true
        let mut i := 0
        for b in testBlocks do
          let ciphertext ← feistelChainIO chainSpecs b
          let recovered ← feistelDechainIO chainSpecs ciphertext
          let ok ← checkBlockEq s!"chain round trip (block {i})" b recovered
          allOk := allOk && ok
          i := i + 1
        return allOk },

    -- The chain must actually transform the block (not be an accidental
    -- identity/no-op), i.e. ciphertext ≠ plaintext for a non-trivial input.
    { name := "feistelChainIO produces a genuinely different block"
      run := do
        let ciphertext ← feistelChainIO chainSpecs block
        let leftChanged := ciphertext.left != block.left
        let rightChanged := ciphertext.right != block.right
        if leftChanged && rightChanged then
          return true
        else
          IO.eprintln "  ciphertext was unexpectedly unchanged from the plaintext block"
          return false },

    -- Decryption in the *wrong* (non-reversed) order must NOT generally
    -- recover the original block -- this guards against a regression where
    -- `feistelDechainIO` (or a manual reimplementation) forgets to walk
    -- `specs.reverse` (the transpose required per
    -- docs/cipher-visualization.md §4). With cryptographic round functions
    -- in the mix, the chance of an accidental match is negligible.
    { name := "feistelDechainIO in forward (non-transposed) order does not recover the block"
      run := do
        let ciphertext ← feistelChainIO chainSpecs block
        -- Deliberately reapply `feistelRoundInvIO` in the *forward* order
        -- instead of `specs.reverse`, mimicking the bug this test guards
        -- against.
        let wrongOrder ← chainSpecs.foldlM (fun b spec => spec.inverse b) ciphertext
        if wrongOrder.left != block.left || wrongOrder.right != block.right then
          return true
        else
          IO.eprintln "  unexpectedly recovered the original block using the wrong (non-transposed) order"
          return false },

    -- Multi-block round trip: `feistelCipherIO` (forward) over several
    -- blocks with a single round function, inverted block-by-block with
    -- `feistelRoundInvIO`, must recover every original block.
    { name := "feistelCipherIO round trip across multiple blocks (AES-256-ECB)"
      run := do
        let f := feistelWithAES256ECB aesKey
        let ciphertexts ← feistelCipherIO testBlocks f
        let recovered ← ciphertexts.mapM (fun b => feistelRoundInvIO b f)
        if ciphertexts.length ≠ testBlocks.length || recovered.length ≠ testBlocks.length then
          IO.eprintln "  multi-block cipher changed the number of blocks"
          return false
        let mut allOk := true
        let mut i := 0
        for (expected, actual) in testBlocks.zip recovered do
          let ok ← checkBlockEq s!"multi-block round trip (block {i})" expected actual
          allOk := allOk && ok
          i := i + 1
        return allOk },

    -- The padding-disabled AES decrypt wrappers must succeed (not throw)
    -- on arbitrary, non-ciphertext data whose size is a multiple of the AES
    -- block size -- confirming they really are total functions, safe to use
    -- as one-way round functions on arbitrary Feistel state.
    { name := "AES-256-ECB/CBC decrypt (no padding) succeed on arbitrary block-sized data"
      run := do
        let arbitrary := patternBytes HALF_BLOCK_SIZE 0x99
        let ecbOk ← (do discard (Crypto.decryptAES256ECBNoPad aesKey arbitrary); pure true)
          <|> pure false
        let cbcOk ← (do discard (Crypto.decryptAES256CBCNoPad aesKey aesIV arbitrary); pure true)
          <|> pure false
        if ecbOk && cbcOk then
          return true
        else
          IO.eprintln s!"  decryptAES256ECBNoPad ok={ecbOk}, decryptAES256CBCNoPad ok={cbcOk}"
          return false },

    -- The padding-disabled AES decrypt wrappers must still reject
    -- non-block-multiple input with a catchable `IO` error (not garbage
    -- output), per the validation in `Crypto.decryptAES256ECBNoPad`/
    -- `CBCNoPad`.
    { name := "AES-256-ECB/CBC decrypt (no padding) reject non-block-multiple input"
      run := do
        let badSize := patternBytes (HALF_BLOCK_SIZE + 1) 0x99
        let ecbRejected ← expectThrows (Crypto.decryptAES256ECBNoPad aesKey badSize)
        let cbcRejected ← expectThrows (Crypto.decryptAES256CBCNoPad aesKey aesIV badSize)
        if ecbRejected && cbcRejected then
          return true
        else
          IO.eprintln s!"  decryptAES256ECBNoPad rejected={ecbRejected}, decryptAES256CBCNoPad rejected={cbcRejected}"
          return false },

    -- Sanity check on the "real" (padded) AES round trip still used for
    -- genuine encrypt/decrypt (as opposed to the one-way chain links
    -- above): `Crypto.decryptAES256ECB`/`CBC` must invert
    -- `Crypto.encryptAES256ECB`/`CBC` for arbitrary-length data.
    { name := "Crypto.encryptAES256ECB/CBC round trip (padded, arbitrary-length data)"
      run := do
        let msg := "The quick brown fox jumps over the lazy dog".toUTF8
        let ecbCiphertext ← Crypto.encryptAES256ECB aesKey msg
        let ecbRecovered ← Crypto.decryptAES256ECB aesKey ecbCiphertext
        let ecbOk ← checkEq "AES-256-ECB round trip" msg ecbRecovered
        let cbcCiphertext ← Crypto.encryptAES256CBC aesKey aesIV msg
        let cbcRecovered ← Crypto.decryptAES256CBC aesKey aesIV cbcCiphertext
        let cbcOk ← checkEq "AES-256-CBC round trip" msg cbcRecovered
        return ecbOk && cbcOk },

    { name := "generated mixed chains round trip in both directions"
      run := do
        let mut allOk := true
        for seed in [0:16] do
          let bytes := ByteArray.mk (Array.range BLOCK_SIZE |>.map fun i =>
            UInt8.ofNat ((seed + 1) * (i * i + 17 * i + 31) + i / 3))
          let input ← Block.ofBits512 bytes
          let offset := seed % chainSpecs.length
          let rotated := chainSpecs.drop offset ++ chainSpecs.take offset
          for count in [0:15] do
            let specs := (rotated ++ rotated).take count
            let encrypted ← feistelChainIO specs input
            let recovered ← feistelDechainIO specs encrypted
            let forwardOk ← checkBlockEq s!"generated seed={seed} links={count}" input recovered
            let decrypted ← feistelDechainIO specs input
            let recoveredReverse ← feistelChainIO specs decrypted
            let inverseOk ← checkBlockEq s!"generated reverse seed={seed} links={count}" input recoveredReverse
            allOk := allOk && forwardOk && inverseOk
        return allOk },

    { name := "chain rejects invalid input and size-changing custom pairs"
      run := do
        let mut allOk := true
        for size in [0, 1, 31, 33, 64] do
          for invalid in
              [{ left := patternBytes size, right := emptyHalf : Block },
               { left := emptyHalf, right := patternBytes size : Block }] do
            let forwardOk ← expectThrows (feistelChainIO [] invalid)
            let inverseOk ← expectThrows (feistelDechainIO [] invalid)
            allOk := allOk && forwardOk && inverseOk
        let invalidPair : CipherPair :=
          { forward := fun b => pure { b with left := ByteArray.empty }
            inverse := fun b => pure { b with right := ByteArray.empty } }
        let calls ← IO.mkRef (0 : Nat)
        let sentinel : CipherPair :=
          { forward := fun b => do calls.modify (· + 1); return b
            inverse := fun b => do calls.modify (· + 1); return b }
        let forwardOk ← expectThrows (feistelChainIO [invalidPair, sentinel] block)
        let inverseOk ← expectThrows (feistelDechainIO [sentinel, invalidPair] block)
        let count ← calls.get
        allOk := allOk && forwardOk && inverseOk && count == 0
        if !allOk then
          IO.eprintln "  invalid block was accepted or processing continued after invalid output"
        return allOk },

    { name := "variable-length messages round trip with exact padded lengths"
      run := do
        let mut allOk := true
        for size in [0:194] do
          let message := patternBytes size (UInt8.ofNat size)
          for specs in [[], chainSpecs] do
            let ciphertext ← encryptMessageIO specs message
            let expectedSize := (size / BLOCK_SIZE + 1) * BLOCK_SIZE
            if ciphertext.size ≠ expectedSize then
              IO.eprintln s!"  message length {size}: expected ciphertext size {expectedSize}, got {ciphertext.size}"
              allOk := false
            let recovered ← decryptMessageIO specs ciphertext
            let ok ← checkEq s!"message length {size}" message recovered
            allOk := allOk && ok
        let paddedEmpty ← encryptMessageIO [] ByteArray.empty
        let paddingOk ← checkEq "full padding block"
          (ByteArray.mk (Array.replicate BLOCK_SIZE (UInt8.ofNat BLOCK_SIZE))) paddedEmpty
        return allOk && paddingOk },

    { name := "message decryption rejects invalid lengths and padding"
      run := do
        let mut allOk := true
        for size in [0, 1, 63, 65, 127] do
          let rejected ← expectThrows (decryptMessageIO [] (patternBytes size))
          allOk := allOk && rejected
        for last in [0, 65, 255] do
          let malformed := patternBytes (BLOCK_SIZE - 1) ++ ByteArray.mk #[UInt8.ofNat last]
          let rejected ← expectThrows (decryptMessageIO [] malformed)
          allOk := allOk && rejected
        let inconsistent := patternBytes (BLOCK_SIZE - 2) ++ ByteArray.mk #[1, 2]
        let rejected ← expectThrows (decryptMessageIO [] inconsistent)
        allOk := allOk && rejected
        if !allOk then
          IO.eprintln "  invalid message length or padding was accepted"
        return allOk },

    { name := "native OpenSSL failures are catchable IO errors"
      run := do
        -- Empty padded ciphertext always fails finalization; no probabilistic
        -- assumption about the padding of random ciphertext is needed.
        let ecbOk ← expectThrows (Crypto.decryptAES256ECB aesKey ByteArray.empty)
        let cbcOk ← expectThrows (Crypto.decryptAES256CBC aesKey aesIV ByteArray.empty)
        let noPadOk ← expectThrows (aes256ECBDecryptNoPad aesKey.bytes (patternBytes 17))
        let pbkdfOk ← expectThrows (pbkdf2Sha256 "password".toUTF8 hkdfSalt 0 32)
        if !ecbOk || !cbcOk || !noPadOk || !pbkdfOk then
          IO.eprintln "  expected a catchable native failure"
          return false
        let hash ← Crypto.hash256 ByteArray.empty
        if Crypto.sha256ToString hash ≠ "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" then
          IO.eprintln "  SHA-256 failed after handling native errors"
          return false
        return true },

    { name := "AEAD round trips and authentication failures retain Option semantics"
      run := do
        let nonce := patternBytes 12 0x42
        let aad := "associated data".toUTF8
        let message := "authenticated message".toUTF8
        let mut allOk := true
        for (encrypt, decrypt) in
            [(aes256GCMEncrypt, aes256GCMDecrypt),
             (chacha20Poly1305Encrypt, chacha20Poly1305Decrypt)] do
          let (ciphertext, tag) ← encrypt aesKey.bytes nonce message aad
          match ← decrypt aesKey.bytes nonce ciphertext tag aad with
          | none =>
            IO.eprintln "  valid AEAD ciphertext was rejected"
            allOk := false
          | some recovered =>
            let ok ← checkEq "AEAD round trip" message recovered
            allOk := allOk && ok
          let badTag := ByteArray.mk (tag.data.modify 0 (· ^^^ 1))
          if (← decrypt aesKey.bytes nonce ciphertext badTag aad).isSome then
            IO.eprintln "  invalid authentication tag was accepted"
            allOk := false
          let invalidTagRejected ← expectThrows
            (decrypt aesKey.bytes nonce ciphertext ByteArray.empty aad)
          if !invalidTagRejected then
            IO.eprintln "  invalid tag setup did not throw an IO error"
          allOk := allOk && invalidTagRejected
        return allOk }
  ]

end Test
