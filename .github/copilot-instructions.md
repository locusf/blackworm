# Copilot instructions for blackworm

Blackworm is a Lean 4 project with two intertwined halves:

1. A dynamically-generated Feistel-network block cipher generator
   (`Blackworm/Basic.lean`), driven by real cryptographic primitives
   (SHA-256, SHA3-256, AES-256, ChaCha20-Poly1305, HKDF, PBKDF2) exposed
   through a C FFI to OpenSSL (`openssl_crypto.c`).
2. A formal proof of that cipher's correctness (`Blackworm/FeistelTheory.lean`),
   built over an *abstract* model — it is deliberately independent of
   `ByteArray`/`IO`/FFI so it type-checks without native dependencies, and it
   `import Mathlib`.

## Build

```bash
lake build          # builds the Lean library (Mathlib pinned in lakefile.lean)
./build.sh          # checks prerequisites, builds all Lean/native targets
lake exe test       # builds the native dependency and runs correctness checks
```

- `.github/workflows/copilot-setup-steps.yml` preinstalls `libssl-dev`/`cmake`,
  sets up the Lean 4 toolchain, primes the Mathlib `.olean` cache, and builds
  the OpenSSL FFI library for the Copilot cloud agent's environment — mirror
  it if the toolchain/dependency setup changes.

- `lakefile.lean` declares an `extern_lib` named `openssl_crypto` that
  tracks and compiles `openssl_crypto.c`, statically links the FFI shim, and
  links system `ssl`/`crypto`. `CMakeLists.txt` is an
  alternative/manual way to build the same C library (shared + static) if you
  need to invoke CMake directly instead of going through Lake.
- Lean toolchain version is pinned in `lean-toolchain`
  (`leanprover/lean4:v4.34.0`); Mathlib is pinned to `v4.34.0` in
  `lakefile.lean`'s `require` declaration — keep these in sync when upgrading.
- `lake exe test` runs the seventeen correctness cases in `Test/Suite.lean`
  through `Test.lean`, exiting nonzero on failure. Lake builds the native
  dependency automatically. The suite covers cipher pairs, Feistel chains
  and rounds, padded messages, dimensions, and native error/AEAD behavior.
  `Blackworm/CryptoExamples.lean`
  additionally contains illustrative `example : IO Unit` blocks.
  Proof obligations in `FeistelTheory.lean` are checked by `lake build`.

## Architecture

- `Blackworm.lean` is the library root; it just imports `Blackworm.Basic` and
  `Blackworm.FeistelTheory` (per `lean_lib Blackworm` in `lakefile.lean`).
- FFI/crypto stack, low-level to high-level:
  - `openssl_crypto.c` — native C implementations calling OpenSSL's EVP API.
    Native operation/allocation failures return IO errors after cleanup;
    AEAD authentication failure remains `none`. Lean-runtime allocation
    itself still follows Lean's out-of-memory policy.
  - `Blackworm/OpenSSLBindings.lean` — `@[extern "openssl_..."] opaque ...`
    declarations that bind 1:1 to the C functions, plus raw size constants
    (`AES_256_KEY_SIZE`, etc.). Adding a new primitive means adding it here
    *and* in the C file with matching extern names.
  - `Blackworm/CryptoInterface.lean` — the `Crypto` namespace: type-safe
    wrapper structs (`AES256Key`, `AES256IV`, `SHA256Hash`, ...) and
    validating wrapper functions (e.g. `encryptAES256ECB` throws
    `IO.userError` if the key size is wrong before calling the opaque FFI
    function). Prefer extending this layer, not the raw bindings, when
    exposing new functionality to cipher code.
  - `Blackworm/Basic.lean` — the actual Feistel cipher: `Block`, a single
    `feistelRound`/`feistelRoundIO`, and generalizations:
    - `feistelCipherIO` runs the *same* round function `f` over a list of
      blocks.
    - `feistelChainIO`/`feistelDechainIO` consume a `List CipherPair`, each
      holding `forward` and `inverse` functions of type `Block → IO Block`.
      `CipherPair.ofFeistel` adapts an existing half-block round function,
      reusing it in both Feistel directions. Custom pairs must be mutually
      inverse; the chain validates two 32-byte halves at entry and after
      each link. **Decryption must walk
      `specs.reverse`** and call `inverse` — undoing chain step 1
      last — this transpose relationship is the crux of the design and is
      mirrored/proved for the abstract Feistel model in the theory file,
      not for arbitrary custom IO pairs.
    - `encryptMessageIO`/`decryptMessageIO` pad/unpad arbitrary byte messages
      with PKCS#7 and process 64-byte blocks independently. This deterministic,
      unauthenticated framing exposes repeated blocks; it is not a secure
      message-encryption mode and padding is not authentication.
    - `feistelWithHash256`, `feistelWithAES256ECB`, `feistelWithHKDF`, etc.
      adapt `Crypto` functions into the `ByteArray → IO ByteArray` shape a
      Feistel round expects.
- `Blackworm/FeistelTheory.lean` (`namespace Blackworm.Feistel`) mirrors the
  above structurally but abstractly, so read it section-by-section alongside
  the corresponding concept in `Basic.lean`:
  - `Abstract` — round/network over any cancellative XOR-like op `α → α → α`;
    proves single-round and full-network invertibility/injectivity for *any*
    round function `F`.
  - `Concrete` — instantiates `Abstract` with `Bits n := Fin n → Bool` and
    position-wise XOR, the model of `xorByteArrays`.
  - `KeyDerivation` — models round-key schedules from a master key (what
    `feistelWithHKDF` provides concretely) and proves schedule length and
    distinctness.
  - `FullCipher` — combines `Abstract` + `KeyDerivation` into the end-to-end
    theorem `feistelDecrypt_feistelEncrypt`.
  - `MultiRound` — a `CipherSet`/`combineCipherSet`: several
    `(round function, round key)` pairs XOR-folded into a single round
    (multiple primitives mixed into one round), rather than one primitive
    per round.
  - `Chain` — generalizes rounds to `RoundSpec`/`encryptChain`/`decryptChain`
    over a heterogeneous `List (RoundSpec α)`, the abstract counterpart of
    chains built with `CipherPair.ofFeistel`. `decryptChain_eq_foldl_reverse` is
    the formal statement of the transpose/reverse requirement above.

## Conventions

- New FFI-backed crypto operations follow a strict three-layer pattern: add
  the `@[extern ...] opaque` declaration in `OpenSSLBindings.lean`, add a
  validating wrapper in the `Crypto` namespace in `CryptoInterface.lean`, then
  (optionally) add a `feistelWith*` adapter in `Basic.lean` if it's meant to
  be used as a Feistel round function.
- Any new Feistel-network property should be proved first in the `Abstract`
  section over a generic cancellative operator, then (if needed) specialized
  in `Concrete`/`FullCipher`/`Chain` — don't prove `ByteArray`-specific
  results directly against `Basic.lean`, since `FeistelTheory.lean` is kept
  independent of `ByteArray`/`IO`/FFI on purpose.
- Wrapper functions in `CryptoInterface.lean` validate input sizes
  (`key.bytes.size ≠ AES_256_KEY_SIZE`, etc.) and `throw (IO.userError ...)`
  before ever calling the opaque FFI function — replicate this pattern for
  new wrappers rather than trusting caller input.
