# blackworm

Requires the pinned Lean toolchain, a system C compiler, and OpenSSL 3
development headers/libraries (for example `libssl-dev` on Ubuntu).
Lake builds and statically links the FFI shim automatically, linking OpenSSL
via `-lssl -lcrypto` (linkage depends on the toolchain). `./build.sh` builds all targets.
For a nonstandard OpenSSL installation use
`lake -KopensslPrefix=/path/to/openssl build test bench`, or set `OPENSSL_DIR`
when using the script. CMake remains an optional standalone FFI build.

## Benchmarking

`Bench.lean` + `Bench/Timing.lean` + `Bench/Suite.lean` are a self-contained
benchmarking scaffold for the dynamically generated Feistel cipher and its
OpenSSL-backed round functions. Like the rest of the project, this Lean code
is compiled through Lean's C backend (see `.lake/build/ir/Bench/*.c` after
building) into a native `bench` executable.

Build and run it with:

```bash
lake build bench           # builds the native FFI and benchmark executable
lake exe bench              # run the default suite
lake exe bench --list       # list available benchmark case names
lake exe bench --only AES   # only run cases whose name contains "AES"
lake exe bench --warmup 20 --iters 200 --blocks 64 --csv results.csv
```

The default suite covers raw OpenSSL primitives (SHA-256, SHA3-256,
AES-256-ECB/CBC, HKDF), single Feistel rounds using each primitive, one
zeroed-overhead round (identity `F`) to isolate the cipher's own
allocation/XOR cost, multi-block `feistelCipherIO` throughput, and a
`feistelChainIO` mixed-cipher-set chain. Each case reports sample count,
min/mean/median/max/stddev latency, and throughput (MiB/s and ops/s).

The `extern_lib` target in `lakefile.lean` tracks `openssl_crypto.c` and
rebuilds its object/archive and dependent executables when the source changes.
Executables no longer depend on a manually built `build/libopenssl_crypto.so`
or a repository-relative runtime search path.

### Fixed: OpenSSL FFI results were never wrapped as `IO` results

While wiring up the benchmark, every `openssl_*` function in
`openssl_crypto.c` was found to return its raw result value directly (e.g.
`return result;`) instead of the `lean_io_result_mk_ok(...)`-wrapped value
Lean's calling convention requires for an `IO α`-typed `@[extern]`
declaration. Lean's generated caller code treats the raw return value as if
its first byte were an `Except`-style ok/error tag, so the byte array's own
object-kind tag was being misread as an error variant, corrupting subsequent
memory reads and crashing (`SIGSEGV` inside `lean_io_result_show_error`) as
soon as any of `hash256`, `hash3_256`, `encryptAES256ECB/CBC`, `hkdf`, etc.
were actually called from compiled Lean code — this had apparently never
been exercised end-to-end before. All twelve `openssl_*` functions have been
fixed to wrap successful results with `lean_io_result_mk_ok`.
Native operation/allocation failures now return catchable IO errors after
cleanup; authenticated decryption still returns `none` on tag verification
failure. Lean-runtime allocation failures remain subject to Lean's own
out-of-memory behavior.

## Testing

`Test.lean` + `Test/Suite.lean` are a self-contained correctness suite for
the chained encrypt/decrypt methodology: `feistelRoundIO`/`feistelRoundInvIO`
round trips per round function, the full mixed cipher-set chain (the same
one benchmarked in `Bench/Suite.lean`, including AES-256-ECB/CBC decryption
used as a padding-disabled one-way round function) round-tripped via
`feistelChainIO`/`feistelDechainIO`, multi-block `feistelCipherIO` round
trips, a negative check that decrypting in the wrong (non-transposed) order
does *not* recover the plaintext, and validation that the no-padding AES
decrypt wrappers are total on block-sized input but still reject
non-block-multiple input. Unlike `bench`, `lake exe test` exits with a
nonzero status if any case fails, making it suitable as a CI gate.

The suite also checks empty-chain identity, custom forward/inverse block
pairs (both round-trip directions and invocation order), and propagation
of errors from either member of a pair. Generated deterministic cases cover
240 chains in both directions. Additional checks cover block dimensions,
padded variable-length messages, native failure recovery, and authenticated
encryption round trips and tag rejection.

Build and run it with:

```bash
lake build test             # builds the native FFI and test executable
lake exe test                # run the suite; exits 0 iff every case passed
```

See [the test visualization](docs/test-visualization.md) for coverage of
all seventeen executed cases, their inputs and assertions, and the runner's
PASS/FAIL and exit-status flow.

## Cipher-chain API

The chain consumes a `List CipherPair`. Each pair contains `forward` and
`inverse` functions of type `Block → IO Block`. `feistelChainIO` applies
the forward members in list order; `feistelDechainIO` applies the inverse
members in reverse order.

Use `CipherPair.ofFeistel` to adapt existing half-block functions:

```lean
let specs : List CipherPair :=
  [feistelWithHash256, feistelWithHash3_256].map CipherPair.ofFeistel
let ciphertext ← feistelChainIO specs block
let recovered ← feistelDechainIO specs ciphertext
```

The adapter uses the same deterministic primitive in both Feistel
directions, not the primitive's inverse. Custom pairs must preserve block
sizes and supply mutually inverse transformations. The chain validates both
32-byte halves at entry and after every link, including custom links.
Malformed blocks throw IO errors; they are never silently truncated or
padded inside a round. The inverse relationship remains a caller obligation.

### Variable-length messages

Use the message API rather than constructing undersized or oversized halves:

```lean
let ciphertext ← encryptMessageIO specs "Hello, world!".toUTF8
let recovered ← decryptMessageIO specs ciphertext
```

Encryption pads with PKCS#7 bytes to a multiple of 64, adding a full padding
block for empty or already-aligned messages, then transforms each block.
Decryption validates the ciphertext length and all trailing padding bytes
before removing them. Output length is `(plaintext.size / 64 + 1) * 64`.

**This is an experimental, deterministic, unauthenticated block framing
API, not a secure message-encryption mode.** Blocks are independent, so
equal plaintext blocks produce equal ciphertext blocks. Padding validation
is not authentication. Use a vetted authenticated scheme for real data;
an empty chain is an identity transformation apart from padding.

## Visualization

See [docs/cipher-visualization.md](docs/cipher-visualization.md) for Mermaid
diagrams of the generated block cipher: the 512-bit block split into two
256-bit halves (each Feistel round transforms one 256-bit half), a
single Feistel round, multiple
`(round function, round key)` pairs combined into one round via a cipher set,
the chain linking blocks/rounds with distinct cipher sets, and the
reverse-order (transpose) decryption of that chain.

## Formal verification

`Blackworm/FeistelTheory.lean` proves properties of an abstract model of
the dynamic Feistel network implemented in `Blackworm/Basic.lean`.
It proves, for any round function and any number of keyed rounds, that the
network is invertible/bijective (`round_left_inv`, `round_right_inv`,
`decryptRounds_encryptRounds`, `encryptRounds_injective`), and it models
round-key derivation from a master key with theorems about the length and
distinctness of the generated schedule (`deriveKeys_length`,
`deriveKeys_nodup`, under an idealized injectivity assumption that is not a
guarantee of actual HKDF output), tying everything together in the theorem
`feistelDecrypt_feistelEncrypt`.

It further generalizes the network to a **dynamically generated cipher
chain**: `CipherSet`/`combineCipherSet` let a single round combine multiple
round-function pairs (e.g. several primitives mixed into the same round),
and `RoundSpec`/`encryptChain`/`decryptChain` let each round/block in the
chain use a completely different cipher set instead of one function shared
by every round. The chain's correctness and injectivity are proved exactly
as for the fixed-`F` case, and `decryptChain_eq_foldl_reverse` makes
explicit the **transpose** required to invert such a chain: decryption must
process the per-block cipher sets in the reverse of the order they were
applied. `Blackworm/Basic.lean` mirrors this concretely with
`CipherPair.ofFeistel` links passed to `feistelChainIO`/`feistelDechainIO`.
These are proofs of the abstract Feistel model, not verification of
arbitrary custom `CipherPair` functions, message padding, IO effects, or the
OpenSSL FFI. Invertibility is not a proof of cryptographic security.

CI builds all targets and runs correctness tests on pull requests targeting
`master`, pushes to `master`, and manual dispatch. Requiring the check for
merges additionally depends on the repository's branch-protection settings.
