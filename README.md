# blackworm

## Benchmarking

`Bench.lean` + `Bench/Timing.lean` + `Bench/Suite.lean` are a self-contained
benchmarking scaffold for the dynamically generated Feistel cipher and its
OpenSSL-backed round functions. Like the rest of the project, this Lean code
is compiled through Lean's C backend (see `.lake/build/ir/Bench/*.c` after
building) into a native `bench` executable.

Build and run it with:

```bash
./build.sh                 # builds the OpenSSL C FFI shared library (once)
lake build bench           # generates Bench/*.c and compiles the executable
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

`Bench.lean`'s `[[lean_exe]]` entry links directly against the OpenSSL C FFI
shared library produced by the CMake build (`build/libopenssl_crypto.so`)
and the system's `libssl`/`libcrypto`; see the comment above it in
`lakefile.toml` for why this bypasses the (non-functional) `[[foreign_library]]`
TOML section.

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
fixed to wrap their return values with `lean_io_result_mk_ok`.

## Visualization

See [docs/cipher-visualization.md](docs/cipher-visualization.md) for Mermaid
diagrams of the generated block cipher: the 512-byte block split into two
256-byte halves (each round-function pair encrypting one 256-byte half), a
single Feistel round, multiple
`(round function, round key)` pairs combined into one round via a cipher set,
the chain linking blocks/rounds with distinct cipher sets, and the
reverse-order (transpose) decryption of that chain.

## Formal verification

`Blackworm/FeistelTheory.lean` is a Lean 4 scaffold that formally verifies
the dynamic Feistel-network block cipher generator in `Blackworm/Basic.lean`.
It proves, for any round function and any number of keyed rounds, that the
network is invertible/bijective (`round_left_inv`, `round_right_inv`,
`decryptRounds_encryptRounds`, `encryptRounds_injective`), and it models
round-key derivation from a master key with theorems about the length and
distinctness of the generated schedule (`deriveKeys_length`,
`deriveKeys_nodup`), tying everything together in the end-to-end theorem
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
`feistelChainIO`/`feistelDechainIO`.

## GitHub configuration

To set up your new GitHub repository, follow these steps:

* Under your repository name, click **Settings**.
* In the **Actions** section of the sidebar, click "General".
* Check the box **Allow GitHub Actions to create and approve pull requests**.
* Click the **Pages** section of the settings sidebar.
* In the **Source** dropdown menu, select "GitHub Actions".

After following the steps above, you can remove this section from the README file.
