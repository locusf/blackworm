# Native build and error handling

## Lake integration

[`lakefile.lean`](lakefile.lean) replaces the former TOML configuration,
whose `foreign_library` section was not a supported Lake target.

- `opensslObject` tracks `openssl_crypto.c` and compiles it with the system
  C compiler and the pinned Lean headers.
- `extern_lib openssl_crypto` archives the object and links the FFI shim
  into dependent executables. OpenSSL is linked via `-lssl -lcrypto`;
  whether those libraries are static or dynamic depends on the toolchain.
- Tests and benchmarks no longer require a prebuilt
  `build/libopenssl_crypto.so` or a repository-relative runtime search path.
- Source, compiler-option, platform, and Lean toolchain changes participate
  in Lake's build tracing. Changes to system OpenSSL headers/libraries may
  require rebuilding the native target.

```bash
lake build Blackworm test bench
lake exe test
```

Install a system C compiler and OpenSSL 3 development headers/libraries
first. For a nonstandard OpenSSL prefix:

```bash
lake -KopensslPrefix=/path/to/openssl build test bench
```

[`build.sh`](build.sh) checks prerequisites and builds all targets without
deleting previous build artifacts. It accepts `OPENSSL_DIR` and detects
Homebrew's OpenSSL prefix on macOS. [`CMakeLists.txt`](CMakeLists.txt) remains
an optional standalone shared/static FFI build, not a Lake prerequisite.

## Native failures

Successful FFI calls return `lean_io_result_mk_ok`; recoverable native
operation and allocation failures return
`lean_io_result_mk_error(lean_mk_io_user_error(...))` after releasing native
buffers and contexts. Cipher/hash/HMAC update calls are checked as well as
initialization and finalization.

Invalid padded AES ciphertext throws an IO error rather than aborting the
process. AEAD setup/update failures throw, while authentication failure
continues to return `none`. Failures of Lean's own allocation functions
remain governed by the Lean runtime's out-of-memory behavior.

The correctness suite exercises native padded-decryption failure,
no-padding block-length failure, PBKDF2 failure, recovery via a SHA-256
known answer, and both AEAD success and tag rejection. These tests do not
inject allocation failures or establish memory safety on every platform.

## Continuous integration

The workflow builds all targets and runs correctness tests before merge
on pull requests targeting `master`, on pushes to `master`, and on manual
dispatch. Branch protection must separately require this check to prevent
merging a failing PR.
