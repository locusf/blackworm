# Visualization: correctness tests

The suite executes eleven cases via `lake exe test`. Three cipher-pair
checks run first: empty-chain identity in both directions, custom block
transformations with distinct inverses (including exact invocation order
and both round-trip directions), and propagation of forward/inverse errors.
The diagrams below describe the remaining eight Feistel/crypto cases in
the order returned by [`defaultCases`](../Test/Suite.lean). They are a
coverage map, not live results. The [`runner`](../Test.lean) prints the
actual PASS/FAIL status.

## Execution and reporting

```mermaid
flowchart TD
    START["lake exe test"] --> BUILD["Build the default suite: 11 cases"]
    BUILD --> NEXT["Run next case"]
    NEXT --> RESULT{"Returns true?"}
    NEXT --> EXCEPTION["Unexpected IO exception"]
    EXCEPTION --> DIAG["Print exception diagnostic"]
    DIAG --> FAIL["Print FAIL; increment failures"]
    RESULT -->|Yes| PASS["Print PASS"]
    RESULT -->|No| FAIL
    PASS --> MORE{"More cases?"}
    FAIL --> MORE
    MORE -->|Yes| NEXT
    MORE -->|No| SUMMARY{"Any failures?"}
    SUMMARY -->|No| OK["Print all passed; exit 0"]
    SUMMARY -->|Yes| BAD["Print failure count; exit 1"]
```

A failed case does not stop later cases. Each numbered case below produces
one status line, even when it checks multiple functions or inputs.

## 1. Single-round recovery with seven round functions

```mermaid
flowchart LR
    INPUT["Block: two identical patterned 32-byte halves"] --> ENC["feistelRoundIO with F"]
    ENC --> DEC["feistelRoundInvIO with the same F"]
    DEC --> CHECK["Check both recovered halves equal the input"]
    FUNCTIONS["Repeat for all 7 round functions"] -.-> ENC
    FUNCTIONS -.-> DEC
```

The seven functions are SHA-256, SHA3-256, AES-256-ECB encryption,
AES-256-CBC encryption, AES-256-ECB decryption without padding,
AES-256-CBC decryption without padding, and HKDF. All seven round trips
must pass. The inverse Feistel round reuses **the same F**, not an inverse
of the hash, HKDF, or AES operation.

## 2. Seven-link mixed-chain recovery

Each node below is a **Feistel round using the named function**, not a raw
primitive applied directly to the entire block.

```mermaid
flowchart TD
    INPUT["For each of 4 input blocks"] --> E["feistelChainIO"]
    E --> F1["1. SHA-256"]
    F1 --> F2["2. AES-256-ECB encryption"]
    F2 --> F3["3. AES-256-ECB decryption, no padding"]
    F3 --> F4["4. AES-256-CBC encryption"]
    F4 --> F5["5. AES-256-CBC decryption, no padding"]
    F5 --> F6["6. HKDF"]
    F6 --> F7["7. SHA3-256"]
    F7 --> C["Ciphertext block"]
    C --> D["feistelDechainIO: inverse Feistel rounds, functions 7 to 1"]
    D --> CHECK["Check both recovered halves equal the input"]
```

The four blocks have all-zero halves, all-`0xFF` halves, patterned halves
with seeds `0x5A`/`0xA5`, and patterned halves with seeds `0x01`/`0x7E`.
Each half is 32 bytes. Every block must round-trip.

## 3 and 4. Guard against a no-op and incorrect inverse order

These are separate cases, each starting with a block whose two halves use
the `0x5A` pattern and independently encrypting it with the seven-link chain.

```mermaid
flowchart TD
    B["Patterned plaintext block"] --> E["feistelChainIO: functions 1 to 7"]
    E --> C["Ciphertext"]
    C --> CHANGE["Case 3: left differs AND right differs from plaintext"]
    C --> WRONG["Case 4: inverse Feistel rounds in WRONG order, 1 to 7"]
    WRONG --> DIFF["Left differs OR right differs from plaintext"]
    CHANGE --> P3["Pass only if both halves changed"]
    DIFF --> P4["Pass only if the original block was NOT recovered"]
```

These assertions concern this specific test input; they do not prove that
every input changes or that wrong-order inversion can never match.

## 5. Multiple-block recovery

```mermaid
flowchart LR
    INPUT["The same 4 blocks used in case 2"] --> ENC["feistelCipherIO with AES-256-ECB encryption as F"]
    ENC --> DEC["Map feistelRoundInvIO with the same F over ciphertext blocks"]
    DEC --> ZIP["Zip original and recovered lists"]
    ZIP --> CHECK["Check both halves of every paired block"]
```

This exercises one Feistel round per block, not the seven-link mixed
chain. The implementation compares zipped pairs; it does not separately
assert the recovered list length.

## 6, 7 and 8. AES wrapper behavior

```mermaid
flowchart TD
    A["Case 6: 32 patterned bytes, seed 0x99"] --> NP["ECB and CBC decrypt, no padding"]
    NP --> SUCCESS["Pass: both calls succeed without an IO error"]
    B["Case 7: 33 patterned bytes, seed 0x99"] --> INVALID["ECB and CBC decrypt, no padding"]
    INVALID --> REJECT["Pass: both calls throw an IO error"]
    MSG["Case 8: 43-byte UTF-8 message"] --> ENC["Padded AES encryption, separately for ECB and CBC"]
    ENC --> DEC["Matching padded AES decryption"]
    DEC --> EQ["Pass: both recovered byte arrays equal the message"]
```

Case 6 uses arbitrary data, not previously generated ciphertext, and checks
success rather than output contents. Case 7 checks rejection of an input
whose length is not a multiple of the 16-byte AES block size; any IO error
satisfies the assertion. Case 8 uses
`The quick brown fox jumps over the lazy dog` to exercise genuine padded
AES round trips independently of Feistel inversion.

## Scope

All keys, IVs, salt, info, and block patterns are deterministic fixtures.
These are runtime correctness checks, not randomized tests, known-answer
cryptographic vectors, security proofs, or performance measurements.
See the [cipher diagrams](cipher-visualization.md) for the construction
and the [README](../README.md#formal-verification) for the separate Lean
proofs.
