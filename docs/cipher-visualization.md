# Visualization: the dynamically generated Feistel cipher chain

This document visualizes how the generated block cipher works **as currently
implemented**, layer by layer:

0. the **512-bit block layout**: each block is 512 bits (64 bytes), split
   into two 256-bit halves, and every Feistel round transforms exactly
   one 256-bit half per round (`BLOCK_BITS`/`HALF_BLOCK_BITS`/`fitTo`/
   `Block.ofBits512` in `Blackworm/Basic.lean`),
1. a single Feistel round (`feistelRound`/`feistelRoundIO` in
   `Blackworm/Basic.lean`, `round` in `Blackworm/FeistelTheory.lean`),
2. **multiple function/key pairs combined inside one round** — a *cipher set*
   (`CipherSet`/`combineCipherSet`/`cipherSetF` in
   `Blackworm/FeistelTheory.lean`),
3. the **chain**: a sequence of rounds/blocks where each link can use a
   completely different round function or cipher set
   (`feistelChainIO`/`feistelDechainIO` in `Blackworm/Basic.lean`,
   `RoundSpec`/`encryptChain`/`decryptChain` in
   `Blackworm/FeistelTheory.lean`), and
4. the **transpose** required for decryption
   (`decryptChain_eq_foldl_reverse`): the chain must be undone in reverse
   order.

> **Accuracy note.** The two halves of the design differ slightly, and the
> diagrams show this honestly:
>
> * In the *concrete* code (`Basic.lean`), each link is a `CipherPair` of
>   forward/inverse block functions. `CipherPair.ofFeistel` builds a pair
>   from a `ByteArray → IO ByteArray` function (e.g. `feistelWithHash256`,
>   `feistelWithAES256ECB key`, `feistelWithHKDF salt info len`). Keys are
>   captured inside these half-block closures.
> * In the *abstract* proof layer (`FeistelTheory.lean`), the pairs are
>   explicit: a `CipherSet` is a `List ((α → α → α) × α)` of
>   `(round function, round key)` pairs, several of which can be XOR-folded
>   into **one** round via `combineCipherSet`, and each chain link is a
>   `RoundSpec` pair `⟨F, k⟩`.
>
> So "multiple function/key pairs per round" is a proved capability of the
> abstract model (`MultiRound` section) which the concrete chain can realize
> by composing/mixing primitives inside one `ByteArray → IO ByteArray`
> closure. The concrete chain stores a `List CipherPair`: each pair has
> `forward` and `inverse` block transformations (`Block → IO Block`).
> `CipherPair.ofFeistel f` wraps a half-block function in a Feistel round
> and its inverse; this pair is distinct from the abstract `(F, k)` pair.

## 0. The 512-bit block: two 256-bit halves

A block is **512 bits** (`BLOCK_BITS`; 64 bytes, `BLOCK_SIZE`).
`Block.ofBits512` splits it into a 256-bit left half and a 256-bit right half
(`HALF_BLOCK_BITS`; 32 bytes each, `HALF_BLOCK_SIZE`); `Block.toBytes`
reassembles it. Each Feistel round transforms exactly one 256-bit half per
round: a 256-bit SHA-256/SHA3-256 digest already matches the half exactly, and
for any other natural output size (a PKCS#7-padded AES ciphertext, an HKDF
output, ...) `fitTo` cycles or truncates it to 256 bits before it is XORed
into the other half, so the halves never grow or shrink.

The chain validates two 32-byte halves at entry and after every link.
Invalid block dimensions throw an IO error, even for an empty chain.
This is a runtime size check, not a proof that custom forward/inverse
functions cancel each other.

```mermaid
flowchart TB
    B["512-bit block (BLOCK_BITS)"]
    B -->|"Block.ofBits512"| L["L — 256 bits\n(HALF_BLOCK_BITS)"]
    B -->|"Block.ofBits512"| R["R — 256 bits\n(HALF_BLOCK_BITS)"]
    R --> F["round function F(k, ·)\n(natural output size varies)"]
    F -->|"fitTo 256 bits"| OUT["256-bit keystream\n— encrypts one 256-bit half"]
    style B fill:#e3f2fd,stroke:#1565c0
    style OUT fill:#e8f5e9,stroke:#2e7d32
```

## 1. A single Feistel round

`feistelRound b f = { left := b.right, right := b.left ⊕ fitTo 256 bits (f b.right) }`
(`⊕` is `xorByteArrays`; abstractly, any cancellative `xor`). Both halves are
256 bits, so each Feistel round transforms a 256-bit half of the state.

```mermaid
flowchart LR
    subgraph input["512-bit Block (input)"]
        L["L (256 bits)"]
        R["R (256 bits)"]
    end
    subgraph output["512-bit Block (output)"]
        L2["L' = R (256 bits)"]
        R2["R' = L ⊕ fitTo 256 bits (F(k, R)) (256 bits)"]
    end
    R --> F["F(k, ·) — function/key pair (F, k)"]
    F --> FIT["fitTo 256 bits"]
    FIT --> X(("⊕"))
    L --> X
    X --> R2
    R --> L2
```

Because only XOR and a swap touch the state, the round is invertible for
*any* round function `F` — even a non-invertible one like SHA-256
(`round_left_inv` / `round_right_inv`, mirrored concretely by
`feistelRoundInvIO`).

## 2. Multiple function/key pairs in one round: the cipher set

A `CipherSet` is a list of `(Fᵢ, kᵢ)` pairs. `combineCipherSet` applies every
pair to the *same* right half and XOR-folds the results; `cipherSetF`
collapses the whole set into one ordinary round function, so the round above
inherits invertibility for free.

```mermaid
flowchart LR
    R["R (right half)"] --> F1["F₁(k₁, R)"]
    R --> F2["F₂(k₂, R)"]
    R --> F3["F₃(k₃, R)"]
    F1 --> X1(("⊕"))
    F2 --> X1
    X1 --> X2(("⊕"))
    F3 --> X2
    X2 --> OUT["combineCipherSet cs R\n(one combined round output)"]
    style OUT fill:#e8f5e9,stroke:#2e7d32
```

Example: one round can mix SHA-256 **and** AES-256-ECB **and** an
HKDF-derived stream simultaneously — several primitives drawn from the pool
into the *same* round, not one primitive per round.

## 3. The chain: blocks/rounds linked together, each with its own cipher set

`feistelChainIO specs b` folds a 512-bit block through `specs` left-to-right,
applying each `CipherPair.forward`. For Feistel links, construct the pairs
with `CipherPair.ofFeistel`; each such link encrypts a 256-bit half.
Custom pairs may instead supply any size-preserving, mutually inverse
block transformations. Abstractly, `encryptChain` models the Feistel case
over `List (RoundSpec α)`, where each `RoundSpec ⟨Fᵢ, kᵢ⟩` may itself be
a whole cipher set packaged via `RoundSpec.ofCipherSet`.

```mermaid
flowchart LR
    P["Plaintext block\n(L₀, R₀)"] --> S1
    subgraph RD1["CipherPair 1 — e.g. SHA-256"]
        S1["forward: Feistel round"] --- U1["inverse: inverse Feistel round"]
    end
    S1 --> B1["(L₁, R₁)"] --> S2
    subgraph RD2["CipherPair 2 — e.g. AES-256-ECB encryption"]
        S2["forward: Feistel round"] --- U2["inverse: inverse Feistel round"]
    end
    S2 --> B2["(L₂, R₂)"] --> S3
    subgraph RD3["CipherPair 3 — mixed round function"]
        S3["forward: Feistel round"] --- U3["inverse: inverse Feistel round"]
    end
    S3 --> C["Ciphertext block\n(L₃, R₃)"]
    style P fill:#e3f2fd,stroke:#1565c0
    style C fill:#fce4ec,stroke:#ad1457
```

Arrows show encryption; undirected lines group the members of each pair.
Each pair here is built with `CipherPair.ofFeistel`, using a deterministic
primitive or mixed half-block function. The abstract counterparts are
`RoundSpec` values, with `RoundSpec.ofCipherSet` modeling the mixed case.

Each forward member is a full Feistel round from §1; the links differ in *which*
round function (or combined cipher set) they use — this is what makes the
chain "dynamically generated" (`deriveChain` in the theory file even derives
the whole spec list from a master key).

## 4. Decryption: the chain in transpose (reverse) order

The round applied **first** during encryption must be undone **last**.
`feistelDechainIO` therefore walks `specs.reverse`, applying
each pair's `inverse`. For `CipherPair.ofFeistel` links this calls
`feistelRoundInvIO`; `decryptChain_eq_foldl_reverse` proves the corresponding
abstract Feistel construction is exactly `decryptChain`, and
`decryptChain_encryptChain` proves its round trip is the identity. These
Feistel proofs do not establish correctness of arbitrary custom IO pairs;
their inverse relationship is the caller's responsibility.

```mermaid
flowchart RL
    C["Ciphertext\n(L₃, R₃)"] --> I3["pair 3.inverse"]
    I3 --> I2["pair 2.inverse"]
    I2 --> I1["pair 1.inverse"]
    I1 --> P["Plaintext\n(L₀, R₀)"]
    style C fill:#fce4ec,stroke:#ad1457
    style P fill:#e3f2fd,stroke:#1565c0
```

```text
encrypt: b -> pair1.forward -> pair2.forward -> pair3.forward -> c
decrypt: c -> pair3.inverse -> pair2.inverse -> pair1.inverse -> b
```

## 5. Variable-length messages

`encryptMessageIO` pads arbitrary bytes with PKCS#7 to a multiple of
64 bytes, then runs the chain independently on each 512-bit block.
The padding byte is the number of bytes added (1–64); empty and aligned
messages receive a full padding block.

```mermaid
flowchart LR
    M["Message: any byte length"] --> PAD["PKCS#7 padding to 64-byte boundary"]
    PAD --> SPLIT["Split into 512-bit blocks"]
    SPLIT --> E["feistelChainIO on each block"]
    E --> C["Concatenate ciphertext blocks"]
    C --> D["Split; feistelDechainIO on each block"]
    D --> CHECK["Check all padding bytes; remove padding"]
    CHECK --> OUT["Original message bytes"]
```

`decryptMessageIO` rejects empty/non-aligned ciphertext and malformed
padding. Neither direction silently truncates oversized inputs.
**This deterministic, independent-block framing is unauthenticated and
reveals repeated plaintext blocks.** It is not a secure message-encryption
mode; successful unpadding is not authentication. Message framing is
runtime-tested, not covered by the abstract Feistel proofs.

## Where each piece lives

| Concept in the diagrams | Concrete (`Blackworm/Basic.lean`) | Abstract proof (`Blackworm/FeistelTheory.lean`) |
| --- | --- | --- |
| 512-bit block, 256-bit halves | `BLOCK_BITS`/`BLOCK_SIZE`, `HALF_BLOCK_BITS`/`HALF_BLOCK_SIZE`, `Block.ofBits512`, `Block.toBytes`, `emptyHalf` | `HalfBlock := Bits 256`, `Block512 := Block HalfBlock` (§`Concrete`; `Block α` itself is size-agnostic) |
| Fitting a round function's output to one 256-bit half | `fitTo` | — (abstract `F` already maps `α → α`) |
| Block `(L, R)` | `Block` (`ByteArray` halves) | `Block α` |
| One round | `feistelRound`, `feistelRoundIO` | `round`, `round_left_inv`, `round_right_inv` |
| Round inverse | `feistelRoundInvIO` | `roundInv` |
| Multiple function/key pairs in one round | mix primitives inside one `ByteArray → IO ByteArray` closure | `CipherSet`, `combineCipherSet`, `cipherSetF` (§`MultiRound`) |
| Forward/inverse block pair | `CipherPair`, `CipherPair.ofFeistel` | `round`/`roundInv` for a `RoundSpec` (Feistel case only) |
| Chain of heterogeneous rounds/blocks | `feistelChainIO` calls each pair's `forward` | `RoundSpec`, `encryptChain` (§`Chain`, Feistel case) |
| Reverse-order (transpose) decryption | `feistelDechainIO` calls `inverse` over `specs.reverse` | `decryptChain`, `decryptChain_eq_foldl_reverse` |
| Abstract Feistel end-to-end correctness | — (not a proof of custom IO pairs or FFI) | `decryptChain_encryptChain`, `feistelDecrypt_feistelEncrypt` |
| Variable-length framing | `encryptMessageIO`, `decryptMessageIO` | — (runtime tests only) |
