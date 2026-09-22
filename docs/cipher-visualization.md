# Visualization: the dynamically generated Feistel cipher chain

This document visualizes how the generated block cipher works **as currently
implemented**, layer by layer:

0. the **512-byte block layout**: each block is 512 bytes, split into two
   256-byte halves, and every round-function pair encrypts exactly one
   256-byte half per round (`BLOCK_SIZE`/`HALF_BLOCK_SIZE`/`fitTo`/
   `Block.ofBytes512` in `Blackworm/Basic.lean`),
1. a single Feistel round (`feistelRound`/`feistelRoundIO` in
   `Blackworm/Basic.lean`, `round` in `Blackworm/FeistelTheory.lean`),
2. **multiple function pairs combined inside one round** — a *cipher set*
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
> * In the *concrete* code (`Basic.lean`), each link of the chain is a single
>   `ByteArray → IO ByteArray` function (e.g. `feistelWithHash256`,
>   `feistelWithAES256ECB key`, `feistelWithHKDF salt info len`). The keys are
>   captured inside these closures, so a "function pair" `(F, k)` appears as
>   one partially-applied function.
> * In the *abstract* proof layer (`FeistelTheory.lean`), the pairs are
>   explicit: a `CipherSet` is a `List ((α → α → α) × α)` of
>   `(round function, round key)` pairs, several of which can be XOR-folded
>   into **one** round via `combineCipherSet`, and each chain link is a
>   `RoundSpec` pair `⟨F, k⟩`.
>
> So "multiple function pairs per round" is a proved capability of the
> abstract model (`MultiRound` section) which the concrete chain can realize
> by composing/mixing primitives inside one `ByteArray → IO ByteArray`
> closure; the concrete `feistelChainIO` itself applies **one function per
> round/block link**.

## 0. The 512-byte block: two 256-byte halves

A block is **512 bytes** (`BLOCK_SIZE`). `Block.ofBytes512` splits it into a
256-byte left half and a 256-byte right half (`HALF_BLOCK_SIZE`);
`Block.toBytes` reassembles it. Each round-function pair encrypts exactly one
256-byte half per round: whatever the primitive's natural output size (a
32-byte SHA-256 digest, a padded AES ciphertext, ...), `fitTo` cycles or
truncates it to 256 bytes before it is XORed into the other half, so the
halves never grow or shrink.

```mermaid
flowchart TB
    B["512-byte block (BLOCK_SIZE)"]
    B -->|"Block.ofBytes512"| L["L — 256 bytes\n(HALF_BLOCK_SIZE)"]
    B -->|"Block.ofBytes512"| R["R — 256 bytes\n(HALF_BLOCK_SIZE)"]
    R --> F["round-function pair F(k, ·)\n(natural output size varies)"]
    F -->|"fitTo 256"| OUT["256-byte keystream\n— encrypts one 256-byte half"]
    style B fill:#e3f2fd,stroke:#1565c0
    style OUT fill:#e8f5e9,stroke:#2e7d32
```

## 1. A single Feistel round

`feistelRound b f = { left := b.right, right := b.left ⊕ fitTo 256 (f b.right) }`
(`⊕` is `xorByteArrays`; abstractly, any cancellative `xor`). Both halves are
256 bytes, so each round-function pair encrypts a 256-byte block of the state.

```mermaid
flowchart LR
    subgraph input["512-byte Block (input)"]
        L["L (256 B)"]
        R["R (256 B)"]
    end
    subgraph output["512-byte Block (output)"]
        L2["L' = R (256 B)"]
        R2["R' = L ⊕ fitTo 256 (F(k, R)) (256 B)"]
    end
    R --> F["F(k, ·)  — round function pair (F, k)"]
    F --> FIT["fitTo 256"]
    FIT --> X(("⊕"))
    L --> X
    X --> R2
    R --> L2
```

Because only XOR and a swap touch the state, the round is invertible for
*any* round function `F` — even a non-invertible one like SHA-256
(`round_left_inv` / `round_right_inv`, mirrored concretely by
`feistelRoundInvIO`).

## 2. Multiple function pairs in one round: the cipher set

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

`feistelChainIO specs b` folds a 512-byte block through `specs` left-to-right,
one (possibly different) function per link, each link's pair encrypting a
256-byte half. Abstractly, `encryptChain` does the
same over `List (RoundSpec α)`, where each `RoundSpec ⟨Fᵢ, kᵢ⟩` may itself be
a whole cipher set packaged via `RoundSpec.ofCipherSet`.

```mermaid
flowchart LR
    P["Plaintext block\n(L₀, R₀)"] --> RD1
    subgraph RD1["Chain link 1 — RoundSpec ⟨F₁, k₁⟩"]
        S1["e.g. feistelWithHash256"]
    end
    RD1 --> B1["(L₁, R₁)"] --> RD2
    subgraph RD2["Chain link 2 — RoundSpec ⟨F₂, k₂⟩"]
        S2["e.g. feistelWithAES256ECB key"]
    end
    RD2 --> B2["(L₂, R₂)"] --> RD3
    subgraph RD3["Chain link 3 — cipher set as one RoundSpec"]
        S3["cipherSetF [(F₃,k₃), (F₄,k₄)]\n(multiple pairs XOR-folded)"]
    end
    RD3 --> C["Ciphertext block\n(L₃, R₃)"]
    style P fill:#e3f2fd,stroke:#1565c0
    style C fill:#fce4ec,stroke:#ad1457
```

Each link is a full Feistel round from §1; the links differ only in *which*
round function (or combined cipher set) they use — this is what makes the
chain "dynamically generated" (`deriveChain` in the theory file even derives
the whole spec list from a master key).

## 4. Decryption: the chain in transpose (reverse) order

The round applied **first** during encryption must be undone **last**.
`feistelDechainIO` therefore walks `specs.reverse`, applying
`feistelRoundInvIO` per link; `decryptChain_eq_foldl_reverse` proves this is
exactly `decryptChain`, and `decryptChain_encryptChain` proves the round trip
is the identity.

```mermaid
flowchart RL
    C["Ciphertext\n(L₃, R₃)"] --> I3["invert link 3\nroundInv ⟨F₃-set⟩"]
    I3 --> I2["invert link 2\nroundInv ⟨F₂, k₂⟩"]
    I2 --> I1["invert link 1\nroundInv ⟨F₁, k₁⟩"]
    I1 --> P["Plaintext\n(L₀, R₀)"]
    style C fill:#fce4ec,stroke:#ad1457
    style P fill:#e3f2fd,stroke:#1565c0
```

```text
encrypt:  b ─[F₁]→ ─[F₂]→ ─[F₃]→ c        (specs, left to right)
decrypt:  c ─[F₃⁻¹]→ ─[F₂⁻¹]→ ─[F₁⁻¹]→ b  (specs.reverse — the transpose)
```

## Where each piece lives

| Concept in the diagrams | Concrete (`Blackworm/Basic.lean`) | Abstract proof (`Blackworm/FeistelTheory.lean`) |
| --- | --- | --- |
| 512-byte block, 256-byte halves | `BLOCK_SIZE`, `HALF_BLOCK_SIZE`, `Block.ofBytes512`, `Block.toBytes`, `emptyHalf` | — (`Block α` is size-agnostic; `Concrete` instantiates `α := Bits n`) |
| Fitting a pair's output to one 256-byte half | `fitTo` | — (abstract `F` already maps `α → α`) |
| Block `(L, R)` | `Block` (`ByteArray` halves) | `Block α` |
| One round | `feistelRound`, `feistelRoundIO` | `round`, `round_left_inv`, `round_right_inv` |
| Round inverse | `feistelRoundInvIO` | `roundInv` |
| Multiple function pairs in one round | mix primitives inside one `ByteArray → IO ByteArray` closure | `CipherSet`, `combineCipherSet`, `cipherSetF` (§`MultiRound`) |
| Chain of heterogeneous rounds/blocks | `feistelChainIO` | `RoundSpec`, `encryptChain` (§`Chain`) |
| Reverse-order (transpose) decryption | `feistelDechainIO` (walks `specs.reverse`) | `decryptChain`, `decryptChain_eq_foldl_reverse` |
| End-to-end correctness | — | `decryptChain_encryptChain`, `feistelDecrypt_feistelEncrypt` |
