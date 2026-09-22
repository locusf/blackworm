import Mathlib

/-!
# Formal Feistel Network Theory

This module is a self-contained Lean 4 scaffold that formally verifies the
core mathematical properties of the dynamic Feistel-network block cipher
generator implemented in `Blackworm.Basic` (`round`/`feistelRound`,
`feistelCipher`, `feistelWithHash256`, `feistelWithAES256ECB`, ... ), and
adds a verified model of round-key derivation ("key schedule"), which the
original implementation was missing.

It is intentionally independent of `ByteArray`, `IO`, and the OpenSSL FFI
layer so that it can be type-checked with no native dependencies: the
`ByteArray` XOR used by `xorByteArrays` in `Blackworm.Basic` is a concrete
instance of the abstract `Cancellative` operator studied below (and the
`Bits n` model in the `Concrete` section instantiates it explicitly).

## Contents

* `Abstract` — the Feistel round/network construction and its two central
  correctness theorems, proved for *any* round function `F` (invertible or
  not) and *any* number of keyed rounds:
  - `round_left_inv` / `round_right_inv` : a single round is invertible.
  - `decryptRounds_encryptRounds` / `encryptRounds_decryptRounds` : an
    arbitrarily deep stack of rounds is invertible.
  - `encryptRounds_injective` : encryption never collides two distinct
    blocks (no information loss from "dynamically" adding more rounds).
* `Concrete` — a genuine instance of the abstract theory over `n`-bit
  half-blocks (`Bits n := Fin n → Bool`) with position-wise XOR, mirroring
  `xorByteArrays`, specialised to the implementation's 256-bit halves /
  512-bit blocks (`HalfBlock`, `Block512`, `decryptRounds_encryptRounds_512`).
* `KeyDerivation` — a model of round-key derivation from a master key and
  a PRF-like mixing function (as used by `feistelWithHKDF` in
  `Blackworm.Basic`), with theorems about the length and distinctness of
  the generated schedule.
* `FullCipher` — glues key derivation and the Feistel network together and
  proves the end-to-end correctness theorem `feistelDecrypt_feistelEncrypt`.
* `MultiRound` — a `CipherSet`: multiple `(round function, round key)` pairs
  combined (xor-folded) within a *single* round, instead of one primitive
  per round.
* `Chain` — generalizes `encryptRounds`/`decryptRounds` (one fixed `F`
  shared by every round) to `encryptChain`/`decryptChain` over a
  heterogeneous `List (RoundSpec α)`, so that a dynamically generated
  cipher chain can use a **different cipher set per round/block**. Proves
  the same correctness/injectivity results, plus the explicit **transpose**
  theorem `decryptChain_eq_foldl_reverse`: inverting such a chain requires
  processing the per-block cipher sets in *reverse* order.
* `DynamicGeneration` — the reformulated top-level theorem: the per-round
  `(cipher, key)` pairs are not fixed in advance but **dynamically generated
  from agreed-upon key material** — a `pickF` function (modelling
  pseudorandom selection of a *different cipher or hash function* from a
  pool for each round) and a `prf` key-derivation function both consume the
  shared master key material and the round index. `dynamicDecrypt_dynamicEncrypt`
  proves that two parties agreeing only on the key material (and the
  deterministic generation procedure) obtain mutually inverse
  encrypt/decrypt transforms, for *any* selection and derivation functions.
-/

namespace Blackworm.Feistel

universe u v

/-! ## Abstract Feistel network -/
section Abstract

variable {α : Type u}

/-- A combining operator `xor : α → α → α` is *cancellative* when XOR-ing
the same value in twice undoes it: `(a xor b) xor b = a`. This is the
*only* algebraic property a Feistel network needs from its combinator; it
holds for ordinary bitwise XOR of fixed-width bit strings/bytes, which is
exactly what `xorByteArrays` in `Blackworm.Basic` implements. -/
def Cancellative (xor : α → α → α) : Prop :=
  ∀ a b, xor (xor a b) b = a

/-- A Feistel block: a left half and a right half, both of type `α`. This
mirrors the `Block` structure in `Blackworm.Basic`. -/
structure Block (α : Type u) where
  left : α
  right : α
  deriving Repr, DecidableEq

variable (xor : α → α → α)

/-- One Feistel round with round function `F` and round key `k`: swap the
halves, and mix the untouched half into the other half via `F k`. This is
the formal counterpart of `feistelRound`/`feistelRoundIO` in
`Blackworm.Basic`. -/
def round (F : α → α → α) (k : α) (b : Block α) : Block α :=
  { left := b.right, right := xor b.left (F k b.right) }

/-- The decryption round corresponding to `round`. -/
def roundInv (F : α → α → α) (k : α) (b : Block α) : Block α :=
  { left := xor b.right (F k b.left), right := b.left }

/-- **Single-round correctness**: decrypting immediately after encrypting
recovers the original block, *for every* round function `F` — including
round functions that are not themselves invertible, such as a hash
function (`feistelWithHash256`) or AES-256 in ECB mode
(`feistelWithAES256ECB`). This is the classical property that makes
Feistel networks useful: `F` can be arbitrarily complex. -/
theorem round_left_inv (hcancel : Cancellative xor) (F : α → α → α) (k : α) (b : Block α) :
    roundInv xor F k (round xor F k b) = b := by
  show
    ({ left := xor (xor b.left (F k b.right)) (F k b.right), right := b.right } : Block α) = b
  rw [hcancel]

/-- The reverse direction: encrypting right after decrypting also recovers
the original block. -/
theorem round_right_inv (hcancel : Cancellative xor) (F : α → α → α) (k : α) (b : Block α) :
    round xor F k (roundInv xor F k b) = b := by
  show
    ({ left := b.left, right := xor (xor b.right (F k b.left)) (F k b.left) } : Block α) = b
  rw [hcancel]

/-- Run a block through a stack of Feistel rounds, one round key per round,
applied in order. This models `Blackworm.Basic.feistelCipher` generalized
to an arbitrary, dynamically-sized list of round keys. -/
def encryptRounds (F : α → α → α) : List α → Block α → Block α
  | [], b => b
  | k :: ks, b => encryptRounds F ks (round xor F k b)

/-- Undo a stack of Feistel rounds, one round key per round, applied in the
same order used by `encryptRounds` (each round is undone as soon as it is
peeled off the front of the key list). -/
def decryptRounds (F : α → α → α) : List α → Block α → Block α
  | [], b => b
  | k :: ks, b => roundInv xor F k (decryptRounds F ks b)

/-- **Network correctness (decrypt after encrypt)**: for any round function
`F` and any list of round keys, decrypting immediately after encrypting
recovers the original block, no matter how many rounds were used. -/
theorem decryptRounds_encryptRounds (hcancel : Cancellative xor) (F : α → α → α) :
    ∀ (keys : List α) (b : Block α),
      decryptRounds xor F keys (encryptRounds xor F keys b) = b := by
  intro keys
  induction keys with
  | nil => intro b; rfl
  | cons k ks ih =>
    intro b
    show
      roundInv xor F k (decryptRounds xor F ks (encryptRounds xor F ks (round xor F k b))) = b
    rw [ih (round xor F k b)]
    exact round_left_inv xor hcancel F k b

/-- **Network correctness (encrypt after decrypt)**: the reverse direction
of `decryptRounds_encryptRounds`. -/
theorem encryptRounds_decryptRounds (hcancel : Cancellative xor) (F : α → α → α) :
    ∀ (keys : List α) (b : Block α),
      encryptRounds xor F keys (decryptRounds xor F keys b) = b := by
  intro keys
  induction keys with
  | nil => intro b; rfl
  | cons k ks ih =>
    intro b
    show
      encryptRounds xor F ks (round xor F k (roundInv xor F k (decryptRounds xor F ks b))) = b
    rw [round_right_inv xor hcancel F k (decryptRounds xor F ks b)]
    exact ih b

/-- **Main theorem**: an arbitrarily deep Feistel network — any number of
keyed rounds, any round function — never loses information: encryption is
injective, so every ciphertext block corresponds to a unique plaintext
block. This is what justifies calling `Blackworm.Basic.feistelCipher` a
*cipher* (as opposed to a lossy hash) no matter how the round count or
round function are "dynamically" generated. -/
theorem encryptRounds_injective (hcancel : Cancellative xor) (F : α → α → α) (keys : List α) :
    ∀ b₁ b₂, encryptRounds xor F keys b₁ = encryptRounds xor F keys b₂ → b₁ = b₂ := by
  intro b₁ b₂ h
  have h2 := congrArg (decryptRounds xor F keys) h
  rwa [decryptRounds_encryptRounds xor hcancel F keys,
       decryptRounds_encryptRounds xor hcancel F keys] at h2

/-- Packaging the two inversion theorems together: `decryptRounds` is a
genuine two-sided inverse of `encryptRounds`, i.e. `encryptRounds xor F
keys` is a bijection on `Block α` with explicit inverse `decryptRounds xor
F keys`. -/
theorem encryptRounds_has_two_sided_inverse (hcancel : Cancellative xor) (F : α → α → α) (keys : List α) :
    (∀ b, decryptRounds xor F keys (encryptRounds xor F keys b) = b) ∧
      ∀ b, encryptRounds xor F keys (decryptRounds xor F keys b) = b :=
  ⟨decryptRounds_encryptRounds xor hcancel F keys, encryptRounds_decryptRounds xor hcancel F keys⟩

end Abstract

/-! ## A concrete instance: fixed-width bit half-blocks -/
section Concrete

/-- Concrete `n`-bit half-blocks: a half-block assigns a bit to each of `n`
positions. This mirrors how `xorByteArrays` in `Blackworm.Basic` combines
fixed-width byte arrays position by position. -/
abbrev Bits (n : Nat) := Fin n → Bool

/-- Position-wise XOR of two `n`-bit half-blocks — the concrete analogue of
`xorByteArrays`. -/
def bitsXor {n : Nat} (a b : Bits n) : Bits n :=
  fun i => Bool.xor (a i) (b i)

/-- Position-wise XOR is cancellative, i.e. it satisfies exactly the
algebraic property the abstract theory above requires. Every theorem in
`Abstract` therefore applies to `n`-bit Feistel blocks built from
`bitsXor`. -/
theorem bitsXor_cancellative (n : Nat) : Cancellative (α := Bits n) bitsXor := by
  intro a b
  funext i
  show Bool.xor (Bool.xor (a i) (b i)) (b i) = a i
  cases a i <;> cases b i <;> rfl

/-- The half-block width used by the concrete implementation: 256 bits
(`HALF_BLOCK_BITS` in `Blackworm.Basic`, carried there as a 32-byte
`ByteArray`). -/
def halfBlockBits : Nat := 256

/-- A concrete 256-bit half-block, the formal counterpart of one 32-byte
half of the `Block` structure in `Blackworm.Basic`. -/
abbrev HalfBlock := Bits halfBlockBits

/-- A concrete 512-bit block: two 256-bit halves, mirroring the
`BLOCK_BITS = 2 * HALF_BLOCK_BITS` layout of `Blackworm.Basic`. -/
abbrev Block512 := Block HalfBlock

/-- **512-bit block correctness**: for any round function on 256-bit
halves and any round-key schedule, decrypting a 512-bit block after
encrypting it recovers the original — the abstract network theorems
specialised to the exact block/half sizes the implementation uses. -/
theorem decryptRounds_encryptRounds_512 (F : HalfBlock → HalfBlock → HalfBlock)
    (keys : List HalfBlock) (b : Block512) :
    decryptRounds bitsXor F keys (encryptRounds bitsXor F keys b) = b :=
  decryptRounds_encryptRounds bitsXor (bitsXor_cancellative halfBlockBits) F keys b

end Concrete

/-! ## Key derivation (round-key schedule) -/
section KeyDerivation

variable {α : Type v}

/-- A key schedule turns a master key and a round count into the list of
per-round subkeys consumed by `encryptRounds`/`decryptRounds`. `prf`
models an idealised pseudorandom mixing function (such as the HKDF-based
`feistelWithHKDF` in `Blackworm.Basic`) that combines the master key with
a round index to produce a fresh subkey; `deriveKeys prf master rounds`
produces `rounds` such subkeys, one per round. This is the key-derivation
scaffolding the original implementation lacked. -/
def deriveKeys (prf : α → Nat → α) (master : α) : Nat → List α
  | 0 => []
  | r + 1 => prf master r :: deriveKeys prf master r

/-- Key derivation is total and produces exactly as many round keys as
rounds requested. -/
theorem deriveKeys_length (prf : α → Nat → α) (master : α) (rounds : Nat) :
    (deriveKeys prf master rounds).length = rounds := by
  induction rounds with
  | zero => rfl
  | succ r ih => simp [deriveKeys, ih]

/-- Characterisation of membership in a derived key schedule: a value
occurs in the schedule of length `rounds` exactly when it is the subkey
produced by some round index below `rounds`. -/
theorem mem_deriveKeys (prf : α → Nat → α) (master : α) (rounds : Nat) (x : α) :
    x ∈ deriveKeys prf master rounds ↔ ∃ i, i < rounds ∧ prf master i = x := by
  induction rounds with
  | zero => simp [deriveKeys]
  | succ r ih =>
    simp only [deriveKeys, List.mem_cons, ih]
    constructor
    · rintro (rfl | ⟨i, hi, rfl⟩)
      · exact ⟨r, by omega, rfl⟩
      · exact ⟨i, by omega, rfl⟩
    · rintro ⟨i, hi, rfl⟩
      rcases Nat.lt_or_ge i r with h | h
      · exact Or.inr ⟨i, h, rfl⟩
      · have hir : i = r := by omega
        exact Or.inl (by rw [hir])

/-- If the mixing function is injective in the round index for a fixed
master key (an idealised PRF property — distinct round indices should
yield distinct subkeys), then the derived key schedule never repeats a
subkey across rounds. This rules out the trivial "same round key every
round" degeneration of a dynamically generated cipher. -/
theorem deriveKeys_nodup (prf : α → Nat → α) (master : α)
    (hprf : ∀ i j, i ≠ j → prf master i ≠ prf master j) (rounds : Nat) :
    (deriveKeys prf master rounds).Nodup := by
  induction rounds with
  | zero => simp [deriveKeys]
  | succ r ih =>
    simp only [deriveKeys, List.nodup_cons]
    refine ⟨?_, ih⟩
    intro hmem
    rw [mem_deriveKeys] at hmem
    obtain ⟨i, hi, hieq⟩ := hmem
    exact hprf i r (by omega) hieq

end KeyDerivation

/-! ## Full cipher: key derivation + Feistel network -/
section FullCipher

variable {α : Type u} (xor : α → α → α)

/-- The full dynamic block cipher: derive `rounds` subkeys from a master
key via `prf`, then run the Feistel network keyed by that schedule. This
is the verified counterpart of `Blackworm.Basic.feistelCipher`, but with
an explicit, provably well-behaved key schedule instead of a fixed or
placeholder key. -/
def feistelEncrypt (F : α → α → α) (prf : α → Nat → α) (master : α) (rounds : Nat)
    (b : Block α) : Block α :=
  encryptRounds xor F (deriveKeys prf master rounds) b

/-- Decryption counterpart of `feistelEncrypt`. -/
def feistelDecrypt (F : α → α → α) (prf : α → Nat → α) (master : α) (rounds : Nat)
    (b : Block α) : Block α :=
  decryptRounds xor F (deriveKeys prf master rounds) b

/-- **Top-level correctness theorem**: for any round function `F`, any
key-derivation function `prf`, any master key and any round count,
decrypting with the same master key and round count recovers the original
plaintext block. This is the end-to-end guarantee that a caller of the
dynamically generated cipher relies on. -/
theorem feistelDecrypt_feistelEncrypt (hcancel : Cancellative xor)
    (F : α → α → α) (prf : α → Nat → α) (master : α)
    (rounds : Nat) (b : Block α) :
    feistelDecrypt xor F prf master rounds (feistelEncrypt xor F prf master rounds b) = b :=
  decryptRounds_encryptRounds xor hcancel F (deriveKeys prf master rounds) b

/-- Corollary: encryption of the full dynamically-keyed cipher is
injective, for any round function and any key-derivation function. -/
theorem feistelEncrypt_injective (hcancel : Cancellative xor)
    (F : α → α → α) (prf : α → Nat → α) (master : α) (rounds : Nat) :
    ∀ b₁ b₂,
      feistelEncrypt xor F prf master rounds b₁ = feistelEncrypt xor F prf master rounds b₂ →
        b₁ = b₂ :=
  encryptRounds_injective xor hcancel F (deriveKeys prf master rounds)

end FullCipher

/-! ## Multiple round-function pairs combined within a single round -/
section MultiRound

variable {α : Type u} (xor : α → α → α)

/-- A "cipher set": a list of `(round function, round key)` pairs that are
all applied to the *same* half within a single round and combined via
`xor`, instead of a single `(F, k)` pair per round. This models drawing on
several primitives from the pool simultaneously in one round (e.g. a hash
function and a block cipher both mixed into the same round), rather than
one primitive per round. -/
abbrev CipherSet (α : Type u) := List ((α → α → α) × α)

/-- Combine the outputs of every `(F, k)` pair in a cipher set, applied to
the same input `x`, via `xor`-folding. An empty cipher set is the identity
(a degenerate, zero-primitive round). -/
def combineCipherSet : CipherSet α → α → α
  | [], x => x
  | (F, k) :: rest, x => xor (F k x) (combineCipherSet rest x)

/-- Every cipher set collapses to a single, ordinary round function taking
an (unused) placeholder key, so a round built from a cipher set is just an
instance of `round` — and therefore inherits `round_left_inv`,
`round_right_inv`, etc. for free. -/
def cipherSetF (cs : CipherSet α) : α → α → α :=
  fun _ x => combineCipherSet xor cs x

end MultiRound

/-! ## A heterogeneous cipher chain: distinct round functions per round/block -/
section Chain

variable {α : Type u} (xor : α → α → α)

/-- A round specification: a round function together with its round key.
This generalizes `encryptRounds`/`decryptRounds`, which share one fixed `F`
across all rounds, so that **each round/block in the dynamically generated
cipher chain can use a completely different round function** (i.e. its own
cipher set via `cipherSetF`), not merely a different key for a shared `F`. -/
structure RoundSpec (α : Type u) where
  F : α → α → α
  k : α

/-- Package a whole cipher set (multiple round-function pairs combined
within one round, via `combineCipherSet`) as a single `RoundSpec`, so that
a block/round in a chain can draw on several primitives at once. The
`sentinelKey` slot is unused by `cipherSetF` (the real per-pair keys already
live inside `cs`); it only satisfies `RoundSpec`'s bookkeeping key field. -/
def RoundSpec.ofCipherSet (cs : CipherSet α) (sentinelKey : α) : RoundSpec α :=
  { F := cipherSetF xor cs, k := sentinelKey }

/-- Run a block through a *heterogeneous* chain of rounds/blocks, where
each entry carries its own round function `spec.F` (possibly built from a
whole cipher set via `cipherSetF`) and round key `spec.k`. This is the
generalisation of `Blackworm.Basic.feistelCipher`/`feistelEncrypt` to a
dynamically generated cipher chain over multiple blocks, each block using
a different cipher set. -/
def encryptChain : List (RoundSpec α) → Block α → Block α
  | [], b => b
  | spec :: rest, b => encryptChain rest (round xor spec.F spec.k b)

/-- Undo a heterogeneous chain of rounds/blocks. Note the recursion peels
`spec` off the *front* of the list but applies its inverse only *after*
recursing on `rest` — i.e. the round applied *first* during encryption is
undone *last* during decryption. This is precisely the **transpose**
required to invert a dynamically generated cipher chain: the sequence of
cipher sets must be undone in the reverse of the order they were applied
(made fully explicit by `decryptChain_eq_foldl_reverse` below). -/
def decryptChain : List (RoundSpec α) → Block α → Block α
  | [], b => b
  | spec :: rest, b => roundInv xor spec.F spec.k (decryptChain rest b)

/-- **Chain correctness (decrypt after encrypt)**: for any heterogeneous
list of per-round/per-block cipher sets, decrypting immediately after
encrypting recovers the original block. -/
theorem decryptChain_encryptChain (hcancel : Cancellative xor) :
    ∀ (specs : List (RoundSpec α)) (b : Block α),
      decryptChain xor specs (encryptChain xor specs b) = b := by
  intro specs
  induction specs with
  | nil => intro b; rfl
  | cons spec rest ih =>
    intro b
    show
      roundInv xor spec.F spec.k
        (decryptChain xor rest (encryptChain xor rest (round xor spec.F spec.k b))) = b
    rw [ih (round xor spec.F spec.k b)]
    exact round_left_inv xor hcancel spec.F spec.k b

/-- **Chain correctness (encrypt after decrypt)**: the reverse direction of
`decryptChain_encryptChain`. -/
theorem encryptChain_decryptChain (hcancel : Cancellative xor) :
    ∀ (specs : List (RoundSpec α)) (b : Block α),
      encryptChain xor specs (decryptChain xor specs b) = b := by
  intro specs
  induction specs with
  | nil => intro b; rfl
  | cons spec rest ih =>
    intro b
    show
      encryptChain xor rest
        (round xor spec.F spec.k (roundInv xor spec.F spec.k (decryptChain xor rest b))) = b
    rw [round_right_inv xor hcancel spec.F spec.k (decryptChain xor rest b)]
    exact ih b

/-- **Injectivity**: a heterogeneous cipher chain over any list of cipher
sets never loses information, no matter how many distinct cipher sets are
chained together or how they were dynamically chosen. -/
theorem encryptChain_injective (hcancel : Cancellative xor) (specs : List (RoundSpec α)) :
    ∀ b₁ b₂, encryptChain xor specs b₁ = encryptChain xor specs b₂ → b₁ = b₂ := by
  intro b₁ b₂ h
  have h2 := congrArg (decryptChain xor specs) h
  rwa [decryptChain_encryptChain xor hcancel specs, decryptChain_encryptChain xor hcancel specs] at h2

/-- `encryptRounds`/`decryptRounds` (a single fixed round function `F`, one
key per round) are the special case of `encryptChain`/`decryptChain` where
every round shares the same `F`. This confirms the chain construction is a
strict generalisation of the original scaffold, not a different one. -/
theorem encryptRounds_eq_encryptChain (F : α → α → α) (keys : List α) (b : Block α) :
    encryptRounds xor F keys b = encryptChain xor (keys.map (fun k => (⟨F, k⟩ : RoundSpec α))) b := by
  induction keys generalizing b with
  | nil => rfl
  | cons k ks ih => simp [encryptRounds, encryptChain, List.map_cons, ih]

theorem decryptRounds_eq_decryptChain (F : α → α → α) (keys : List α) (b : Block α) :
    decryptRounds xor F keys b = decryptChain xor (keys.map (fun k => (⟨F, k⟩ : RoundSpec α))) b := by
  induction keys generalizing b with
  | nil => rfl
  | cons k ks ih => simp [decryptRounds, decryptChain, List.map_cons, ih]

/-- **The transpose theorem, made explicit**: `decryptChain` (defined by
structural recursion that peels specs off the *front*) is definitionally
equal to an *iterative* left-fold that walks the *reversed* list of cipher
sets, applying each `roundInv` in turn. This is the formal statement of
"a transpose of the function set is needed" to invert a dynamically
generated cipher chain over multiple blocks: whatever order the per-block
cipher sets were dynamically generated/applied in, decryption must consume
that same list *reversed*. -/
theorem decryptChain_eq_foldl_reverse (specs : List (RoundSpec α)) (b : Block α) :
    decryptChain xor specs b =
      specs.reverse.foldl (fun acc spec => roundInv xor spec.F spec.k acc) b := by
  induction specs generalizing b with
  | nil => rfl
  | cons spec rest ih =>
    show roundInv xor spec.F spec.k (decryptChain xor rest b) =
      (spec :: rest).reverse.foldl (fun acc spec => roundInv xor spec.F spec.k acc) b
    rw [List.reverse_cons, List.foldl_append, List.foldl_cons, List.foldl_nil, ← ih b]

end Chain

/-! ## Dynamically generated cipher pairs from agreed key material -/
section DynamicGeneration

variable {α : Type u} (xor : α → α → α)

/-- Generate the per-round `(cipher, key)` pairs of a dynamic block cipher
from agreed-upon key material. For each round index `i`:

* `pickF material i` **selects the round function itself** — modelling a
  pseudorandom draw of a *different cipher or hash function* (e.g. SHA-256,
  AES-256-ECB, an HKDF-based mixer, or a whole `CipherSet` collapsed via
  `cipherSetF`) from the primitive pool, keyed by the shared key material
  bytes; and
* `prf material i` derives that round's subkey from the same material
  (exactly as in `deriveKeys`).

Because both selections are deterministic functions of `(material, i)`, two
parties that agree on the key material bytes generate *identical* pairings
without ever transmitting the chosen ciphers. -/
def deriveSpecs (pickF : α → Nat → (α → α → α)) (prf : α → Nat → α) (material : α) :
    Nat → List (RoundSpec α)
  | 0 => []
  | r + 1 => ⟨pickF material r, prf material r⟩ :: deriveSpecs pickF prf material r

/-- Spec generation is total and produces exactly one `(cipher, key)` pair
per round. -/
theorem deriveSpecs_length (pickF : α → Nat → (α → α → α)) (prf : α → Nat → α)
    (material : α) (rounds : Nat) :
    (deriveSpecs pickF prf material rounds).length = rounds := by
  induction rounds with
  | zero => rfl
  | succ r ih => simp [deriveSpecs, ih]

/-- The dynamically generated block cipher: generate `rounds` cipher pairs
from the agreed key material via `pickF`/`prf`, then run the heterogeneous
Feistel chain they describe. Unlike `feistelEncrypt`, where a single fixed
`F` is keyed differently per round, here **the block cipher pairs themselves
are generated from the key material for each round**. -/
def dynamicEncrypt (pickF : α → Nat → (α → α → α)) (prf : α → Nat → α)
    (material : α) (rounds : Nat) (b : Block α) : Block α :=
  encryptChain xor (deriveSpecs pickF prf material rounds) b

/-- Decryption counterpart of `dynamicEncrypt`: regenerate the *same* cipher
pairs from the *same* agreed key material and undo the chain (in reverse
order, per `decryptChain`/`decryptChain_eq_foldl_reverse`). -/
def dynamicDecrypt (pickF : α → Nat → (α → α → α)) (prf : α → Nat → α)
    (material : α) (rounds : Nat) (b : Block α) : Block α :=
  decryptChain xor (deriveSpecs pickF prf material rounds) b

/-- **Reformulated top-level correctness theorem**: for *any* function
`pickF` selecting a (possibly different) cipher or hash function per round,
*any* key-derivation function `prf`, any agreed key material and any round
count, decrypting with the same key material recovers the original
plaintext block. The two parties need only agree on the key material bytes
(and the deterministic generation procedure); the randomly generated cipher
pairing per round is reconstructed identically on both sides. -/
theorem dynamicDecrypt_dynamicEncrypt (hcancel : Cancellative xor)
    (pickF : α → Nat → (α → α → α)) (prf : α → Nat → α)
    (material : α) (rounds : Nat) (b : Block α) :
    dynamicDecrypt xor pickF prf material rounds
        (dynamicEncrypt xor pickF prf material rounds b) = b :=
  decryptChain_encryptChain xor hcancel (deriveSpecs pickF prf material rounds) b

/-- The reverse direction: encrypting after decrypting with the same agreed
key material also recovers the original block. -/
theorem dynamicEncrypt_dynamicDecrypt (hcancel : Cancellative xor)
    (pickF : α → Nat → (α → α → α)) (prf : α → Nat → α)
    (material : α) (rounds : Nat) (b : Block α) :
    dynamicEncrypt xor pickF prf material rounds
        (dynamicDecrypt xor pickF prf material rounds b) = b :=
  encryptChain_decryptChain xor hcancel (deriveSpecs pickF prf material rounds) b

/-- Corollary: the dynamically generated cipher is injective — no matter
which ciphers or hash functions the key material happens to select for each
round, encryption never collides two distinct blocks. -/
theorem dynamicEncrypt_injective (hcancel : Cancellative xor)
    (pickF : α → Nat → (α → α → α)) (prf : α → Nat → α)
    (material : α) (rounds : Nat) :
    ∀ b₁ b₂,
      dynamicEncrypt xor pickF prf material rounds b₁ =
          dynamicEncrypt xor pickF prf material rounds b₂ →
        b₁ = b₂ :=
  encryptChain_injective xor hcancel (deriveSpecs pickF prf material rounds)

/-- The previous fixed-`F` cipher (`feistelEncrypt`) is the degenerate
special case of the dynamically generated cipher in which `pickF` ignores
the key material and always selects the same round function. This confirms
the reformulation strictly generalises the original theorem. -/
theorem feistelEncrypt_eq_dynamicEncrypt (F : α → α → α) (prf : α → Nat → α)
    (master : α) (rounds : Nat) (b : Block α) :
    feistelEncrypt xor F prf master rounds b =
      dynamicEncrypt xor (fun _ _ => F) prf master rounds b := by
  unfold feistelEncrypt dynamicEncrypt
  rw [encryptRounds_eq_encryptChain]
  congr 1
  induction rounds with
  | zero => rfl
  | succ r ih => simp [deriveKeys, deriveSpecs, List.map_cons, ih]

end DynamicGeneration

end Blackworm.Feistel
