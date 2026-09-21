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
  `xorByteArrays`.
* `KeyDerivation` — a model of round-key derivation from a master key and
  a PRF-like mixing function (as used by `feistelWithHKDF` in
  `Blackworm.Basic`), with theorems about the length and distinctness of
  the generated schedule.
* `FullCipher` — glues key derivation and the Feistel network together and
  proves the end-to-end correctness theorem `feistelDecrypt_feistelEncrypt`.
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

end Blackworm.Feistel
