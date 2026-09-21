# blackworm

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
