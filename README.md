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

## GitHub configuration

To set up your new GitHub repository, follow these steps:

* Under your repository name, click **Settings**.
* In the **Actions** section of the sidebar, click "General".
* Check the box **Allow GitHub Actions to create and approve pull requests**.
* Click the **Pages** section of the settings sidebar.
* In the **Source** dropdown menu, select "GitHub Actions".

After following the steps above, you can remove this section from the README file.
