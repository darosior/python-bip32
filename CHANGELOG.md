## Next

- Added test vector #4 for private keys with leading zeros (see https://github.com/bitcoin/bips/pull/1030)

## 0.1

- Started to use a changelog
- New `InvalidInputError` raised instead of bluntly asserting on insane inputs
- New `PrivateDerivationError` raised when trying to access private keys without private
    keys being set (eg for hardened derivation).
- Bugfix: we can now parse "master paths": ie do `pubkey_from_path("m")` or
    `pubkey_from_path([])`
