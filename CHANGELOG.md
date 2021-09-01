# 2.0

This is a breaking release.

- Added test vector #5 for more sanity checks when deserializing an xpub or an
  xpriv (see https://github.com/bitcoin/bips/pull/921).
- Renamed `get_master_xpub` and `get_master_xpriv` to `get_xpub` and `get_xpriv`.
- We now refuse to create a `BIP32` object with:
  - An unknown network
  - A depth of 0 (master) and a non-0 index or fingerprint

## 1.0

- Added test vector #4 for private keys with leading zeros (see https://github.com/bitcoin/bips/pull/1030)
- (**Breaking**) Bumped Coincurve dependency to `0.15`
- Re-arranged the 2 dependencies to use "compatible release" notation

## 0.1

- Started to use a changelog
- New `InvalidInputError` raised instead of bluntly asserting on insane inputs
- New `PrivateDerivationError` raised when trying to access private keys without private
    keys being set (eg for hardened derivation).
- Bugfix: we can now parse "master paths": ie do `pubkey_from_path("m")` or
    `pubkey_from_path([])`
