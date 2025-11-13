# 5.1

- Support Coincurve up to version 21. This version notably bumps libsecp to version 0.6.0 and gets rid of all runtime dependencies.

# 5.0

This is a breaking release.

- Migrate project to new `pyproject.toml` standard from `setup.py`/`requirements.txt`.
- As part of migration, top-level `__version__` variable was dropped from the package.
- Support for Python 3.8 was dropped due to a breaking change in the way setuptools interpret the license keys in `pyproject.toml`.

# 4.0

This is a breaking release.

- Drop support for Python 3.7.
- Support Coincurve up to version 20.
- Drop base58 dependency. Port base58 code directly in-tree as a `base58` module.
- Fix circular dependency in source installation.
- A new method `get_fingerprint()` was added.


# 3.4

- Support Coincurve up to version 18. This version includes support for BIP340 x-only keys and
  Schnorr signatures.


# 3.3

- Implement a pure Python fallback for RIPEMD160 in case `hashlib` does not provide it.
  NOTE: the Python implementation was copied from a test-only implementation and is not constant
  time. This shouldn't be an issue for the usage we make of it here.

# 3.1

- Actually support Coincurve up to version 17..

# 3.0

This is a breaking release.

- Python 3.10 support.
- Drop Python 3.6 support (EOL).
- Support Coincurve up to version 17.

# 2.1

- Two new methods were added: `get_xpub_bytes()` and `get_xpriv_bytes()`

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
