# python-bip32

A basic implementation of the [bip-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

## Usage

```python
>>> from bip32 import BIP32, HARDENED_INDEX
>>> bip32 = BIP32.from_seed(bytes.fromhex("01"))
>>> bip32.get_xpriv_from_path([1, HARDENED_INDEX, 9998]) # m/1/0'/9998
b'xprv9y4sBgCuub5x2DtbdNBDDCZ3btybk8YZZaTvzV5rmYd3PbU63XLo2QEj6cUt4JAqpF8gJiRKFUW8Vm7thPkccW2DpUvBxASycypEHxmZzts'
>>> bip32 = BIP32.from_xpriv("xprv9y4sBgCuub5x2DtbdNBDDCZ3btybk8YZZaTvzV5rmYd3PbU63XLo2QEj6cUt4JAqpF8gJiRKFUW8Vm7thPkccW2DpUvBxASycypEHxmZzts")
>>> bip32.get_xpub_from_path([HARDENED_INDEX, 42]) # m/0'/42
b'xpub6AKC3u8URPxDojLnFtNdEPFkNsXxHfgRhySvVfEJy9SVvQAn14XQjAoFY48mpjgutJNfA54GbYYRpR26tFEJHTHhfiiZZ2wdBBzydVp12yU'
>>> bip32 = BIP32.from_xpub("xpub6AKC3u8URPxDojLnFtNdEPFkNsXxHfgRhySvVfEJy9SVvQAn14XQjAoFY48mpjgutJNfA54GbYYRpR26tFEJHTHhfiiZZ2wdBBzydVp12yU")
>>> bip32.get_xpub_from_path([42, 43]) # pubkey-only derivation: m/42/43
b'xpub6BZqjUq4rJ9bMGN5cwbPHWAzTg9D47fktRC3Le4J4woFcRP8KxvTDsLVoP4qpBqhtVJCvKwE98fvpCSmLA1rdchuJCN6Bxs2Pyt1k9naBhC'
```

## Installation

```
pip install bip32
```

### Dependencies

This uses [`coincurve`](https://github.com/ofek/coincurve) as a wrapper for [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1), which you may have already installed anyway, for EC operations.

## Interface

All public keys below are compressed.

All `path` below are a list of integers representing the index of the key at each depth.

### BIP32

#### from_seed(seed)

__*classmethod*__

Instanciate from a raw seed (as `bytes`). See [bip-0032's master key
generation](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#master-key-generation).

#### from_xpriv(xpriv)

__*classmethod*__

Instanciate with an encoded serialized extended private key (as `str`) as master.

#### from_xpub(xpub)

__*classmethod*__

Instanciate with an encoded serialized extended public key (as `str`) as master.

You'll only be able to derive unhardened public keys.

#### get_extended_privkey_from_path(path)

Returns `(chaincode (bytes), privkey (bytes))` of the private key pointed by the path.

#### get_privkey_from_path(path)

Returns `privkey (bytes)`, the private key pointed by the path.

#### get_extended_pubkey_from_path(path)

Returns `(chaincode (bytes), pubkey (bytes))` of the public key pointed by the path.

Note that you don't need to have provided the master private key if the path doesn't
include an index `>= HARDENED_INDEX`.

#### get_pubkey_from_path(path)

Returns `pubkey (bytes)`, the public key pointed by the path.

Note that you don't need to have provided the master private key if the path doesn't
include an index `>= HARDENED_INDEX`.

#### get_xpriv_from_path(path)

Returns `xpriv (str)` the serialized and encoded extended private key pointed by the given
path.

#### get_xpub_from_path(path)

Returns `xpub (str)` the serialized and encoded extended public key pointed by the given
path.

Note that you don't need to have provided the master private key if the path doesn't
include an index `>= HARDENED_INDEX`.

### get_master_xpriv(path)

Equivalent to `get_xpriv_from_path([])`.

### get_master_xpub(path)

Equivalent to `get_xpub_from_path([])`.
