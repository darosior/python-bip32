# python-bip32

A basic implementation of [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).

## Usage

```python
>>> from bip32 import BIP32, HARDENED_INDEX
>>> bip32 = BIP32.from_seed(bytes.fromhex("01"))
# Specify the derivation path as a list ...
>>> bip32.get_xpriv_from_path([1, HARDENED_INDEX, 9998])
'xprv9y4sBgCuub5x2DtbdNBDDCZ3btybk8YZZaTvzV5rmYd3PbU63XLo2QEj6cUt4JAqpF8gJiRKFUW8Vm7thPkccW2DpUvBxASycypEHxmZzts'
# ... Or in usual m/the/path/
>>> bip32.get_xpriv_from_path("m/1/0'/9998")
'xprv9y4sBgCuub5x2DtbdNBDDCZ3btybk8YZZaTvzV5rmYd3PbU63XLo2QEj6cUt4JAqpF8gJiRKFUW8Vm7thPkccW2DpUvBxASycypEHxmZzts'
>>> bip32.get_xpub_from_path([HARDENED_INDEX, 42])
'xpub69uEaVYoN1mZyMon8qwRP41YjYyevp3YxJ68ymBGV7qmXZ9rsbMy9kBZnLNPg3TLjKd2EnMw5BtUFQCGrTVDjQok859LowMV2SEooseLCt1'
# You can also use "h" or "H" to signal for hardened derivation
>>> bip32.get_xpub_from_path("m/0h/42")
'xpub69uEaVYoN1mZyMon8qwRP41YjYyevp3YxJ68ymBGV7qmXZ9rsbMy9kBZnLNPg3TLjKd2EnMw5BtUFQCGrTVDjQok859LowMV2SEooseLCt1'
# You can use pubkey-only derivation
>>> bip32 = BIP32.from_xpub("xpub6AKC3u8URPxDojLnFtNdEPFkNsXxHfgRhySvVfEJy9SVvQAn14XQjAoFY48mpjgutJNfA54GbYYRpR26tFEJHTHhfiiZZ2wdBBzydVp12yU")
>>> bip32.get_xpub_from_path([42, 43])
'xpub6FL7T3s7GuVb4od1gvWuumhg47y6TZtf2DSr6ModQpX4UFGkQXw8oEVhJXcXJ4edmtAWCTrefD64B9RP4sYSkSumTW1wadTS3SYurBGYccT'
>>> bip32.get_xpub_from_path("m/42/43")
'xpub6FL7T3s7GuVb4od1gvWuumhg47y6TZtf2DSr6ModQpX4UFGkQXw8oEVhJXcXJ4edmtAWCTrefD64B9RP4sYSkSumTW1wadTS3SYurBGYccT'
>>> bip32.get_pubkey_from_path("m/1/1/1/1/1/1/1/1/1/1/1")
b'\x02\x0c\xac\n\xa8\x06\x96C\x8e\x9b\xcf\x83]\x0c\rCm\x06\x1c\xe9T\xealo\xa2\xdf\x195\xebZ\x9b\xb8\x9e'
```

## Installation

```
pip install bip32
```

### Dependencies

This uses [`coincurve`](https://github.com/ofek/coincurve) as a wrapper for [`libsecp256k1`](https://github.com/bitcoin-core/secp256k1) for EC operations.

### Running the test suite

```
# From the root of the repository
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt && pip install pytest
PYTHONPATH=$PYTHONPATH:$PWD/bip32 pytest -vvv
```

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

#### get_xpriv()

Equivalent to `get_xpriv_from_path([])`.

#### get_xpriv_bytes()

Equivalent to `get_xpriv([])`, but not serialized in base58.

#### get_xpub()

Equivalent to `get_xpub_from_path([])`.

#### get_xpub_bytes()

Equivalent to `get_xpub([])`, but not serialized in base58.

#### get_fingerprint()

Returns `fingerprint (bytes)`, equivalent to `utils._pubkey_to_fingerprint(self.pubkey)`.
