import base58
import coincurve
import hashlib
import hmac


HARDENED_INDEX = 0x80000000
ENCODING_PREFIX = {
    "main": {
        "private": 0x0488ADE4,
        "public": 0x0488B21E,
    },
    "test": {
        "private": 0x04358394,
        "public": 0x043587CF,
    },
}


class BIP32DerivationError(Exception):
    """We derived an invalid (secret > N or point(secret) is infinity) key!"""


def _derive_unhardened_private_child(privkey, chaincode, index):
    """A.k.a CKDpriv, in bip-0032

    :param privkey: The parent's private key, as bytes
    :param chaincode: The parent's chaincode, as bytes
    :param index: The index of the node to derive, as int

    :return: (child_privatekey, child_chaincode)
    """
    assert isinstance(privkey, bytes) and isinstance(chaincode, bytes)
    assert not index & HARDENED_INDEX
    pubkey = coincurve.PublicKey.from_secret(privkey).format()
    # payload is the I from the BIP. Index is 32 bits unsigned int, BE.
    payload = hmac.new(chaincode, pubkey + index.to_bytes(4, "big"),
                       hashlib.sha512).digest()
    try:
        child_private = coincurve.PrivateKey(payload[:32]).add(privkey)
    except ValueError:
        raise BIP32DerivationError("Invalid private key at index {}, try the "
                                   "next one!".format(index))
    return bytes.fromhex(child_private.to_hex()), payload[32:]


def _derive_hardened_private_child(privkey, chaincode, index):
    """A.k.a CKDpriv, in bip-0032, but the hardened way

    :param privkey: The parent's private key, as bytes
    :param chaincode: The parent's chaincode, as bytes
    :param index: The index of the node to derive, as int

    :return: (child_privatekey, child_chaincode)
    """
    assert isinstance(privkey, bytes) and isinstance(chaincode, bytes)
    assert index & HARDENED_INDEX
    # payload is the I from the BIP. Index is 32 bits unsigned int, BE.
    payload = hmac.new(chaincode, b'\x00' + privkey + index.to_bytes(4, "big"),
                       hashlib.sha512).digest()
    try:
        child_private = coincurve.PrivateKey(payload[:32]).add(privkey)
    except ValueError:
        raise BIP32DerivationError("Invalid private key at index {}, try the "
                                   "next one!".format(index))
    return bytes.fromhex(child_private.to_hex()), payload[32:]


def _derive_public_child(pubkey, chaincode, index):
    """A.k.a CKDpub, in bip-0032.

    :param pubkey: The parent's (compressed) public key, as bytes
    :param chaincode: The parent's chaincode, as bytes
    :param index: The index of the node to derive, as int

    :return: (child_pubkey, child_chaincode)
    """
    assert isinstance(pubkey, bytes) and isinstance(chaincode, bytes)
    assert not index & HARDENED_INDEX
    # payload is the I from the BIP. Index is 32 bits unsigned int, BE.
    payload = hmac.new(chaincode, pubkey + index.to_bytes(4, "big"),
                       hashlib.sha512).digest()
    try:
        tmp_pub = coincurve.PublicKey.from_secret(payload[:32])
    except ValueError:
        raise BIP32DerivationError("Invalid private key at index {}, try the "
                                   "next one!".format(index))
    parent_pub = coincurve.PublicKey(pubkey)
    child_pub = coincurve.PublicKey.combine_keys([tmp_pub, parent_pub])
    return child_pub.format(), payload[32:]


def _pubkey_to_fingerprint(pubkey):
    rip = hashlib.new("ripemd160")
    rip.update(hashlib.sha256(pubkey).digest())
    return rip.digest()[:4]


def _serialize_extended_key(key, depth, parent_pubkey, index, chaincode,
                            network="main"):
    """Serialize an extended private *OR* public key, as spec by bip-0032.

    :param key: The public or private key to serialize. Note that if this is
                a public key it MUST be compressed.
    :param depth: 0x00 for master nodes, 0x01 for level-1 derived keys, etc..
    :param parent_pubkey: The parent pubkey used to derive the fingerprint.
                          None if master.
    :param index: The index of the key being serialized. 0x00000000 if master.
    :param chaincode: The chain code (not the labs !!).

    :return: The serialized extended key.
    """
    for param in {key, chaincode}:
        assert isinstance(param, bytes)
    for param in {depth, index}:
        assert isinstance(param, int)
    if parent_pubkey:
        assert isinstance(parent_pubkey, bytes) and len(parent_pubkey) == 33
        fingerprint = _pubkey_to_fingerprint(parent_pubkey)
    else:
        fingerprint = bytes(4)  # master
    # A privkey or a compressed pubkey
    assert len(key) in {32, 33}
    if network not in {"main", "test"}:
        raise ValueError("Unsupported network")
    is_privkey = len(key) == 32
    prefix = ENCODING_PREFIX[network]["private" if is_privkey else "public"]
    extended = prefix.to_bytes(4, "big")
    extended += depth.to_bytes(1, "big")
    extended += fingerprint
    extended += index.to_bytes(4, "big")
    extended += chaincode
    if is_privkey:
        extended += b'\x00'
    extended += key
    return extended


def _unserialize_extended_key(extended_key):
    """Unserialize an extended private *OR* public key, as spec by bip-0032.

    :param extended_key: The extended key to unserialize __as bytes__

    :return: prefix (int), depth (int), fingerprint (bytes), index (int),
             chaincode (bytes), key (bytes)
    """
    assert isinstance(extended_key, bytes) and len(extended_key) == 78
    prefix = int.from_bytes(extended_key[:4], "big")
    depth = extended_key[4]
    fingerprint = extended_key[4:9]
    index = int.from_bytes(extended_key[9:13], "big")
    chaincode, key = extended_key[13:45], extended_key[45:]
    return prefix, depth, fingerprint, index, chaincode, key


def _hardened_index_in_path(path):
    return len([i for i in path if i & HARDENED_INDEX]) > 0


class BIP32:
    def __init__(self, chaincode, privkey=None, pubkey=None):
        """
        :param chaincode: The master chaincode, used to derive keys. As bytes.
        :param privkey: The master private key for this index (default 0).
                        Can be None for pubkey-only derivation.
                        As bytes.
        :param pubkey: The master public key for this index (default 0).
                       Can be None if private key is specified.
                       Compressed format. As bytes.
        """
        assert isinstance(chaincode, bytes)
        assert privkey is not None or pubkey is not None
        if privkey is not None:
            assert isinstance(privkey, bytes)
        if pubkey is not None:
            assert isinstance(pubkey, bytes)
        else:
            pubkey = coincurve.PublicKey.from_secret(privkey).format()
        self.master_chaincode = chaincode
        self.master_privkey = privkey
        self.master_pubkey = pubkey

    def get_extended_privkey_from_path(self, path):
        """Get an extended privkey from a list of indexes (path).

        :param path: A list of integers (index of each depth).
                     depth = len(path).
        :return: chaincode (bytes), privkey (bytes)
        """
        chaincode, privkey = self.master_chaincode, self.master_privkey
        for index in path:
            if index & HARDENED_INDEX:
                privkey, chaincode = \
                    _derive_hardened_private_child(privkey, chaincode, index)
            else:
                privkey, chaincode = \
                    _derive_unhardened_private_child(privkey, chaincode, index)
        return chaincode, privkey

    def get_privkey_from_path(self, path):
        """Get a privkey from a list of indexes (path).

        :param path: A list of integers (index of each depth).
                     depth = len(path).
        :return: privkey (bytes)
        """
        return self.get_extended_privkey_from_path(path)[1]

    def get_extended_pubkey_from_path(self, path):
        """Get an extended pubkey from a list of indexes (path).

        :param path: A list of integers (index of each depth).
                     depth = len(path).
        :return: chaincode (bytes), pubkey (bytes)
        """
        chaincode, key = self.master_chaincode, self.master_privkey
        # We'll need the private key at some point anyway, so let's derive
        # everything from private keys.
        if _hardened_index_in_path(path):
            for index in path:
                if index & HARDENED_INDEX:
                    key, chaincode = \
                        _derive_hardened_private_child(key, chaincode, index)
                else:
                    key, chaincode = \
                        _derive_unhardened_private_child(key, chaincode, index)
                pubkey = coincurve.PublicKey.from_secret(key).format()
        # We won't need private keys for the whole path, so let's only use
        # public key derivation.
        else:
            key = self.master_pubkey
            for index in path:
                key, chaincode = \
                    _derive_public_child(key, chaincode, index)
                pubkey = key
        return chaincode, pubkey

    def get_pubkey_from_path(self, path):
        """Get a privkey from a list of indexes (path).

        :param path: A list of integers (index of each depth).
                     depth = len(path).
        :return: privkey (bytes)
        """
        return self.get_extended_pubkey_from_path(path)[1]

    def get_xpriv_from_path(self, path):
        """Get an encoded extended privkey from a list of indexes (path).

        :param path: A list of integers (index of each depth).
                     depth = len(path).
        :return: The encoded extended pubkey as str.
        """
        if len(path) == 0:
            return self.get_master_xpriv()
        elif len(path) == 1:
            parent_pubkey = self.master_pubkey
        else:
            parent_pubkey = self.get_pubkey_from_path(path[:-1])
        chaincode, privkey = self.get_extended_privkey_from_path(path)
        extended_key = _serialize_extended_key(privkey, len(path),
                                               parent_pubkey,
                                               path[-1], chaincode)
        return base58.b58encode_check(extended_key)

    def get_xpub_from_path(self, path):
        """Get an encoded extended pubkey from a list of indexes (path).

        :param path: A list of integers (index of each depth).
                     depth = len(path).
        :return: The encoded extended pubkey as str.
        """
        if len(path) == 0:
            return self.get_master_xpub()
        elif len(path) == 1:
            parent_pubkey = self.master_pubkey
        else:
            parent_pubkey = self.get_pubkey_from_path(path[:-1])
        chaincode, pubkey = self.get_extended_pubkey_from_path(path)
        extended_key = _serialize_extended_key(pubkey, len(path),
                                               parent_pubkey,
                                               path[-1], chaincode)
        return base58.b58encode_check(extended_key)

    def get_master_xpriv(self):
        """Get the encoded extended private key of the master private key"""
        extended_key = _serialize_extended_key(self.master_privkey, 0,
                                               None, 0, self.master_chaincode)
        return base58.b58encode_check(extended_key)

    def get_master_xpub(self):
        """Get the encoded extended public key of the master public key"""
        extended_key = _serialize_extended_key(self.master_pubkey, 0,
                                               None, 0, self.master_chaincode)
        return base58.b58encode_check(extended_key)

    @classmethod
    def from_xpriv(cls, xpriv):
        """Get a BIP32 "wallet" out of this xpriv"""
        extended_key = base58.b58decode_check(xpriv)
        (prefix, depth, fingerprint,
         index, chaincode, key) = _unserialize_extended_key(extended_key)
        return BIP32(chaincode, key, None)

    @classmethod
    def from_xpub(cls, xpriv):
        """Get a BIP32 "wallet" out of this xpriv"""
        extended_key = base58.b58decode_check(xpriv)
        (prefix, depth, fingerprint,
         index, chaincode, key) = _unserialize_extended_key(extended_key)
        return BIP32(chaincode, None, key)

    @classmethod
    def from_seed(cls, seed):
        """Get a BIP32 "wallet" out of this seed (maybe after BIP39?)

        :param seed: The seed as bytes.
        """
        secret = hmac.new("Bitcoin seed".encode(), seed,
                          hashlib.sha512).digest()
        return BIP32(secret[32:], secret[:32], None)
