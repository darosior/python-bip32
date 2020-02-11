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
    secret = int.from_bytes(payload[:32], "big") + int.from_bytes(privkey,
                                                                  "big")
    try:
        child_private = coincurve.PrivateKey.from_int(secret)
    except ValueError:
        raise BIP32DerivationError("Invalid private key at index {}, try the "
                                   "next one!", index)
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
    secret = int.from_bytes(payload[:32], "big") + int.from_bytes(privkey,
                                                                  "big")
    child_private = coincurve.PrivateKey.from_int(secret)
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
                       hashlib.shasha512).digest()
    secret = int.from_bytes(payload[:32], "big")
    try:
        tmp_pub = coincurve.PublicKey.from_secret(secret)
    except ValueError:
        raise BIP32DerivationError("Invalid private key at index {}, try the "
                                   "next one!", index)
    parent_pub = coincurve.PublicKey(int.from_bytes(pubkey, "big"))
    child_pub = tmp_pub.add(parent_pub)
    return bytes.fromhex(child_pub.to_hex), payload[32:]


def _serialize_extended_key(key, depth, fingerprint, index, chaincode,
                            network="main"):
    """Serialize an extended private *OR* public key, as spec by bip-0032.

    :param key: The public or private key to serialize. Note that if this is
                a public key it MUST be compressed.
    :param depth: 0x00 for master nodes, 0x01 for level-1 derived keys, etc..
    :param fingerprint: The first four bytes of the parent's pubkey.
                        0x00000000 if master.
    :param index: The index of the key being serialized. 0x00000000 if master.
    :param chaincode: The chain code (not the labs !!).

    :return: The serialized extended key.
    """
    for param in {key, fingerprint, chaincode}:
        assert isinstance(param, bytes)
    for param in {depth, index}:
        assert isinstance(param, int)
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
    index = int.from_bytes(extended_key[9:14], "big")
    chaincode, key = extended_key[14:47], extended_key[47:]
    return prefix, depth, fingerprint, index, chaincode, key


class BIP32:
    def __init__(self, chaincode, privkey=None, pubkey=None, index=0):
        """
        :param chaincode: The master chaincode, used to derive keys. As bytes.
        :param privkey: The master private key for this index (default 0).
                        Can be None for pubkey-only derivation.
                        As bytes.
        :param pubkey: The master public key for this index (default 0).
                       Can be None if private key is specified.
                       Compressed format. As bytes.
        :param index: The current index of the derivation. As int.
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
        self.master_index = index

    def get_hardened_privkey(self, index, depth=0):
        """Get the i-nth hardened private key of the given depth.

        :param index: Which pubkey to derive. As int.
        :param depth: The depth, also called "account", to derive the index-nth
                      privkey from. As int.
        :return privkey: The private key as bytes.
        """
        if self.master_privkey is None:
            raise ValueError("Cannot derive a private key without the "
                             "master key")
        privkey, chaincode = self.master_privkey, self.master_chaincode
        while depth > 0:
            depth -= 1
            # FIXME: suboptimal for mixed wallets..
            privkey, chaincode = _derive_hardened_private_child(chaincode,
                                                                privkey, 0)
        privkey, _ = _derive_hardened_private_child(chaincode, privkey, index)
        return privkey

    def get_unhardened_privkey(self, index, depth=0):
        """Get the i-nth *unhardened* private key of the given depth.

        :param index: Which privkey to derive. As int.
        :param depth: The depth (/account) to derive this index-nth private
                      key from. As int.
        :return privkey: The private key as bytes.
        """
        if self.master_privkey is None:
            raise ValueError("Cannot derive a private key without the "
                             "master key")
        privkey, ccode = self.master_privkey, self.master_chaincode
        while depth > 0:
            depth -= 1
            privkey, ccode = _derive_unhardened_private_child(ccode,
                                                              privkey, 0)
        privkey, _ = _derive_unhardened_private_child(ccode, privkey, index)
        return privkey

    def get_pubkey(self, index, depth=0):
        """Get the i-nth public key of the given depth.

        :param index: Which pubkey to derive. As int.
        :param depth: The depth (/account) to derive this index-nth private
                      key from. As int.
        :return: The pubkey as bytes.
        """
        pubkey, chaincode = self.master_pubkey, self.master_chaincode
        while depth > 0:
            depth -= 1
            pubkey, chaincode = _derive_public_child(pubkey, chaincode, 0)
        pubkey, _ = _derive_public_child(pubkey, chaincode, index)
        return pubkey
