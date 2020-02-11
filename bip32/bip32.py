import coincurve
import hashlib
import hmac


HARDENED_INDEX = 0x80000000


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
