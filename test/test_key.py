import binascii

import nacl.utils

from semux.key import (
    Key,
    verify_message,
    PUBLIC_KEY_LEN,
    PRIVATE_KEY_LEN,
    ENCODED_PUBLIC_KEY_LEN,
    ENCODED_PRIVATE_KEY_LEN,
    ADDRESS_LEN
)
from semux.hash import hash256
from semux.signature import SIG_LEN, Signature

TEST_ENCODED_PRIVATEKEY = b'302e020100300506032b657004220420bd2f24b259aac4bfce3792c31d0f62a7f28b439c3e4feb97050efe5fe254f2af'
TEST_ENCODED_PUBLICKEY = b'302a300506032b6570032100b72dc8ebc9f53d21837dc96483da08765ea11f25c1bd4c3cb49318c944d67b9b'
TEST_ADDRESS = b'0680a919c78faa59b127014b6181979ae0a62dbd'
TEST_SIG = b'e345ba4cbdc7dcca559d7b60a4740a750d565409481ffb6ee18e4d0c104bdd8d37457e383b1cd515e2f8e1a4a3ecbd771a29ef0520e4b017ca6e005881f07606b72dc8ebc9f53d21837dc96483da08765ea11f25c1bd4c3cb49318c944d67b9b'


def test_key_constants():
    key = Key.from_random()
    assert len(key.public.encode()) == PUBLIC_KEY_LEN
    assert len(key.private.encode()) == PRIVATE_KEY_LEN
    assert len(key.encoded_public) == ENCODED_PUBLIC_KEY_LEN
    assert len(key.encoded_private) == ENCODED_PRIVATE_KEY_LEN
    assert len(key.to_address(True)) == ADDRESS_LEN


def test_from_encoded():
    key = Key.from_encoded_private(binascii.unhexlify(TEST_ENCODED_PRIVATEKEY))
    assert binascii.hexlify(key.encoded_private) == TEST_ENCODED_PRIVATEKEY
    assert binascii.hexlify(key.encoded_public) == TEST_ENCODED_PUBLICKEY
    assert key.to_address() == TEST_ADDRESS

    key2 = Key.from_encoded_private(key.encoded_private)
    assert key2.encoded_private == key.encoded_private
    assert key2.private == key.private
    assert key2.public == key.public
    assert key2.seed == key.seed
    assert key2.to_address(False) == key.to_address(False)
    assert key2.to_address() == key.to_address()


def test_sign_verify():
    msg = hash256(b'test')
    key = Key.from_random()
    sig = key.sign(msg)

    assert len(sig.to_bytes()) == SIG_LEN
    assert verify_message(msg, sig) is True
    assert sig.public_key == key.public.encode()
    assert sig.get_address() == key.to_address(True)


def test_sign_verify_large():
    msg = nacl.utils.random(1024 * 1024)
    key = Key.from_random()
    sig = key.sign(msg)

    assert verify_message(msg, sig) is True
    assert sig.public_key == key.public.encode()


def test_bad_signature():
    msg = hash256(b'test')
    random_sig = Signature.from_bytes(nacl.utils.random(SIG_LEN))

    assert verify_message(msg, random_sig) is False


def test_expected_sign():
    key = Key.from_encoded_private(binascii.unhexlify(TEST_ENCODED_PRIVATEKEY))
    sig = Signature.from_bytes(binascii.unhexlify(TEST_SIG))

    assert sig.public_key == key.public.encode()
    assert sig.signed_message == key.sign(b'test').signed_message
    assert sig.get_address() == key.to_address(True)
    assert sig.to_bytes() == binascii.unhexlify(TEST_SIG)
