import binascii

from semux.aes import encrypt, decrypt


raw = b"test"
key = binascii.unhexlify(
    "1122334455667788112233445566778811223344556677881122334455667788"
)
iv = binascii.unhexlify("11223344556677881122334455667788")
encrypted = binascii.unhexlify("182b93aa58d6291381660e5bad673dd4")


def test_encrypt():
    result = encrypt(raw, key, iv)
    assert result == encrypted


def test_decrypt():
    result = decrypt(encrypted, key, iv)
    assert result == raw
