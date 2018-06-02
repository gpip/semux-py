from binascii import hexlify
from semux.hash import hash256, hash160


def test_hash256():
    assert hexlify(hash256(b'')) == b'0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8'
    assert hexlify(hash256(b'test')) == b'928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202'


def test_hash160():
    assert hexlify(hash160(b'')) == b'a13dcd79a9c0e088317b189c88641f4ab671ab15'
    assert hexlify(hash160(b'test')) == b'86e8402b7615f07a2acb2ef1f4a54d323bbede77'
