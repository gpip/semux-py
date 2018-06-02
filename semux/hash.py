import hashlib

from pyblake2 import blake2b

__all__ = ["hash256", "hash160"]


def hash256(data):
    return blake2b(data, digest_size=32).digest()


def hash160(data):
    return hashlib.new("ripemd160", hash256(data)).digest()
