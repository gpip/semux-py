import nacl.signing

from .hash import hash160
from .encoding import to_x509

__all__ = ["SIG_LEN", "Signature"]

S_LEN = 64
A_LEN = 32
SIG_LEN = 96  # S_LEN + A_LEN


class Signature:

    @staticmethod
    def from_bytes(data):
        if len(data) != SIG_LEN:
            raise ValueError(
                "Invalid data length, expected %d got %d" % (SIG_LEN, len(data))
            )
        return Signature(data[:S_LEN], data[S_LEN:])

    def __init__(self, signed_message, public_key):
        if len(signed_message) != S_LEN:
            raise ValueError(
                "Invalid signed message length, expected %d got %d"
                % (S_LEN, len(signed_message))
            )
        if len(public_key) != A_LEN:
            raise ValueError(
                "Invalid public key length, expected %d got %d"
                % (A_LEN, len(public_key))
            )

        self.signed_message = signed_message
        self.public_key = public_key

    def get_verifying_key(self):
        return nacl.signing.VerifyKey(self.public_key)

    def get_address(self):
        return hash160(to_x509(self.public_key))

    def to_bytes(self):
        return self.signed_message + self.public_key
