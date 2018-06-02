import binascii

import nacl.utils
import nacl.signing
import nacl.encoding
from nacl.exceptions import BadSignatureError

from .hash import hash160
from .encoding import to_pkcs8, from_pkcs8, to_x509
from .signature import Signature

__all__ = [
    "PUBLIC_KEY_LEN",
    "ENCODED_PUBLIC_KEY_LEN",
    "PRIVATE_KEY_LEN",
    "ENCODED_PRIVATE_KEY_LEN",
    "ADDRESS_LEN",
    "SEED_LEN",
    "verify_message",
    "Key",
]

PUBLIC_KEY_LEN = 32
ENCODED_PUBLIC_KEY_LEN = 44

PRIVATE_KEY_LEN = 32
ENCODED_PRIVATE_KEY_LEN = 48

SEED_LEN = 32
ADDRESS_LEN = 20


def verify_message(message, signature):
    """
    Verify a signed message.

    Args:
        message (bytes): plain text message
        signature (bytes): generated signature

    Returns:
        boolean. True if signature is valid, False otherwise.
    """
    public = signature.get_verifying_key()
    try:
        public.verify(message, signature.signed_message)
        return True
    except BadSignatureError:
        return False


def generate_keypair(seed=None):
    """
    Generate a new key pair.

    Args:
        seed (bytes, optional): if specified the keypair will be generated
            based on this seed, otherwise a random seed will be picked.
    """
    if seed is None:
        seed = nacl.utils.random(SEED_LEN)
    if len(seed) != SEED_LEN:
        raise ValueError("seed must contain %d bytes, got %s" % (SEED_LEN, len(seed)))

    signing_key = nacl.signing.SigningKey(seed)
    return signing_key


class Key:

    @staticmethod
    def from_signing_key(signing_key):
        """
        Args:
            signing_key (nacl.signing.SigningKey)

        Returns:
            Key
        """
        public = signing_key.verify_key
        seed = signing_key._seed
        return Key(public, signing_key, seed)

    @staticmethod
    def from_seed(seed=None):
        signing_key = generate_keypair(seed)
        return Key.from_signing_key(signing_key)

    @staticmethod
    def from_random():
        return Key.from_seed()

    @staticmethod
    def from_encoded_private(encoded_private):
        seed = from_pkcs8(encoded_private)
        return Key.from_seed(seed)

    def __init__(self, public, private, seed):
        encoded_public = public.encode()
        if len(encoded_public) != PUBLIC_KEY_LEN:
            raise ValueError(
                "Invalid public key, expected length %d got %d"
                % (PUBLIC_KEY_LEN, len(encoded_public))
            )

        encoded_private = private.encode()
        if len(encoded_private) != PRIVATE_KEY_LEN:
            raise ValueError(
                "Invalid private key, expected length %d got %d"
                % (PRIVATE_KEY_LEN, len(encoded_private))
            )

        if len(seed) != SEED_LEN:
            raise ValueError(
                "Invalid seed, expected length %d got %d" % (SEED_LEN, len(seed))
            )

        self.public = public
        self.private = private
        self.seed = seed
        self.encoded_public = to_x509(public.encode())
        self.encoded_private = to_pkcs8(private.encode())

        if len(self.encoded_public) != ENCODED_PUBLIC_KEY_LEN:
            raise ValueError("Unexpected encoding mismatch for public key")
        if len(self.encoded_private) != ENCODED_PRIVATE_KEY_LEN:
            raise ValueError("Unexpected encoding mismatch for private key")

    def to_address(self, raw=False):
        """
        Return the Semux address derived from the public key.
        """
        h160 = hash160(self.encoded_public)
        if len(h160) != ADDRESS_LEN:
            raise ValueError("Unexpected encoding mismatch for address")
        if not raw:
            h160 = binascii.hexlify(h160)
        return h160

    def sign(self, message):
        """
        Sign a message.
        """
        signed_msg = self.private.sign(message)
        return Signature(signed_msg.signature, self.public.encode())
