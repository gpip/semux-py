# WARNING:
# bcrypt is not compatible with bouncycastle's implementation, it's necessary
# to patch https://github.com/pyca/bcrypt with the following change:
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# diff --git a/src/_csrc/bcrypt.c b/src/_csrc/bcrypt.c
# index a773602..51e5b83 100644
# --- a/src/_csrc/bcrypt.c
# +++ b/src/_csrc/bcrypt.c
# @@ -160,7 +160,7 @@ bcrypt_hashpass(const char *key, const char *salt, char *encrypted,
#
#         snprintf(encrypted, 8, "$2%c$%2.2u$", minor, logr);
#         encode_base64(encrypted + 7, csalt, BCRYPT_MAXSALT);
# -       encode_base64(encrypted + 7 + 22, ciphertext, 4 * BCRYPT_WORDS - 1);
# +       encode_base64(encrypted + 7 + 22, ciphertext, 4 * BCRYPT_WORDS);
#         explicit_bzero(&state, sizeof(state));
#         explicit_bzero(ciphertext, sizeof(ciphertext));
#         explicit_bzero(csalt, sizeof(csalt));
#
# -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
#
# There is still some incompatibility with semux's wallet v3 as it is not
# able to decrypt the keys.

import io
import os
import base64
import string
import binascii

import bcrypt

from .key import Key
from .hash import hash256, hash160
from .aes import encrypt, decrypt
from .filecodec import read_int, read_size, write_int, write_size

__all__ = ["bcrypt_derive", "encode_wallet", "decode_wallet"]

BCRYPT_COST = 12  # 1 << 12 rounds

# bcrypt encoding/decoding source origin:
# https://github.com/fwenzel/python-bcrypt
BCRYPT_SALTLEN = 16
B64_CHARS = ''.join((string.ascii_uppercase, string.ascii_lowercase,
                     string.digits, '+/')).encode()
B64_CHARS_BCRYPT = ''.join(('./', string.ascii_uppercase,
                            string.ascii_lowercase, string.digits)).encode()
B64_TO_BCRYPT = bytes.maketrans(B64_CHARS, B64_CHARS_BCRYPT)
B64_FROM_BCRYPT = bytes.maketrans(B64_CHARS_BCRYPT, B64_CHARS)

X509 = binascii.unhexlify('302a300506032b6570032100')


def _b64_encode(data):
    """
    base64 encode wrapper.

    Uses alternative chars and removes base 64 padding.
    """
    enc = base64.b64encode(data)
    return enc.translate(B64_TO_BCRYPT, b'=')


def _b64_decode(data):
    """
    base64 decode wrapper.

    Uses alternative chars and handles possibly missing padding.
    """
    encoded = data.translate(B64_FROM_BCRYPT)
    padding = '=' * (4 - len(data) % 4) if len(data) % 4 else ''
    return base64.b64decode(encoded + padding.encode())


def _encode_salt(csalt, log_rounds):
    """"
    encode_salt(csalt, log_rounds) -> encoded_salt

    Encode a raw binary salt and the specified log2(rounds) as a
    standard bcrypt text salt.
    """
    if len(csalt) != BCRYPT_SALTLEN:
        raise ValueError("Invalid salt length")

    if log_rounds < 4 or log_rounds > 31:
        raise ValueError("Invalid number of rounds")

    salt = '$2a${log_rounds:02d}${b64salt}'.format(
        log_rounds=log_rounds,
        b64salt=_b64_encode(csalt).decode()
    )
    return salt.encode()


def bcrypt_derive(password, salt, cost=BCRYPT_COST):
    if not isinstance(password, bytes):
        password = password.encode()

    # "mimic" bouncycastle behavior.
    if b'\x00' in password.rstrip(b'\x00'):
        raise ValueError('NUL byte in the middle of the password is disallowed')
    password = password.rstrip(b'\x00')

    salt = _encode_salt(salt, cost)
    key = bcrypt.hashpw(password, salt)
    if not isinstance(key, bytes):
        # py-bcrypt returns a str, bcrypt returns bytes.
        key = key.encode()

    result = _b64_decode(key[29:])
    return result


def decode_wallet(fobj, password=b''):
    data = {
        'version': None,
        'accounts': [],
        'aliases_raw': ''
    }

    key = None
    version = read_int(fobj)
    if version in (1, 2):
        key = hash256(password)
    elif version == 3:
        salt = fobj.read(read_size(fobj))
        key = bcrypt_derive(password, salt)
    else:
        raise Exception('Unknown wallet version %d' % version)
    data['version'] = version

    num_accounts = read_int(fobj)
    for i in range(num_accounts):
        acc = _decode_account(fobj, key, version, has_pwd=password != b'')
        addy = (
            binascii.hexlify(acc['address']).decode() if acc['address'] else ''
        )
        pubkey = (
            binascii.hexlify(acc['public_key']) if acc['public_key'] else ''
        )
        data['accounts'].append({
            'address': '0x%s' % addy,
            'public': pubkey,
            'private': acc['privkey']
        })

    if version in (2, 3):
        # XXX TODO
        # Decode address aliases.
        iv = fobj.read(read_size(fobj))
        aliases_encrypted = fobj.read(read_size(fobj))
        if key:
            aliases_raw = decrypt(aliases_encrypted, key, iv)
            data['aliases_raw'] = aliases_raw

    return data


def _decode_account(f, key, version, has_pwd=True):
    if version == 1:
        iv = f.read(read_int(f))
        public_key = f.read(read_int(f))
        encrypted_privkey = f.read(read_int(f))
    elif version == 2:
        iv = f.read(read_size(f))
        public_key = f.read(read_size(f))
        encrypted_privkey = f.read(read_size(f))
    elif version == 3:
        iv = f.read(read_size(f))
        public_key = None
        encrypted_privkey = f.read(read_size(f))

    if has_pwd:
        # Decode from PKCS#8 DER.
        privkey_pkcs8 = decrypt(encrypted_privkey, key, iv)
        if not privkey_pkcs8:
            raise ValueError('Failed to decrypt wallet key')
        privkey = Key.from_encoded_private(privkey_pkcs8)
        if public_key and privkey.encoded_public != public_key:
            raise Exception('key mismatch, check your password')
    else:
        privkey = None

    address = None
    if public_key:
        address = hash160(public_key)
        public_key = public_key[len(X509):]
    if privkey:
        address = privkey.to_address(True)
        public_key = privkey.public.encode()

    return {
        'iv': iv,
        'public_key': public_key,
        'encrypted_privkey': encrypted_privkey,
        'address': address,
        'privkey': privkey,
    }


def encode_wallet(password, accounts, aliases, salt=None):
    data = io.BytesIO()

    version = 3
    write_int(data, version)

    salt = salt or os.urandom(BCRYPT_SALTLEN)
    write_size(data, len(salt))
    data.write(salt)

    key = bcrypt_derive(password, salt)
    _encode_wallet_accounts(data, accounts, key)
    _encode_wallet_aliases(data, aliases, key)

    return data.getvalue()


def _encode_wallet_accounts(f, accounts, key):
    write_int(f, len(accounts))
    for acc in accounts:
        iv = os.urandom(16)
        write_size(f, len(iv))
        f.write(iv)

        enc = encrypt(acc.encoded_private, key, iv)
        write_size(f, len(enc))
        f.write(enc)


def _encode_wallet_aliases(f, aliases, key):
    # XXX TODO
    data = io.BytesIO()
    write_int(data, len(aliases))

    iv = os.urandom(16)
    write_size(f, len(iv))
    f.write(iv)
    enc = encrypt(data.getvalue(), key, iv)
    write_size(f, len(enc))
    f.write(enc)
