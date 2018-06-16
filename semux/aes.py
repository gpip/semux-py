from Crypto.Cipher import AES

__all__ = ["encrypt", "decrypt"]


def encrypt(raw_data, key, iv):
    # Pad data.
    length = 16 - (len(raw_data) % 16)
    raw_data += bytes([length]) * length

    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc_data = cipher.encrypt(raw_data)
    return enc_data


def decrypt(enc_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    raw_pad = cipher.decrypt(enc_data)
    # Remove padding
    raw = raw_pad[0:-raw_pad[-1]]

    return raw
