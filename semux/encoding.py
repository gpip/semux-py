__all__ = ["to_pkcs8", "from_pkcs8", "to_x509"]

OID_OLD = 0x64
OID_ED25519 = 0x70
OID_BYTE = 11
IDLEN_BYTE = 6


def to_pkcs8(data):
    total_len = 16 + len(data)

    result = bytearray(
        [
            # sequence
            0x30,
            total_len - 2,
            # version
            0x02,
            1,
            # no public key included
            0,
            # sequence, algorithm identifier
            0x30,
            5,
            # oid
            0x06,
            3,
            (1 * 40) + 3,
            0x65,
            OID_ED25519,
            # no params set
            # octet string
            0x04,
            2 + len(data),
            # curve
            0x04,
            len(data),
        ]
    )
    return bytes(result) + data


def from_pkcs8(encoded_data):
    total_len = 48
    id_len = 5

    oid = encoded_data[OID_BYTE]
    if oid == OID_OLD:
        total_len = 49
        id_len = 8
    elif oid == OID_ED25519:
        if encoded_data[IDLEN_BYTE] == 7:
            total_len = 50
            id_len = 7
    else:
        raise ValueError("Unknown encoding format")

    if len(encoded_data) != total_len:
        raise ValueError(
            "Unexpected data length, got %d expected %d"
            % (len(encoded_data), total_len)
        )

    # Decode
    e = encoded_data
    if (
        e[0] != 0x30
        or e[1] != (total_len - 2)
        or e[2] != 0x02
        or e[3] != 1
        or e[4] != 0
        or e[5] != 0x30
        or e[6] != id_len
        or e[7] != 0x06
        or e[8] != 3
        or e[9] != (1 * 40) + 3
        or e[10] != 0x65
    ):
        raise ValueError("Unsupported key spec")

    # e[11] was checked above already.

    if oid == OID_OLD:
        if e[12] != 0x0a or e[13] != 1 or e[14] != 1:
            raise ValueError("Unsupported key spec")
        indx = 15
    else:
        indx = 12
        if id_len == 7:
            if e[indx] != 0x05 or e[indx + 1] != 0:
                raise ValueError("Unsupported key spec")
            indx = 14

        # octet string for the data
        if e[indx] != 0x04 or e[indx + 1] != 2 + 32:
            raise ValueError("Unsupported key spec")
        indx += 2

    if e[indx] != 0x04 or e[indx + 1] != 32:
        raise ValueError("Unsupported key spec")

    return e[indx + 2 : indx + 2 + 32]


def to_x509(data):
    total_len = 12 + len(data)

    result = bytearray(
        [
            # sequence
            0x30,
            total_len - 2,
            # sequence, algorithm identifier
            0x30,
            5,
            # oid
            0x06,
            3,
            (1 * 40) + 3,
            0x65,
            OID_ED25519,
            # no params set
            # key
            0x03,
            1 + len(data),
            0,
        ]
    )
    return bytes(result) + data
