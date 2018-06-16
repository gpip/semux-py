import struct

__all__ = ["read_size", "read_int", "write_int", "write_size"]


def read_size(f):
    size = 0
    for i in range(4):
        b = ord(f.read(1))
        size = (size << 7) | (b & 0x7f)
        if b & 0x80 == 0:
            break
    return size


def read_int(f):
    return struct.unpack('>I', f.read(4))[0]


def write_int(f, i):
    f.write(struct.pack('>I', i))


def write_size(f, size):
    buf = [0, 0, 0, 0]
    i = len(buf)
    while True:
        i -= 1
        buf[i] = size & 0x7f
        size >>= 7
        if not size:
            break

    while i < len(buf):
        if i != len(buf) - 1:
            val = chr(buf[i] | 0x80)
        else:
            val = chr(buf[i])
        f.write(val.encode())
        i += 1
