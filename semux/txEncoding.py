__all__ = ['SimpleDecoder', 'SimpleEncoder']

'''
ported from
https://github.com/semuxproject/semux/blob/master/src/main/java/org/semux/util/SimpleDecoder.java
'''
class SimpleDecoder:

    def __init__(self, data, _from=None, _to=None):
        self.data = data
        if _from is None:
            self._from = 0
        else:
            self._from = _from

        if _to is None:
            self._to = len(data)
        else:
            self._to = _to

        self.index = self._from

    def unsignedInt(self, i):
        return i & 0xffffffff

    def readBoolean(self):
        i = self.index
        self.index += 1
        return self.data[i]

    def readByte(self):
        i = self.index
        self.index += 1
        return self.data[i]

    def readShort(self):
        i = self.index
        self.index += 2
        return (self.data[i] & 0xFF) << 8 | (self.data[i+1] & 0xFF)

    def readInt(self):
        i = self.index
        self.index += 4
        return (self.data[i] << 24) | (self.data[i+1] & 0xFF) << 16 | (self.data[i+2] & 0xFF) << 8 | (self.data[i+3] & 0xFF)

    def readLong(self):
        i1 = int(self.readInt())
        i2 = int(self.readInt())

        return (self.unsignedInt(i1) << 32 | self.unsignedInt(i2))

    
    # amount in Nano SEM, value*1000000000
    def readAmount(self):
        return self.readLong()

    def readSize(self):
        size = 0
        for i in range(4):
            b = self.data[self.index]
            self.index += 1

            size = (size << 7 | (b & 0x7F ))
            if (b & 0x80) == 0:
                break

        return int(size)

    def readBytes(self, vlq=True):
        if vlq:
            _len = int(self.readSize())
        else:
            _len = int(self.readInt())

        buf = bytearray(_len)
        i = self.index
        self.index += _len
        buf = self.data[i:self.index]
        return buf

    def readIndex(self):
        return self.index



'''
ported from
https://github.com/semuxproject/semux/blob/master/src/main/java/org/semux/util/SimpleEncoder.java
'''
import array

class SimpleEncoder:
    def __init__(self, toAppend=None):
        self.out = bytearray()
        if toAppend is not None:
            self.out.append(toAppend)

    def writeBoolean(self, b):
        self.out.append(b)

    def writeByte(self, b):
        self.out.append(b)

    def writeShort(self, s):
        self.out.append(0xFF & (s >> 8))
        self.out.append(0xFF & s)

    def writeInt(self, i):
        self.out.append(0xFF & (i >> 24))
        self.out.append(0xFF & (i >> 16))
        self.out.append(0xFF & (i >> 8))
        self.out.append(0xFF & i)

    def writeLong(self, l):
        i1 = int(l >> 32)
        i2 = int(l)

        self.writeInt(i1)
        self.writeInt(i2)

    # a is in Nano SEM, value*1000000000
    def writeAmount(self, a):
        self.writeLong(a)

    def writeSize(self, size):
        buf = array.array('i',(0 for i in range(0,4)))
        i = len(buf)
        while size > 0:
            buf[i-1] = size & 0x7F
            size = size >> 7
            i = i-1

        while i < len(buf):
            if i != (len(buf)-1):
                self.out.append(buf[i] | 0x80)
                i += 1
            else:
                self.out.append(buf[i])
                i += 1

    # @param b - bytearray
    def writeBytes(self, b, vlq=True):
        if vlq:
            self.writeSize(len(b))
        else:
            self.writeInt(len(b))
        if len(b) == 0:
            self.out.append(0)
        else:
            self.out = self.out + b

    def toBytes(self):
        return self.out

    def getWriteIndex(self):
        return len(self.out)-1
