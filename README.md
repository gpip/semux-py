# Semux Python Library

## Install

```
pip install semux
```

## Usage

Generate random address:

```
from semux.key import Key

k = Key.from_random()
k.to_address()
```

Save and restore private key:

```
import binascii
from semux.key import Key

k = Key.from_random()
save = binascii.hexlify(k.encoded_private)

restored = Key.from_encoded_private(binascii.unhexlify(save))
```

Sign and verify message:

```
from semux.hash import hash256
from semux.key import Key, verify_message
from semux.signature import Signature

k = Key.from_random()
sig = k.sign(hash256(b'message'))
saved_sig = binascii.hexlify(sig.to_bytes())

restored_sig = Signature.from_bytes(binascii.unhexlify(saved_sig))
assert verify_message(hash256(b'message'), restored_sig) is True
```


## Code formatting

```
black semux/
```

## Origin

This library started from https://gist.github.com/gpip/ed7595abf368e6858a3723555ba734e2 and https://github.com/semuxproject/semux-js-sdk
