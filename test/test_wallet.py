import os
import binascii

from semux.wallet import bcrypt_derive, decode_wallet
from semux.key import Key

HERE = os.path.dirname(os.path.abspath(__file__))

# bouncycastle test vectors
TEST_VECTORS = [
    # password, salt, log cost, expected
    ["", "144b3d691a7b4ecf39cf735c7fa7a79c", 6, "557e94f34bf286e8719a26be94ac1e16d95ef9f819dee092"],
    ["00", "144b3d691a7b4ecf39cf735c7fa7a79c", 6, "557e94f34bf286e8719a26be94ac1e16d95ef9f819dee092"],
    ["00", "26c63033c04f8bcba2fe24b574db6274", 8, "56701b26164d8f1bc15225f46234ac8ac79bf5bc16bf48ba"],
    ["00", "9b7c9d2ada0fd07091c915d1517701d6", 10, "7b2e03106a43c9753821db688b5cc7590b18fdf9ba544632"],
    ["6100", "a3612d8c9a37dac2f99d94da03bd4521", 6, "e6d53831f82060dc08a2e8489ce850ce48fbf976978738f3"],
    ["6100", "7a17b15dfe1c4be10ec6a3ab47818386", 8, "a9f3469a61cbff0a0f1a1445dfe023587f38b2c9c40570e1"],
    ["6100", "9bef4d04e1f8f92f3de57323f8179190", 10, "5169fd39606d630524285147734b4c981def0ee512c3ace1"],
    ["61626300", "2a1f1dc70a3d147956a46febe3016017", 6, "d9a275b493bcbe1024b0ff80d330253cfdca34687d8f69e5"],
    ["61626300", "4ead845a142c9bc79918c8797f470ef5", 8, "8d4131a723bfbbac8a67f2e035cae08cc33b69f37331ea91"],
    ["61626300", "631c554493327c32f9c26d9be7d18e4c", 10, "8cd0b863c3ff0860e31a2b42427974e0283b3af7142969a6"],
    ["6162636465666768696a6b6c6d6e6f707172737475767778797a00", "02d1176d74158ee29cffdac6150cf123", 6, "4d38b523ce9dc6f2f6ff9fb3c2cd71dfe7f96eb4a3baf19f"],
    ["6162636465666768696a6b6c6d6e6f707172737475767778797a00", "715b96caed2ac92c354ed16c1e19e38a", 8, "98bf9ffc1f5be485f959e8b1d526392fbd4ed2d5719f506b"],
    ["6162636465666768696a6b6c6d6e6f707172737475767778797a00", "85727e838f9049397fbec90566ede0df", 10, "cebba53f67bd28af5a44c6707383c231ac4ef244a6f5fb2b"],
    ["7e21402324255e262a28292020202020207e21402324255e262a2829504e4246524400", "8512ae0d0fac4ec9a5978f79b6171028", 6, "26f517fe5345ad575ba7dfb8144f01bfdb15f3d47c1e146a"],
    ["7e21402324255e262a28292020202020207e21402324255e262a2829504e4246524400", "1ace2de8807df18c79fced54678f388f", 8, "d51d7cdf839b91a25758b80141e42c9f896ae80fd6cd561f"],
    ["7e21402324255e262a28292020202020207e21402324255e262a2829504e4246524400", "36285a6267751b14ba2dc989f6d43126", 10, "db4fab24c1ff41c1e2c966f8b3d6381c76e86f52da9e15a9"],
    ["c2a300", "144b3d691a7b4ecf39cf735c7fa7a79c", 6, "5a6c4fedb23980a7da9217e0442565ac6145b687c7313339"],
]


WALLET_V1_NOPWD = {
    'version': 1,
    'accounts': [{
        'address': '0x83b9e57d516fa79df1e33e9056a77703937a6825',
        'public': b'533a082ebe5ab09d0fc55d6ba1dc5be2a42455ab28af8822e26de1ec8cdf705e',
        'private': None
    }],
    'aliases_raw': ''
}


def test_vectors():
    for entry in TEST_VECTORS:
        pwd = binascii.unhexlify(entry[0])
        salt = binascii.unhexlify(entry[1])
        cost = entry[2]
        expected = binascii.unhexlify(entry[3])

        # looks like bcrypt is supposed to chop off the last byte but
        # bouncycastle keeps it.
        assert bcrypt_derive(pwd, salt, cost) == expected


def test_wallet_v1():
    wfile = os.path.join(HERE, 'resource', 'wallet_v1')
    decoded = decode_wallet(open(wfile, 'rb'))
    assert decoded == WALLET_V1_NOPWD


def test_wallet_v1_pwd():
    wfile = os.path.join(HERE, 'resource', 'wallet_v1')
    decoded = decode_wallet(open(wfile, 'rb'), b'password')

    entry = decoded['accounts'][0]
    assert isinstance(entry['private'], Key)
    assert '0x%s' % (entry['private'].to_address().decode()) == entry['address']
