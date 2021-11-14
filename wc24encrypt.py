from xcrypt import generate4
from struct import pack
from binascii import unhexlify
from Crypto.Cipher import AES
from libnlzsstools import compress
import rsa

def u8(val):
    return pack(">B", val)

def u16(val):
    return pack(">H", val)

def u32(val):
    return pack(">I", val)

def ParseContainer(type_data, buffer_data, aes_key, iv_key, rsa_key):
    compressed_data = _compress(bytes(buffer_data.read()))
    signature = rsa.sign(compressed_data, rsa_key.read(), "SHA-1")
    if iv_key is not None:
        try:
            iv = unhexlify(iv_key.read())
        except:
            iv = iv_key.read()
    else:
        iv = generate4() * 4
    try:
        key = unhexlify(aes_key)
    except:
        key = aes_key.read()
    aes = AES.new(key, AES.MODE_OFB, iv=iv_key)
    processed = aes.encrypt(compressed_data.read())
    input_dict = [
        b"WC24",
        u32(1),
        u32(0),
        u8(1),
        u8(0) * 3,
        u8(0) * 32,
        iv,
        signature,
        processed
    ]
    # Thanks https://www.geeksforgeeks.org/python-convert-dictionary-to-concatenated-string/
    output_dict = []
    res = ' '
    for values in input_dict:
        res += item + str(output_dict[values])
    return unhexlify(res)
