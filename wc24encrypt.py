import rsa
import struct
from binascii import unhexlify
from Crypto.Cipher import AES
from NZLSSLib import compress
from os import urandom

def u8(data):
    return struct.pack(">B", data)


def u16(data):
    return struct.pack(">H", data)


def u32(data):
    return struct.pack(">I", data)


def ParseContainer(type_data, buffer_data, aes_key, iv_key, rsa_key):
    compressed_data = _compress(bytes(buffer_data.read()))
    private_key = rsa.PrivateKey.load_pkcs1(rsa_key, "PEM")
    signature = rsa.sign(data, private_key, "SHA-1")
    if type_data == "enc":
        if iv_key is not None:
            try:
                iv = unhexlify(iv_key)
            except:
                iv = iv_key.read()
        else:
            iv = os.urandom(16)
        try:
            key = unhexlify(aes_key)
        except:
            key = aes_key.read()
        aes = AES.new(key, AES.MODE_OFB, iv=iv_key)
        processed = aes.encrypt(compressed_data)
    elif type_data == "dec":
        processed = compressed_data
    content_dict = {}
    content_dict["magic"] = b"WC24" if type_data == "enc" else u32(0)
    content_dict["version"] = u32(1) if type_data == "enc" else u32(0)
    content_dict["filler"] = u32(0)
    content_dict["crypt_type"] = u8(1) if type_data == "enc" else u8(0)
    content_dict["pad"] = u8(0) * 3
    content_dict["reserved"] = u8(0) * 32
    content_dict["iv"] = iv if type_data == "enc" else u8(0) * 16
    content_dict["signature"] = signature
    content_dict["data"] = processed
    output_dict = []
    for values in content.values():
        output.append(values)
    # Thanks https://www.geeksforgeeks.org/python-convert-dictionary-to-concatenated-string/
    res = ' '
    for item in output_dict:
        res += item + str(output_dict[item])
    return unhexlify(res)
