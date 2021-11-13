import os
import rsa
import struct
from binascii import unhexlify
from Crypto.Cipher import AES
from NZLSSLib import compress


def u8(data):
    return struct.pack(">B", data)


def u16(data):
    return struct.pack(">H", data)


def u32(data):
    return struct.pack(">I", data)


def ParseContainer(type_data, buffer_data, compress_flag, aes_key, iv_key, rsa_key):

    compressed_data = _compress(bytes(buffer_data))
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
            key = open(aes_key, "rb").read()

        aes = AES.new(key, AES.MODE_OFB, iv=iv)
        processed = aes.encrypt(compressed_data)
    elif type_data == "dec":
        processed = compressed_data

    content = {}

    content["magic"] = b"WC24" if type_data == "enc" else u32(0)
    content["version"] = u32(1) if type_data == "enc" else u32(0)
    content["filler"] = u32(0)
    content["crypt_type"] = u8(1) if type_data == "enc" else u8(0)
    content["pad"] = u8(0) * 3
    content["reserved"] = u8(0) * 32
    content["iv"] = iv if type_data == "enc" else u8(0) * 16
    content["signature"] = signature
    content["data"] = processed
    output = []
    for values in content.values():
        output.append(values)
