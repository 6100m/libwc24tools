import os
import rsa
import struct
from binascii import unhexlify
from Crypto.Cipher import AES
from nlzss import encode_file


def u8(data):
    return struct.pack(">B", data)


def u16(data):
    return struct.pack(">H", data)


def u32(data):
    return struct.pack(">I", data)


def ParseContainer(type, input, output, compress_flag, aes_key, iv_key, rsa_key):

    if compress_flag is not None:
        encode_file(in_path=args.input[0], out_path="temp")
        filename = "temp"
    else:
        filename = input

    with open(filename, "rb") as f:
        data = f.read()

    if args.rsa_key_path is not None:
        rsa_key_path = rsa_key
    else:
        rsa_key_path = "Private.pem"

    with open(rsa_key_path, "rb") as source_file:
        private_key_data = source_file.read()

    private_key = rsa.PrivateKey.load_pkcs1(private_key_data, "PEM")

    signature = rsa.sign(data, private_key, "SHA-1")

    if args.type[0] == "enc":
        if args.iv_key is not None:
            try:
                iv = unhexlify(iv_key)
            except:
                iv = open(args.iv_key, "rb").read()
        else:
            iv = os.urandom(16)

        try:
            key = unhexlify(args.aes_key)
        except:
            key = open(args.aes_key, "rb").read()

        aes = AES.new(key, AES.MODE_OFB, iv=iv)
        processed = aes.encrypt(data)
    elif type == "dec":
        processed = data

    content = {}

    content["magic"] = b"WC24" if type == "enc" else u32(0)
    content["version"] = u32(1) if type == "enc" else u32(0)
    content["filler"] = u32(0)
    content["crypt_type"] = u8(1) if type == "enc" else u8(0)
    content["pad"] = u8(0) * 3
    content["reserved"] = u8(0) * 32
    content["iv"] = iv if type == "enc" else u8(0) * 16
    content["signature"] = signature
    content["data"] = processed

    if os.path.exists(putput):
        os.remove(output)

    if type == "dec":
        os.remove("temp")

    for values in content.values():
        with open(output, "ab+") as f:
            f.write(values)
