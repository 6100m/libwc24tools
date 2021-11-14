from xcrypt import generate4
from struct import pack
from binascii import unhexlify
from Crypto.Cipher.AES import new, encrypt
from libnlzsstools import _compress
from rsa import sign

def u8(val):
    return pack(">B", val)

def u16(val):
    return pack(">H", val)

def u32(val):
    return pack(">I", val)

def ParseContainer(buff, aes_key, iv_key, rsa_key):
    lz = _compress(bytes(buff.read()))
    sig = sign(
        lz.read(), rsa_key.read(), "SHA-1")
    if iv_key is not None:
        try:
            iv = unhexlify(iv_key)
        except:
            iv = iv_key
    else:
        iv = generate25()[:-9]
    try:
        key = unhexlify(aes_key)
    except:
        key = aes_key.read()
    aes = AES.new(key, AES.MODE_OFB, iv=iv_key)
    enc = aes.encrypt(lz.read())
    inp_lst = [
        b"WC24",
        u32(1),
        u32(0),
        u8(1),
        u8(0) * 3,
        u8(0) * 32,
        iv,
        sig,
        enc
    ]
    # Thanks https://www.geeksforgeeks.org/python-convert-dictionary-to-concatenated-string/
    out_lst = []
    res = ' '
    for data in inp_lst:
        res += item + str(out_lst[data])
    return unhexlify(res)
