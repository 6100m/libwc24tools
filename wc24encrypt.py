from xcrypt import generate25
from struct import pack
from binascii import unhexlify
from Crypto.Cipher.AES import new, encrypt
from nlzss_mod import _compress
from rsa import sign

def u8(i):
    return pack(">B", i)

def u16(i):
    return pack(">H", i)

def u32(i):
    return pack(">I", i)

def Parser(buff, aes_, iv_, key):
    lz = _compress(bytes(buff.read()))
    sig = sign(lz.read(), key.read(), "SHA-1")
    if iv_ is not None:
        try:
            iv = unhexlify(iv_)
        except:
            iv = iv_
    else:
        iv = generate25()[:-9]
    try:
        key = unhexlify(aes_)
    except:
        key = aes_
    aes = new(key, AES.MODE_OFB, iv=iv_)
    enc = encrypt(lz.read())
    inp = [
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
    # Thanks:
    # geeksforgeeks.org/python-convert-dictionary-to-concatenated-string
    out = []
    buf = ' '
    for data in inp:
        buf += item + str(out[data])
    return unhexlify(buf)
