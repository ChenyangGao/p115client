#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 4)
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"
__all__ = [
    "rsa_encrypt", "rsa_decrypt", "ecdh_aes_encrypt", "ecdh_aes_decrypt", 
    "ecdh_encode_token", "ecdh_decode_token", "make_upload_payload", 
]

from collections.abc import Buffer
from base64 import b64decode, b64encode
from binascii import b2a_hex, crc32
from hashlib import md5, sha1
from random import randrange
from time import time
from typing import Final
from urllib.parse import urlencode

from .util import (
    from_bytes, to_bytes, rsa_encrypt_with_pubkey, 
    rsa_decrypt_with_pubkey, xor, rsa_gen_key, 
)


CRC_SALT: Final = b"^j>WD3Kr?J2gLFjD4W2y@"
MD5_SALT: Final = b"Qclm8MGWUv59TnrR0XPg"
G_key_l: Final  = b"x\x06\xadL3\x86]\x18L\x01?F"
G_key_s: Final  = b")#!^"

AES_PUBKEY: Final   = b"\x1d\x03\x0e\x80\xa1x\xdc\xee\xce\xcd\xa3w\xde\x12\x8d\x8e\xd9\xdd\xcfU\xaea\xedF\xea\x12\x1a\x1c\xfc\x81"
AES_KEY: Final      = b"\xfb\x1a\x19\xd6R\xf5\xaa\xf7\xbce\x1d\x0fi\xbfB/"
AES_IV: Final       = b"i\xbfB/I\x96\x05P\xa0\xadD\xec4F\xcbL"
RSA_RAND_KEY: Final = b"\x00" * 16
RSA_KEY: Final      = b"\x8d\xa5\xa5\x8d"


def rsa_encrypt(
    data: Buffer, 
    /, 
    rand_key: bytes = RSA_RAND_KEY, 
) -> bytes:
    """把数据用 RSA 公钥加密

    :param data: 数据原文
    :param randkey: 16 字节 (128 位) 的随机字节串

    :return: 数据密文
    """
    if rand_key is RSA_RAND_KEY:
        key = RSA_KEY
    else:
        key = rsa_gen_key(rand_key)
    tmp = xor(data, key)[::-1]
    xor_data = rand_key + xor(tmp, G_key_l)
    return b64encode(rsa_encrypt_with_pubkey(xor_data))


def rsa_decrypt(
    cipher_data: Buffer, 
    /, 
    rand_key: bytes = RSA_RAND_KEY, 
) -> bytearray:
    """把数据用 RSA 公钥解密

    :param cipher_data: 数据密文
    :param randkey: 16 字节 (128 位) 的随机字节串

    :return: 数据原文
    """
    if rand_key is RSA_RAND_KEY:
        key = RSA_KEY
    else:
        key = rsa_gen_key(rand_key)
    data = rsa_decrypt_with_pubkey(b64decode(cipher_data))
    view = memoryview(data)
    randkey = view[:16]
    key_l = rsa_gen_key(randkey, 12)
    tmp = memoryview(xor(view[16:], key_l))[::-1]
    return xor(tmp, key)


def ecdh_aes_encrypt(
    data: Buffer, 
    /, 
    aes_key: bytes = AES_KEY, 
    aes_iv: bytes = AES_IV, 
) -> bytes:
    """用 AES 加密数据，密钥由 ECDH 生成

    :param data: 数据原文
    :param aes_key: AES Key，16 字节 (128 位) 的随机字节串
    :param aes_iv: AES Initialization Vector，16 字节 (128 位) 的随机字节串

    :return: 数据密文
    """
    from Crypto.Cipher import AES

    if not isinstance(data, (bytes, bytearray)):
        data = bytes(data)
    pad_size = -len(data) & 15
    return AES.new(aes_key, AES.MODE_CBC, aes_iv).encrypt(
        data + to_bytes(pad_size) * pad_size)


def ecdh_aes_decrypt(
    cipher_data: Buffer, 
    /, 
    decompress: bool = False, 
    aes_key: bytes = AES_KEY, 
    aes_iv: bytes = AES_IV, 
) -> bytes:
    """用 AES 解密数据，密钥由 ECDH 生成

    :param data: 数据密文
    :param decompress: 是否用 lz4 进行解压缩
    :param aes_key: AES Key，16 字节 (128 位) 的随机字节串
    :param aes_iv: AES Initialization Vector，16 字节 (128 位) 的随机字节串

    :return: 数据原文
    """
    from Crypto.Cipher import AES

    view = memoryview(cipher_data)
    data = AES.new(aes_key, AES.MODE_CBC, aes_iv).decrypt(
        view[:len(view) & -16])
    view = memoryview(data)
    if decompress:
        from lz4.block import decompress as lz4_decompress # type: ignore
        size = view[0] + (view[1] << 8)
        return lz4_decompress(view[2:size+2], 0x2000)
    else:
        padding = view[-1]
        if view[-padding:] == bytes(view[-1:]) * padding:
            view = view[:-padding]
        return view.tobytes()


def ecdh_encode_token(
    timestamp: int, 
    /, 
    pubkey: None | bytes = None, 
) -> bytes:
    """用时间戳生成 token，并包含由 ECDH 生成的公钥

    :param timestamp: 时间戳，单位：秒
    :param pubkey: ECDH 生成的公钥，如果为空则用默认

    :return: token
    """
    token = bytearray()
    if pubkey:
        r1, r2 = randrange(256), randrange(256)
        ts = to_bytes(timestamp, (timestamp.bit_length() + 0b111) >> 3)
        token.extend(pubkey[i] ^ r1 for i in range(15))
        token.append(r1)
        token.append(0x73 ^ r1)
        token.extend((r1,) * 3)
        token.extend(r1 ^ ts[3-i] for i in range(4))
        token.extend(pubkey[i] ^ r2 for i in range(15, len(pubkey)))
        token.append(r2)
        token.append(0x01 ^ r2)
        token.extend((r2,) * 3)
        crc = crc32(CRC_SALT + token) & 0xffffffff
        h_crc32 = to_bytes(crc, 4)
        token.extend(h_crc32[3-i] for i in range(4))
    else:
        token += b"\x1d\x03\x0e\x80\xa1x\xdc\xee\xce\xcd\xa3w\xde\x12\x8d\x00s\x00\x00\x00"
        token += to_bytes(timestamp, 4, byteorder="little")
        token += b"\x8e\xd9\xdd\xcfU\xaea\xedF\xea\x12\x1a\x1c\xfc\x81\x00\x01\x00\x00\x00"
        token += to_bytes(crc32(b"^j>WD3Kr?J2gLFjD4W2y@" + token), 4, byteorder="little")
    return b64encode(token)


def ecdh_decode_token(token: str | bytes, /) -> tuple[int, bytes]:
    """解密 token 数据

    :param token: token

    :return: (timestamp, pub_key) 的 2 元组
    """
    data = b64decode(token)
    r1 = data[15]
    r2 = data[39]
    return (
        from_bytes(bytes(i ^ r1 for i in data[20:24]), byteorder="little"), 
        bytes(c ^ r1 for c in data[:15]) + bytes(c ^ r2 for c in data[24:39]), 
    )


def make_upload_payload(payload: dict, /) -> dict:
    """为上传构建 HTTP 请求参数
    """
    t = payload["t"] = int(time())
    sig_sha1 = sha1(payload["userkey"].encode("ascii"))
    sig_sha1.update(b2a_hex(sha1(bytes("{userid}{fileid}{target}0".format_map(payload), "ascii")).digest()))
    sig_sha1.update(b"000000")
    payload["sig"] = sig_sha1.hexdigest().upper()
    token_md5 = md5(MD5_SALT)
    token_md5.update("{fileid}{filesize}{sign_key}{sign_val}{userid}{t}".format_map(payload).encode("ascii"))
    token_md5.update(b2a_hex(md5(b"%d" % int(payload["userid"])).digest()))
    token_md5.update(payload["appversion"].encode("ascii"))
    payload["token"] = token_md5.hexdigest()
    return {
        "params": {"k_ec": ecdh_encode_token(t).decode("ascii")}, 
        "data": ecdh_aes_encrypt(urlencode(sorted((k, v) for k, v in payload.items() if v)).encode("latin-1")), 
    }

