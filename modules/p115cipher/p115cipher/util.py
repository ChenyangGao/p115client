#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "rsa_encrypt_with_pubkey", "rsa_decrypt_with_pubkey", 
    "generate_ecdh_pair", "xor", 
]

from collections.abc import Buffer, Iterator
from typing import Final, Literal


G_kts: Final = bytes((
    0xf0, 0xe5, 0x69, 0xae, 0xbf, 0xdc, 0xbf, 0x8a, 0x1a, 0x45, 0xe8, 0xbe, 0x7d, 0xa6, 0x73, 0xb8, 
    0xde, 0x8f, 0xe7, 0xc4, 0x45, 0xda, 0x86, 0xc4, 0x9b, 0x64, 0x8b, 0x14, 0x6a, 0xb4, 0xf1, 0xaa, 
    0x38, 0x01, 0x35, 0x9e, 0x26, 0x69, 0x2c, 0x86, 0x00, 0x6b, 0x4f, 0xa5, 0x36, 0x34, 0x62, 0xa6, 
    0x2a, 0x96, 0x68, 0x18, 0xf2, 0x4a, 0xfd, 0xbd, 0x6b, 0x97, 0x8f, 0x4d, 0x8f, 0x89, 0x13, 0xb7, 
    0x6c, 0x8e, 0x93, 0xed, 0x0e, 0x0d, 0x48, 0x3e, 0xd7, 0x2f, 0x88, 0xd8, 0xfe, 0xfe, 0x7e, 0x86, 
    0x50, 0x95, 0x4f, 0xd1, 0xeb, 0x83, 0x26, 0x34, 0xdb, 0x66, 0x7b, 0x9c, 0x7e, 0x9d, 0x7a, 0x81, 
    0x32, 0xea, 0xb6, 0x33, 0xde, 0x3a, 0xa9, 0x59, 0x34, 0x66, 0x3b, 0xaa, 0xba, 0x81, 0x60, 0x48, 
    0xb9, 0xd5, 0x81, 0x9c, 0xf8, 0x6c, 0x84, 0x77, 0xff, 0x54, 0x78, 0x26, 0x5f, 0xbe, 0xe8, 0x1e, 
    0x36, 0x9f, 0x34, 0x80, 0x5c, 0x45, 0x2c, 0x9b, 0x76, 0xd5, 0x1b, 0x8f, 0xcc, 0xc3, 0xb8, 0xf5, 
))
ECDH_REMOTE_PUBKEY: Final = bytes((
    0x57, 0xA2, 0x92, 0x57, 0xCD, 0x23, 0x20, 0xE5, 0xD6, 0xD1, 0x43, 0x32, 0x2F, 0xA4, 0xBB, 0x8A, 
    0x3C, 0xF9, 0xD3, 0xCC, 0x62, 0x3E, 0xF5, 0xED, 0xAC, 0x62, 0xB7, 0x67, 0x8A, 0x89, 0xC9, 0x1A, 
    0x83, 0xBA, 0x80, 0x0D, 0x61, 0x29, 0xF5, 0x22, 0xD0, 0x34, 0xC8, 0x95, 0xDD, 0x24, 0x65, 0x24, 
    0x3A, 0xDD, 0xC2, 0x50, 0x95, 0x3B, 0xEE, 0xBA, 
))
RSA_PUBKEY_PAIR: Final = (
    0x8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683, 
    0x10001, 
)


from_bytes = int.from_bytes
to_bytes   = int.to_bytes


def acc_step(
    start: int, 
    stop: None | int = None, 
    step: int = 1, 
) -> Iterator[tuple[int, int, int]]:
    if stop is None:
        start, stop = 0, start
    for i in range(start + step, stop, step):
        yield start, (start := i), step
    if start != stop:
        yield start, stop, stop - start


def bytes_xor(
    v1: Buffer, 
    v2: Buffer, 
    /, 
    size: int = 0, 
    byteorder: Literal["little", "big"] = "big", 
) -> bytes:
    if size:
        v1 = memoryview(v1)[:size]
        v2 = memoryview(v2)[:size]
    else:
        size = len(memoryview(v1))
    return to_bytes(from_bytes(v1) ^ from_bytes(v2), size, byteorder=byteorder)


def xor(
    src: Buffer, 
    key: Buffer, 
    /, 
    byteorder: Literal["little", "big"] = "big", 
) -> bytearray:
    src = memoryview(src)
    key = memoryview(key)
    secret = bytearray()
    if i := len(src) & 0b11:
        secret += bytes_xor(src, key, i, byteorder=byteorder)
    for i, j, s in acc_step(i, len(src), len(key)):
        secret += bytes_xor(src[i:j], key[:s], byteorder=byteorder)
    return secret


def generate_ecdh_pair() -> tuple[bytes, bytes]:
    """获取 AES 密钥对（基于 ECC-DH 协议）

    :return: (公钥, 私钥) 的 2 元组

    .. code::

        aes_pubkey, aes_secret = generate_ecdh_pair()
        aes_key = secret[:16]
        aes_iv  = secret[-16:]
    """
    from ecdsa import ECDH, NIST224p, SigningKey # type: ignore

    secret_key = SigningKey.generate(NIST224p)
    public_key = secret_key.verifying_key
    ecdh = ECDH(NIST224p)
    ecdh.load_private_key(secret_key)
    ecdh.load_received_public_key_bytes(ECDH_REMOTE_PUBKEY)
    public = public_key.pubkey.point.to_bytes()
    x, y = public[:28], public[28:]
    pubkey = bytes((28 + 1, 0x02 + (from_bytes(y) & 1))) + x
    # NOTE: Roughly equivalent to
    # n = int((ecdh.public_key.pubkey.point * from_bytes(secret_key.to_string())).x())
    # secret = to_bytes(n, (n.bit_length() + 0b111) >> 3)
    secret = ecdh.generate_sharedsecret_bytes()
    return pubkey, secret


def rsa_gen_key(
    rand_key: bytes, 
    sk_len: int = 4, 
    /, 
) -> bytearray:
    xor_key = bytearray(sk_len)
    length = sk_len * (sk_len - 1)
    index = 0
    for i in range(sk_len):
        x = (rand_key[i] + G_kts[index]) & 0xff
        xor_key[i] = G_kts[length] ^ x
        length -= sk_len
        index += sk_len
    return xor_key


def pad_pkcs1_v1_5(message: Buffer, /) -> int:
    data = bytearray(b"\x00")
    data += b"\x02" * (126 - len(memoryview(message)))
    data += b"\x00"
    data += message
    return from_bytes(data)


def rsa_encrypt_with_pubkey(data: Buffer, /) -> bytes:
    "把数据用 RSA 公钥加密"
    cipher_data = bytearray()
    view = memoryview(data)
    for l, r, _ in acc_step(0, len(view), 117):
        cipher_data += to_bytes(pow(pad_pkcs1_v1_5(view[l:r]), RSA_PUBKEY_PAIR[1], RSA_PUBKEY_PAIR[0]), 128)
    return cipher_data


def rsa_decrypt_with_pubkey(cipher_data: Buffer, /) -> bytearray:
    "把数据用 RSA 公钥解密"
    data = bytearray()
    view = memoryview(cipher_data)
    for l, r, _ in acc_step(0, len(view), 128):
        p = pow(from_bytes(view[l:r]), RSA_PUBKEY_PAIR[1], RSA_PUBKEY_PAIR[0])
        b = to_bytes(p, (p.bit_length() + 0b111) >> 3)
        data += memoryview(b)[b.index(0)+1:]
    return data

