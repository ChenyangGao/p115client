#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 5)
__all__ = [
    "ALPHABET", "PREFIX_TO_TRANSTAB", "PREFIX_TO_TRANSTAB_REV", 
    "PREFIX_TO_FIRST_SUFFIX", "FIRST_SUFFIX_TO_PREFIX", 
    "get_stable_point", "is_valid_pickcode", "pickcode_to_id", 
    "id_to_pickcode", "to_id", "to_pickcode", 
]
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"

from string import ascii_lowercase, digits
from typing import Final, Literal


#: 字符表，任何一个 pickcode 只包含这 36 个字符
ALPHABET: Final = digits + ascii_lowercase
#: pickcode 的前缀对应的替换表，用来把明文转换为密文
PREFIX_TO_TRANSTAB: Final = {
    "a": str.maketrans("fuln1ytpj3smg8d5a094qh7cxkbi62zvewro", ALPHABET), 
    "b": str.maketrans("sk721n9a0emlfpcrzbqdw3gjh6ty5xui48vo", ALPHABET), 
    "c": str.maketrans("ywcz3hite6f1j0guoakvdb2ns7p8qr9ml5x4", ALPHABET), 
    "d": str.maketrans("rq2vl5o7wsken9u8tp4jg3zbyc6xmhifd01a", ALPHABET), 
    "e": str.maketrans("ljm9eqbcfhw7ktv3x1dgp5ua8y6s4znr2io0", ALPHABET), 
    "fa": str.maketrans("fumk0ytpj3sng8d5a194qh7cxlbi62zvewro", ALPHABET), 
    "fb": str.maketrans("sk732o9a1enmfpcrzbqdw4gjh6ty5xui08vl", ALPHABET), 
    "fc": str.maketrans("ywcz6hite9f4j3gup2kvdb5osal0qr1nm8x7", ALPHABET), 
    "fd": str.maketrans("on6vl0r2wpkeq9u3ts8jg7zbyc1xmhifd45a", ALPHABET), 
    "fe": str.maketrans("ljm0es2cfhwakqv6x4dgp8r1by9u7znt5io3", ALPHABET), 
}
#: pickcode 的前缀对应的替换表，用来把密文转换为明文
PREFIX_TO_TRANSTAB_REV: Final = {k: {v: k for k, v in v.items()} for k, v in PREFIX_TO_TRANSTAB.items()}
#: pickcode 的前缀（如果首字母是 "f"，则是 pickcode[:2]，否则是 pickcode[0]）和后缀首字符 pickcode[-4] 的对应关系（之所以可以如此，因为不动点左起第 1 个字符固定是 0）
PREFIX_TO_FIRST_SUFFIX: Final = {a: chr(b[ord("0")]) for a, b in PREFIX_TO_TRANSTAB.items()}
#: pickcode 的后缀首字符 pickcode[-4] 和前缀（如果首字母是 "f"，则是 pickcode[:2]，否则是 pickcode[0]）的对应关系
FIRST_SUFFIX_TO_PREFIX: Final = {v: k for k, v in PREFIX_TO_FIRST_SUFFIX.items()}


def b36encode(n: int, /) -> str:
    "数字转换为 36 进制字符串"
    if n < 0:
        return "-" + b36encode(-n)
    elif n < 36:
        return ALPHABET[n]
    chars: list[str] = []
    add_char = chars.append
    while n:
        n, r = divmod(n, 36)
        add_char(ALPHABET[r])
    return "".join(reversed(chars))


def b36decode(s: str, /) -> int:
    "36 进制字符串转换为数字"
    return int(s, 36)


def get_stable_point(pickcode: str, /) -> str:
    """获取 pickcode 所对应的不动点

    .. node::
        同一个用户，它的网盘中的所有文件或目录的 pickcode，从这个函数得到的结果都相同

    :param pickcode: 提取码、不动点或者加密后的不动点

    :return: 不动点，长度为 4，范围在 0-9 和 a-z 内的字符串，左起第 1 个字符是 0
    """
    len_pickcode = len(pickcode)
    if len_pickcode < 4:
        return "0" * (4 - len_pickcode) + pickcode
    elif len_pickcode >= 6 and pickcode[:2] in ("fa", "fb", "fc", "fd", "fe"):
        prefix = pickcode[:2]
    elif len_pickcode >= 5 and pickcode[0] in ("a", "b", "c", "d", "e"):
        prefix = pickcode[0]
    elif pickcode[-4] == "0":
        return pickcode[-4:]
    else:
        prefix = FIRST_SUFFIX_TO_PREFIX[pickcode[-4]]
    transtab = PREFIX_TO_TRANSTAB_REV[prefix]
    return pickcode[-4:].translate(transtab)


def is_valid_pickcode(pickcode: str, /) -> bool:
    """是否合法的 pickcode

    :param pickcode: 提取码

    :return: 是否合法
    """
    if not pickcode:
        return True
    elif pickcode.strip(ALPHABET):
        return False
    len_pickcode = len(pickcode)
    if pickcode.startswith("f") and len_pickcode < 7 or len_pickcode < 6:
        return False
    prefix = pickcode[:2] if pickcode.startswith("f") else pickcode[0]
    return prefix in PREFIX_TO_TRANSTAB and prefix == FIRST_SUFFIX_TO_PREFIX[pickcode[-4]]


def pickcode_to_id(pickcode: str, /) -> int:
    """从 115 的 pickcode 得到 id

    .. note::
        0. 规定根目录 id 为 0 所对应的提取码为空字符串 ""
        1. 提取码中只含有 0-9 和 a-z 这 36 个字符
        2. 提取码由 3 部分组成 `f"{前缀}{中缀}{后缀}"`，而提取码的前缀唯一确定了简单替换加密所用的替换表：

            - 前缀：如果首字母是 "f"，则是 `pickcode[:2]`，否则是 `pickcode[0]`
            - 后缀：最后 4 个字符 `pickcode[-4:]`，同一个用户，由前缀所对应的的替换表进行解密后可得一个固定值，称为不动点（它的第 1 个字符是 "0"）
            - 中缀：除去前缀和后缀剩余的部分，解密后可以得到 id 的 36 进制表示

        3. 如果 `pickcode` 的首字母是 "f"，暗示这是个目录，允许的形式有 5 种，都包含前后缀和一个经过加密的 id：

            - f"fa{加密id}4{剩余3位后缀}"
            - f"fb{加密id}w{剩余3位后缀}"
            - f"fc{加密id}r{剩余3位后缀}"
            - f"fd{加密id}5{剩余3位后缀}"
            - f"fe{加密id}3{剩余3位后缀}"

        4. 如果 `pickcode` 的首字母是 "a"、"b"、"c"、"d"、"e" 之一，暗示这是个文件，允许的结构有 5 种，都包含前后缀和一个经过加密的 id：

            - f"a{加密id}h{剩余3位后缀}"
            - f"b{加密id}8{剩余3位后缀}"
            - f"c{加密id}d{剩余3位后缀}"
            - f"d{加密id}x{剩余3位后缀}"
            - f"e{加密id}z{剩余3位后缀}"

        5. 前缀和后缀的第 1 个字符是一一对应的，可以互相推导。同一个用户的不动点固定，但不同用户不动点往往不同。     

    :param pickcode: 提取码

    :return: id
    """
    if not pickcode:
        return 0
    if pickcode.startswith("f"):
        prefix = pickcode[:2]
        cipher = pickcode[2:-4]
    else:
        prefix = pickcode[0]
        cipher = pickcode[1:-4]
    transtab = PREFIX_TO_TRANSTAB_REV[prefix]
    return b36decode(cipher.translate(transtab))


def id_to_pickcode(
    id: int, 
    /, 
    stable_point: str = "0000", 
    prefix: Literal["", "a", "b", "c", "d", "e", "fa", "fb", "fc", "fd", "fe"] = "a", 
) -> str:
    """从 115 的 id 得到 pickcode

    :param id: 文件或目录的 id
    :param stable_point: 不动点（长度为 4，范围在 0-9 和 a-z 内的字符串，左起第 1 个字符是 0），或者是 `pickcode` 或者 `pickcode[-4:]`
    :param prefix: 前缀，如果为 ""，则自动确定，确定不了时默认为 "a"

    :return: 提取码
    """
    if not id:
        return ""
    elif id < 0:
        raise ValueError(f"negtive id is not allowed, got {id!r}")
    len_stable_point = len(stable_point)
    prefix_: str = prefix or "a"
    is_stable_point = True
    if len_stable_point < 4:
        stable_point = "0" * (4 - len_stable_point) + stable_point
    elif len_stable_point >= 6 and stable_point[:2] in ("fa", "fb", "fc", "fd", "fe"):
        prefix_ = stable_point[:2]
        is_stable_point = False
    elif len_stable_point >= 5 and stable_point[0] in ("a", "b", "c", "d", "e"):
        prefix_ = stable_point[0]
        is_stable_point = False
    elif stable_point[-4] != "0":
        prefix_ = FIRST_SUFFIX_TO_PREFIX[stable_point[-4]]
        is_stable_point = False
    if len_stable_point > 4:
        stable_point = stable_point[-4:]
    transtab = PREFIX_TO_TRANSTAB[prefix or prefix_]
    if is_stable_point:
        suffix = stable_point.translate(transtab)
    elif not prefix or prefix == prefix_:
        suffix = stable_point
        prefix_ = prefix or prefix_
    else:
        stable_point = stable_point.translate(PREFIX_TO_TRANSTAB_REV[prefix_])
        suffix = stable_point.translate(transtab)
        prefix_ = prefix
    cipher = b36encode(id).translate(transtab)
    return prefix_ + cipher + suffix


def to_id(pickcode: int | str, /) -> int:
    """把可能是 id 或 pickcode 的一律转换成 id

    .. note::
        规定：根目录 id 为 0 对应的提取码是 ""

    :param pickcode: 可能是 pickcode 或 id

    :return: id
    """
    if isinstance(pickcode, int):
        id = pickcode
        if id < 0:
            raise ValueError(f"negtive id is not allowed, got {id!r}")
        return id
    if not pickcode:
        return 0
    elif pickcode.startswith(("a", "b", "c", "d", "e", "f")):
        return pickcode_to_id(pickcode)
    else:
        return int(pickcode)


def to_pickcode(
    id: int | str, 
    /, 
    stable_point: str = "0000", 
    prefix: Literal["", "a", "b", "c", "d", "e", "fa", "fb", "fc", "fd", "fe"] = "a", 
) -> str:
    """把可能是 id 或 pickcode 的一律转换成 pickcode

    .. note::
        规定：空提取码 "" 对应的 id 是 0

    :param id: 可能是 id 或 pickcode
    :param stable_point: 不动点（长度为 4，范围在 0-9 和 a-z 内的字符串，左起第 1 个字符是 0），或者是 `pickcode` 或者 `pickcode[-4:]`
    :param prefix: 前缀，如果为 ""，则自动确定，确定不了时默认为 "a"

    :return: pickcode
    """
    if not id:
        return ""
    elif isinstance(id, str):
        if id.startswith(("a", "b", "c", "d", "e", "f")):
            return id
        id = int(id)
    return id_to_pickcode(id, stable_point, prefix=prefix)

