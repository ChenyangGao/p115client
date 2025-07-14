#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 2)
__all__ = [
    "pickcode_to_id", "id_to_pickcode", "is_valid_pickcode", 
    "to_pickcode", "to_id", 
]
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"

from string import ascii_lowercase, digits
from typing import Final, Literal


ALPHABET: Final = digits + ascii_lowercase
FILE_GROUP_TO_KEY: Final = {"a": "hfyr", "b": "8sfv", "c": "dxt6", "d": "x50u", "e": "zlvx"}
FILE_KEY_TO_TRANSTABS: Final = {
    "hfyr": str.maketrans(ALPHABET, "fuln1ytpj3smg8d5a094qh7cxkbi62zvewro"), 
    "8sfv": str.maketrans(ALPHABET, "sk721n9a0emlfpcrzbqdw3gjh6ty5xui48vo"),
    "dxt6": str.maketrans(ALPHABET, "ywcz3hite6f1j0guoakvdb2ns7p8qr9ml5x4"),
    "x50u": str.maketrans(ALPHABET, "rq2vl5o7wsken9u8tp4jg3zbyc6xmhifd01a"),
    "zlvx": str.maketrans(ALPHABET, "ljm9eqbcfhw7ktv3x1dgp5ua8y6s4znr2io0"),
}
FILE_KEY_TO_TRANSTABS_REV: Final = {
    k: {v: k for k, v in v.items()} for k, v in FILE_KEY_TO_TRANSTABS.items()}
DIR_GROUP_TO_KEY: Final = {"a": "4fyr", "b": "wsfv", "c": "rmt6", "d": "5y6u", "e": "3wmx"}
DIR_KEY_TO_TRANSTABS: Final = {
    "4fyr": str.maketrans(ALPHABET, "fumk0ytpj3sng8d5a194qh7cxlbi62zvewro"), 
    "wsfv": str.maketrans(ALPHABET, "sk732o9a1enmfpcrzbqdw4gjh6ty5xui08vl"), 
    "rmt6": str.maketrans(ALPHABET, "ywcz6hite9f4j3gup2kvdb5osal0qr1nm8x7"),
    "5y6u": str.maketrans(ALPHABET, "on6vl0r2wpkeq9u3ts8jg7zbyc1xmhifd45a"), 
    "3wmx": str.maketrans(ALPHABET, "ljm0es2cfhwakqv6x4dgp8r1by9u7znt5io3"), 
}
DIR_KEY_TO_TRANSTABS_REV: Final = {
    k: {v: k for k, v in v.items()} for k, v in DIR_KEY_TO_TRANSTABS.items()}


def b36encode(n: int, /) -> str:
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
    return int(s, 36)


def pickcode_to_id(pickcode: str, /) -> int:
    """从 115 的 pickcode 得到 id

    .. note::
        0. 规定根目录 id 为 0 所对应的提取码为空字符串 ""
        1. 提取码 `pickcode` 中只含有 0-9 和 a-z 这 36 个字符
        2. 如果 `pickcode` 的首字母是 "f"，暗示这是个目录，允许的形式有 5 种，都包含前后缀和一个经过加密的 id：

            - f"fa{加密id}4fyr"
            - f"fb{加密id}wsfv"
            - f"fc{加密id}rmt6"
            - f"fd{加密id}5y6u"
            - f"fe{加密id}3wmx"

        3. 如果 `pickcode` 的首字母是 "a"、"b"、"c"、"d"、"e" 之一，暗示这是个文件，允许的结构有 5 种，都包含前后缀和一个经过加密的 id：

            - f"a{加密id}hfyr"
            - f"b{加密id}8sfv"
            - f"c{加密id}dxt6"
            - f"d{加密id}x50u"
            - f"e{加密id}zlvx"

        4. 后缀表示某个加密算法的 key，用来把 0-9 和 a-z 这 36 个字符打乱，然后做简单替换加密。后缀的这 4 个字符，都各自分别对应打乱后的 "05ri"
        5. 加密 id 的办法是，先把整数 id 换算成 base36，然后根据相应的后缀，算出字符映射表，然后进行简单替换加密

    :param pickcode: 提取码

    :return: id
    """
    if not pickcode:
        return 0
    elif pickcode.startswith("f"):
        b36s = pickcode[2:-4].translate(DIR_KEY_TO_TRANSTABS[pickcode[-4:]])
    else:
        b36s = pickcode[1:-4].translate(FILE_KEY_TO_TRANSTABS[pickcode[-4:]])
    return b36decode(b36s)


def id_to_pickcode(
    id: int, 
    /, 
    is_dir: bool = False, 
    key_group: Literal["a", "b", "c", "d", "e"] = "a", 
) -> str:
    """从 115 的 id 得到 pickcode

    :param id: 文件或目录的 id
    :param is_dir: 是否目录（可以乱填）
    :param key_group: 用哪一组字符映射（可以乱填）

    :return: 提取码
    """
    if not id:
        return ""
    elif id < 0:
        raise ValueError(f"negtive id is not allowed, got {id!r}")
    b36s = b36encode(id)
    if is_dir:
        key = DIR_GROUP_TO_KEY[key_group]
        transtab = DIR_KEY_TO_TRANSTABS_REV[key]
    else:
        key = FILE_GROUP_TO_KEY[key_group]
        transtab = FILE_KEY_TO_TRANSTABS_REV[key]
    pickcode = key_group + b36s.translate(transtab) + key
    if is_dir:
        pickcode = "f" + pickcode
    return pickcode


def is_valid_pickcode(pickcode: str, /) -> bool:
    """是否合法的 pickcode

    :param pickcode: 提取码

    :return: 是否合法
    """
    if not pickcode:
        return True
    elif pickcode.strip(ALPHABET):
        return False
    elif pickcode.startswith("f"):
        return DIR_GROUP_TO_KEY.get(pickcode[1]) == pickcode[-4:]
    else:
        return FILE_GROUP_TO_KEY.get(pickcode[0]) == pickcode[-4:]


def to_pickcode(id: int | str = 0, /) -> str:
    """把可能是 id 或 pickcode 的一律转换成 pickcode

    .. note::
        规定：空提取码 "" 对应的 id 是 0

    :param id: 可能是 id 或 pickcode

    :return: pickcode
    """
    if not id:
        return ""
    elif isinstance(id, str):
        if id.startswith(("a", "b", "c", "d", "e", "f")):
            return id
        id = int(id)
    return id_to_pickcode(id)


def to_id(pickcode: int | str = "", /) -> int:
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

