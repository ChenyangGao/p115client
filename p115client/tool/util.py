#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "get_status_code", "is_timeouterror", "posix_escape_name", 
    "reduce_image_url_layers", "share_extract_payload", 
    "unescape_115_charref", "determine_part_size", 
]
__doc__ = "这个模块提供了一些工具函数"

from re import compile as re_compile
from typing import cast, Final, NotRequired, TypedDict
from urllib.parse import parse_qsl, urlsplit


CRE_115_CHARREF_sub: Final = re_compile("\\[\x02([0-9]+)\\]").sub
CRE_SHARE_LINK_search = re_compile(r"(?:^|(?<=/))(?P<share_code>[a-z0-9]+)(?:-|\?|\?password=)(?P<receive_code>[a-z0-9]{4})").search


class SharePayload(TypedDict):
    share_code: str
    receive_code: NotRequired[None | str]


def get_status_code(e: BaseException, /) -> None | int:
    """获取 HTTP 请求异常的状态码（如果有的话）
    """
    status = (
        getattr(e, "status", None) or 
        getattr(e, "code", None) or 
        getattr(e, "status_code", None)
    )
    if status is None and hasattr(e, "response"):
        response = e.response
        status = (
            getattr(response, "status", None) or 
            getattr(response, "code", None) or 
            getattr(response, "status_code", None)
        )
    return status


def is_timeouterror(exc: BaseException) -> bool:
    """判断是不是超时异常
    """
    exctype = type(exc)
    if issubclass(exctype, TimeoutError):
        return True
    for exctype in exctype.mro():
        if "Timeout" in exctype.__name__:
            return True
    return False


def posix_escape_name(name: str, /, repl: str = "|") -> str:
    """把文件名中的 "/" 转换为另一个字符（默认为 "|"）

    :param name: 文件名
    :param repl: 替换为的目标字符

    :return: 替换后的名字
    """
    return name.replace("/", repl)


def reduce_image_url_layers(url: str, /, size: str | int = "") -> str:
    """从图片的缩略图链接中提取信息，以减少一次 302 访问
    """
    if not url.startswith(("http://thumb.115.com/", "https://thumb.115.com/")):
        return url
    urlp = urlsplit(url)
    sha1, _, size0 = urlp.path.rsplit("/")[-1].partition("_")
    if size == "":
        size = size0 or "0"
    return f"https://imgjump.115.com/?sha1={sha1}&{urlp.query}&size={size}"


def share_extract_payload(link: str, /) -> SharePayload:
    """从链接中提取 share_code 和 receive_code
    """
    link = link.strip("/")
    if link.isalnum():
        return SharePayload(share_code=link)
    elif m := CRE_SHARE_LINK_search(link):
        return cast(SharePayload, m.groupdict())
    urlp = urlsplit(link)
    if urlp.path:
        payload = SharePayload(share_code=urlp.path.rstrip("/").rpartition("/")[-1])
        if urlp.query:
            for k, v in parse_qsl(urlp.query):
                if k == "password":
                    payload["receive_code"] = v
                    break
        return payload
    else:
        raise ValueError("can't extract share_code for {link!r}")


def unescape_115_charref(s: str, /) -> str:
    """对 115 的字符引用进行解码

    :example:

        .. code:: python

            unescape_115_charref("[\x02128074]0号：优质资源") == "👊0号：优质资源"
    """
    return CRE_115_CHARREF_sub(lambda a: chr(int(a[1])), s)


def determine_part_size(
    size: int, 
    min_part_size: int = 1024 * 1024 * 10, 
    max_part_count: int = 10 ** 4, 
) -> int:
    """确定分片上传（multipart upload）时的分片大小

    :param size: 数据大小
    :param min_part_size:  用户期望的分片大小
    :param max_part_count: 最大的分片个数

    :return: 分片大小
    """
    if size <= min_part_size:
        return size
    n = -(-size // max_part_count)
    part_size = min_part_size
    while part_size < n:
        part_size <<= 1
    return part_size

