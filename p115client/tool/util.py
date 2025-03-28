#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "get_status_code", "is_timeouterror", "posix_escape_name", "reduce_image_url_layers", 
    "share_extract_payload", "unescape_115_charref", 
]
__doc__ = "这个模块提供了一些工具函数"

from re import compile as re_compile
from typing import cast, Final, TypedDict
from urllib.parse import urlsplit


CRE_115_CHARREF_sub: Final = re_compile("\\[\x02([0-9]+)\\]").sub
CRE_SHARE_LINK_search1 = re_compile(r"(?:/s/|share\.115\.com/)(?P<share_code>[a-z0-9]+)\?password=(?:(?P<receive_code>[a-z0-9]{4}))?").search
CRE_SHARE_LINK_search2 = re_compile(r"(?P<share_code>[a-z0-9]+)(?:-(?P<receive_code>[a-z0-9]{4}))?").search


class SharePayload(TypedDict):
    share_code: str
    receive_code: None | str


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

    .. hint::
        `link` 支持 3 种形式（圆括号中的字符表示可有可无）：

        1. http(s)://115.com/s/{share_code}?password={receive_code}(#) 或 http(s)://share.115.com/{share_code}?password={receive_code}(#)
        2. (/){share_code}-{receive_code}(/)
        3. {share_code}
    """
    m = CRE_SHARE_LINK_search1(link)
    if m is None:
        m = CRE_SHARE_LINK_search2(link)
    if m is None:
        raise ValueError("not a valid 115 share link")
    return cast(SharePayload, m.groupdict())


def unescape_115_charref(s: str, /) -> str:
    """对 115 的字符引用进行解码

    :example:

        .. code:: python

            unescape_115_charref("[\x02128074]0号：优质资源") == "👊0号：优质资源"
    """
    return CRE_115_CHARREF_sub(lambda a: chr(int(a[1])), s)

