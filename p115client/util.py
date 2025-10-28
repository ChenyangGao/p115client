#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "complete_url", "reduce_image_url_layers", "share_extract_payload", 
    "unescape_115_charref", "determine_part_size", "to_cdn_url", 
    "is_valid_id", "is_valid_sha1", "is_valid_name", "is_valid_pickcode", 
    "posix_escape_name", 
]
__doc__ = "这个模块提供了一些工具函数，且不依赖于 p115client.client 中的实现"

from collections.abc import Callable, Mapping, Sequence
from re import compile as re_compile
from string import digits, hexdigits
from typing import cast, Any, Final, NotRequired, TypedDict
from urllib.parse import parse_qsl, urlencode, urlsplit

from p115pickcode import is_valid_pickcode
from yarl import URL


URL_PATH_TRANSTAB: Final = {b: f"%{b:X}" for b in b"?#"}
CRE_115_CHARREF_sub: Final = re_compile("\\[\x02([0-9]+)\\]").sub
CRE_SHARE_LINK_search: Final = re_compile(r"(?:^|(?<=/))(?P<share_code>[a-z0-9]+)(?:-|\?password=|\?)(?P<receive_code>[a-z0-9]{4})(?!==)\b").search


class SharePayload(TypedDict):
    share_code: str
    receive_code: NotRequired[None | str]


def complete_url(
    path: str | Callable[[], str] = "", 
    /, 
    base_url: str | Callable[[], str] = "", 
    app: str | Callable[[], str] = "", 
    domain: str | Callable[[], str] = "", 
    as_query: bool = False, 
    query: Mapping[str, Any] | Sequence[tuple[str, Any]] = (), 
) -> str:
    """完整 HTTP Web 接口 URL

    :param path: 请求路径
    :param base_url: 请求基地址，例如 `https://webapi.115.com`
    :param app: 使用此设备 app 的接口
    :param domain: 域，拼接位置根据 `base_url` 和 `as_query` 确定

        - 如果 `base_url` 为空，那么 `base_url` 会被处理为 `http://{domain}.115.com`
        - 如果 `as_query` 为 False，那么拼接到 `base_url` 之后
        - 如果 `as_query` 为 True，那么拼接到 `query` 之中

    :param as_query: 是否把 `path` 参数视为查询参数

        - 如果为 False，则拼接到 `base_url` 之后
        - 如果为 True，则拼接到 `query` 之中

    :param query: 其它查询参数

    :return: 接口 URL

    .. note::
        大概有以下几种接口 URL

        - `https://115.com{path}?{query}`
        - `https://{domain}.115.com{path}?{query}`
        - `https://115cdn.com/{domain}{path}?{query}`
        - `https://115vod.com/{domain}{path}?{query}`
        - `https://f.115.com/api/proxy/115?domain={domain}&path={path}&{query}`
        - `https://n.115.com/api/proxy/115?domain={domain}&path={path}&{query}`

        其中 `https://f.115.com` 和 `https://n.115.com` 可以拼接查询参数 `domain`，默认值是 "webapi"
    """
    if callable(path):
        path = path()
    if callable(base_url):
        base_url = base_url()
    if callable(app):
        app = app()
    if callable(domain):
        domain = domain()
    if path and not path.startswith("/"):
        path = "/" + path
    if base_url:
        if base_url.endswith(("://115cdn.com", "://115vod.com")):
            as_query = False
            if not domain:
                domain = "site"
    else:
        as_query = False
        if app or path.startswith("/open/"):
            base_url = "https://proapi.115.com"
        elif domain:
            if domain in ("web.api", "pro.api"):
                base_url = f"http://{domain}.115.com"
            else:
                base_url = f"https://{domain}.115.com"
        else:
            base_url = "https://webapi.115.com"
    if app and not path.startswith("/open/"):
        if app not in frozenset((
            "ios", "115ios", "ipad", "115ipad", 
            "android", "115android", "qandroid", "qios", 
            "wechatmini", "alipaymini", "tv", "apple_tv", 
        )):
            app = "android"
        path = "/" + app + path
    url = base_url
    if as_query:
        query = dict(query)
        if domain:
            query["domain"] = domain
        if path:
            query["path"] = path
    else:
        if domain:
            url += "/" + domain
        if path:
            url += path.translate(URL_PATH_TRANSTAB)
    if query_string := urlencode(query):
        sep = "&" if "?" in url else "?"
        url += sep + query_string
    return url


def reduce_image_url_layers(
    url: str, 
    /, 
    size: str | int = "", 
) -> str:
    """从图片的缩略图链接中提取信息，以减少一次 302 访问

    :param url: 图片缩略图链接
    :param size: 图片规格大小，如果为 0，则是原图大小

    :return: 提取后的图片缩略图链接
    """
    if not url.startswith("://thumb.115.com/"):
        return url
    urlp = urlsplit(url)
    sha1, _, size0 = urlp.path.rsplit("/")[-1].partition("_")
    if size == "":
        size = size0 or "0"
    return f"https://imgjump.115.com/?sha1={sha1}&{urlp.query}&size={size}"


def share_extract_payload(link: str, /) -> SharePayload:
    """从链接中提取 share_code 和 receive_code

    :param link: 分享链接

    :return: 链接信息，是一个字典，包含 2 个 key
        - "share_code": 分享码
        - "receive_code": 提取码

    .. note::
        分享链接主要有如下几种格式：

        - `https://115cdn.com/s/{share_code}?password={receive_code}`
        - `https://115.com/s/{share_code}?password={receive_code}`
        - `https://share.115.com/{share_code}?password={receive_code}`
        - `{share_code}-{receive_code}`
        - `/{share_code}-{receive_code}/`
        - `#{share_code}-{receive_code}#`
    """
    link = link.strip("/#")
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
        raise ValueError("can't extract share_code from {link!r}")


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


def to_cdn_url(
    url: str, 
    /, 
    host: str = "115cdn.com", 
) -> str:
    """尝试把 ``url`` 转换为特定 CDN 域名下的链接，如果不能转换，则原样输出

    :param url: 待转换的链接
    :param host: 域名，比如可取 "115cdn.com" 或 "https://115vod.com"

    :return: 转换后的链接
    """
    urlp = URL(url)
    original_host = urlp.host
    if original_host == "115.com":
        return str(urlp.with_host(host).with_path("/site" + urlp.path))
    elif not original_host or not original_host.endswith(".115.com") or len(original_host.split(".", 3)) > 3:
        return url
    prefix = original_host.partition(".")[0]
    if not prefix or prefix == "proapi":
        return url
    return str(urlp.with_host(host).with_path(prefix + urlp.path))


def is_valid_id(id: int | str, /) -> bool:
    if isinstance(id, int):
        return id >= 0
    if id == "0":
        return True
    return len(id) > 0 and not (id.startswith("0") or id.strip(digits))


def is_valid_sha1(sha1: str, /) -> bool:
    return len(sha1) == 40 and not sha1.strip(hexdigits)


def is_valid_name(name: str, /) -> bool:
    return not (">" in name or "/" in name)


def posix_escape_name(name: str, /, repl: str = "|") -> str:
    """把文件名中的 "/" 转换为另一个字符

    .. note::
        默认把 "/" 替换成 "|"，借鉴 `alist`。
        更一般的，可借鉴 MacOSX，替换成 ":"。

    :param name: 文件名
    :param repl: 替换为的目标字符

    :return: 替换后的名字
    """
    return name.replace("/", repl)

