#!/usr/bin/env python3
# encoding: utf-8

from __future__ import annotations

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "check_response", "normalize_attr", "normalize_attr_simple", "normalize_attr_web", 
    "normalize_attr_app", "normalize_attr_app2", "P115OpenClient", "P115Client", 
]

from asyncio import Lock as AsyncLock
from base64 import b64encode
from collections.abc import (
    AsyncGenerator, AsyncIterable, Awaitable, Buffer, Callable, Coroutine, Generator, 
    ItemsView, Iterable, Iterator, Mapping, MutableMapping, Sequence, 
)
from datetime import date, datetime, timedelta
from errno import EBUSY, EEXIST, EFBIG, EINVAL, EIO, EISDIR, ENODATA, ENOENT, ENOSPC, ENOSYS, ENOTSUP
from functools import partial
from hashlib import md5, sha1
from http.cookiejar import Cookie, CookieJar
from http.cookies import Morsel
from inspect import isawaitable
from itertools import count, cycle, dropwhile, product, repeat
from math import nan
from operator import itemgetter
from os import fsdecode, fstat, isatty, stat, PathLike, path as ospath
from pathlib import Path, PurePath
from platform import system
from posixpath import splitext
from re import compile as re_compile, MULTILINE
from string import digits
from sys import exc_info
from _thread import start_new_thread
from tempfile import TemporaryFile
from threading import Lock
from time import time
from typing import cast, overload, Any, Final, Literal, Self, Unpack
from urllib.parse import quote, unquote, urlencode, urlsplit, urlunsplit
from uuid import uuid4
from warnings import warn

from argtools import argcount
from asynctools import ensure_async
from cookietools import cookies_str_to_dict, create_cookie
from dictattr import AttrDict
from filewrap import (
    bytes_iter_to_reader, bytes_iter_to_async_reader, 
    progress_bytes_iter, progress_bytes_async_iter, 
    copyfileobj, copyfileobj_async, SupportsRead, 
)
from ed2k import ed2k_hash, ed2k_hash_async, Ed2kHash
from hashtools import HashObj, file_digest, file_mdigest, file_digest_async, file_mdigest_async
from http_request import encode_multipart_data, encode_multipart_data_async, SupportsGeturl
from http_response import get_total_length
from httpfile import HTTPFileReader, AsyncHTTPFileReader
from iterutils import run_gen_step
from orjson import dumps, loads
from p115cipher.fast import rsa_encode, rsa_decode, ecdh_encode_token, ecdh_aes_encode, ecdh_aes_decode, make_upload_payload
from property import locked_cacheproperty
from re import compile as re_compile
from startfile import startfile, startfile_async # type: ignore
from undefined import undefined
from yarl import URL

from .const import CLASS_TO_TYPE, CLIENT_API_MAP, SSOENT_TO_APP, SUFFIX_TO_TYPE
from .exception import (
    AuthenticationError, BusyOSError, DataError, LoginError, NotSupportedError, 
    P115OSError, OperationalError, P115Warning, 
)
from .type import RequestKeywords, MultipartResumeData, P115Cookies, P115URL
from ._upload import buffer_length, make_dataiter, oss_upload, oss_multipart_upload


CRE_SET_COOKIE: Final = re_compile(r"[0-9a-f]{32}=[0-9a-f]{32}.*")
CRE_CLIENT_API_search: Final = re_compile(r"^ +((?:GET|POST) .*)", MULTILINE).search
CRE_COOKIES_UID_search: Final = re_compile(r"(?<=\bUID=)[^\s;]+").search
CRE_API_match: Final = re_compile(r"http://(web|pro)api.115.com(?=/|\?|#|$)").match
ED2K_NAME_TRANSTAB: Final = dict(zip(b"/|", ("%2F", "%7C")))
# 当前的系统平台
SYS_PLATFORM = system()
# 替换表，用于半角转全角，包括了 Windows 中不允许出现在文件名中的字符
match SYS_PLATFORM:
    case "Windows":
        NAME_TANSTAB_FULLWIDH = {c: chr(c+65248) for c in b"\\/:*?|><"}
    case "Darwin":
        NAME_TANSTAB_FULLWIDH = {ord("/"): ":", ord(":"): "："}
    case _:
        NAME_TANSTAB_FULLWIDH = {ord("/"): "／"}

get_proapi_origin = cycle(("http://proapi.115.com", "https://proapi.115.com")).__next__
get_webapi_origin = cycle(("http://webapi.115.com", "https://webapi.115.com")).__next__
get_cdn_origin = cycle(("http://115cdn.com", "http://115vod.com")).__next__
_default_k_ec = {"k_ec": ecdh_encode_token(0).decode()}
_default_code_verifier = "0" * 64
_default_code_challenge = b64encode(md5(b"0" * 64).digest()).decode()
_default_code_challenge_method = "md5"
_httpx_request = None


def make_prefix_generator(
    n: int = 1, 
    /, 
    seq=("/behavior", "/category", "/files", "/history", "/label", "/movies", "/offine", "/photo", "/rb", "/share", "/user", "/usershare"), 
) -> Callable[[], str]:
    if n == 0:
        return cycle(("",)).__next__
    def gen(n: int = 1, /):
        yield ""
        if n:
            yield from seq
            if n == 1:
                return
            if n >= 2:
                it: Iterable[int] = range(2, n+1)
            else:
                it = count(2)
            for i in it:
                for t in product(*repeat(seq, i)):
                    yield "".join(t)
    if n < 0:
        return gen().__next__
    elif n <= 4:
        return cycle(gen(n)).__next__
    def loop():
        while True:
            yield from gen(n)
    return loop().__next__


def complete_api(
    path: str, /, 
    base: str = "", 
    base_url: bool | str | Callable[[], str] = False, 
) -> str:
    if path and not path.startswith("/"):
        path = "/" + path
    if callable(base_url):
        base_url = base_url()
    if base_url:
        if base_url is True:
            base_url = get_cdn_origin()
            if not base:
                base = "site"
            if base and not base.startswith("/"):
                base = "/" + base
            return f"{base_url}{base}{path}"
        else:
            return f"{base_url}{path}"
    else:
        if base and not base.endswith("."):
            base = base + "."
        return f"http://{base}115.com{path}"


def complete_webapi(
    path: str, 
    /, 
    base_url: bool | str | Callable[[], str] = False, 
    get_prefix: None | Callable[[], str] = None, #make_prefix_generator(4), 
) -> str:
    if get_prefix is not None:
        if path and not path.startswith("/"):
            path = "/" + path
        path = get_prefix() + path
    if callable(base_url):
        base_url = base_url()
    if isinstance(base_url, str) and base_url:
        base = ""
    else:
        base = "webapi"
    return complete_api(path, base, base_url=base_url)


def complete_proapi(
    path: str, 
    /, 
    base_url: bool | str | Callable[[], str] = False, 
    app: str = "", 
) -> str:
    if path and not path.startswith("/"):
        path = "/" + path
    if app == "open":
        app = "android"
    if app and not app.startswith("/"):
        app = "/" + app
    if callable(base_url):
        base_url = base_url()
    elif base_url is True:
        base_url = get_proapi_origin()
    elif base_url is False:
        base_url = "https://proapi.115.com"
    elif not base_url:
        base_url = "http://proapi.115.com"
    if not app and path.startswith("/open/") and base_url == "http://proapi.115.com":
        base_url = "https://proapi.115.com"
    return f"{base_url}{app}{path}"


def complete_lixian_api(
    path: str | Mapping | Sequence[tuple], 
    /, 
    base_url: None | bool | str | Callable[[], str] = None, 
) -> str:
    if isinstance(path, str):
        path = path.lstrip("/")
    else:
        if path := urlencode(path):
            path = "?" + path
    if not path.startswith(("lixian", "web/lixian")):
        path = "/lixian/" + path
    if callable(base_url):
        base_url = base_url()
    if base_url is None:
        base = "lixian"
        base_url = False
    else:
        base = ""
    return complete_api(path, base, base_url=base_url)


def json_loads(content: Buffer, /):
    try:
        if isinstance(content, (bytes, bytearray, memoryview)):
            return loads(content)
        else:
            return loads(memoryview(content))
    except Exception as e:
        if isinstance(content, memoryview):
            content = content.tobytes()
        raise DataError(ENODATA, content) from e


def default_parse(resp, content: Buffer, /):
    if not isinstance(content, (bytes, bytearray, memoryview)):
        content = memoryview(content)
    if content and content[0] + content[-1] not in (b"{}", b"[]", b'""'):
        try:
            content = ecdh_aes_decode(content, decompress=True)
        except Exception:
            pass
    return json_loads(memoryview(content))


def get_status_code(e: BaseException, /) -> int:
    for attr in ("status", "code", "status_code"):
        if isinstance(status := getattr(e, attr, None), int):
            return status
    if response := getattr(e, "response", None):
        for attr in ("status", "code", "status_code"):
            if isinstance(status := getattr(response, attr, None), int):
                return status
    return 0


def default_check_for_relogin(e: BaseException, /) -> bool:
    return get_status_code(e) == 405


def get_default_request():
    global _httpx_request
    if _httpx_request is None:
        from httpx_request import request
        _httpx_request = partial(request, timeout=(5, 60, 60, 5))
    return _httpx_request


def parse_upload_init_response(resp, content: bytes, /) -> dict:
    data = ecdh_aes_decode(content, decompress=True)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        data = memoryview(data)
    return json_loads(data)


def items(m: Mapping, /) -> ItemsView:
    try:
        if isinstance((items := getattr(m, "items")()), ItemsView):
            return items
    except (AttributeError, TypeError):
        pass
    return ItemsView(m)


def cookies_equal(cookies1: None | str, cookies2: None | str, /) -> bool:
    if not (cookies1 and cookies2):
        return False
    if cookies1 == cookies2:
        return True
    cks1 = cookies_str_to_dict(cookies1)
    cks2 = cookies_str_to_dict(cookies2)
    return cks1.get("UID", nan) == cks2.get("UID", nan) and cks1.get("SEID", nan) == cks2.get("SEID", nan)


def convert_digest(digest, /):
    if isinstance(digest, str):
        if digest == "crc32":
            from binascii import crc32
            digest = lambda: crc32
        elif digest == "ed2k":
            digest = Ed2kHash()
    return digest


def make_url(url: str, params, /):
    query = ""
    if isinstance(params, str):
        query = params
    elif isinstance(params, Iterable):
        if not isinstance(params, (Mapping, Sequence)):
            params = tuple(params)
        query = urlencode(params)
    if query:
        if "?" in url:
            urlp = urlsplit(url)
            if urlp.query:
                urlp = urlp._replace(query=urlp.query+"&"+query)
            else:
                urlp = urlp._replace(query=query)
            url = urlunsplit(urlp)
        else:
            url += "?" + query
    return url


def make_ed2k_url(
    name: str, 
    size: int | str, 
    hash: str, 
    /, 
) -> str:
    return f"ed2k://|file|{name.translate(ED2K_NAME_TRANSTAB)}|{size}|{hash}|/"


def get_first(m: Mapping, /, *keys, default=None):
    for k in keys:
        if k in m:
            return m[k]
    return default


@overload
def check_response(resp: dict, /) -> dict:
    ...
@overload
def check_response(resp: Awaitable[dict], /) -> Coroutine[Any, Any, dict]:
    ...
def check_response(resp: dict | Awaitable[dict], /) -> dict | Coroutine[Any, Any, dict]:
    """检测 115 的某个接口的响应，如果成功则直接返回，否则根据具体情况抛出一个异常，基本上是 OSError 的实例
    """
    def check(resp, /) -> dict:
        if not isinstance(resp, dict):
            raise P115OSError(EIO, resp)
        if resp.get("state", True):
            return resp
        if code := get_first(resp, "errno", "errNo", "errcode", "errCode", "code"):
            resp.setdefault("errno", code)
            if "error" not in resp:
                resp.setdefault("error", get_first(resp, "msg", "error_msg", "message"))
            match code:
                # {"state": false, "errno": 99, "error": "请重新登录"}
                case 99:
                    raise LoginError(EIO, resp)
                # {"state": false, "errno": 911, "error": "请验证账号"}
                case 911:
                    raise AuthenticationError(EIO, resp)
                # {"state": false, "errno": 20001, "error": "目录名称不能为空"}
                case 20001:
                    raise OperationalError(EINVAL, resp)
                # {"state": false, "errno": 20004, "error": "该目录名称已存在。"}
                case 20004:
                    raise FileExistsError(EEXIST, resp)
                # {"state": false, "errno": 20009, "error": "父目录不存在。"}
                case 20009:
                    raise FileNotFoundError(ENOENT, resp)
                # {"state": false, "errno": 20018, "error": "文件不存在或已删除。"}
                # {"state": false, "errno": 50015, "error": "文件不存在或已删除。"}
                # {"state": false, "errno": 430004, "error": "文件（夹）不存在或已删除。"}
                case 20018 | 50015 | 430004:
                    raise FileNotFoundError(ENOENT, resp)
                # {"state": false, "errno": 20020, "error": "后缀名不正确，请重新输入"}
                case 20020:
                    raise OperationalError(ENOTSUP, resp)
                # {"state": false, "errno": 20021, "error": "后缀名不正确，请重新输入"}
                case 20021:
                    raise OperationalError(ENOTSUP, resp)
                # {"state": false, "errno": 31001, "error": "所预览的文件不存在。"}
                case 31001:
                    raise FileNotFoundError(ENOENT, resp)
                # {"state": false, "errno": 31004, "error": "文档未上传完整，请上传完成后再进行查看。"}
                case 31004:
                    raise FileNotFoundError(ENOENT, resp)
                # {"state": false, "errno": 50003, "error": "很抱歉，该文件提取码不存在。"}
                case 50003:
                    raise FileNotFoundError(ENOENT, resp)
                # {"state": false, "errno": 90008, "error": "文件（夹）不存在或已经删除。"}
                case 90008:
                    raise FileNotFoundError(ENOENT, resp)
                # {"state": false, "errno": 91002, "error": "不能将文件复制到自身或其子目录下。"}
                case 91002:
                    raise NotSupportedError(ENOTSUP, resp)
                # {"state": false, "errno": 91004, "error": "操作的文件(夹)数量超过5万个"}
                case 91004:
                    raise NotSupportedError(ENOTSUP, resp)
                # {"state": false, "errno": 91005, "error": "空间不足，复制失败。"}
                case 91005:
                    raise OperationalError(ENOSPC, resp)
                # {"state": false, "errno": 231011, "error": "文件已删除，请勿重复操作"}
                case 231011:
                    raise FileNotFoundError(ENOENT, resp)
                # {"state": false, "errno": 300104, "error": "文件超过200MB，暂不支持播放"}
                case 300104:
                    raise P115OSError(EFBIG, resp)
                # {"state": false, "errno": 590075, "error": "操作太频繁，请稍候再试"}
                case 590075:
                    raise BusyOSError(EBUSY, resp)
                # {"state": false, "errno": 800001, "error": "目录不存在。"}
                case 800001:
                    raise FileNotFoundError(ENOENT, resp)
                # {"state": false, "errno": 980006, "error": "404 Not Found"}
                case 980006:
                    raise NotSupportedError(ENOSYS, resp)
                # {"state": false, "errno": 990001, "error": "登陆超时，请重新登陆。"}
                case 990001:
                    # NOTE: 可能就是被下线了
                    raise AuthenticationError(EIO, resp)
                # {"state": false, "errno": 990002, "error": "参数错误。"}
                case 990002:
                    raise P115OSError(EINVAL, resp)
                # {"state": false, "errno": 990003, "error": "操作失败。"}
                case 990003:
                    raise OperationalError(EIO, resp)
                # {"state": false, "errno": 990005, "error": "你的账号有类似任务正在处理，请稍后再试！"}
                case 990005:
                    raise BusyOSError(EBUSY, resp)
                # {"state": false, "errno": 990009, "error": "删除[...]操作尚未执行完成，请稍后再试！"}
                # {"state": false, "errno": 990009, "error": "还原[...]操作尚未执行完成，请稍后再试！"}
                # {"state": false, "errno": 990009, "error": "复制[...]操作尚未执行完成，请稍后再试！"}
                # {"state": false, "errno": 990009, "error": "移动[...]操作尚未执行完成，请稍后再试！"}
                case 990009:
                    raise BusyOSError(EBUSY, resp)
                # {"state": false, "errno": 990023, "error": "操作的文件(夹)数量超过5万个"}
                case 990023:
                    raise OperationalError(ENOTSUP, resp)
                # {"state": 0, "errno": 40100000, "error": "参数错误！"}
                case 40100000:
                    raise OperationalError(EINVAL, resp)
                # {"state": 0, "errno": 40101004, "error": "IP登录异常,请稍候再登录！"}
                case 40101004:
                    raise LoginError(EIO, resp)
                # {"state": 0, "errno": 40101017, "error": "用户验证失败！"}
                case 40101017:
                    raise AuthenticationError(EIO, resp)
                # {"state": 0, "errno": 40101032, "error": "请重新登录"}
                case 40101032:
                    raise LoginError(EIO, resp)
        elif "msg_code" in resp:
            match resp["msg_code"]:
                case 50028:
                    raise P115OSError(EFBIG, resp)
                case 70004:
                    raise IsADirectoryError(EISDIR, resp)
                case 70005 | 70008:
                    raise FileNotFoundError(ENOENT, resp)
        raise P115OSError(EIO, resp)
    if isinstance(resp, dict):
        return check(resp)
    elif isawaitable(resp):
        async def check_await() -> dict:
            return check(await resp)
        return check_await()
    else:
        raise P115OSError(EIO, resp)


def normalize_attr_web(
    info: Mapping, 
    /, 
    simple: bool = False, 
    keep_raw: bool = False, 
    dict_cls: None | type[dict] = None, 
) -> dict[str, Any]:
    """翻译 `P115Client.fs_files`、`P115Client.fs_search`、`P115Client.share_snap` 等接口响应的文件信息数据，使之便于阅读

    :param info: 原始数据
    :param simple: 只提取少量必要字段 "is_dir", "id", "parent_id", "name", "sha1", "size", "pickcode", "is_collect", "ctime", "mtime", "type"
    :param keep_raw: 是否保留原始数据，如果为 True，则保存到 "raw" 字段
    :param dict_cls: 字典类型

    :return: 翻译后的 dict 类型数据
    """
    if dict_cls is None:
        if simple:
            dict_cls = dict
        else:
            dict_cls = AttrDict
    attr: dict[str, Any] = dict_cls()
    is_directory = attr["is_dir"] = "fid" not in info
    if not simple:
        attr["is_directory"] = is_directory
    if is_directory:
        attr["id"] = int(info["cid"])        # cid => category_id
        attr["parent_id"] = int(info["pid"]) # pid => parent_id
    else:
        attr["id"] = int(info["fid"])        # fid => file_id
        attr["parent_id"] = int(info["cid"])
    attr["name"] = info["n"]
    attr["sha1"] = info.get("sha") or ""
    attr["size"] = int(info.get("s") or 0)
    if "pc" in info:
        attr["pickcode"] = info["pc"]
        if not simple:
            attr["pick_code"] = attr["pickcode"]
            if "pt" in info:
                attr["pick_time"] = int(info["pt"] or 0)
            if "e" in info:
                attr["pick_expire"] = int(info["e"] or 0)
    if simple:
        if "c" in info:
            attr["is_collect"] = int(info["c"])
        if "tp" in info:
            attr["ctime"] = int(info["tp"])
        if "te" in info:
            attr["mtime"] = int(info["te"])
    else:
        attr["labels"] = info["fl"]
        if "score" in info:
            attr["score"] = int(info.get("score") or 0)
        attr["ico"] = info.get("ico", "folder" if is_directory else "")
        if "te" in info:
            attr["mtime"] = attr["user_utime"] = int(info["te"])
        if "tp" in info:
            attr["ctime"] = attr["user_ptime"] = int(info["tp"])
        if "to" in info:
            attr["atime"] = attr["user_otime"] = int(info["to"])
        if "tu" in info:
            attr["utime"] = int(info["tu"])
        if t := info.get("t"):
            if isinstance(t, (int, float)):
                attr["time"] = t
            elif t.isdecimal():
                attr["time"] = int(t)
        if "fdes" in info:
            val = info["fdes"]
            if isinstance(val, str):
                attr["desc"] = val
            attr["has_desc"] = bool(val)
        for key, name in (
            ("aid", "area_id"), 
            ("hdf", "hidden"), 
            ("hdf", "is_private"), 
            ("issct", "is_shortcut"), 
            ("ispl", "show_play_long"), 
            ("is_top", "is_top"), 
            ("iv", "is_video"), 
            ("m", "star"), 
            ("m", "is_mark"), 
            ("c", "violated"), 
            ("c", "is_collect"), 
            ("sh", "is_share"), 
            #("d", "has_desc"), 
            #("p", "has_pass"), 
        ):
            if key in info:
                attr[name] = int(info[key] or 0)
        for key, name in (
            ("dp", "dir_path"), 
            ("style", "style"), 
            ("ns", "name_show"), 
            ("cc", "cover"), 
            ("sta", "status"), 
            ("class", "class"), 
            ("u", "thumb"), 
            ("play_long", "play_long"), 
            ("audio_play_long", "audio_play_long"), 
            ("current_time", "current_time"), 
            ("last_time", "last_time"), 
            ("played_end", "played_end"), 
        ):
            if key in info:
                attr[name] = info[key]
        if vdi := info.get("vdi"):
            attr["defination"] = vdi
            match vdi:
                case 2:
                    attr["defination_str"] = "video-hd"
                case 3:
                    attr["defination_str"] = "video-fhd"
                case 4:
                    attr["defination_str"] = "video-1080p"
                case 5:
                    attr["defination_str"] = "video-4k"
                case 100:
                    attr["defination_str"] = "video-origin"
                case _:
                    attr["defination_str"] = "video-sd"
    if is_directory:
        attr["type"] = 0
    elif info.get("iv") or "vdi" in info:
        attr["type"] = 4
    elif type := CLASS_TO_TYPE.get(attr.get("class", "")):
        attr["type"] = type
    elif type := SUFFIX_TO_TYPE.get(splitext(attr["name"])[1].lower()):
        attr["type"] = type
    else:
        attr["type"] = 99
    if keep_raw:
        attr["raw"] = info
    return attr


def normalize_attr_app(
    info: Mapping, 
    /, 
    simple: bool = False, 
    keep_raw: bool = False, 
    dict_cls: None | type[dict] = None, 
) -> dict[str, Any]:
    """翻译 `P115Client.fs_files_app` 接口响应的文件信息数据，使之便于阅读

    :param info: 原始数据
    :param simple: 只提取少量必要字段 "is_dir", "id", "parent_id", "name", "sha1", "size", "pickcode", "is_collect", "ctime", "mtime", "type"
    :param keep_raw: 是否保留原始数据，如果为 True，则保存到 "raw" 字段
    :param dict_cls: 字典类型

    :return: 翻译后的 dict 类型数据
    """
    if dict_cls is None:
        if simple:
            dict_cls = dict
        else:
            dict_cls = AttrDict
    attr: dict[str, Any] = dict_cls()
    is_directory = attr["is_dir"] = info["fc"] == "0" # fc => file_category
    if not simple:
        attr["is_directory"] = is_directory
    attr["id"] = int(info["fid"])        # fid => file_id
    attr["parent_id"] = int(info["pid"]) # pid => parent_id
    attr["name"] = info["fn"]
    sha1 = attr["sha1"] = info.get("sha1") or ""
    attr["size"] = int(info.get("fs") or 0)
    if "pc" in info:
        attr["pickcode"] = info["pc"]
        if not simple:
            attr["pick_code"] = attr["pickcode"]
    if simple:
        if "ic" in info:
            attr["is_collect"] = int(info["ic"])
        if "uppt" in info:
            attr["ctime"] = int(info["uppt"])
        if "upt" in info:
            attr["mtime"] = int(info["upt"])
    else:
        attr["labels"] = info["fl"]
        attr["ico"] = info.get("ico", "folder" if attr["is_dir"] else "")
        if "ftype" in info:
            attr["file_type"] = int(info["ftype"] or 0)
        if "thumb" in info:
            thumb = info["thumb"]
            if thumb.startswith("?"):
                thumb = f"http://imgjump.115.com{thumb}&size=0&sha1={sha1}"
            attr["thumb"] = thumb
        if "uppt" in info: # pptime
            attr["ctime"] = attr["user_ptime"] = int(info["uppt"])
        if "upt" in info: # ptime
            attr["mtime"] = attr["user_utime"] = int(info["upt"])
        if "uet" in info: # utime
            attr["utime"] = int(info["uet"])
        for key, name in (
            ("aid", "area_id"), 
            ("fatr", "audio_play_long"), 
            ("fta", "status"), 
            ("ism", "star"), 
            ("ism", "is_mark"), 
            ("is_top", "is_top"), 
            ("isp", "hidden"), 
            ("isp", "is_private"), 
            ("ispl", "show_play_long"), 
            ("iss", "is_share"), 
            ("isv", "is_video"), 
            ("issct", "is_shortcut"), 
            ("ic", "violated"), 
            ("ic", "is_collect"), 
            ("unzip_status", "unzip_status"), 
        ):
            if key in info:
                attr[name] = int(info[key] or 0)
        for key, name in (
            ("def", "defination"), 
            ("def2", "defination2"), 
            ("fco", "cover"), 
            ("fco", "folder_cover"), 
            ("fdesc", "desc"), 
            ("flabel", "fflabel"), 
            ("multitrack", "multitrack"), 
            ("play_long", "play_long"), 
            ("muc", "cover"), 
            ("muc", "music_cover"), 
            ("d_img", "d_img"), 
            ("v_img", "video_img_url"), 
            ("audio_play_long", "audio_play_long"), 
            ("current_time", "current_time"), 
            ("last_time", "last_time"), 
            ("played_end", "played_end"), 
            ("uo", "source_url"), 
        ):
            if key in info:
                attr[name] = info[key]
    if is_directory:
        attr["type"] = 0
    elif (thumb := info.get("thumb")) and thumb.startswith("?"):
        attr["type"] = 2
    elif "muc" in info:
        attr["type"] = 3
    elif info.get("isv") or "def" in info or "def2" in info or "v_img" in info:
        attr["type"] = 4
    elif type := SUFFIX_TO_TYPE.get(splitext(attr["name"])[1].lower()):
        attr["type"] = type
    else:
        attr["type"] = 99
    if keep_raw:
        attr["raw"] = info
    return attr


def normalize_attr_app2(
    info: Mapping, 
    /, 
    simple: bool = False, 
    keep_raw: bool = False, 
    dict_cls: None | type[dict] = None, 
) -> dict[str, Any]:
    """翻译 `P115Client.fs_files_app2` 接口响应的文件信息数据，使之便于阅读

    :param info: 原始数据
    :param simple: 只提取少量必要字段 "is_dir", "id", "parent_id", "name", "sha1", "size", "pickcode", "is_collect", "ctime", "mtime", "type"
    :param keep_raw: 是否保留原始数据，如果为 True，则保存到 "raw" 字段
    :param dict_cls: 字典类型

    :return: 翻译后的 dict 类型数据
    """
    if dict_cls is None:
        if simple:
            dict_cls = dict
        else:
            dict_cls = AttrDict
    attr: dict[str, Any] = dict_cls()
    is_directory = attr["is_dir"] = "file_id" not in info
    if not simple:
        attr["is_directory"] = is_directory
    if is_directory:
        attr["id"] = int(info["file_id"])
        attr["parent_id"] = int(info["category_id"])
        attr["name"] = info["file_name"]
    else:
        attr["id"] = int(info["category_id"])
        attr["parent_id"] = int(info["parent_id"])
        attr["name"] = info["category_name"]
    attr["sha1"] = info.get("sha1") or ""
    attr["size"] = int(info.get("file_size") or 0)
    if "pick_code" in info:
        attr["pickcode"] = info["pick_code"]
        if not simple:
            attr["pick_code"] = attr["pickcode"]
    if simple:
        if "is_collect" in info:
            attr["is_collect"] = int(info["is_collect"])
        if "user_pptime" in info:
            attr["ctime"] = int(info["user_pptime"])
        if "user_ptime" in info:
            attr["mtime"] = int(info["user_ptime"])
    else:
        if is_directory:
            if "thumb_url" in info:
                attr["thumb"] = info["thumb_url"]
            if "file_description" in info:
                attr["desc"] = info["file_description"]
            if "file_tag" in info:
                attr["file_type"] = int(info["file_tag"])
            if "music_cover" in info:
                attr["cover"] = info["music_cover"]
            if "user_pptime" in info:
                attr["ctime"] = attr["user_ptime"] = int(info["user_pptime"])
            if "user_ptime" in info:
                attr["mtime"] = attr["user_utime"] = int(info["user_ptime"])
            if "user_utime" in info:
                attr["utime"] = int(info["user_utime"])
        else:
            if "category_desc" in info:
                attr["desc"] = info["category_desc"]
            if "category_cover" in info:
                attr["cover"] = info["category_cover"]
            if "pptime" in info:
                attr["ctime"] = attr["user_ptime"] = int(info["pptime"])
            if "ptime" in info:
                attr["mtime"] = attr["user_utime"] = int(info["ptime"])
            if "utime" in info:
                attr["utime"] = int(info["utime"])
        attr["ico"] = info.get("ico", "folder" if attr["is_dir"] else "")
        attr["labels"] = info["fl"]
        for key, name in (
            ("area_id", "area_id"), 
            ("has_desc", "has_desc"), 
            ("has_pass", "has_pass"), 
            ("is_mark", "star"), 
            ("is_mark", "is_mark"), 
            ("is_top", "is_top"), 
            ("is_private", "hidden"), 
            ("is_private", "is_private"), 
            ("show_play_long", "show_play_long"), 
            ("is_share", "is_share"), 
            ("is_video", "is_video"), 
            ("is_collect", "violated"), 
            ("is_collect", "is_collect"), 
            ("can_delete", "can_delete"), 
            ("file_category", "file_category"), 
        ):
            if key in info:
                attr[name] = int(info[key] or 0)
        for name in (
            "pick_time", "pick_expire", "file_status", "file_sort", "definition", 
            "definition2", "play_long", "current_time", "played_end", 
            "last_time", "cate_mark", "category_file_count", "category_order", 
        ):
            if name in info:
                attr[name] = int(info[name] or 0)
        for name in (
            "file_eda", "file_question", "file_answer", "password", "video_img_url", 
            "play_url", "d_img", 
        ):
            if name in info:
                attr[name] = info[name]
    if is_directory:
        attr["type"] = 0
    elif "thumb_url" in info:
        attr["type"] = 2
    elif "music_cover" in info or "play_url" in info:
        attr["type"] = 3
    elif info.get("is_video") or "definition" in info or "definition2" in info or "video_img_url" in info:
        attr["type"] = 4
    elif type := SUFFIX_TO_TYPE.get(splitext(attr["name"])[1].lower()):
        attr["type"] = type
    else:
        attr["type"] = 99
    if keep_raw:
        attr["raw"] = info
    return attr


def normalize_attr(
    info: Mapping, 
    /, 
    simple: bool = False, 
    keep_raw: bool = False, 
    dict_cls: None | type[dict] = None, 
) -> dict[str, Any]:
    """翻译获取自罗列目录、搜索、获取文件信息等接口的数据，使之便于阅读

    :param info: 原始数据
    :param simple: 只提取少量必要字段 "is_dir", "id", "parent_id", "name", "sha1", "size", "pickcode", "is_collect", "ctime", "mtime"
    :param keep_raw: 是否保留原始数据，如果为 True，则保存到 "raw" 字段
    :param dict_cls: 字典类型

    :return: 翻译后的 dict 类型数据
    """
    if "fn" in info:
        return normalize_attr_app(info, simple=simple, keep_raw=keep_raw, dict_cls=dict_cls)
    elif "file_id" in info or "category_id" in info:
        return normalize_attr_app2(info, simple=simple, keep_raw=keep_raw, dict_cls=dict_cls)
    else:
        return normalize_attr_web(info, simple=simple, keep_raw=keep_raw, dict_cls=dict_cls)


def normalize_attr_simple(
    info: Mapping, 
    /, 
    keep_raw: bool = False, 
) -> dict[str, Any]:
    return normalize_attr(info, simple=True, keep_raw=keep_raw)


class IgnoreCaseDict[V](dict[str, V]):

    def __contains__(self, key, /) -> bool:
        if isinstance(key, str):
            return super().__contains__(key.lower())
        return False

    def __delitem__(self, key: str, /):
        return super().__delitem__(key.lower())

    def __getitem__(self, key: str, /) -> V:
        return super().__getitem__(key.lower())

    def __setitem__(self, key: str, value: V, /):
        super().__setitem__(key.lower(), value)

    @overload # type: ignore
    @classmethod
    def fromkeys(cls, iterable: Iterable[str], value: None = None, /) -> IgnoreCaseDict[None | Any]:
        ...
    @overload
    @classmethod
    def fromkeys[T](cls, iterable: Iterable[str], value: T, /) -> IgnoreCaseDict[T]:
        ...
    @classmethod
    def fromkeys(cls, iterable: Iterable[str], value=None, /) -> IgnoreCaseDict:
        return cls(zip(map(str.lower, iterable), repeat(value)))

    @overload
    def get(self, key: str) -> None | V:
        ...
    @overload
    def get[T](self, key: str, default: T) -> V | T:
        ...
    def get(self, key: str, default=None):
        return super().get(key.lower(), default)

    def pop(self, key: str, default=undefined) -> V:
        if default is undefined:
            return super().pop(key.lower())
        return super().pop(key.lower(), default)

    def setdefault(self, key: str, default = None, /) -> V:
        return super().setdefault(key.lower(), default)

    def update(self, /, *args, **kwargs):
        update = super().update
        for arg in args:
            if not arg:
                continue
            if isinstance(arg, Mapping):
                arg = items(arg)
            update(((k.lower(), v) for k, v in arg))
        if kwargs:
            update(((k.lower(), v) for k, v in kwargs.items()))


class ClientRequestMixin:

    def __del__(self, /):
        self.close()

    @locked_cacheproperty
    def session(self, /):
        """同步请求的 session 对象
        """
        import httpx_request
        from httpx import Client, HTTPTransport, Limits
        session = Client(
            limits=Limits(max_connections=256, max_keepalive_connections=64, keepalive_expiry=10), 
            transport=HTTPTransport(retries=5), 
            verify=False, 
        )
        setattr(session, "_headers", self.headers)
        setattr(session, "_cookies", self.cookies)
        return session

    @locked_cacheproperty
    def async_session(self, /):
        """异步请求的 session 对象
        """
        import httpx_request
        from httpx import AsyncClient, AsyncHTTPTransport, Limits
        session = AsyncClient(
            limits=Limits(max_connections=256, max_keepalive_connections=64, keepalive_expiry=10), 
            transport=AsyncHTTPTransport(retries=5), 
            verify=False, 
        )
        setattr(session, "_headers", self.headers)
        setattr(session, "_cookies", self.cookies)
        return session

    @property
    def cookies(self, /):
        """请求所用的 Cookies 对象（同步和异步共用）
        """
        try:
            return self.__dict__["cookies"]
        except KeyError:
            from httpx import Cookies
            cookies = self.__dict__["cookies"] = Cookies()
            return cookies

    @cookies.setter
    def cookies(
        self, 
        cookies: None | str | Mapping[str, None | str] | Iterable[Mapping | Cookie | Morsel] = None, 
        /, 
    ):
        """更新 cookies
        """
        cookiejar = self.cookiejar
        if cookies is None:
            cookiejar.clear()
            return
        if isinstance(cookies, str):
            cookies = cookies.strip().rstrip(";")
            if not cookies:
                return
            cookies = cookies_str_to_dict(cookies)
            if not cookies:
                return
        set_cookie = cookiejar.set_cookie
        clear_cookie = cookiejar.clear
        cookie: Mapping | Cookie | Morsel
        if isinstance(cookies, Mapping):
            if not cookies:
                return
            for key, val in items(cookies):
                if val:
                    set_cookie(create_cookie(key, val, domain=".115.com"))
                else:
                    for cookie in cookiejar:
                        if cookie.name == key:
                            clear_cookie(domain=cookie.domain, path=cookie.path, name=cookie.name)
                            break
        else:
            from httpx import Cookies
            if isinstance(cookies, Cookies):
                cookies = cookies.jar
            for cookie in cookies:
                set_cookie(create_cookie("", cookie))

    @property
    def cookiejar(self, /) -> CookieJar:
        """请求所用的 CookieJar 对象（同步和异步共用）
        """
        return self.cookies.jar

    @property
    def cookies_str(self, /) -> P115Cookies:
        """所有 .115.com 域下的 cookie 值
        """
        return P115Cookies.from_cookiejar(self.cookiejar)

    @locked_cacheproperty
    def headers(self, /) -> MutableMapping:
        """请求头，无论同步还是异步请求都共用这个请求头
        """
        from multidict import CIMultiDict
        return CIMultiDict({
            "accept": "application/json, text/plain, */*", 
            "accept-encoding": "gzip, deflate", 
            "connection": "keep-alive", 
            "user-agent": "Mozilla/5.0 AppleWebKit/600 Safari/600 Chrome/124.0.0.0", 
        })

    def close(self, /) -> None:
        """删除 session 和 async_session 属性，如果它们未被引用，则应该会被自动清理
        """
        self.__dict__.pop("session", None)
        self.__dict__.pop("async_session", None)

    def request(
        self, 
        /, 
        url: str, 
        method: str = "GET", 
        params = None, 
        data = None, 
        *, 
        ecdh_encrypt: bool = False, 
        async_: Literal[False, True] = False, 
        request: None | Callable[[Unpack[RequestKeywords]], Any] = None, 
        **request_kwargs, 
    ):
        """帮助函数：可执行同步和异步的网络请求

        :param url: HTTP 的请求链接
        :param method: HTTP 的请求方法
        :param params: 查询参数
        :param ecdh_encrypt: 使用 ecdh 算法进行加密（返回值也要解密）
        :param async_: 说明 `request` 是同步调用还是异步调用
        :param request: HTTP 请求调用，如果为 None，则默认用 httpx 执行请求
            如果传入调用，则必须至少能接受以下几个关键词参数：

            - url:     HTTP 的请求链接
            - method:  HTTP 的请求方法
            - headers: HTTP 的请求头
            - data:    HTTP 的请求体
            - parse:   解析 HTTP 响应的方法，默认会构建一个 Callable，会把响应的字节数据视为 JSON 进行反序列化解析

                - 如果为 None，则直接把响应对象返回
                - 如果为 ...(Ellipsis)，则把响应对象关闭后将其返回
                - 如果为 True，则根据响应头来确定把响应得到的字节数据解析成何种格式（反序列化），请求也会被自动关闭
                - 如果为 False，则直接返回响应得到的字节数据，请求也会被自动关闭
                - 如果为 Callable，则使用此调用来解析数据，接受 1-2 个位置参数，并把解析结果返回给 `request` 的调用者，请求也会被自动关闭
                    - 如果只接受 1 个位置参数，则把响应对象传给它
                    - 如果能接受 2 个位置参数，则把响应对象和响应得到的字节数据（响应体）传给它

        :param request_kwargs: 其余的请求参数，会被传给 `request`

        :return: 直接返回 `request` 执行请求后的返回值

        .. note:: 
            `request` 可以由不同的请求库来提供，下面是封装了一些模块

            1. `httpx_request <https://pypi.org/project/httpx_request/>`_，由 `httpx <https://pypi.org/project/httpx/>`_ 封装，支持同步和异步调用，本模块默认用的就是这个封装

                .. code:: python

                    from httpx_request import request

            2. `python-urlopen <https://pypi.org/project/python-urlopen/>`_，由 `urllib.request.urlopen <https://docs.python.org/3/library/urllib.request.html#urllib.request.urlopen>`_ 封装，支持同步调用，性能相对最差

                .. code:: python

                    from urlopen import request

            3. `urllib3_request <https://pypi.org/project/urllib3_request/>`_，由 `urllib3 <https://pypi.org/project/urllib3/>`_ 封装，支持同步调用，性能相对较好，推荐使用

                .. code:: python

                    from urllib3_request import request

            4. `requests_request <https://pypi.org/project/requests_request/>`_，由 `requests <https://pypi.org/project/requests/>`_ 封装，支持同步调用

                .. code:: python

                    from requests_request import request

            5. `aiohttp_client_request <https://pypi.org/project/aiohttp_client_request/>`_，由 `aiohttp <https://pypi.org/project/aiohttp/>`_ 封装，支持异步调用，异步并发能力最强，推荐使用

                .. code:: python

                    from aiohttp_client_request import request

            6. `blacksheep_client_request <https://pypi.org/project/blacksheep_client_request/>`_，由 `blacksheep <https://pypi.org/project/blacksheep/>`_ 封装，支持异步调用

                .. code:: python

                    from blacksheep_client_request import request
        """
        if url.startswith("//"):
            url = "http:" + url
        elif not url.startswith(("http://", "https://")):
            if url.startswith("?"):
                url = "http://115.com" + url
            else:
                if not url.startswith("/"):
                    url = "/" + url
                if url.startswith(("/app/", "/android/", "/115android/", "/ios/", "/115ios/", "/115ipad/", "/wechatmini/", "/alipaymini/")):
                    url = "http://proapi.115.com" + url
                else:
                    url = "http://webapi.115.com" + url
        if params:
            url = make_url(url, params)
        if request is None:
            request_kwargs["session"] = self.async_session if async_ else self.session
            request_kwargs["async_"] = async_
            headers: IgnoreCaseDict[str] = IgnoreCaseDict()
            request = get_default_request()
        else:
            headers = IgnoreCaseDict(self.headers)
        headers.update(request_kwargs.get("headers") or {})
        if m := CRE_API_match(url):
            headers["host"] = m.expand(r"\1.api.115.com")
        request_kwargs["headers"] = headers
        if ecdh_encrypt:
            url = make_url(url, _default_k_ec)
            if data:
                request_kwargs["data"] = ecdh_aes_encode(urlencode(data).encode("latin-1") + b"&")
            headers["content-type"] = "application/x-www-form-urlencoded"
        elif isinstance(data, (list, dict)):
            request_kwargs["data"] = urlencode(data).encode("latin-1")
            headers["content-type"] = "application/x-www-form-urlencoded"
        elif data is not None:
            request_kwargs["data"] = data
        request_kwargs.setdefault("parse", default_parse)
        return request(url=url, method=method, **request_kwargs)

    ########## Qrcode API ##########

    @overload
    @staticmethod
    def login_qrcode(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> bytes:
        ...
    @overload
    @staticmethod
    def login_qrcode(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, bytes]:
        ...
    @staticmethod
    def login_qrcode(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> bytes | Coroutine[Any, Any, bytes]:
        """下载登录二维码图片

        GET https://qrcodeapi.115.com/api/1.0/web/1.0/qrcode

        :params uid: 二维码的 uid

        :return: 图片的二进制数据（PNG 图片）
        """
        api = "https://qrcodeapi.115.com/api/1.0/web/1.0/qrcode"
        if isinstance(payload, str):
            payload = {"uid": payload}
        request_kwargs.setdefault("parse", False)
        if request is None:
            return get_default_request()(url=api, params=payload, async_=async_, **request_kwargs)
        else:
            return request(url=api, params=payload, **request_kwargs)

    @overload
    @staticmethod
    def login_qrcode_access_token_open(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @staticmethod
    def login_qrcode_access_token_open(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def login_qrcode_access_token_open(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """绑定扫码并获取开放平台应用的 access_token 和 refresh_token

        POST https://qrcodeapi.115.com/open/deviceCodeToToken

        .. note::
            https://www.yuque.com/115yun/open/shtpzfhewv5nag11#QCCVQ

        :payload:
            - uid: str
            - code_verifier: str = <default> 💡 默认字符串是 64 个 "0"
        """
        api = "https://qrcodeapi.115.com/open/deviceCodeToToken"
        if isinstance(payload, str):
            payload = {"uid": payload, "code_verifier": _default_code_verifier}
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, method="POST", data=payload, async_=async_, **request_kwargs)
        else:
            return request(url=api, method="POST", data=payload, **request_kwargs)

    @overload
    @staticmethod
    def login_qrcode_refresh_token_open(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @staticmethod
    def login_qrcode_refresh_token_open(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def login_qrcode_refresh_token_open(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """用一个 refresh_token 去获取新的 access_token 和 refresh_token，然后原来的 refresh_token 作废

        POST https://qrcodeapi.115.com/open/refreshToken

        .. note::
            https://www.yuque.com/115yun/open/shtpzfhewv5nag11#ve54x

        :payload:
            - refresh_token: str
        """
        api = "https://qrcodeapi.115.com/open/refreshToken"
        if isinstance(payload, str):
            payload = {"refresh_token": payload}
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, method="POST", data=payload, async_=async_, **request_kwargs)
        else:
            return request(url=api, method="POST", data=payload, **request_kwargs)

    @overload
    @staticmethod
    def login_qrcode_scan_cancel(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @staticmethod
    def login_qrcode_scan_cancel(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def login_qrcode_scan_cancel(
        payload: str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """取消扫描二维码，payload 数据取自 `login_qrcode_scan` 接口响应

        GET https://hnqrcodeapi.115.com/api/2.0/cancel.php

        :payload:
            - key: str
            - uid: str
            - client: int = 0
        """
        api = "https://hnqrcodeapi.115.com/api/2.0/cancel.php"
        if isinstance(payload, str):
            payload = {"key": payload, "uid": payload, "client": 0}
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, params=payload, async_=async_, **request_kwargs)
        else:
            return request(url=api, params=payload, **request_kwargs)

    @overload
    @staticmethod
    def login_qrcode_scan_result(
        uid: str, 
        app: str = "alipaymini", 
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @staticmethod
    def login_qrcode_scan_result(
        uid: str, 
        app: str = "alipaymini", 
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def login_qrcode_scan_result(
        uid: str, 
        app: str = "alipaymini", 
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取扫码登录的结果，包含 cookie

        POST https://passportapi.115.com/app/1.0/{app}/1.0/login/qrcode/

        :param uid: 扫码的 uid
        :param app: 绑定的 app
        :param request: 自定义请求函数
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 接口返回值
        """
        if app == "desktop":
            app = "web"
        api = f"http://passportapi.115.com/app/1.0/{app}/1.0/login/qrcode/"
        payload = {"account": uid}
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, method="POST", data=payload, async_=async_, **request_kwargs)
        else:
            return request(url=api, method="POST", data=payload, **request_kwargs)

    @overload
    @staticmethod
    def login_qrcode_scan_status(
        payload: dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @staticmethod
    def login_qrcode_scan_status(
        payload: dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def login_qrcode_scan_status(
        payload: dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取二维码的状态（未扫描、已扫描、已登录、已取消、已过期等），payload 数据取自 `login_qrcode_token` 接口响应

        GET https://qrcodeapi.115.com/get/status/

        .. note::
            https://www.yuque.com/115yun/open/shtpzfhewv5nag11#lAsp2

        :payload:
            - uid: str
            - time: int
            - sign: str
        """
        api = "https://qrcodeapi.115.com/get/status/"
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, params=payload, async_=async_, **request_kwargs)
        else:
            return request(url=api, params=payload, **request_kwargs)

    @overload
    @staticmethod
    def login_qrcode_token(
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @staticmethod
    def login_qrcode_token(
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def login_qrcode_token(
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取登录二维码，扫码可用

        GET https://qrcodeapi.115.com/api/1.0/web/1.0/token/
        """
        api = "https://qrcodeapi.115.com/api/1.0/web/1.0/token/"
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, async_=async_, **request_kwargs)
        else:
            return request(url=api, **request_kwargs)

    @overload
    @staticmethod
    def login_qrcode_token_open(
        payload: int | str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @staticmethod
    def login_qrcode_token_open(
        payload: int | str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def login_qrcode_token_open(
        payload: int | str | dict, 
        /, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取开放平台的登录二维码，扫码可用

        POST https://qrcodeapi.115.com/open/authDeviceCode

        .. note::
            https://www.yuque.com/115yun/open/shtpzfhewv5nag11#WzRhM

            code_challenge 默认用的字符串为 64 个 0，hash 算法为 md5

        :payload:
            - client_id: int | str 💡 AppID
            - code_challenge: str = <default> 💡 PKCE 相关参数，计算方式如下

                .. code:: python

                    from base64 import b64encode
                    from hashlib import sha256
                    from secrets import token_bytes

                    # code_verifier 可以是 43~128 位随机字符串
                    code_verifier = token_bytes(64).hex()
                    code_challenge = b64encode(sha256(code_verifier.encode()).digest()).decode()

            - code_challenge_method: str = <default> 💡 计算 `code_challenge` 的 hash 算法，支持 "md5", "sha1", "sha256"
        """
        api = "https://qrcodeapi.115.com/open/authDeviceCode"
        if isinstance(payload, (int, str)):
            payload = {
                "client_id": payload, 
                "code_challenge": _default_code_challenge, 
                "code_challenge_method": _default_code_challenge_method, 
            }
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, method="POST", data=payload, async_=async_, **request_kwargs)
        else:
            return request(url=api, method="POST", data=payload, **request_kwargs)

    @overload
    @classmethod
    def login_with_qrcode(
        cls, 
        /, 
        app: None | str = "", 
        console_qrcode: bool = True, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @classmethod
    def login_with_qrcode(
        cls, 
        /, 
        app: None | str = "", 
        console_qrcode: bool = True, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @classmethod
    def login_with_qrcode(
        cls, 
        /, 
        app: None | str = "", 
        console_qrcode: bool = True, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """二维码扫码登录

        .. hint::
            仅获取响应，如果需要更新此 `client` 的 `cookies`，请直接用 `login` 方法

        :param app: 扫二维码后绑定的 `app` （或者叫 `device`）
        :param console_qrcode: 在命令行输出二维码，否则在浏览器中打开
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 响应信息，如果 `app` 为 None 或 ""，则返回二维码信息，否则返回绑定扫码后的信息（包含 cookies）

        -----

        app 至少有 24 个可用值，目前找出 14 个：

        - web
        - ios
        - 115ios
        - android
        - 115android
        - 115ipad
        - tv
        - qandroid
        - windows
        - mac
        - linux
        - wechatmini
        - alipaymini
        - harmony

        还有几个备选（暂不可用）：

        - bios
        - bandroid
        - ipad（登录机制有些不同，暂时未破解）
        - qios（登录机制有些不同，暂时未破解）
        - desktop（就是 web，但是用 115 浏览器登录）

        :设备列表如下:

        +-------+----------+------------+-------------------------+
        | No.   | ssoent   | app        | description             |
        +=======+==========+============+=========================+
        | 01    | A1       | web        | 网页版                  |
        +-------+----------+------------+-------------------------+
        | 02    | A2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 03    | A3       | ?          | 未知: iphone            |
        +-------+----------+------------+-------------------------+
        | 04    | A4       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 05    | B1       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 06    | D1       | ios        | 115生活(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 07    | D2       | ?          | 未知: ios               |
        +-------+----------+------------+-------------------------+
        | 08    | D3       | 115ios     | 115(iOS端)              |
        +-------+----------+------------+-------------------------+
        | 09    | F1       | android    | 115生活(Android端)      |
        +-------+----------+------------+-------------------------+
        | 10    | F2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 11    | F3       | 115android | 115(Android端)          |
        +-------+----------+------------+-------------------------+
        | 12    | H1       | ipad       | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 13    | H2       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 14    | H3       | 115ipad    | 115(iPad端)             |
        +-------+----------+------------+-------------------------+
        | 15    | I1       | tv         | 115网盘(Android电视端)  |
        +-------+----------+------------+-------------------------+
        | 16    | M1       | qandriod   | 115管理(Android端)      |
        +-------+----------+------------+-------------------------+
        | 17    | N1       | qios       | 115管理(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 18    | O1       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 19    | P1       | windows    | 115生活(Windows端)      |
        +-------+----------+------------+-------------------------+
        | 20    | P2       | mac        | 115生活(macOS端)        |
        +-------+----------+------------+-------------------------+
        | 21    | P3       | linux      | 115生活(Linux端)        |
        +-------+----------+------------+-------------------------+
        | 22    | R1       | wechatmini | 115生活(微信小程序)     |
        +-------+----------+------------+-------------------------+
        | 23    | R2       | alipaymini | 115生活(支付宝小程序)   |
        +-------+----------+------------+-------------------------+
        | 24    | S1       | harmony    | 115(Harmony端)          |
        +-------+----------+------------+-------------------------+
        """
        def gen_step():
            resp = yield cls.login_qrcode_token(
                async_=async_, 
                **request_kwargs, 
            )
            qrcode_token = resp["data"]
            login_uid = qrcode_token["uid"]
            qrcode = qrcode_token.pop("qrcode", "")
            if not qrcode:
                qrcode = "http://115.com/scan/dg-" + login_uid
            if console_qrcode:
                from qrcode import QRCode # type: ignore
                qr = QRCode(border=1)
                qr.add_data(qrcode)
                qr.print_ascii(tty=isatty(1))
            else:
                url = "https://qrcodeapi.115.com/api/1.0/web/1.0/qrcode?uid=" + login_uid
                if async_:
                    yield partial(startfile_async, url)
                else:
                    startfile(url)
            while True:
                try:
                    resp = yield cls.login_qrcode_scan_status(
                        qrcode_token, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                except Exception:
                    continue
                match resp["data"].get("status"):
                    case 0:
                        print("[status=0] qrcode: waiting")
                    case 1:
                        print("[status=1] qrcode: scanned")
                    case 2:
                        print("[status=2] qrcode: signed in")
                        break
                    case -1:
                        raise LoginError(EIO, "[status=-1] qrcode: expired")
                    case -2:
                        raise LoginError(EIO, "[status=-2] qrcode: canceled")
                    case _:
                        raise LoginError(EIO, f"qrcode: aborted with {resp!r}")
            if app:
                return cls.login_qrcode_scan_result(
                    login_uid, 
                    app, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                return qrcode_token
        return run_gen_step(gen_step, async_=async_)

    @overload
    @classmethod
    def login_with_open(
        cls, 
        /, 
        app_id: int | str, 
        console_qrcode: bool = True, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @classmethod
    def login_with_open(
        cls, 
        /, 
        app_id: int | str, 
        console_qrcode: bool = True, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @classmethod
    def login_with_open(
        cls, 
        /, 
        app_id: int | str, 
        console_qrcode: bool = True, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """二维码扫码登录开放平台

        :param console_qrcode: 在命令行输出二维码，否则在浏览器中打开
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 响应信息
        """
        def gen_step():
            resp = yield cls.login_qrcode_token_open(
                app_id, 
                async_=async_, 
                **request_kwargs, 
            )
            qrcode_token = resp["data"]
            login_uid = qrcode_token["uid"]
            qrcode = qrcode_token.pop("qrcode", "")
            if not qrcode:
                qrcode = "http://115.com/scan/dg-" + login_uid
            if console_qrcode:
                from qrcode import QRCode # type: ignore
                qr = QRCode(border=1)
                qr.add_data(qrcode)
                qr.print_ascii(tty=isatty(1))
            else:
                url = "https://qrcodeapi.115.com/api/1.0/web/1.0/qrcode?uid=" + login_uid
                if async_:
                    yield partial(startfile_async, url)
                else:
                    startfile(url)
            while True:
                try:
                    resp = yield cls.login_qrcode_scan_status(
                        qrcode_token, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                except Exception:
                    continue
                match resp["data"].get("status"):
                    case 0:
                        print("[status=0] qrcode: waiting")
                    case 1:
                        print("[status=1] qrcode: scanned")
                    case 2:
                        print("[status=2] qrcode: signed in")
                        break
                    case -1:
                        raise LoginError(EIO, "[status=-1] qrcode: expired")
                    case -2:
                        raise LoginError(EIO, "[status=-2] qrcode: canceled")
                    case _:
                        raise LoginError(EIO, f"qrcode: aborted with {resp!r}")
            return cls.login_qrcode_access_token_open(
                login_uid, 
                async_=async_, 
                **request_kwargs, 
            )
        return run_gen_step(gen_step, async_=async_)

    upload_endpoint = "http://oss-cn-shenzhen.aliyuncs.com"

    def upload_endpoint_url(
        self, 
        /, 
        bucket: str, 
        object: str, 
        endpoint: None | str = None, 
    ) -> str:
        """构造上传时的 url

        :param bucket: 存储桶
        :param object: 存储对象 id
        :param endpoint: 终点 url

        :return: 上传时所用的 url
        """
        if endpoint is None:
            endpoint = self.upload_endpoint
        urlp = urlsplit(endpoint)
        return f"{urlp.scheme}://{bucket}.{urlp.netloc}/{object}"

    ########## Other Encapsulations ##########

    @overload
    def open(
        self, 
        /, 
        url: str | Callable[[], str], 
        start: int = 0, 
        seek_threshold: int = 1 << 20, 
        headers: None | Mapping = None, 
        http_file_reader_cls: None | type[HTTPFileReader] = None, 
        *, 
        async_: Literal[False] = False, 
    ) -> HTTPFileReader:
        ...
    @overload
    def open(
        self, 
        /, 
        url: str | Callable[[], str] | Callable[[], Awaitable[str]], 
        start: int = 0, 
        seek_threshold: int = 1 << 20, 
        headers: None | Mapping = None, 
        http_file_reader_cls: None | type[AsyncHTTPFileReader] = None, 
        *, 
        async_: Literal[True], 
    ) -> AsyncHTTPFileReader:
        ...
    def open(
        self, 
        /, 
        url: str | Callable[[], str] | Callable[[], Awaitable[str]], 
        start: int = 0, 
        seek_threshold: int = 1 << 20, 
        headers: None | Mapping = None, 
        http_file_reader_cls: None | type[HTTPFileReader] | type[AsyncHTTPFileReader] = None, 
        *, 
        async_: Literal[False, True] = False, 
    ) -> HTTPFileReader | AsyncHTTPFileReader:
        """打开下载链接，返回文件对象

        :param url: 115 文件的下载链接（可以从网盘、网盘上的压缩包内、分享链接中获取）

            - P115Client.download_url
            - P115Client.share_download_url
            - P115Client.extract_download_url

        :param start: 开始索引
        :param seek_threshold: 当向前 seek 的偏移量不大于此值时，调用 read 来移动文件位置（可避免重新建立连接）
        :param http_file_reader_cls: 返回的文件对象的类，需要是 `httpfile.HTTPFileReader` 的子类
        :param headers: 请求头
        :param async_: 是否异步

        :return: 返回打开的文件对象，可以读取字节数据
        """
        if headers is None:
            headers = self.headers
        else:
            headers = {**self.headers, **headers}
        if async_:
            if http_file_reader_cls is None:
                from httpfile import AsyncHttpxFileReader
                http_file_reader_cls = AsyncHttpxFileReader
            return http_file_reader_cls(
                url, # type: ignore
                headers=headers, 
                start=start, 
                seek_threshold=seek_threshold, 
            )
        else:
            if http_file_reader_cls is None:
                http_file_reader_cls = HTTPFileReader
            return http_file_reader_cls(
                url, # type: ignore
                headers=headers, 
                start=start, 
                seek_threshold=seek_threshold, 
            )

    @overload
    def ed2k(
        self, 
        /, 
        url: str | Callable[[], str], 
        headers: None | Mapping = None, 
        name: str = "", 
        *, 
        async_: Literal[False] = False, 
    ) -> str:
        ...
    @overload
    def ed2k(
        self, 
        /, 
        url: str | Callable[[], str], 
        headers: None | Mapping = None, 
        name: str = "", 
        *, 
        async_: Literal[True], 
    ) -> Coroutine[Any, Any, str]:
        ...
    def ed2k(
        self, 
        /, 
        url: str | Callable[[], str], 
        headers: None | Mapping = None, 
        name: str = "", 
        *, 
        async_: Literal[False, True] = False, 
    ) -> str | Coroutine[Any, Any, str]:
        """下载文件流并生成它的 ed2k 链接

        :param url: 115 文件的下载链接（可以从网盘、网盘上的压缩包内、分享链接中获取）
        :param headers: 请求头
        :param name: 文件名
        :param async_: 是否异步

        :return: 文件的 ed2k 链接
        """
        trantab = dict(zip(b"/|", ("%2F", "%7C")))
        if async_:
            async def request():
                async with self.open(url, headers=headers, async_=True) as file:
                    return make_ed2k_url(name or file.name, *(await ed2k_hash_async(file)))
            return request()
        else:
            with self.open(url, headers=headers) as file:
                return make_ed2k_url(name or file.name, *ed2k_hash(file))

    @overload
    def hash[T](
        self, 
        /, 
        url: str | Callable[[], str], 
        digest: str | HashObj | Callable[[], HashObj] | Callable[[], Callable[[bytes, T], T]] = "md5", 
        start: int = 0, 
        stop: None | int = None, 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[False] = False, 
    ) -> tuple[int, HashObj | T]:
        ...
    @overload
    def hash[T](
        self, 
        /, 
        url: str | Callable[[], str], 
        digest: str | HashObj | Callable[[], HashObj] | Callable[[], Callable[[bytes, T], T]] | Callable[[], Callable[[bytes, T], Awaitable[T]]] = "md5", 
        start: int = 0, 
        stop: None | int = None, 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[True], 
    ) -> Coroutine[Any, Any, tuple[int, HashObj | T]]:
        ...
    def hash[T](
        self, 
        /, 
        url: str | Callable[[], str], 
        digest: str | HashObj | Callable[[], HashObj] | Callable[[], Callable[[bytes, T], T]] | Callable[[], Callable[[bytes, T], Awaitable[T]]] = "md5", 
        start: int = 0, 
        stop: None | int = None, 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[False, True] = False, 
    ) -> tuple[int, HashObj | T] | Coroutine[Any, Any, tuple[int, HashObj | T]]:
        """下载文件流并用一种 hash 算法求值

        :param url: 115 文件的下载链接（可以从网盘、网盘上的压缩包内、分享链接中获取）
        :param digest: hash 算法

            - 如果是 str，则可以是 `hashlib.algorithms_available` 中任一，也可以是 "ed2k" 或 "crc32"
            - 如果是 HashObj (来自 python-hashtools)，就相当于是 `_hashlib.HASH` 类型，需要有 update 和 digest 等方法
            - 如果是 Callable，则返回值必须是 HashObj，或者是一个可用于累计的函数，第 1 个参数是本次所传入的字节数据，第 2 个参数是上一次的计算结果，返回值是这一次的计算结果，第 2 个参数可省略

        :param start: 开始索引，可以为负数（从文件尾部开始）
        :param stop: 结束索引（不含），可以为负数（从文件尾部开始）
        :param headers: 请求头
        :param async_: 是否异步

        :return: 元组，包含文件的 大小 和 hash 计算结果
        """
        digest = convert_digest(digest)
        if async_:
            async def request():
                nonlocal stop
                async with self.open(url, start=start, headers=headers, async_=True) as file: # type: ignore
                    if stop is None:
                        return await file_digest_async(file, digest)
                    else:
                        if stop < 0:
                            stop += file.length
                        return await file_digest_async(file, digest, stop=max(0, stop-start)) # type: ignore
            return request()
        else:
            with self.open(url, start=start, headers=headers) as file:
                if stop is None:
                    return file_digest(file, digest) # type: ignore
                else:
                    if stop < 0:
                        stop = stop + file.length
                    return file_digest(file, digest, stop=max(0, stop-start)) # type: ignore

    @overload
    def hashes[T](
        self, 
        /, 
        url: str | Callable[[], str], 
        digest: str | HashObj | Callable[[], HashObj] | Callable[[], Callable[[bytes, T], T]] = "md5", 
        *digests: str | HashObj | Callable[[], HashObj] | Callable[[], Callable[[bytes, T], T]], 
        start: int = 0, 
        stop: None | int = None, 
        headers: None | Mapping = None, 
        async_: Literal[False] = False, 
    ) -> tuple[int, list[HashObj | T]]:
        ...
    @overload
    def hashes[T](
        self, 
        /, 
        url: str | Callable[[], str], 
        digest: str | HashObj | Callable[[], HashObj] | Callable[[], Callable[[bytes, T], T]] | Callable[[], Callable[[bytes, T], Awaitable[T]]] = "md5", 
        *digests: str | HashObj | Callable[[], HashObj] | Callable[[], Callable[[bytes, T], T]] | Callable[[], Callable[[bytes, T], Awaitable[T]]], 
        start: int = 0, 
        stop: None | int = None, 
        headers: None | Mapping = None, 
        async_: Literal[True], 
    ) -> Coroutine[Any, Any, tuple[int, list[HashObj | T]]]:
        ...
    def hashes[T](
        self, 
        /, 
        url: str | Callable[[], str], 
        digest: str | HashObj | Callable[[], HashObj] | Callable[[], Callable[[bytes, T], T]] | Callable[[], Callable[[bytes, T], Awaitable[T]]] = "md5", 
        *digests: str | HashObj | Callable[[], HashObj] | Callable[[], Callable[[bytes, T], T]] | Callable[[], Callable[[bytes, T], Awaitable[T]]], 
        start: int = 0, 
        stop: None | int = None, 
        headers: None | Mapping = None, 
        async_: Literal[False, True] = False, 
    ) -> tuple[int, list[HashObj | T]] | Coroutine[Any, Any, tuple[int, list[HashObj | T]]]:
        """下载文件流并用一组 hash 算法求值

        :param url: 115 文件的下载链接（可以从网盘、网盘上的压缩包内、分享链接中获取）
        :param digest: hash 算法

            - 如果是 str，则可以是 `hashlib.algorithms_available` 中任一，也可以是 "ed2k" 或 "crc32"
            - 如果是 HashObj (来自 python-hashtools)，就相当于是 `_hashlib.HASH` 类型，需要有 update 和 digest 等方法
            - 如果是 Callable，则返回值必须是 HashObj，或者是一个可用于累计的函数，第 1 个参数是本次所传入的字节数据，第 2 个参数是上一次的计算结果，返回值是这一次的计算结果，第 2 个参数可省略

        :param digests: 同 `digest`，但可以接受多个
        :param start: 开始索引，可以为负数（从文件尾部开始）
        :param stop: 结束索引（不含），可以为负数（从文件尾部开始）
        :param headers: 请求头
        :param async_: 是否异步

        :return: 元组，包含文件的 大小 和一组 hash 计算结果
        """
        digests = (convert_digest(digest), *map(convert_digest, digests))
        if async_:
            async def request():
                nonlocal stop
                async with self.open(url, start=start, headers=headers, async_=True) as file: # type: ignore
                    if stop is None:
                        return await file_mdigest_async(file, *digests)
                    else:
                        if stop < 0:
                            stop += file.length
                        return await file_mdigest_async(file *digests, stop=max(0, stop-start)) # type: ignore
            return request()
        else:
            with self.open(url, start=start, headers=headers) as file:
                if stop is None:
                    return file_mdigest(file, *digests) # type: ignore
                else:
                    if stop < 0:
                        stop = stop + file.length
                    return file_mdigest(file, *digests, stop=max(0, stop-start)) # type: ignore

    @overload
    def read_bytes(
        self, 
        /, 
        url: str, 
        start: int = 0, 
        stop: None | int = None, 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> bytes:
        ...
    @overload
    def read_bytes(
        self, 
        /, 
        url: str, 
        start: int = 0, 
        stop: None | int = None, 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, bytes]:
        ...
    def read_bytes(
        self, 
        /, 
        url: str, 
        start: int = 0, 
        stop: None | int = None, 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> bytes | Coroutine[Any, Any, bytes]:
        """读取文件一定索引范围的数据

        :param url: 115 文件的下载链接（可以从网盘、网盘上的压缩包内、分享链接中获取）
        :param start: 开始索引，可以为负数（从文件尾部开始）
        :param stop: 结束索引（不含），可以为负数（从文件尾部开始）
        :param headers: 请求头
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数
        """
        def gen_step():
            def get_bytes_range(start, stop):
                if start < 0 or (stop and stop < 0):
                    length: int = yield self.read_bytes_range(
                        url, 
                        bytes_range="-1", 
                        headers=headers, 
                        async_=async_, 
                        **{**request_kwargs, "parse": lambda resp: get_total_length(resp)}, 
                    )
                    if start < 0:
                        start += length
                    if start < 0:
                        start = 0
                    if stop is None:
                        return f"{start}-"
                    elif stop < 0:
                        stop += length
                if stop is None:
                    return f"{start}-"
                elif start >= stop:
                    return None
                return f"{start}-{stop-1}"
            bytes_range = yield from get_bytes_range(start, stop)
            if not bytes_range:
                return b""
            return self.read_bytes_range(
                url, 
                bytes_range=bytes_range, 
                headers=headers, 
                async_=async_, 
                **request_kwargs, 
            )
        return run_gen_step(gen_step, async_=async_)

    @overload
    def read_bytes_range(
        self, 
        /, 
        url: str, 
        bytes_range: str = "0-", 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> bytes:
        ...
    @overload
    def read_bytes_range(
        self, 
        /, 
        url: str, 
        bytes_range: str = "0-", 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, bytes]:
        ...
    def read_bytes_range(
        self, 
        /, 
        url: str, 
        bytes_range: str = "0-", 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> bytes | Coroutine[Any, Any, bytes]:
        """读取文件一定索引范围的数据

        :param url: 115 文件的下载链接（可以从网盘、网盘上的压缩包内、分享链接中获取）
        :param bytes_range: 索引范围，语法符合 `HTTP Range Requests <https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests>`_
        :param headers: 请求头
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数
        """
        headers = dict(headers) if headers else {}
        if isinstance(url, P115URL) and (headers_extra := url.get("headers")):
            headers.update(headers_extra)
        headers["Accept-Encoding"] = "identity"
        headers["Range"] = f"bytes={bytes_range}"
        request_kwargs["headers"] = headers
        request_kwargs.setdefault("method", "GET")
        request_kwargs.setdefault("parse", False)
        return self.request(url, async_=async_, **request_kwargs)

    @overload
    def read_block(
        self, 
        /, 
        url: str, 
        size: int = -1, 
        offset: int = 0, 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> bytes:
        ...
    @overload
    def read_block(
        self, 
        /, 
        url: str, 
        size: int = -1, 
        offset: int = 0, 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, bytes]:
        ...
    def read_block(
        self, 
        /, 
        url: str, 
        size: int = -1, 
        offset: int = 0, 
        headers: None | Mapping = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> bytes | Coroutine[Any, Any, bytes]:
        """读取文件一定索引范围的数据

        :param url: 115 文件的下载链接（可以从网盘、网盘上的压缩包内、分享链接中获取）
        :param size: 读取字节数（最多读取这么多字节，如果遇到 EOF (end-of-file)，则会小于这个值），如果小于 0，则读取到文件末尾
        :param offset: 偏移索引，从 0 开始，可以为负数（从文件尾部开始）
        :param headers: 请求头
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数
        """
        def gen_step():
            if size == 0:
                return b""
            elif size > 0:
                stop: int | None = offset + size
            else:
                stop = None
            return self.read_bytes(
                url, 
                start=offset, 
                stop=stop, 
                headers=headers, 
                async_=async_, 
                **request_kwargs, 
            )
        return run_gen_step(gen_step, async_=async_)


class P115OpenClient(ClientRequestMixin):
    """115 的客户端对象

    .. note::
        https://www.yuque.com/115yun/open

    :param app_id_or_refresh_token: 申请到的 AppID 或 refresh_token

        - 如果是 int，视为 AppID
        - 如果是 str，如果可以解析为数字，则视为 AppID，否则视为 refresh_token

    :param console_qrcode: 当输入为 AppID 时，进行扫码。如果为 True，则在命令行输出二维码，否则在浏览器中打开
    """
    app_id: int | str
    refresh_token: str

    def __init__(
        self, 
        /, 
        app_id_or_refresh_token: int | str, 
        console_qrcode: bool = True, 
    ):
        self.init(
            app_id_or_refresh_token, 
            console_qrcode=console_qrcode, 
            instance=self, 
        )

    @overload
    @classmethod
    def init(
        cls, 
        /, 
        app_id_or_refresh_token: int | str, 
        console_qrcode: bool = True, 
        instance: None | Self = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> Self:
        ...
    @overload
    @classmethod
    def init(
        cls, 
        /, 
        app_id_or_refresh_token: int | str, 
        console_qrcode: bool = True, 
        instance: None | Self = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, Self]:
        ...
    @classmethod
    def init(
        cls, 
        /, 
        app_id_or_refresh_token: int | str, 
        console_qrcode: bool = True, 
        instance: None | Self = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> Self | Coroutine[Any, Any, Self]:
        def gen_step():
            if instance is None:
                self = cls.__new__(cls)
            else:
                self = instance
            if isinstance(app_id_or_refresh_token, str) and (
                app_id_or_refresh_token.startswith("0") or 
                app_id_or_refresh_token.strip(digits)
            ):
                resp = yield self.login_qrcode_refresh_token_open(
                    app_id_or_refresh_token, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                app_id = self.app_id = app_id_or_refresh_token
                resp = yield self.login_with_open(
                    app_id, 
                    console_qrcode=console_qrcode, 
                    async_=async_, 
                    **request_kwargs, 
                )
            check_response(resp)
            data = resp["data"]
            self.refresh_token = data["refresh_token"]
            self.access_token = data["access_token"]
            return self
        return run_gen_step(gen_step, async_=async_)

    @classmethod
    def from_token(cls, /, access_token: str, refresh_token: str) -> P115OpenClient:
        self = cls.__new__(cls)
        self.access_token = access_token
        self.refresh_token = refresh_token
        return self

    @property
    def access_token(self, /) -> str:
        return self.__dict__["access_token"]

    @access_token.setter
    def access_token(self, token, /):
        self.headers["Authorization"] = "Bearer " + token
        self.__dict__["access_token"] = token

    @property
    def upload_token(self, /) -> dict:
        token = self.__dict__.get("upload_token", {})
        if not token or token["Expiration"] < (datetime.now() - timedelta(hours=7, minutes=30)).strftime("%FT%XZ"):
            resp = self.upload_gettoken_open()
            check_response(resp)
            token = self.__dict__["upload_token"] = resp["data"]
        return token

    @overload
    def refresh_access_token(
        self, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> str:
        ...
    @overload
    def refresh_access_token(
        self, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, str]:
        ...
    def refresh_access_token(
        self, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> str | Coroutine[Any, Any, str]:
        """更新 access_token 和 refresh_token （⚠️ 目前是 7200 秒内就要求刷新一次）
        """
        def gen_step():
            resp = yield self.login_qrcode_refresh_token_open(
                self.refresh_token, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            data = resp["data"]
            self.refresh_token = data["refresh_token"]
            access_token = self.access_token = data["access_token"]
            return access_token
        return run_gen_step(gen_step, async_=async_)

    @overload
    def download_url(
        self, 
        pickcode: str, 
        /, 
        strict: bool = True, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> P115URL:
        ...
    @overload
    def download_url(
        self, 
        pickcode: str, 
        /, 
        strict: bool = True, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, P115URL]:
        ...
    def download_url(
        self, 
        pickcode: str, 
        /, 
        strict: bool = True, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> P115URL | Coroutine[Any, Any, P115URL]:
        """获取文件的下载链接，此接口是对 `download_url_info` 的封装

        .. note::
            获取的直链中，部分查询参数的解释：

            - `t`: 过期时间戳
            - `u`: 用户 id
            - `c`: 允许同时打开次数，如果为 0，则是无限次数
            - `f`: 请求时要求携带请求头
                - 如果为空，则无要求
                - 如果为 1，则需要 User-Agent（和请求直链时的一致）
                - 如果为 3，则需要 User-Agent（和请求直链时的一致） 和 Cookie（由请求直链时的响应所返回的 Set-Cookie 响应头）

        :param pickcode: 提取码
        :param strict: 如果为 True，当目标是目录时，会抛出 IsADirectoryError 异常
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 下载链接
        """
        resp = self.download_url_info_open(
            pickcode, 
            async_=async_, 
            **request_kwargs, 
        )
        def get_url(resp: dict, /) -> P115URL:
            resp["pickcode"] = pickcode
            check_response(resp)
            for fid, info in resp["data"].items():
                url = info["url"]
                if strict and not url:
                    raise IsADirectoryError(
                        EISDIR, 
                        f"{fid} is a directory, with response {resp}", 
                    )
                return P115URL(
                    url["url"] if url else "", 
                    id=int(fid), 
                    pickcode=info["pick_code"], 
                    name=info["file_name"], 
                    size=int(info["file_size"]), 
                    sha1=info["sha1"], 
                    is_directory=not url, 
                    headers=resp["headers"], 
                )
            raise FileNotFoundError(
                ENOENT, 
                f"no such pickcode: {pickcode!r}, with response {resp}", 
            )
        if async_:
            async def async_request() -> P115URL:
                return get_url(await cast(Coroutine[Any, Any, dict], resp)) 
            return async_request()
        else:
            return get_url(cast(dict, resp))

    @overload
    def download_url_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def download_url_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def download_url_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取文件的下载链接

        POST https://proapi.115.com/open/ufile/downurl

        .. hint::
            相当于 `P115Client.download_url_app(app="chrome")`

        .. note::
            https://www.yuque.com/115yun/open/um8whr91bxb5997o

        :payload:
            - pick_code: str 💡 提取码，多个用逗号 "," 隔开
        """
        api = complete_proapi("/open/ufile/downurl", base_url)
        if isinstance(payload, str):
            payload = {"pick_code": payload}
        request_headers = request_kwargs.get("headers")
        headers = request_kwargs.get("headers")
        if headers:
            if isinstance(headers, Mapping):
                headers = ItemsView(headers)
            headers = request_kwargs["headers"] = {
                "user-agent": next((v for k, v in headers if k.lower() == "user-agent" and v), "")}
        else:
            headers = request_kwargs["headers"] = {"user-agent": ""}
        def parse(_, content: bytes, /) -> dict:
            json = json_loads(content)
            json["headers"] = headers
            return json
        request_kwargs.setdefault("parse", parse)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_copy(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_copy(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_copy(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """文件复制

        POST https://proapi.115.com/open/ufile/copy

        .. note::
            https://www.yuque.com/115yun/open/lvas49ar94n47bbk

        :payload:
            - file_id: int | str 💡 文件或目录的 id，多个用逗号 "," 隔开
            - pid: int | str = 0 💡 父目录 id
            - nodupli: 0 | 1 = 0 💡 复制的文件在目标目录是否允许重复：0:可以 1:不可以
        """
        api = complete_proapi("/open/ufile/copy", base_url)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload}
        elif isinstance(payload, dict):
            payload = dict(payload)
        else:
            payload = {"file_id": ",".join(map(str, payload))}
        if not payload.get("file_id"):
            return {"state": False, "message": "no op"}
        payload = cast(dict, payload)
        payload.setdefault("pid", pid)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_delete(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_delete(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_delete(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除文件或目录

        POST https://proapi.115.com/open/ufile/delete

        .. note::
            https://www.yuque.com/115yun/open/kt04fu8vcchd2fnb

        :payload:
            - file_ids: int | str 💡 文件或目录的 id，多个用逗号 "," 隔开
        """
        api = complete_proapi("/open/ufile/delete", base_url)
        if isinstance(payload, (int, str)):
            payload = {"file_ids": payload}
        elif not isinstance(payload, dict):
            payload = {"file_ids": ",".join(map(str, payload))}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_files(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_files(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_files(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """更新文件或目录

        GET https://proapi.115.com/open/ufile/files

        .. hint::
            相当于 `P115Client.fs_files_app`

        .. note::
            https://www.yuque.com/115yun/open/kz9ft9a7s57ep868

        :payload:
            - cid: int | str = 0 💡 目录 id
            - limit: int = 32 💡 分页大小，最大值不一定，看数据量，7,000 应该总是安全的，10,000 有可能报错，但有时也可以 20,000 而成功
            - offset: int = 0 💡 分页开始的索引，索引从 0 开始计算

            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
            - asc: 0 | 1 = <default> 💡 是否升序排列。0:降序 1:升序
            - code: int | str = <default>
            - count_folders: 0 | 1 = 1 💡 统计文件数和目录数
            - cur: 0 | 1 = <default>   💡 是否只显示当前目录
            - custom_order: 0 | 1 | 2 = <default> 💡 是否使用记忆排序。0:使用记忆排序（自定义排序失效） 1:使用自定义排序（不使用记忆排序） 2:自定义排序（非目录置顶）。如果指定了 "asc"、"fc_mix"、"o" 中其一，则此参数会被自动设置为 2
            - date: str = <default> 💡 筛选日期
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - fields: str = <default>
            - for: str = <default> 💡 文件格式，例如 "doc"
            - format: str = "json" 💡 返回格式，默认即可
            - hide_data: str = <default>
            - is_q: 0 | 1 = <default>
            - is_share: 0 | 1 = <default>
            - min_size: int = 0 💡 最小的文件大小
            - max_size: int = 0 💡 最大的文件大小
            - natsort: 0 | 1 = <default> 💡 是否执行自然排序(natural sorting)
            - nf: str = <default> 💡 不要显示文件（即仅显示目录），但如果 show_dir=0，则此参数无效
            - o: str = <default> 💡 用某字段排序（未定义的值会被视为 "user_utime"）

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_etime": 事件时间（无效，效果相当于 "user_utime"）
              - "user_utime": 修改时间
              - "user_ptime": 创建时间（无效，效果相当于 "user_utime"）
              - "user_otime": 上一次打开时间（无效，效果相当于 "user_utime"）

            - r_all: 0 | 1 = <default>
            - record_open_time: 0 | 1 = 1 💡 是否要记录目录的打开时间
            - scid: int | str = <default>
            - show_dir: 0 | 1 = 1 💡 是否展示目录：1:展示 0:不展示
            - snap: 0 | 1 = <default>
            - source: str = <default>
            - sys_dir: int | str = <default> 💡 系统通用目录
            - star: 0 | 1 = <default> 💡 是否星标文件
            - stdir: 0 | 1 = <default>
            - suffix: str = <default> 💡 后缀名（优先级高于 `type`）
            - type: int = <default> 💡 文件类型

              - 0: 全部（仅当前目录）
              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍
              - 8: 其它
              - 9: 相当于 8
              - 10: 相当于 8
              - 11: 相当于 8
              - 12: ？？？
              - 13: ？？？
              - 14: ？？？
              - 15: 图片和视频，相当于 2 和 4
              - >= 16: 相当于 8
        """
        api = complete_proapi("/open/ufile/files", base_url)
        if isinstance(payload, (int, str)):
            payload = {
                "aid": 1, "count_folders": 1, "limit": 32, "offset": 0, 
                "record_open_time": 1, "show_dir": 1, "cid": payload, 
            }
        else:
            payload = {
                "aid": 1, "count_folders": 1, "limit": 32, "offset": 0, 
                "record_open_time": 1, "show_dir": 1, "cid": 0, **payload, 
            }
        if payload.keys() & frozenset(("asc", "fc_mix", "o")):
            payload["custom_order"] = 2
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_info(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_info(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_info(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取文件或目录详情

        GET https://proapi.115.com/open/folder/get_info

        .. hint::
            相当于 `P115Client.fs_category_get_app`

        .. note::
            https://www.yuque.com/115yun/open/rl8zrhe2nag21dfw

        :payload:
            - file_id: int | str 💡 文件或目录的 id
        """
        api = complete_proapi("/open/folder/get_info", base_url)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_mkdir(
        self, 
        payload: str | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_mkdir(
        self, 
        payload: str | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_mkdir(
        self, 
        payload: str | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """新建目录

        POST https://proapi.115.com/open/folder/add

        .. note::
            https://www.yuque.com/115yun/open/qur839kyx9cgxpxi

        :payload:
            - file_name: str 💡 新建目录名称，限制255个字符
            - pid: int | str = 0 💡 新建目录所在的父目录ID (根目录的ID为0)
        """
        api = complete_proapi("/open/folder/add", base_url)
        if isinstance(payload, str):
            payload = {"pid": pid, "file_name": payload}
        else:
            payload = {"pid": pid, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_move(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_move(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_move(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """文件移动

        POST https://proapi.115.com/open/ufile/move

        .. note::
            https://www.yuque.com/115yun/open/vc6fhi2mrkenmav2

        :payload:
            - file_ids: int | str 💡 文件或目录的 id，多个用逗号 "," 隔开
            - to_cid: int | str = 0 💡 父目录 id
        """
        api = complete_proapi("/open/ufile/move", base_url)
        if isinstance(payload, (int, str)):
            payload = {"file_ids": payload}
        elif isinstance(payload, dict):
            payload = dict(payload)
        else:
            payload = {"file_ids": ",".join(map(str, payload))}
        if not payload.get("file_ids"):
            return {"state": False, "message": "no op"}
        payload = cast(dict, payload)
        payload.setdefault("to_cid", pid)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_search(
        self, 
        payload: str | dict = ".", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_search(
        self, 
        payload: str | dict = ".", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_search(
        self, 
        payload: str | dict = ".", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """搜索文件或目录

        GET https://proapi.115.com/open/ufile/search

        .. hint::
            相当于 `P115Client.fs_search_app2`

        .. note::
            https://www.yuque.com/115yun/open/ft2yelxzopusus38

        :payload:
            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
            - asc: 0 | 1 = <default> 💡 是否升序排列
            - cid: int | str = 0 💡 目录 id。cid=-1 时，表示不返回列表任何内容
            - count_folders: 0 | 1 = <default>
            - date: str = <default> 💡 筛选日期
            - fc: 0 | 1 = <default> 💡 只显示文件或目录。1:只显示目录 2:只显示文件
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - file_label: int | str = <default> 💡 标签 id
            - format: str = "json" 💡 输出格式（不用管）
            - gte_day: str 💡 搜索结果匹配的开始时间；格式：YYYY-MM-DD
            - limit: int = 32 💡 一页大小，意思就是 page_size
            - lte_day: str 💡 搜索结果匹配的结束时间；格式：YYYY-MM-DD
            - o: str = <default> 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_utime": 修改时间
              - "user_ptime": 创建时间
              - "user_otime": 上一次打开时间

            - offset: int = 0  💡 索引偏移，索引从 0 开始计算
            - pick_code: str = <default> 💡 是否查询提取码，如果该值为 1 则查询提取码为 `search_value` 的文件
            - search_value: str = "." 💡 搜索文本，可以是 sha1
            - show_dir: 0 | 1 = 1
            - source: str = <default>
            - star: 0 | 1 = <default>
            - suffix: str = <default>
            - type: int = <default> 💡 文件类型

              - 0: 全部（仅当前目录）
              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍
              - 99: 仅文件

            - version: str = <default> 💡 版本号，比如 3.1
        """
        api = complete_proapi("/open/ufile/search", base_url)
        if isinstance(payload, str):
            payload = {
                "aid": 1, "cid": 0, "format": "json", "limit": 32, "offset": 0, 
                "show_dir": 1, "search_value": payload, 
            }
        else:
            payload = {
                "aid": 1, "cid": 0, "format": "json", "limit": 32, "offset": 0, 
                "show_dir": 1, "search_value": ".", **payload, 
            }
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_star_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        star: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_star_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        star: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_star_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        star: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """为文件或目录设置或取消星标，此接口是对 `fs_update_open` 的封装

        .. note::
            即使其中任何一个 id 目前已经被删除，也可以操作成功

        :payload:
            - file_id: int | str    💡 只能传入 1 个
            - file_id[0]: int | str 💡 如果有多个，则按顺序给出
            - file_id[1]: int | str
            - ...
            - star: 0 | 1 = 1
        """
        api = complete_webapi("/files/star", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload, "star": int(star)}
        elif not isinstance(payload, dict):
            payload = {f"file_id[{i}]": id for i, id in enumerate(payload)}
            if not payload:
                return {"state": False, "message": "no op"}
            payload["star"] = int(star)
        else:
            payload = {"star": int(star), **payload}
        return self.fs_update(payload, async_=async_, **request_kwargs)

    @overload
    def fs_update(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_update(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_update(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """设置文件或目录（备注、标签等）

        POST https://proapi.115.com/open/ufile/update

        .. hint::
            即使文件已经被删除，也可以操作成功

        .. note::
            https://www.yuque.com/115yun/open/gyrpw5a0zc4sengm

        :payload:
            - file_id: int | str    💡 只能传入 1 个
            - file_id[0]: int | str 💡 如果有多个，则按顺序给出
            - file_id[1]: int | str
            - ...
            - file_name: str = <default> 💡 文件名
            - star: 0 | 1 = <default> 💡 是否星标：0:取消星标 1:设置星标
            - ...
        """
        api = complete_proapi("/open/ufile/update", base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def recyclebin_clean(
        self, 
        payload: int | str | Iterable[int | str] | dict = {}, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def recyclebin_clean(
        self, 
        payload: int | str | Iterable[int | str] | dict = {}, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def recyclebin_clean(
        self, 
        payload: int | str | Iterable[int | str] | dict = {}, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """回收站：删除或清空

        POST https://proapi.115.com/open/rb/del

        .. note:
            https://www.yuque.com/115yun/open/gwtof85nmboulrce

        :payload:
            - tid: int | str 💡 多个用逗号 "," 隔开
        """
        api = complete_proapi("/open/rb/del", base_url)
        if isinstance(payload, (int, str)):
            payload = {"tid": payload}
        elif not isinstance(payload, dict):
            payload = {"tid": ",".join(map(str, payload))}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def recyclebin_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def recyclebin_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def recyclebin_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """回收站：列表

        GET https://proapi.115.com/open/rb/list

        .. note::
            https://www.yuque.com/115yun/open/bg7l4328t98fwgex

        :payload:
            - limit: int = 32
            - offset: int = 0
        """ 
        api = complete_proapi("/open/rb/list", base_url)
        if isinstance(payload, int):
            payload = {"limit": 32, "offset": payload}
        else:
            payload = {"limit": 32, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def recyclebin_revert(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def recyclebin_revert(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def recyclebin_revert(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """回收站：还原

        POST https://proapi.115.com/open/rb/revert

        .. note::
            https://www.yuque.com/115yun/open/gq293z80a3kmxbaq

        :payload:
            - tid: int | str 💡 多个用逗号 "," 隔开
        """
        api = complete_proapi("/open/rb/revert", base_url)
        if isinstance(payload, (int, str)):
            payload = {"tid": payload}
        elif not isinstance(payload, dict):
            payload = {"tid": ",".join(map(str, payload))}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def upload_gettoken(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_gettoken(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_gettoken(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取阿里云 OSS 的 token（上传凭证）

        GET https://proapi.115.com/open/upload/get_token

        .. note::
            https://www.yuque.com/115yun/open/kzacvzl0g7aiyyn4
        """
        api = complete_proapi("/open/upload/get_token", base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def upload_init(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_init(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_init(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """文件秒传

        POST https://proapi.115.com/open/upload/init

        .. note::
            https://www.yuque.com/115yun/open/ul4mrauo5i2uza0q

        :payload:
            - file_name: str 💡 文件名
            - file_size: int 💡 文件大小，单位是字节
            - target: str 💡 上传目标，格式为 f"U_{aid}_{pid}"
            - fileid: str 💡 文件的 sha1 值
            - preid: str = <default> 💡 文件的前 128 KB 数据的 sha1 值
            - pick_code: str = <default> 💡 上传任务 key
            - topupload: int = 0 💡 上传调度文件类型调度标记

                -  0: 单文件上传任务标识 1 条单独的文件上传记录
                -  1: 文件夹任务调度的第 1 个子文件上传请求标识 1 次文件夹上传记录
                -  2: 文件夹任务调度的其余后续子文件不作记作单独上传的上传记录 
                - -1: 没有该参数

            - sign_key: str = "" 💡 二次验证时读取文件的范围
            - sign_val: str = "" 💡 二次验证的签名值
        """
        api = complete_proapi("/open/upload/init", base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def upload_resume(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_resume(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_resume(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取恢复断点续传所需信息

        POST https://proapi.115.com/open/upload/resume

        .. note::
            https://www.yuque.com/115yun/open/tzvi9sbcg59msddz

        :payload:
            - fileid: str 💡 文件的 sha1 值
            - file_size: int 💡 文件大小，单位是字节
            - target: str 💡 上传目标，格式为 f"U_{aid}_{pid}"
            - pick_code: str 💡 提取码
        """
        api = complete_proapi("/open/upload/resume", base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def upload_file_init(
        self, 
        /, 
        filename: str, 
        filesize: int, 
        filesha1: str, 
        preid: str = "", 
        read_range_bytes_or_hash: None | Callable[[str], str | Buffer] = None, 
        pid: int = 0, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_file_init(
        self, 
        /, 
        filename: str, 
        filesize: int, 
        filesha1: str, 
        preid: str = "", 
        read_range_bytes_or_hash: None | Callable[[str], str | Buffer] = None, 
        pid: int = 0, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_file_init(
        self, 
        /, 
        filename: str, 
        filesize: int, 
        filesha1: str, 
        preid: str = "", 
        read_range_bytes_or_hash: None | Callable[[str], str | Buffer] = None, 
        pid: int = 0, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """秒传接口，此接口是对 `upload_init` 的封装。

        .. note::

            - 文件大小 和 sha1 是必需的，只有 sha1 是没用的。
            - 如果文件大于等于 1 MB (1048576 B)，就需要 2 次检验一个范围哈希，就必须提供 `read_range_bytes_or_hash`

        :param filename: 文件名
        :param filesize: 文件大小
        :param filesha1: 文件的 sha1
        :param preid: 文件的前 128 KB 数据的 sha1 值（目前这个参数没啥用，不要传）
        :param read_range_bytes_or_hash: 调用以获取二次验证的数据或计算 sha1，接受一个数据范围，格式符合 `HTTP Range Requests <https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests>`_，返回值如果是 str，则视为计算好的 sha1，如果为 Buffer，则视为数据（之后会被计算 sha1）
        :param pid: 上传文件到此目录的 id
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 接口响应
        """
        filesha1 = filesha1.upper()
        target = f"U_1_{pid}"
        def gen_step():
            payload = {
                "file_name": filename, 
                "file_size": filesize, 
                "target": target, 
                "fileid": filesha1, 
                "preid": preid, 
                "topupload": 1, 
            }
            resp = yield self.upload_init_open(
                payload, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            if resp["data"]["status"] == 7:
                if read_range_bytes_or_hash is None:
                    raise ValueError("filesize >= 1 MB, thus need pass the `read_range_bytes_or_hash` argument")
                payload["sign_key"] = resp["data"]["sign_key"]
                sign_check: str = resp["data"]["sign_check"]
                data: str | Buffer
                if async_:
                    data = yield ensure_async(read_range_bytes_or_hash)(sign_check)
                else:
                    data = read_range_bytes_or_hash(sign_check)
                if isinstance(data, str):
                    payload["sign_val"] = data.upper()
                else:
                    payload["sign_val"] = sha1(data).hexdigest().upper()
                resp = yield self.upload_init_open(
                    payload, 
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
                check_response(resp)
            resp["data"] = {**payload, **resp["data"], "sha1": filesha1, "cid": pid}
            return resp
        return run_gen_step(gen_step, async_=async_)

    @overload
    def upload_file(
        self, 
        /, 
        file: ( str | PathLike | URL | SupportsGeturl | 
                Buffer | SupportsRead[Buffer] | Iterable[Buffer] ), 
        filename: None | str = None, 
        pid: int = 0, 
        filesize: int = -1, 
        filesha1: str = "", 
        partsize: int = 0, 
        multipart_resume_data: None | MultipartResumeData = None, 
        collect_resume_data: None | Callable[[MultipartResumeData], Any] = None, 
        make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any]] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_file(
        self, 
        /, 
        file: ( str | PathLike | URL | SupportsGeturl | 
                Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer] ), 
        filename: None | str = None, 
        pid: int = 0, 
        filesize: int = -1, 
        filesha1: str = "", 
        partsize: int = 0, 
        multipart_resume_data: None | MultipartResumeData = None, 
        collect_resume_data: None | Callable[[MultipartResumeData], Any] = None, 
        make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any]] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_file(
        self, 
        /, 
        file: ( str | PathLike | URL | SupportsGeturl | 
                Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer] ), 
        filename: None | str = None, 
        pid: int = 0, 
        filesize: int = -1, 
        filesha1: str = "", 
        partsize: int = 0, 
        multipart_resume_data: None | MultipartResumeData = None, 
        collect_resume_data: None | Callable[[MultipartResumeData], Any] = None, 
        make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any]] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """文件上传，这是高层封装，推荐使用

        :param file: 待上传的文件

            - 如果为 `collections.abc.Buffer`，则作为二进制数据上传
            - 如果为 `filewrap.SupportsRead` (`pip install python-filewrap`)，则作为文件上传
            - 如果为 `str` 或 `os.PathLike`，则视为路径，打开后作为文件上传
            - 如果为 `yarl.URL` 或 `http_request.SupportsGeturl` (`pip install python-http_request`)，则视为超链接，打开后作为文件上传
            - 如果为 `collections.abc.Iterable[collections.abc.Buffer]` 或 `collections.abc.AsyncIterable[collections.abc.Buffer]`，则迭代以获取二进制数据，逐步上传

        :param filename: 文件名，如果为 None，则会自动确定
        :param pid: 上传文件到此目录的 id
        :param filesize: 文件大小，如果为 -1，则会自动确定
        :param filesha1: 文件的 sha1，如果未提供，则会自动确定
        :param partsize: 分块上传的分块大小，如果 <= 0，则不进行分块上传
        :param multipart_resume_data: 如果不为 None，则断点续传，并且恢复相关参数
        :param collect_resume_data: 如果不为 None，则调用以输出分块上传的恢复数据（用于下次继续执行）
        :param make_reporthook: 调用以推送上传进度

            .. note::
                - 如果为 None，则不推送进度
                - 否则，必须是 Callable。可接受 int 或 None 作为总文件大小，如果为 None 或者不传，则不确定文件大小。返回值作为实际的更新器，暂名为 `update`，假设一次的更新值为 `step`

                    - 如果返回值为 Callable，则更新时调用 `update(step)`
                    - 如果返回值为 Generator，则更新时调用 `update.send(step)`
                    - 如果返回值为 AsyncGenerator，则更新时调用 `await update.asend(step)`

                1. 你可以直接用第三方的进度条

                    .. code:: python

                        from tqdm import tqdm

                        make_report = lambda total=None: tqdm(total=total).update

                2. 或者你也可以自己写一个进度条

                    .. code:: python

                        from collections import deque
                        from time import perf_counter

                        def make_report(total: None | int = None):
                            dq: deque[tuple[int, float]] = deque(maxlen=64)
                            push = dq.append
                            read_num = 0
                            push((read_num, perf_counter()))
                            while True:
                                read_num += yield
                                cur_t = perf_counter()
                                speed = (read_num - dq[0][0]) / 1024 / 1024 / (cur_t - dq[0][1])
                                if total:
                                    percentage = read_num / total * 100
                                    print(f"\\r\\x1b[K{read_num} / {total} | {speed:.2f} MB/s | {percentage:.2f} %", end="", flush=True)
                                else:
                                    print(f"\\r\\x1b[K{read_num} | {speed:.2f} MB/s", end="", flush=True)
                                push((read_num, cur_t))

        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 接口响应
        """
        def gen_step():
            nonlocal file, filename, filesize, filesha1
            def do_upload(file):
                return self.upload_file_open(
                    file=file, 
                    filename=filename, 
                    pid=pid, 
                    filesize=filesize, 
                    filesha1=filesha1, 
                    partsize=partsize, 
                    collect_resume_data=collect_resume_data, 
                    make_reporthook=make_reporthook, # type: ignore
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
            if filesize == 0:
                filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
            need_calc_filesha1 = not filesha1 and multipart_resume_data is None
            read_range_bytes_or_hash: None | Callable = None
            try:
                file = getattr(file, "getbuffer")()
            except (AttributeError, TypeError):
                pass
            if isinstance(file, Buffer):
                filesize = buffer_length(file)
                if filesize == 0:
                    filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
                elif need_calc_filesha1:
                    filesha1 = sha1(file).hexdigest()
                if multipart_resume_data is None and filesize >= 1 << 20:
                    view = memoryview(file)
                    def read_range_bytes_or_hash(sign_check: str, /) -> memoryview:
                        start, end = map(int, sign_check.split("-"))
                        return view[start:end+1]
            elif isinstance(file, SupportsRead):
                seek = getattr(file, "seek", None)
                seekable = False   
                curpos = 0
                if callable(seek):
                    if async_:
                        seek = ensure_async(seek, threaded=True)
                    try:
                        seekable = getattr(file, "seekable")()
                    except (AttributeError, TypeError):
                        try:
                            curpos = yield seek(0, 1)
                            seekable = True
                        except Exception:
                            seekable = False
                if need_calc_filesha1:
                    if not seekable:
                        fsrc = file
                        file = TemporaryFile()
                        if async_:
                            yield copyfileobj_async(fsrc, file)
                        else:
                            copyfileobj(fsrc, file)
                        file.seek(0)
                        return do_upload(file)
                    try:
                        if async_:
                            filesize, filesha1_obj = yield file_digest_async(file, "sha1")
                        else:
                            filesize, filesha1_obj = file_digest(file, "sha1")
                    finally:
                        yield seek(curpos)
                    filesha1 = filesha1_obj.hexdigest()
                if filesize < 0:
                    try:
                        fileno = getattr(file, "fileno")()
                        filesize = fstat(fileno).st_size - curpos
                    except (AttributeError, TypeError, OSError):
                        try:
                            filesize = len(file) - curpos # type: ignore
                        except TypeError:
                            if seekable:
                                try:
                                    filesize = (yield seek(0, 2)) - curpos
                                finally:
                                    yield seek(curpos)
                if filesize == 0:
                    filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
                elif multipart_resume_data is None and filesize >= 1 << 20:
                    read: Callable[[int], Buffer] | Callable[[int], Awaitable[Buffer]]
                    if seekable:
                        if async_:
                            async_read = ensure_async(file.read, threaded=True)
                            async def read_range_bytes_or_hash(sign_check: str, /):
                                start, end = map(int, sign_check.split("-"))
                                await seek(curpos + start)
                                return await async_read(end - start + 1)
                        else:
                            read = cast(Callable[[int], Buffer], file.read)
                            def read_range_bytes_or_hash(sign_check: str, /):
                                start, end = map(int, sign_check.split("-"))
                                seek(curpos + start)
                                return read(end - start + 1)
            elif isinstance(file, (URL, SupportsGeturl)):
                if isinstance(file, URL):
                    url: str = str(file)
                else:
                    url = file.geturl()
                if async_:
                    from httpfile import AsyncHttpxFileReader
                    async def request():
                        file = await AsyncHttpxFileReader.new(url, headers={"user-agent": ""})
                        async with file:
                            return await do_upload(file)
                    return request
                else:
                    with HTTPFileReader(url, headers={"user-agent": ""}) as file:
                        return do_upload(file)
            elif isinstance(file, (str, PathLike)):
                path = fsdecode(file)
                if not filename:
                    filename = ospath.basename(path)
                if async_:
                    async def request():
                        from aiofile import async_open
                        async with async_open(path, "rb") as file:
                            setattr(file, "fileno", file.file.fileno)
                            setattr(file, "seekable", lambda: True)
                            return await do_upload(file)
                    return request
                else:
                    return do_upload(open(path, "rb"))
            else:
                if need_calc_filesha1:
                    if async_:
                        file = bytes_iter_to_async_reader(file) # type: ignore
                    else:
                        file = bytes_iter_to_reader(file) # type: ignore
                    return do_upload(file)
            if multipart_resume_data is not None:
                bucket = multipart_resume_data["bucket"]
                object = multipart_resume_data["object"]
                url    = cast(str, multipart_resume_data.get("url", ""))
                if not url:
                    url = self.upload_endpoint_url(bucket, object)
                callback_var = loads(multipart_resume_data["callback"]["callback_var"])
                yield self.upload_resume_open(
                    {
                        "fileid": object, 
                        "file_size": multipart_resume_data["filesize"], 
                        "target": callback_var["x:target"], 
                        "pick_code": callback_var["x:pick_code"], 
                    }, 
                    async_=async_, 
                    **request_kwargs, 
                )
                return oss_multipart_upload(
                    self.request, 
                    file, # type: ignore
                    url=url, 
                    bucket=bucket, 
                    object=object, 
                    token=self.upload_token, 
                    callback=multipart_resume_data["callback"], 
                    upload_id=multipart_resume_data["upload_id"], 
                    partsize=multipart_resume_data["partsize"], 
                    filesize=multipart_resume_data.get("filesize", filesize), 
                    collect_resume_data=collect_resume_data, 
                    make_reporthook=make_reporthook, # type: ignore
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
            if not filename:
                filename = getattr(file, "name", "")
                filename = ospath.basename(filename)
            if filename:
                filename = filename.translate(NAME_TANSTAB_FULLWIDH)
            else:
                filename = str(uuid4())
            if filesize < 0:
                filesize = getattr(file, "length", 0)
            resp = yield self.upload_file_init_open(
                filename=filename, 
                filesize=filesize, 
                filesha1=filesha1, 
                read_range_bytes_or_hash=read_range_bytes_or_hash, 
                pid=pid, 
                async_=async_, # type: ignore
                **request_kwargs, 
            )
            data = resp["data"]
            match data["status"]:
                case 2:
                    return resp
                case 1:
                    bucket, object, callback = data["bucket"], data["object"], data["callback"]
                case _:
                    raise P115OSError(EINVAL, resp)
            url = self.upload_endpoint_url(bucket, object)
            token = self.upload_token
            if partsize <= 0:
                return oss_upload(
                    self.request, 
                    file, # type: ignore
                    url=url, 
                    bucket=bucket, 
                    object=object, 
                    callback=callback, 
                    token=token, 
                    filesize=filesize, 
                    make_reporthook=make_reporthook, # type: ignore
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
            else:
                return oss_multipart_upload(
                    self.request, 
                    file, # type: ignore
                    url=url, 
                    bucket=bucket, 
                    object=object, 
                    callback=callback, 
                    token=token, 
                    partsize=partsize, 
                    filesize=filesize, 
                    collect_resume_data=collect_resume_data, 
                    make_reporthook=make_reporthook, # type: ignore
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
        return run_gen_step(gen_step, async_=async_)

    @overload
    def user_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取用户信息

        GET https://proapi.115.com/open/user/info

        .. note::
            https://www.yuque.com/115yun/open/ot1litggzxa1czww
        """
        api = complete_proapi("/open/user/info", base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    download_url_open = download_url
    download_url_info_open = download_url_info
    fs_copy_open = fs_copy
    fs_delete_open = fs_delete
    fs_files_open = fs_files
    fs_info_open = fs_info
    fs_mkdir_open = fs_mkdir
    fs_move_open = fs_move
    fs_search_open = fs_search
    fs_star_set_open = fs_star_set
    fs_update_open = fs_update
    recyclebin_clean_open = recyclebin_clean
    recyclebin_list_open = recyclebin_list
    recyclebin_revert_open = recyclebin_revert
    upload_gettoken_open = upload_gettoken
    upload_init_open = upload_init
    upload_resume_open = upload_resume
    user_info_open = user_info
    upload_file_init_open = upload_file_init
    upload_file_open = upload_file


class P115Client(P115OpenClient):
    """115 的客户端对象

    .. note::
        目前允许 1 个用户同时登录多个开放平台应用（用 AppID 区别），但如果多次登录同 1 个应用，则只有最近登录的有效

        目前不允许短时间内再次用 `refresh_token` 刷新 `access_token`，但你可以用登录的方式再次授权登录以获取 `access_token`，即可不受频率限制

        1 个 `refresh_token` 只能使用 1 次，可获取新的 `refresh_token` 和 `access_token`，如果请求刷新时，发送成功但读取失败，可能导致 `refresh_token` 报废，这时需要重新授权登录

    :param cookies: 115 的 cookies，要包含 `UID`、`CID`、`KID` 和 `SEID` 等

        - 如果是 None，则会要求人工扫二维码登录
        - 如果是 str，则要求是格式正确的 cookies 字符串，例如 "UID=...; CID=...; KID=...; SEID=..."
        - 如果是 bytes 或 os.PathLike，则视为路径，当更新 cookies 时，也会往此路径写入文件，格式要求同上面的 `str`
        - 如果是 collections.abc.Mapping，则是一堆 cookie 的名称到值的映射
        - 如果是 collections.abc.Iterable，则其中每一条都视为单个 cookie

    :param check_for_relogin: 网页请求抛出异常时，判断是否要重新登录并重试

        - 如果为 False，则不重试
        - 如果为 True，则自动通过判断 HTTP 响应码为 405 时重新登录并重试
        - 如果为 collections.abc.Callable，则调用以判断，当返回值为 bool 类型且值为 True，或者值为 405 时重新登录，然后循环此流程，直到成功或不可重试

    :param ensure_cookies: 检查以确保 cookies 是有效的，如果失效，就重新登录
    :param app: 重新登录时人工扫二维码后绑定的 `app` （或者叫 `device`），如果不指定，则根据 cookies 的 UID 字段来确定，如果不能确定，则用 "qandroid"
    :param console_qrcode: 在命令行输出二维码，否则在浏览器中打开

    -----

    :设备列表如下:

    +-------+----------+------------+-------------------------+
    | No.   | ssoent   | app        | description             |
    +=======+==========+============+=========================+
    | 01    | A1       | web        | 网页版                  |
    +-------+----------+------------+-------------------------+
    | 02    | A2       | ?          | 未知: android           |
    +-------+----------+------------+-------------------------+
    | 03    | A3       | ?          | 未知: iphone            |
    +-------+----------+------------+-------------------------+
    | 04    | A4       | ?          | 未知: ipad              |
    +-------+----------+------------+-------------------------+
    | 05    | B1       | ?          | 未知: android           |
    +-------+----------+------------+-------------------------+
    | 06    | D1       | ios        | 115生活(iOS端)          |
    +-------+----------+------------+-------------------------+
    | 07    | D2       | ?          | 未知: ios               |
    +-------+----------+------------+-------------------------+
    | 08    | D3       | 115ios     | 115(iOS端)              |
    +-------+----------+------------+-------------------------+
    | 09    | F1       | android    | 115生活(Android端)      |
    +-------+----------+------------+-------------------------+
    | 10    | F2       | ?          | 未知: android           |
    +-------+----------+------------+-------------------------+
    | 11    | F3       | 115android | 115(Android端)          |
    +-------+----------+------------+-------------------------+
    | 12    | H1       | ipad       | 未知: ipad              |
    +-------+----------+------------+-------------------------+
    | 13    | H2       | ?          | 未知: ipad              |
    +-------+----------+------------+-------------------------+
    | 14    | H3       | 115ipad    | 115(iPad端)             |
    +-------+----------+------------+-------------------------+
    | 15    | I1       | tv         | 115网盘(Android电视端)  |
    +-------+----------+------------+-------------------------+
    | 16    | M1       | qandriod   | 115管理(Android端)      |
    +-------+----------+------------+-------------------------+
    | 17    | N1       | qios       | 115管理(iOS端)          |
    +-------+----------+------------+-------------------------+
    | 18    | O1       | ?          | 未知: ipad              |
    +-------+----------+------------+-------------------------+
    | 19    | P1       | windows    | 115生活(Windows端)      |
    +-------+----------+------------+-------------------------+
    | 20    | P2       | mac        | 115生活(macOS端)        |
    +-------+----------+------------+-------------------------+
    | 21    | P3       | linux      | 115生活(Linux端)        |
    +-------+----------+------------+-------------------------+
    | 22    | R1       | wechatmini | 115生活(微信小程序)     |
    +-------+----------+------------+-------------------------+
    | 23    | R2       | alipaymini | 115生活(支付宝小程序)   |
    +-------+----------+------------+-------------------------+
    | 24    | S1       | harmony    | 115(Harmony端)          |
    +-------+----------+------------+-------------------------+
    """
    cookies_path: None | PurePath = None
    app_id: int | str
    refresh_token: str

    def __init__(
        self, 
        /, 
        cookies: None | str | bytes | PathLike | Mapping[str, str] | Iterable[Mapping | Cookie | Morsel] = None, 
        check_for_relogin: bool | Callable[[BaseException], bool | int] = False, 
        ensure_cookies: bool = False, 
        app: None | str = None, 
        console_qrcode: bool = True, 
    ):
        self.init(
            cookies=cookies, 
            check_for_relogin=check_for_relogin, 
            ensure_cookies=ensure_cookies, 
            app=app, 
            console_qrcode=console_qrcode, 
            instance=self, 
        )

    def __eq__(self, other, /) -> bool:
        try:
            return type(self) is type(other) and self.user_id == other.user_id
        except AttributeError:
            return False

    def __hash__(self, /) -> int:
        return id(self)

    @property
    def cookies(self, /):
        """请求所用的 Cookies 对象（同步和异步共用）
        """
        try:
            return self.__dict__["cookies"]
        except KeyError:
            from httpx import Cookies
            cookies = self.__dict__["cookies"] = Cookies()
            return cookies

    @cookies.setter
    def cookies(
        self, 
        cookies: None | str | Mapping[str, None | str] | Iterable[Mapping | Cookie | Morsel] = None, 
        /, 
    ):
        """更新 cookies
        """
        cookies_old = self.cookies_str
        cookiejar = self.cookiejar
        if cookies is None:
            cookiejar.clear()
            if cookies_old != "":
                self._write_cookies("")
            return
        if isinstance(cookies, str):
            cookies = cookies.strip().rstrip(";")
            if not cookies:
                return
            cookies = cookies_str_to_dict(cookies)
            if not cookies:
                return
        set_cookie = cookiejar.set_cookie
        clear_cookie = cookiejar.clear
        cookie: Mapping | Cookie | Morsel
        if isinstance(cookies, Mapping):
            if not cookies:
                return
            for key, val in items(cookies):
                if val:
                    set_cookie(create_cookie(key, val, domain=".115.com"))
                else:
                    for cookie in cookiejar:
                        if cookie.name == key:
                            clear_cookie(domain=cookie.domain, path=cookie.path, name=cookie.name)
                            break
        else:
            from httpx import Cookies
            if isinstance(cookies, Cookies):
                cookies = cookies.jar
            for cookie in cookies:
                set_cookie(create_cookie("", cookie))
        user_id = self.user_id
        self.__dict__.pop("user_id", None)
        if self.user_id != user_id:
            self.__dict__.pop("user_key", None)
        cookies_new = self.cookies_str
        if not cookies_equal(cookies_old, cookies_new):
            self._write_cookies(cookies_new)

    @locked_cacheproperty
    def user_id(self, /) -> int:
        cookie_uid = self.cookies.get("UID")
        if cookie_uid:
            return int(cookie_uid.split("_")[0])
        else:
            return 0

    @locked_cacheproperty
    def user_key(self, /) -> str:
        return check_response(self.upload_key())["data"]["userkey"]

    def _read_cookies(
        self, 
        /, 
        encoding: str = "latin-1", 
    ) -> None | str:
        cookies_path = self.__dict__.get("cookies_path")
        if not cookies_path:
            return None
        cookies_mtime_old = self.__dict__.get("cookies_mtime", 0)
        try:
            cookies_mtime = cookies_path.stat().st_mtime
        except OSError:
            cookies_mtime = 0
        if cookies_mtime_old >= cookies_mtime:
            return self.cookies_str
        try:
            with cookies_path.open("rb") as f:
                cookies = str(f.read(), encoding)
            setattr(self, "cookies", cookies)
            self.cookies_mtime = cookies_mtime
            return cookies
        except OSError:
            return None

    def _write_cookies(
        self, 
        cookies: None | str = None, 
        /, 
        encoding: str = "latin-1", 
    ):
        if not (cookies_path := self.__dict__.get("cookies_path")):
            return
        if cookies is None:
            cookies = str(self.cookies_str)
        cookies_bytes = bytes(cookies, encoding)
        with cookies_path.open("wb") as f:
            f.write(cookies_bytes)
        try:
            self.cookies_mtime = cookies_path.stat().st_mtime
        except OSError:
            self.cookies_mtime = 0

    @overload # type: ignore
    @classmethod
    def init(
        cls, 
        /, 
        cookies: None | str | bytes | PathLike | Mapping[str, str] | Iterable[Mapping | Cookie | Morsel] = None, 
        check_for_relogin: bool | Callable[[BaseException], bool | int] = False, 
        ensure_cookies: bool = False, 
        app: None | str = None, 
        console_qrcode: bool = True, 
        instance: None | Self = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> Self:
        ...
    @overload
    @classmethod
    def init(
        cls, 
        /, 
        cookies: None | str | bytes | PathLike | Mapping[str, str] | Iterable[Mapping | Cookie | Morsel] = None, 
        check_for_relogin: bool | Callable[[BaseException], bool | int] = False, 
        ensure_cookies: bool = False, 
        app: None | str = None, 
        console_qrcode: bool = True, 
        instance: None | Self = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, Self]:
        ...
    @classmethod
    def init(
        cls, 
        /, 
        cookies: None | str | bytes | PathLike | Mapping[str, str] | Iterable[Mapping | Cookie | Morsel] = None, 
        check_for_relogin: bool | Callable[[BaseException], bool | int] = False, 
        ensure_cookies: bool = False, 
        app: None | str = None, 
        console_qrcode: bool = True, 
        instance: None | Self = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> Self | Coroutine[Any, Any, Self]:
        def gen_step():
            if instance is None:
                self = cls.__new__(cls)
            else:
                self = instance
            if cookies is None:
                yield self.login(
                    app, 
                    console_qrcode=console_qrcode, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                if isinstance(cookies, (bytes, PathLike)):
                    if isinstance(cookies, PurePath) and hasattr(cookies, "open"):
                        self.cookies_path = cookies
                    else:
                        self.cookies_path = Path(fsdecode(cookies))
                    if async_:
                        yield ensure_async(self._read_cookies, threaded=True)
                    else:
                        self._read_cookies()
                elif cookies:
                    setattr(self, "cookies", cookies)
                if ensure_cookies:
                    yield self.login(
                        app, 
                        console_qrcode=console_qrcode, 
                        async_=async_, 
                        **request_kwargs, 
                    )
            setattr(self, "check_for_relogin", check_for_relogin)
            return self
        return run_gen_step(gen_step, async_=async_)

    @locked_cacheproperty
    def request_lock(self, /) -> Lock:
        return Lock()

    @locked_cacheproperty
    def request_alock(self, /) -> AsyncLock:
        return AsyncLock()

    @property
    def check_for_relogin(self, /) -> None | Callable[[BaseException], bool | int]:
        return self.__dict__.get("check_for_relogin")

    @check_for_relogin.setter
    def check_for_relogin(self, call: None | bool | Callable[[BaseException], bool | int], /):
        if call is None:
            self.__dict__["check_for_relogin"] = None
        elif call is False:
            self.__dict__.pop("check_for_relogin", None)
        else:
            if call is True:
                call = default_check_for_relogin
            self.__dict__["check_for_relogin"] = call

    @overload
    def login(
        self, 
        /, 
        app: None | str = None, 
        console_qrcode: bool = True, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> Self:
        ...
    @overload
    def login(
        self, 
        /, 
        app: None | str = None, 
        console_qrcode: bool = True, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, Self]:
        ...
    def login(
        self, 
        /, 
        app: None | str = None, 
        console_qrcode: bool = True, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> Self | Coroutine[Any, Any, Self]:
        """扫码二维码登录，如果已登录则忽略

        :param app: 扫二维码后绑定的 `app` （或者叫 `device`），如果不指定，则根据 cookies 的 UID 字段来确定，如果不能确定，则用 "qandroid"
        :param console_qrcode: 在命令行输出二维码，否则在浏览器中打开
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 返回对象本身

        -----

        app 至少有 24 个可用值，目前找出 14 个：

        - web
        - ios
        - 115ios
        - android
        - 115android
        - 115ipad
        - tv
        - qandroid
        - windows
        - mac
        - linux
        - wechatmini
        - alipaymini
        - harmony

        还有几个备选（暂不可用）：

        - bios
        - bandroid
        - ipad（登录机制有些不同，暂时未破解）
        - qios（登录机制有些不同，暂时未破解）
        - desktop（就是 web，但是用 115 浏览器登录）

        :设备列表如下:

        +-------+----------+------------+-------------------------+
        | No.   | ssoent   | app        | description             |
        +=======+==========+============+=========================+
        | 01    | A1       | web        | 网页版                  |
        +-------+----------+------------+-------------------------+
        | 02    | A2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 03    | A3       | ?          | 未知: iphone            |
        +-------+----------+------------+-------------------------+
        | 04    | A4       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 05    | B1       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 06    | D1       | ios        | 115生活(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 07    | D2       | ?          | 未知: ios               |
        +-------+----------+------------+-------------------------+
        | 08    | D3       | 115ios     | 115(iOS端)              |
        +-------+----------+------------+-------------------------+
        | 09    | F1       | android    | 115生活(Android端)      |
        +-------+----------+------------+-------------------------+
        | 10    | F2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 11    | F3       | 115android | 115(Android端)          |
        +-------+----------+------------+-------------------------+
        | 12    | H1       | ipad       | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 13    | H2       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 14    | H3       | 115ipad    | 115(iPad端)             |
        +-------+----------+------------+-------------------------+
        | 15    | I1       | tv         | 115网盘(Android电视端)  |
        +-------+----------+------------+-------------------------+
        | 16    | M1       | qandriod   | 115管理(Android端)      |
        +-------+----------+------------+-------------------------+
        | 17    | N1       | qios       | 115管理(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 18    | O1       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 19    | P1       | windows    | 115生活(Windows端)      |
        +-------+----------+------------+-------------------------+
        | 20    | P2       | mac        | 115生活(macOS端)        |
        +-------+----------+------------+-------------------------+
        | 21    | P3       | linux      | 115生活(Linux端)        |
        +-------+----------+------------+-------------------------+
        | 22    | R1       | wechatmini | 115生活(微信小程序)     |
        +-------+----------+------------+-------------------------+
        | 23    | R2       | alipaymini | 115生活(支付宝小程序)   |
        +-------+----------+------------+-------------------------+
        | 24    | S1       | harmony    | 115(Harmony端)          |
        +-------+----------+------------+-------------------------+
        """
        def gen_step():
            nonlocal app
            status = yield self.login_status(async_=async_, **request_kwargs)
            if status:
                return self
            if not app:
                app = yield self.login_app(async_=async_, **request_kwargs)
            if not app:
                app = "alipaymini"
            resp = yield self.login_with_qrcode(
                app, 
                console_qrcode=console_qrcode, 
                async_=async_, 
                **request_kwargs, 
            )
            try:
                check_response(resp)
            except AuthenticationError:
                resp = yield self.login_with_qrcode(
                    app, 
                    console_qrcode=console_qrcode, 
                    async_=async_, 
                    **request_kwargs, 
                )
                check_response(resp)
            setattr(self, "cookies", resp["data"]["cookie"])
            return self
        return run_gen_step(gen_step, async_=async_)

    @overload
    def login_qrcode_scan(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def login_qrcode_scan(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def login_qrcode_scan(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """扫描二维码，payload 数据取自 `login_qrcode_token` 接口响应

        GET https://qrcodeapi.115.com/api/2.0/prompt.php

        :payload:
            - uid: str
        """
        api = "https://qrcodeapi.115.com/api/2.0/prompt.php"
        if isinstance(payload, str):
            payload = {"uid": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def login_qrcode_scan_confirm(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def login_qrcode_scan_confirm(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def login_qrcode_scan_confirm(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """确认扫描二维码，payload 数据取自 `login_qrcode_scan` 接口响应

        GET https://hnqrcodeapi.115.com/api/2.0/slogin.php

        :payload:
            - key: str
            - uid: str
            - client: int = 0
        """
        api = "https://hnqrcodeapi.115.com/api/2.0/slogin.php"
        if isinstance(payload, str):
            payload = {"key": payload, "uid": payload, "client": 0}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def login_with_app(
        self, 
        /, 
        app: None | str = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def login_with_app(
        self, 
        /, 
        app: None | str = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def login_with_app(
        self, 
        /, 
        app: None | str = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """执行一次自动扫登录二维码，然后绑定到指定设备

        :param app: 绑定的 `app` （或者叫 `device`），如果为 None 或 ""，则和当前 client 的登录设备相同
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 响应信息，包含 cookies

        -----

        app 至少有 24 个可用值，目前找出 14 个：

        - web
        - ios
        - 115ios
        - android
        - 115android
        - 115ipad
        - tv
        - qandroid
        - windows
        - mac
        - linux
        - wechatmini
        - alipaymini
        - harmony

        还有几个备选（暂不可用）：

        - bios
        - bandroid
        - ipad（登录机制有些不同，暂时未破解）
        - qios（登录机制有些不同，暂时未破解）
        - desktop（就是 web，但是用 115 浏览器登录）

        :设备列表如下:

        +-------+----------+------------+-------------------------+
        | No.   | ssoent   | app        | description             |
        +=======+==========+============+=========================+
        | 01    | A1       | web        | 网页版                  |
        +-------+----------+------------+-------------------------+
        | 02    | A2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 03    | A3       | ?          | 未知: iphone            |
        +-------+----------+------------+-------------------------+
        | 04    | A4       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 05    | B1       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 06    | D1       | ios        | 115生活(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 07    | D2       | ?          | 未知: ios               |
        +-------+----------+------------+-------------------------+
        | 08    | D3       | 115ios     | 115(iOS端)              |
        +-------+----------+------------+-------------------------+
        | 09    | F1       | android    | 115生活(Android端)      |
        +-------+----------+------------+-------------------------+
        | 10    | F2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 11    | F3       | 115android | 115(Android端)          |
        +-------+----------+------------+-------------------------+
        | 12    | H1       | ipad       | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 13    | H2       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 14    | H3       | 115ipad    | 115(iPad端)             |
        +-------+----------+------------+-------------------------+
        | 15    | I1       | tv         | 115网盘(Android电视端)  |
        +-------+----------+------------+-------------------------+
        | 16    | M1       | qandriod   | 115管理(Android端)      |
        +-------+----------+------------+-------------------------+
        | 17    | N1       | qios       | 115管理(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 18    | O1       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 19    | P1       | windows    | 115生活(Windows端)      |
        +-------+----------+------------+-------------------------+
        | 20    | P2       | mac        | 115生活(macOS端)        |
        +-------+----------+------------+-------------------------+
        | 21    | P3       | linux      | 115生活(Linux端)        |
        +-------+----------+------------+-------------------------+
        | 22    | R1       | wechatmini | 115生活(微信小程序)     |
        +-------+----------+------------+-------------------------+
        | 23    | R2       | alipaymini | 115生活(支付宝小程序)   |
        +-------+----------+------------+-------------------------+
        | 24    | S1       | harmony    | 115(Harmony端)          |
        +-------+----------+------------+-------------------------+
        """
        def gen_step():
            nonlocal app
            if not app:
                app = yield self.login_app(async_=async_, **request_kwargs)
            if not app:
                raise ValueError("can't determine the login app")
            uid: str = yield self.login_without_app(async_=async_, **request_kwargs)
            return self.login_qrcode_scan_result(
                uid, 
                app, 
                async_=async_, 
                **request_kwargs, 
            )
        return run_gen_step(gen_step, async_=async_)

    @overload
    def login_without_app(
        self, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> str:
        ...
    @overload
    def login_without_app(
        self, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, str]:
        ...
    def login_without_app(
        self, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> str | Coroutine[Any, Any, str]:
        """执行一次自动扫登录二维码，但不绑定设备，返回扫码的 uid，可用于之后绑定设备
        """
        def gen_step():
            uid = check_response((yield self.login_qrcode_token(
                async_=async_, 
                **request_kwargs, 
            )))["data"]["uid"]
            check_response((yield self.login_qrcode_scan(
                uid, 
                async_=async_, 
                **request_kwargs, 
            )))
            check_response((yield self.login_qrcode_scan_confirm(
                uid, 
                async_=async_, 
                **request_kwargs, 
            )))
            return uid
        return run_gen_step(gen_step, async_=async_)

    @overload
    def login_another_app(
        self, 
        /, 
        app: None | str = None, 
        replace: bool | Self = False, 
        check_for_relogin: bool | Callable[[BaseException], bool | int] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> Self:
        ...
    @overload
    def login_another_app(
        self, 
        /, 
        app: None | str = None, 
        replace: bool | Self = False, 
        check_for_relogin: bool | Callable[[BaseException], bool | int] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, Self]:
        ...
    def login_another_app(
        self, 
        /, 
        app: None | str = None, 
        replace: bool | Self = False, 
        check_for_relogin: bool | Callable[[BaseException], bool | int] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> Self | Coroutine[Any, Any, Self]:
        """登录某个设备（同一个设备可以有多个同时在线，但可以通过某些操作，把除了最近登录的那个都下线，也可以专门把最近登录那个也下线）

        .. hint::
            一个设备被新登录者下线，意味着这个 cookies 失效了，不能执行任何需要权限的操作

            但一个设备的新登录者，并不总是意味着把较早的登录者下线，一般需要触发某个检查机制后，才会把同一设备下除最近一次登录外的所有 cookies 失效

        :param app: 要登录的 app，如果为 None，则用当前登录设备，如果无当前登录设备，则报错
        :param replace: 替换某个 client 对象的 cookie

            - 如果为 P115Client, 则把获取到的 `cookies` 更新到此对象
            - 如果为 True，则把获取到的 `cookies` 更新到 `self`
            - 如果为 False，否则返回新的 `P115Client` 对象

        :param check_for_relogin: 网页请求抛出异常时，判断是否要重新登录并重试

            - 如果为 False，则不重试
            - 如果为 True，则自动通过判断 HTTP 响应码为 405 时重新登录并重试
            - 如果为 collections.abc.Callable，则调用以判断，当返回值为 bool 类型且值为 True，或者值为 405 时重新登录，然后循环此流程，直到成功或不可重试

        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        -----

        :设备列表如下:

        +-------+----------+------------+-------------------------+
        | No.   | ssoent   | app        | description             |
        +=======+==========+============+=========================+
        | 01    | A1       | web        | 网页版                  |
        +-------+----------+------------+-------------------------+
        | 02    | A2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 03    | A3       | ?          | 未知: iphone            |
        +-------+----------+------------+-------------------------+
        | 04    | A4       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 05    | B1       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 06    | D1       | ios        | 115生活(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 07    | D2       | ?          | 未知: ios               |
        +-------+----------+------------+-------------------------+
        | 08    | D3       | 115ios     | 115(iOS端)              |
        +-------+----------+------------+-------------------------+
        | 09    | F1       | android    | 115生活(Android端)      |
        +-------+----------+------------+-------------------------+
        | 10    | F2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 11    | F3       | 115android | 115(Android端)          |
        +-------+----------+------------+-------------------------+
        | 12    | H1       | ipad       | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 13    | H2       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 14    | H3       | 115ipad    | 115(iPad端)             |
        +-------+----------+------------+-------------------------+
        | 15    | I1       | tv         | 115网盘(Android电视端)  |
        +-------+----------+------------+-------------------------+
        | 16    | M1       | qandriod   | 115管理(Android端)      |
        +-------+----------+------------+-------------------------+
        | 17    | N1       | qios       | 115管理(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 18    | O1       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 19    | P1       | windows    | 115生活(Windows端)      |
        +-------+----------+------------+-------------------------+
        | 20    | P2       | mac        | 115生活(macOS端)        |
        +-------+----------+------------+-------------------------+
        | 21    | P3       | linux      | 115生活(Linux端)        |
        +-------+----------+------------+-------------------------+
        | 22    | R1       | wechatmini | 115生活(微信小程序)     |
        +-------+----------+------------+-------------------------+
        | 23    | R2       | alipaymini | 115生活(支付宝小程序)   |
        +-------+----------+------------+-------------------------+
        | 24    | S1       | harmony    | 115(Harmony端)          |
        +-------+----------+------------+-------------------------+
        """
        def gen_step():
            nonlocal app
            if not app and isinstance(replace, P115Client):
                app = yield replace.login_app(async_=True)
            resp = yield self.login_with_app(app, async_=async_, **request_kwargs)
            cookies = check_response(resp)["data"]["cookie"]
            ssoent = self.login_ssoent
            if isinstance(replace, P115Client):
                inst = replace
                setattr(inst, "cookies", cookies)
            elif replace:
                inst = self
                setattr(inst, "cookies", cookies)
            else:
                inst = type(self)(cookies, check_for_relogin=check_for_relogin)
            if self is not inst and ssoent == inst.login_ssoent:
                warn(f"login with the same ssoent {ssoent!r}, {self!r} will expire within 60 seconds", category=P115Warning)
            return inst
        return run_gen_step(gen_step, async_=async_)

    @overload
    def login_another_open(
        self, 
        /, 
        app_id: int | str, 
        replace: Literal[True] | Self, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> Self:
        ...
    @overload
    def login_another_open(
        self, 
        /, 
        app_id: int | str, 
        replace: Literal[True] | Self, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, Self]:
        ...
    @overload
    def login_another_open(
        self, 
        /, 
        app_id: int | str, 
        replace: Literal[False] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> P115OpenClient:
        ...
    @overload
    def login_another_open(
        self, 
        /, 
        app_id: int | str, 
        replace: Literal[False] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, P115OpenClient]:
        ...
    def login_another_open(
        self, 
        /, 
        app_id: int | str, 
        replace: bool | Self = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> P115OpenClient | Coroutine[Any, Any, P115OpenClient] | Self | Coroutine[Any, Any, Self]:
        """登录某个开放接口应用

        :param app_id: AppID
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数
        """
        def gen_step():
            resp = yield self.login_qrcode_token_open(app_id, async_=async_, **request_kwargs)
            login_uid = check_response(resp)["data"]["uid"]
            yield self.login_qrcode_scan(login_uid, async_=async_, **request_kwargs)
            yield self.login_qrcode_scan_confirm(login_uid, async_=async_, **request_kwargs)
            resp = yield self.login_qrcode_access_token_open(login_uid, async_=async_, **request_kwargs)
            check_response(resp)
            data = resp["data"]
            if replace is False:
                inst: P115OpenClient | Self = P115OpenClient.from_token(data["access_token"], data["refresh_token"])
            else:
                if replace is True:
                    inst = self
                else:
                    inst = replace
                inst.refresh_token = data["refresh_token"]
                inst.access_token = data["access_token"]
            inst.app_id = app_id
            return inst
        return run_gen_step(gen_step, async_=async_)

    @overload
    @classmethod
    def login_bind_app(
        cls, 
        /, 
        uid: str, 
        app: str = "alipaymini", 
        check_for_relogin: bool | Callable[[BaseException], bool | int] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> Self:
        ...
    @overload
    @classmethod
    def login_bind_app(
        cls, 
        /, 
        uid: str, 
        app: str = "alipaymini", 
        check_for_relogin: bool | Callable[[BaseException], bool | int] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, Self]:
        ...
    @classmethod
    def login_bind_app(
        cls, 
        /, 
        uid: str, 
        app: str = "alipaymini", 
        check_for_relogin: bool | Callable[[BaseException], bool | int] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> Self | Coroutine[Any, Any, Self]:
        """获取绑定到某个设备的 cookies

        .. hint::
            同一个设备可以有多个 cookies 同时在线

            其实只要你不主动去执行检查，这些 cookies 可以同时生效，只是看起来像“黑户”

        :param uid: 登录二维码的 uid
        :param app: 待绑定的设备名称
        :param check_for_relogin: 网页请求抛出异常时，判断是否要重新登录并重试

            - 如果为 False，则不重试
            - 如果为 True，则自动通过判断 HTTP 响应码为 405 时重新登录并重试
            - 如果为 collections.abc.Callable，则调用以判断，当返回值为 bool 类型且值为 True，或者值为 405 时重新登录，然后循环此流程，直到成功或不可重试

        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 新的实例

        -----

        :设备列表如下:

        +-------+----------+------------+-------------------------+
        | No.   | ssoent   | app        | description             |
        +=======+==========+============+=========================+
        | 01    | A1       | web        | 网页版                  |
        +-------+----------+------------+-------------------------+
        | 02    | A2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 03    | A3       | ?          | 未知: iphone            |
        +-------+----------+------------+-------------------------+
        | 04    | A4       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 05    | B1       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 06    | D1       | ios        | 115生活(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 07    | D2       | ?          | 未知: ios               |
        +-------+----------+------------+-------------------------+
        | 08    | D3       | 115ios     | 115(iOS端)              |
        +-------+----------+------------+-------------------------+
        | 09    | F1       | android    | 115生活(Android端)      |
        +-------+----------+------------+-------------------------+
        | 10    | F2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 11    | F3       | 115android | 115(Android端)          |
        +-------+----------+------------+-------------------------+
        | 12    | H1       | ipad       | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 13    | H2       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 14    | H3       | 115ipad    | 115(iPad端)             |
        +-------+----------+------------+-------------------------+
        | 15    | I1       | tv         | 115网盘(Android电视端)  |
        +-------+----------+------------+-------------------------+
        | 16    | M1       | qandriod   | 115管理(Android端)      |
        +-------+----------+------------+-------------------------+
        | 17    | N1       | qios       | 115管理(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 18    | O1       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 19    | P1       | windows    | 115生活(Windows端)      |
        +-------+----------+------------+-------------------------+
        | 20    | P2       | mac        | 115生活(macOS端)        |
        +-------+----------+------------+-------------------------+
        | 21    | P3       | linux      | 115生活(Linux端)        |
        +-------+----------+------------+-------------------------+
        | 22    | R1       | wechatmini | 115生活(微信小程序)     |
        +-------+----------+------------+-------------------------+
        | 23    | R2       | alipaymini | 115生活(支付宝小程序)   |
        +-------+----------+------------+-------------------------+
        | 24    | S1       | harmony    | 115(Harmony端)          |
        +-------+----------+------------+-------------------------+
        """
        def gen_step():
            resp = yield cls.login_qrcode_scan_result(uid, app, async_=async_, **request_kwargs)
            cookies = check_response(resp)["data"]["cookie"]
            return cls(cookies, check_for_relogin=check_for_relogin)
        return run_gen_step(gen_step, async_=async_)

    @overload
    def logout(
        self, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> Any:
        ...
    @overload
    def logout(
        self, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, Any]:
        ...
    def logout(
        self, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> Any | Coroutine[Any, Any, Any]:
        """退出当前设备的登录状态
        """
        ssoent = self.login_ssoent
        if not ssoent:
            if async_:
                async def none():
                    return None
                return none()
            else:
                return None
        return self.logout_by_ssoent(ssoent, async_=async_, **request_kwargs)

    def request(
        self, 
        /, 
        url: str, 
        method: str = "GET", 
        params = None, 
        data = None, 
        *, 
        ecdh_encrypt: bool = False, 
        get_cookies: None | Callable[..., None | str] = None, 
        revert_cookies: None | Callable[[str], Any] = None, 
        async_: Literal[False, True] = False, 
        request: None | Callable[[Unpack[RequestKeywords]], Any] = None, 
        **request_kwargs, 
    ):
        """帮助函数：可执行同步和异步的网络请求

        :param url: HTTP 的请求链接
        :param method: HTTP 的请求方法
        :param params: 查询参数
        :param ecdh_encrypt: 使用 ecdh 算法进行加密（返回值也要解密）
        :param get_cookies: 调用以获取 cookies
        :param revert_cookies: 调用以退还 cookies
        :param async_: 说明 `request` 是同步调用还是异步调用
        :param request: HTTP 请求调用，如果为 None，则默认用 httpx 执行请求
            如果传入调用，则必须至少能接受以下几个关键词参数：

            - url:     HTTP 的请求链接
            - method:  HTTP 的请求方法
            - headers: HTTP 的请求头
            - data:    HTTP 的请求体
            - parse:   解析 HTTP 响应的方法，默认会构建一个 Callable，会把响应的字节数据视为 JSON 进行反序列化解析

                - 如果为 None，则直接把响应对象返回
                - 如果为 ...(Ellipsis)，则把响应对象关闭后将其返回
                - 如果为 True，则根据响应头来确定把响应得到的字节数据解析成何种格式（反序列化），请求也会被自动关闭
                - 如果为 False，则直接返回响应得到的字节数据，请求也会被自动关闭
                - 如果为 Callable，则使用此调用来解析数据，接受 1-2 个位置参数，并把解析结果返回给 `request` 的调用者，请求也会被自动关闭
                    - 如果只接受 1 个位置参数，则把响应对象传给它
                    - 如果能接受 2 个位置参数，则把响应对象和响应得到的字节数据（响应体）传给它

        :param request_kwargs: 其余的请求参数，会被传给 `request`

        :return: 直接返回 `request` 执行请求后的返回值

        .. note:: 
            `request` 可以由不同的请求库来提供，下面是封装了一些模块

            1. `httpx_request <https://pypi.org/project/httpx_request/>`_，由 `httpx <https://pypi.org/project/httpx/>`_ 封装，支持同步和异步调用，本模块默认用的就是这个封装

                .. code:: python

                    from httpx_request import request

            2. `python-urlopen <https://pypi.org/project/python-urlopen/>`_，由 `urllib.request.urlopen <https://docs.python.org/3/library/urllib.request.html#urllib.request.urlopen>`_ 封装，支持同步调用，性能相对最差

                .. code:: python

                    from urlopen import request

            3. `urllib3_request <https://pypi.org/project/urllib3_request/>`_，由 `urllib3 <https://pypi.org/project/urllib3/>`_ 封装，支持同步调用，性能相对较好，推荐使用

                .. code:: python

                    from urllib3_request import request

            4. `requests_request <https://pypi.org/project/requests_request/>`_，由 `requests <https://pypi.org/project/requests/>`_ 封装，支持同步调用

                .. code:: python

                    from requests_request import request

            5. `aiohttp_client_request <https://pypi.org/project/aiohttp_client_request/>`_，由 `aiohttp <https://pypi.org/project/aiohttp/>`_ 封装，支持异步调用，异步并发能力最强，推荐使用

                .. code:: python

                    from aiohttp_client_request import request

            6. `blacksheep_client_request <https://pypi.org/project/blacksheep_client_request/>`_，由 `blacksheep <https://pypi.org/project/blacksheep/>`_ 封装，支持异步调用

                .. code:: python

                    from blacksheep_client_request import request
        """
        if url.startswith("//"):
            url = "http:" + url
        elif not url.startswith(("http://", "https://")):
            if url.startswith("?"):
                url = "http://115.com" + url
            else:
                if not url.startswith("/"):
                    url = "/" + url
                if url.startswith(("/app/", "/android/", "/115android/", "/ios/", "/115ios/", "/115ipad/", "/wechatmini/", "/alipaymini/")):
                    url = "http://proapi.115.com" + url
                else:
                    url = "http://webapi.115.com" + url
        if params:
            url = make_url(url, params)
        if request is None:
            request_kwargs["session"] = self.async_session if async_ else self.session
            request_kwargs["async_"] = async_
            headers: IgnoreCaseDict[str] = IgnoreCaseDict()
            request = get_default_request()
        else:
            headers = IgnoreCaseDict(self.headers)
        headers.update(request_kwargs.get("headers") or {})
        need_set_cookies = get_cookies is not None or "cookie" not in headers
        if m := CRE_API_match(url):
            headers["host"] = m.expand(r"\1.api.115.com")
        request_kwargs["headers"] = headers
        if ecdh_encrypt:
            url = make_url(url, _default_k_ec)
            if data:
                request_kwargs["data"] = ecdh_aes_encode(urlencode(data).encode("latin-1") + b"&")
            headers["content-type"] = "application/x-www-form-urlencoded"
        elif isinstance(data, (list, dict)):
            request_kwargs["data"] = urlencode(data).encode("latin-1")
            headers["content-type"] = "application/x-www-form-urlencoded"
        elif data is not None:
            request_kwargs["data"] = data
        request_kwargs.setdefault("parse", default_parse)
        use_cookies = not url.startswith("https://proapi.115.com/open/")
        if not use_cookies:
            headers["cookie"] = ""
        def gen_step():
            if async_:
                lock: Lock | AsyncLock = self.request_alock
            else:
                lock = self.request_lock
            check_for_relogin = self.check_for_relogin
            cant_relogin = not callable(check_for_relogin)
            if get_cookies is not None:
                get_cookies_need_arg = argcount(get_cookies) >= 1
            cookies_new: None | str
            cookies_: None | str = None
            for i in count(0):
                exc = None
                try:
                    if use_cookies:
                        if get_cookies is None:
                            if need_set_cookies:
                                cookies_old = headers["cookie"] = self.cookies_str
                        else:
                            if get_cookies_need_arg:
                                cookies_ = yield get_cookies(async_)
                            else:
                                cookies_ = yield get_cookies()
                            if not cookies_:
                                raise ValueError("can't get new cookies")
                            headers["cookie"] = cookies_
                    resp = yield partial(request, url=url, method=method, **request_kwargs)
                    return resp
                except BaseException as e:
                    exc = e
                    if cant_relogin or use_cookies and not need_set_cookies:
                        raise
                    if isinstance(e, (AuthenticationError, LoginError)):
                        if use_cookies and (
                            get_cookies is not None or 
                            cookies_old != self.cookies_str or 
                            cookies_old != self._read_cookies()
                        ):
                            continue
                        raise
                    res = yield partial(cast(Callable, check_for_relogin), e)
                    if not res if isinstance(res, bool) else res != 405:
                        raise
                    if use_cookies:
                        if get_cookies is not None:
                            continue
                        cookies = self.cookies_str
                        if not cookies_equal(cookies, cookies_old):
                            continue
                        cookies_mtime = getattr(self, "cookies_mtime", 0)
                        yield lock.acquire
                        try:
                            cookies_new = self.cookies_str
                            cookies_mtime_new = getattr(self, "cookies_mtime", 0)
                            if cookies_equal(cookies, cookies_new):
                                m = CRE_COOKIES_UID_search(cookies)
                                uid = "" if m is None else m[0]
                                need_read_cookies = cookies_mtime_new > cookies_mtime
                                if need_read_cookies:
                                    cookies_new = self._read_cookies()
                                if i and cookies_equal(cookies_old, cookies_new):
                                    raise
                                if not (need_read_cookies and cookies_new):
                                    warn(f"relogin to refresh cookies: UID={uid!r} app={self.login_app()!r}", category=P115Warning)
                                    yield self.login_another_app(
                                        replace=True, 
                                        async_=async_, # type: ignore
                                    )
                        finally:
                            lock.release()
                    else:
                        access_token = self.access_token
                        yield lock.acquire
                        try:
                            if access_token != self.access_token:
                                continue
                            if hasattr(self, "app_id"):
                                app_id = self.app_id
                                yield self.login_another_open(
                                    app_id, 
                                    replace=True, 
                                    async_=async_, # type: ignore
                                )
                                warn(f"relogin to refresh token: {app_id=}", category=P115Warning)
                            else:
                                resp = yield self.refresh_access_token(
                                    async_=async_, # type: ignore
                                )
                                check_response(resp)
                                warn("relogin to refresh token (using refresh_token)", category=P115Warning)
                        finally:
                            lock.release()
                finally:
                    if (use_cookies and cookies_ and 
                        get_cookies is not None and 
                        revert_cookies is not None and (
                            not exc or not (
                                isinstance(exc, (AuthenticationError, LoginError)) or 
                                get_status_code(exc) == 405
                            )
                        )
                    ):
                        yield partial(revert_cookies, cookies_)
        return run_gen_step(gen_step, async_=async_)

    ########## Activity API ##########

    @overload
    def act_xys_adopt(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_adopt(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_adopt(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """采纳助愿

        POST https://act.115.com/api/1.0/web/1.0/act2024xys/adopt

        :payload:
            - did: str 💡 许愿的 id
            - aid: int | str 💡 助愿的 id
            - to_cid: int = <default> 💡 助愿中的分享链接转存到你的网盘中目录的 id
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/adopt", "act", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def act_xys_aid_desire(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_aid_desire(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_aid_desire(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """创建助愿（如果提供 file_ids，则会创建一个分享链接）

        POST https://act.115.com/api/1.0/web/1.0/act2024xys/aid_desire

        :payload:
            - id: str 💡 许愿 id
            - content: str 💡 助愿文本，不少于 5 个字，不超过 500 个字
            - images: int | str = <default> 💡 图片文件在你的网盘的 id，多个用逗号 "," 隔开
            - file_ids: int | str = <default> 💡 文件在你的网盘的 id，多个用逗号 "," 隔开
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/aid_desire", "act", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def act_xys_aid_desire_del(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_aid_desire_del(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_aid_desire_del(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除助愿

        POST https://act.115.com/api/1.0/web/1.0/act2024xys/del_aid_desire

        :payload:
            - ids: int | str 💡 助愿的 id，多个用逗号 "," 隔开
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/del_aid_desire", "act", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"ids": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def act_xys_desire_aid_list(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_desire_aid_list(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_desire_aid_list(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取许愿的助愿列表

        GET https://act.115.com/api/1.0/web/1.0/act2024xys/desire_aid_list

        :payload:
            - id: str         💡 许愿的 id
            - start: int = 0  💡 开始索引
            - page: int = 1   💡 第几页
            - limit: int = 10 💡 分页大小
            - sort: int | str = <default> 💡 排序
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/desire_aid_list", "act", base_url=base_url)
        if isinstance(payload, str):
            payload = {"start": 0, "page": 1, "limit": 10, "id": payload}
        else:
            payload = {"start": 0, "page": 1, "limit": 10, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def act_xys_get_act_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_get_act_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_get_act_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取许愿树活动的信息

        GET https://act.115.com/api/1.0/web/1.0/act2024xys/get_act_info
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/get_act_info", "act", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def act_xys_get_desire_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_get_desire_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_get_desire_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取的许愿信息

        GET https://act.115.com/api/1.0/web/1.0/act2024xys/get_desire_info

        :payload:
            - id: str 💡 许愿的 id
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/get_desire_info", "act", base_url=base_url)
        if isinstance(payload, str):
            payload = {"id": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def act_xys_home_list(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_home_list(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_home_list(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """首页的许愿树（随机刷新 15 条）

        GET https://act.115.com/api/1.0/web/1.0/act2024xys/home_list
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/home_list", "act", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def act_xys_my_aid_desire(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_my_aid_desire(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_my_aid_desire(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """我的助愿列表

        GET https://act.115.com/api/1.0/web/1.0/act2024xys/my_aid_desire

        :payload:
            - type: 0 | 1 | 2 = 0 💡 类型

              - 0: 全部
              - 1: 进行中
              - 2: 已实现

            - start: int = 0  💡 开始索引
            - page: int = 1   💡 第几页
            - limit: int = 10 💡 分页大小
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/my_aid_desire", "act", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"start": 0, "page": 1, "limit": 10, "type": payload}
        else:
            payload = {"type": 0, "start": 0, "page": 1, "limit": 10, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def act_xys_my_desire(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_my_desire(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_my_desire(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """我的许愿列表

        GET https://act.115.com/api/1.0/web/1.0/act2024xys/my_desire

        :payload:
            - type: 0 | 1 | 2 = 0 💡 类型

              - 0: 全部
              - 1: 进行中
              - 2: 已实现

            - start: int = 0  💡 开始索引
            - page: int = 1   💡 第几页
            - limit: int = 10 💡 分页大小
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/my_desire", "act", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"start": 0, "page": 1, "limit": 10, "type": payload}
        else:
            payload = {"type": 0, "start": 0, "page": 1, "limit": 10, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def act_xys_wish(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_wish(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_wish(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """创建许愿

        POST https://act.115.com/api/1.0/web/1.0/act2024xys/wish

        :payload:
            - content: str 💡 许愿文本，不少于 5 个字，不超过 500 个字
            - rewardSpace: int = 5 💡 奖励容量，单位是 GB
            - images: int | str = <default> 💡 图片文件在你的网盘的 id，多个用逗号 "," 隔开
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/wish", "act", base_url=base_url)
        if isinstance(payload, str):
            payload = {"rewardSpace": 5, "content": payload}
        else:
            payload = {"rewardSpace": 5, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def act_xys_wish_del(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def act_xys_wish_del(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def act_xys_wish_del(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除许愿

        POST https://act.115.com/api/1.0/web/1.0/act2024xys/del_wish

        :payload:
            - ids: str 💡 许愿的 id，多个用逗号 "," 隔开
        """
        api = complete_api("/api/1.0/web/1.0/act2024xys/del_wish", "act", base_url=base_url)
        if isinstance(payload, str):
            payload = {"ids": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    ########## App API ##########

    @overload
    @staticmethod
    def app_version_list(
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs
    ) -> dict:
        ...
    @overload
    @staticmethod
    def app_version_list(
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def app_version_list(
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取当前各平台最新版 115 app 下载链接

        GET https://appversion.115.com/1/web/1.0/api/chrome
        """
        api = "https://appversion.115.com/1/web/1.0/api/chrome"
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, async_=async_, **request_kwargs)
        else:
            return request(url=api, **request_kwargs)

    @overload
    @staticmethod
    def app_version_list2(
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs
    ) -> dict:
        ...
    @overload
    @staticmethod
    def app_version_list2(
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def app_version_list2(
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取当前各平台最新版 115 app 下载链接

        GET https://appversion.115.com/1/web/1.0/api/getMultiVer
        """
        api = "https://appversion.115.com/1/web/1.0/api/getMultiVer"
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, async_=async_, **request_kwargs)
        else:
            return request(url=api, **request_kwargs)

    ########## Captcha System API ##########

    @overload
    def captcha_all(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> bytes:
        ...
    @overload
    def captcha_all(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, bytes]:
        ...
    def captcha_all(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> bytes | Coroutine[Any, Any, bytes]:
        """返回一张包含 10 个汉字的图片，包含验证码中 4 个汉字（有相应的编号，从 0 到 9，计数按照从左到右，从上到下的顺序）

        GET https://captchaapi.115.com/?ct=index&ac=code&t=all
        """
        api = complete_api("/?ct=index&ac=code&t=all", "captchaapi", base_url=base_url)
        request_kwargs.setdefault("parse", False)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def captcha_code(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> bytes:
        ...
    @overload
    def captcha_code(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, bytes]:
        ...
    def captcha_code(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> bytes | Coroutine[Any, Any, bytes]:
        """更新验证码，并获取图片数据（含 4 个汉字）

        GET https://captchaapi.115.com/?ct=index&ac=code
        """
        api = complete_api("/?ct=index&ac=code", "captchaapi", base_url=base_url)
        request_kwargs.setdefault("parse", False)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def captcha_sign(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def captcha_sign(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def captcha_sign(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取验证码的签名字符串

        GET https://captchaapi.115.com/?ac=code&t=sign
        """
        api = complete_api("/?ac=code&t=sign", "captchaapi", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def captcha_single(
        self, 
        id: int, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> bytes:
        ...
    @overload
    def captcha_single(
        self, 
        id: int, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, bytes]:
        ...
    def captcha_single(
        self, 
        id: int, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> bytes | Coroutine[Any, Any, bytes]:
        """10 个汉字单独的图片，包含验证码中 4 个汉字，编号从 0 到 9

        GET https://captchaapi.115.com/?ct=index&ac=code&t=single&id={id}
        """
        if not 0 <= id <= 9:
            raise ValueError(f"expected integer between 0 and 9, got {id}")
        api = complete_api(f"/?ct=index&ac=code&t=single&id={id}", "captchaapi", base_url=base_url)
        request_kwargs.setdefault("parse", False)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def captcha_verify(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def captcha_verify(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def captcha_verify(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """提交验证码

        POST https://webapi.115.com/user/captcha

        :payload:
            - code: int | str 💡 从 0 到 9 中选取 4 个数字的一种排列
            - sign: str = <default>     💡 来自 `captcha_sign` 接口的响应
            - ac: str = "security_code" 💡 默认就行，不要自行决定
            - type: str = "web"         💡 默认就行，不要自行决定
            - ctype: str = "web"        💡 需要和 type 相同
            - client: str = "web"       💡 需要和 type 相同
        """
        api = complete_webapi("/user/captcha", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"ac": "security_code", "type": "web", "ctype": "web", "client": "web", "code": payload}
        else:
            payload = {"ac": "security_code", "type": "web", "ctype": "web", "client": "web", **payload}
        def gen_step():
            if "sign" not in payload:
                resp = yield self.captcha_sign(async_=async_)
                payload["sign"] = resp["sign"]
            return partial(
                self.request, 
                url=api, 
                method="POST", 
                data=payload, 
                async_=async_, 
                **request_kwargs, 
            )
        return run_gen_step(gen_step, async_=async_)

    ########## Download API ##########

    @overload
    def download_folders(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def download_folders(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def download_folders(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取待下载的目录列表

        GET https://proapi.115.com/app/chrome/downfolders

        .. note::
            一页最多可获取 3000 条记录

        :payload:
            - pickcode: str 💡 提取码
            - page: int = 1 💡 第几页
        """
        api = complete_proapi("/app/chrome/downfolders", base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        payload.setdefault("page", 1)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def download_files(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def download_files(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def download_files(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取待下载的文件列表

        GET https://proapi.115.com/app/chrome/downfiles

        .. note::
            一页最多可获取 3000 条记录，不提供文件名

        :payload:
            - pickcode: str 💡 提取码
            - page: int = 1 💡 第几页
        """
        api = complete_proapi("/app/chrome/downfiles", base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        payload.setdefault("page", 1)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def download_downfolder_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def download_downfolder_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def download_downfolder_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取待下载的文件列表

        GET https://proapi.115.com/android/folder/downfolder

        .. caution::
            一次性拉完，当文件过多时，会报错

        :payload:
            - pickcode: str 💡 提取码
        """
        api = complete_proapi("/folder/downfolder", base_url, app)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def download_url(
        self, 
        pickcode: str, 
        /, 
        strict: bool = True, 
        use_web_api: bool = False, 
        app: str = "chrome", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> P115URL:
        ...
    @overload
    def download_url(
        self, 
        pickcode: str, 
        /, 
        strict: bool = True, 
        use_web_api: bool = False, 
        app: str = "chrome", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, P115URL]:
        ...
    def download_url(
        self, 
        pickcode: str, 
        /, 
        strict: bool = True, 
        use_web_api: bool = False, 
        app: str = "chrome", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> P115URL | Coroutine[Any, Any, P115URL]:
        """获取文件的下载链接，此接口是对 `download_url_app` 的封装

        .. note::
            获取的直链中，部分查询参数的解释：

            - `t`: 过期时间戳
            - `u`: 用户 id
            - `c`: 允许同时打开次数，如果为 0，则是无限次数
            - `f`: 请求时要求携带请求头
                - 如果为空，则无要求
                - 如果为 1，则需要 User-Agent（和请求直链时的一致）
                - 如果为 3，则需要 User-Agent（和请求直链时的一致） 和 Cookie（由请求直链时的响应所返回的 Set-Cookie 响应头）

        :param pickcode: 提取码
        :param strict: 如果为 True，当目标是目录时，会抛出 IsADirectoryError 异常
        :param use_web_api: 是否使用网页版接口执行请求（优先级高于 `app`）
        :param app: 使用此设备的接口
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 下载链接
        """
        if use_web_api:
            resp = self.download_url_web(
                pickcode, 
                async_=async_, 
                **request_kwargs, 
            )
            def get_url(resp: dict, /) -> P115URL:
                resp["pickcode"] = pickcode
                try:
                    check_response(resp)
                except IsADirectoryError:
                    if strict:
                        raise
                return P115URL(
                    resp.get("file_url", ""), 
                    id=int(resp["file_id"]), 
                    pickcode=pickcode, 
                    name=resp["file_name"], 
                    size=int(resp["file_size"]), 
                    is_directory=not resp["state"], 
                    headers=resp["headers"], 
                )
        else:
            resp = self.download_url_app(
                pickcode, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
            def get_url(resp: dict, /) -> P115URL:
                resp["pickcode"] = pickcode
                check_response(resp)
                if "url" in resp["data"]:
                    url = resp["data"]["url"]
                    return P115URL(
                        url, 
                        pickcode=pickcode, 
                        name=unquote(urlsplit(url).path.rsplit("/", 1)[-1]), 
                        is_directory=False, 
                        headers=resp["headers"], 
                    )
                for fid, info in resp["data"].items():
                    url = info["url"]
                    if strict and not url:
                        raise IsADirectoryError(
                            EISDIR, 
                            f"{fid} is a directory, with response {resp}", 
                        )
                    return P115URL(
                        url["url"] if url else "", 
                        id=int(fid), 
                        pickcode=info["pick_code"], 
                        name=info["file_name"], 
                        size=int(info["file_size"]), 
                        sha1=info["sha1"], 
                        is_directory=not url, 
                        headers=resp["headers"], 
                    )
                raise FileNotFoundError(
                    ENOENT, 
                    f"no such pickcode: {pickcode!r}, with response {resp}", 
                )
        if async_:
            async def async_request() -> P115URL:
                return get_url(await cast(Coroutine[Any, Any, dict], resp)) 
            return async_request()
        else:
            return get_url(cast(dict, resp))

    @overload
    def download_url_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "chrome", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def download_url_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "chrome", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def download_url_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "chrome", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取文件的下载链接

        POST https://proapi.115.com/app/chrome/downurl

        :payload:
            - pickcode: str 💡 如果 `app` 为 "chrome"，则可以接受多个，多个用逗号 "," 隔开
        """
        if app == "chrome":
            api = complete_proapi("/app/chrome/downurl", base_url)
            if isinstance(payload, str):
                payload = {"pickcode": payload}
        else:
            api = complete_proapi("/2.0/ufile/download", base_url, app)
            if isinstance(payload, str):
                payload = {"pick_code": payload}
            else:
                payload = {"pick_code": payload["pickcode"]}
        request_headers = request_kwargs.get("headers")
        headers = request_kwargs.get("headers")
        if headers:
            if isinstance(headers, Mapping):
                headers = ItemsView(headers)
            headers = request_kwargs["headers"] = {
                "user-agent": next((v for k, v in headers if k.lower() == "user-agent" and v), "")}
        else:
            headers = request_kwargs["headers"] = {"user-agent": ""}
        def parse(_, content: bytes, /) -> dict:
            json = json_loads(content)
            if json["state"]:
                json["data"] = json_loads(rsa_decode(json["data"]))
            json["headers"] = headers
            return json
        request_kwargs.setdefault("parse", parse)
        request_kwargs["data"] = {"data": rsa_encode(dumps(payload)).decode("ascii")}
        return self.request(
            url=api, 
            method="POST", 
            async_=async_, 
            **request_kwargs, 
        )

    @overload
    def download_url_web(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def download_url_web(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def download_url_web(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取文件的下载链接（网页版接口，不推荐使用）

        GET https://webapi.115.com/files/download

        :payload:
            - pickcode: str
            - dl: int = <default>
        """
        api = complete_webapi("/files/download", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        headers = request_kwargs.get("headers")
        if headers:
            if isinstance(headers, Mapping):
                headers = ItemsView(headers)
            headers = request_kwargs["headers"] = {
                "user-agent": next((v for k, v in headers if k.lower() == "user-agent" and v), "")}
        else:
            headers = request_kwargs["headers"] = {"user-agent": ""}
        def parse(resp, content: bytes, /) -> dict:
            json = json_loads(content)
            if "Set-Cookie" in resp.headers:
                if isinstance(resp.headers, Mapping):
                    match = CRE_SET_COOKIE.search(resp.headers["Set-Cookie"])
                    if match is not None:
                        headers["Cookie"] = match[0]
                else:
                    for k, v in reversed(resp.headers.items()):
                        if k == "Set-Cookie" and CRE_SET_COOKIE.match(v) is not None:
                            headers["Cookie"] = v
                            break
            json["headers"] = headers
            return json
        request_kwargs.setdefault("parse", parse)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    ########## Extraction API ##########

    @overload
    def extract_add_file(
        self, 
        payload: list | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_add_file(
        self, 
        payload: list | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_add_file(
        self, 
        payload: list | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """解压缩到某个目录，推荐直接用封装函数 `extract_file`

        POST https://webapi.115.com/files/add_extract_file

        :payload:
            - pick_code: str
            - extract_file: str = ""
            - extract_dir: str = ""
            - extract_file[]: str
            - extract_file[]: str
            - ...
            - to_pid: int | str = 0
            - paths: str = "文件"
        """
        api = complete_webapi("/files/add_extract_file", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def extract_download_url(
        self, 
        /, 
        pickcode: str, 
        path: str, 
        use_web_api: bool = False, 
        app: str = "android", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> P115URL:
        ...
    @overload
    def extract_download_url(
        self, 
        /, 
        pickcode: str, 
        path: str, 
        use_web_api: bool = False, 
        app: str = "android", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, P115URL]:
        ...
    def extract_download_url(
        self, 
        /, 
        pickcode: str, 
        path: str, 
        use_web_api: bool = False, 
        app: str = "android", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> P115URL | Coroutine[Any, Any, P115URL]:
        """获取压缩包中文件的下载链接

        :param pickcode: 压缩包的提取码
        :param path: 文件在压缩包中的路径
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 下载链接
        """
        path = path.rstrip("/")
        if use_web_api:
            resp = self.extract_download_url_web(
                {"pick_code": pickcode, "full_name": path.lstrip("/")}, 
                async_=async_, 
                **request_kwargs, 
            )
        else:
            resp = self.extract_download_url_app(
                {"pick_code": pickcode, "full_name": path.lstrip("/")}, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
        def get_url(resp: dict, /) -> P115URL:
            from posixpath import basename
            data = check_response(resp)["data"]
            url = quote(data["url"], safe=":/?&=%#")
            return P115URL(
                url, 
                name=basename(path), 
                path=path, 
                headers=resp["headers"], 
            )
        if async_:
            async def async_request() -> P115URL:
                return get_url(await cast(Coroutine[Any, Any, dict], resp))
            return async_request()
        else:
            return get_url(cast(dict, resp))

    @overload
    def extract_download_url_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_download_url_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_download_url_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取压缩包中文件的下载链接

        GET https://proapi.115.com/android/2.0/ufile/extract_down_file

        :payload:
            - pick_code: str
            - full_name: str
        """
        api = complete_proapi("/2.0/ufile/extract_down_file", base_url, app)
        request_headers = request_kwargs.get("headers")
        headers = request_kwargs.get("headers")
        if headers:
            if isinstance(headers, Mapping):
                headers = ItemsView(headers)
            headers = request_kwargs["headers"] = {
                "user-agent": next((v for k, v in headers if k.lower() == "user-agent" and v), "")}
        else:
            headers = request_kwargs["headers"] = {"user-agent": ""}
        def parse(_, content: bytes, /) -> dict:
            json = json_loads(content)
            json["headers"] = headers
            return json
        request_kwargs.setdefault("parse", parse)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def extract_download_url_web(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_download_url_web(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_download_url_web(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取压缩包中文件的下载链接

        GET https://webapi.115.com/files/extract_down_file

        :payload:
            - pick_code: str
            - full_name: str
        """
        api = complete_webapi("/files/extract_down_file", base_url=base_url)
        request_headers = request_kwargs.get("headers")
        headers = request_kwargs.get("headers")
        if headers:
            if isinstance(headers, Mapping):
                headers = ItemsView(headers)
            headers = request_kwargs["headers"] = {
                "user-agent": next((v for k, v in headers if k.lower() == "user-agent" and v), "")}
        else:
            headers = request_kwargs["headers"] = {"user-agent": ""}
        def parse(resp, content: bytes, /) -> dict:
            json = json_loads(content)
            if "Set-Cookie" in resp.headers:
                if isinstance(resp.headers, Mapping):
                    match = CRE_SET_COOKIE.search(resp.headers["Set-Cookie"])
                    if match is not None:
                        headers["Cookie"] = match[0]
                else:
                    for k, v in reversed(resp.headers.items()):
                        if k == "Set-Cookie" and CRE_SET_COOKIE.match(v) is not None:
                            headers["Cookie"] = v
                            break
            json["headers"] = headers
            return json
        request_kwargs.setdefault("parse", parse)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def extract_file(
        self, 
        /, 
        pickcode: str, 
        paths: str | Sequence[str], 
        dirname: str, 
        to_pid: int | str,
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_file(
        self, 
        /, 
        pickcode: str, 
        paths: str | Sequence[str], 
        dirname: str, 
        to_pid: int | str,
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_file(
        self, 
        /, 
        pickcode: str, 
        paths: str | Sequence[str] = "", 
        dirname: str = "", 
        to_pid: int | str = 0,
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """解压缩到某个目录，是对 `extract_add_file` 的封装，推荐使用
        """
        dirname = dirname.strip("/")
        dir2 = f"文件/{dirname}" if dirname else "文件"
        data = [
            ("pick_code", pickcode), 
            ("paths", dir2), 
            ("to_pid", to_pid), 
        ]
        if async_:
            async def async_request():
                nonlocal async_, paths
                async_ = cast(Literal[True], async_)
                if not paths:
                    resp = await self.extract_list(pickcode, dirname, async_=async_, **request_kwargs)
                    if not resp["state"]:
                        return resp
                    paths = [
                        p["file_name"] if p["file_category"] else p["file_name"]+"/" 
                        for p in resp["data"]["list"]
                    ]
                    while (next_marker := resp["data"].get("next_marker")):
                        resp = await self.extract_list(
                            pickcode, dirname, next_marker, async_=async_, **request_kwargs)
                        paths.extend(
                            p["file_name"] if p["file_category"] else p["file_name"]+"/" 
                            for p in resp["data"]["list"]
                        )
                if isinstance(paths, str):
                    data.append(
                        ("extract_dir[]" if paths.endswith("/") else "extract_file[]", paths.strip("/"))
                    )
                else:
                    data.extend(
                        ("extract_dir[]" if path.endswith("/") else "extract_file[]", path.strip("/")) 
                        for path in paths
                    )
                return await self.extract_add_file(data, async_=async_, **request_kwargs)
            return async_request()
        else:
            if not paths:
                resp = self.extract_list(pickcode, dirname, async_=async_, **request_kwargs)
                if not resp["state"]:
                    return resp
                paths = [
                    p["file_name"] if p["file_category"] else p["file_name"]+"/" 
                    for p in resp["data"]["list"]
                ]
                while (next_marker := resp["data"].get("next_marker")):
                    resp = self.extract_list(
                        pickcode, dirname, next_marker, async_=async_, **request_kwargs)
                    paths.extend(
                        p["file_name"] if p["file_category"] else p["file_name"]+"/" 
                        for p in resp["data"]["list"]
                    )
            if isinstance(paths, str):
                data.append(
                    ("extract_dir[]" if paths.endswith("/") else "extract_file[]", paths.strip("/"))
                )
            else:
                data.extend(
                    ("extract_dir[]" if path.endswith("/") else "extract_file[]", path.strip("/")) 
                    for path in paths
                )
            return self.extract_add_file(data, async_=async_, **request_kwargs)

    @overload
    def extract_folders(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_folders(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_folders(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取压缩文件的文件列表（简略信息）

        GET https://webapi.115.com/files/extract_folders

        :payload:
            - pick_code: str
            - full_dir_name: str
        """
        api = complete_webapi("/files/extract_folders", base_url=base_url)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def extract_folders_post(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_folders_post(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_folders_post(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取压缩文件的文件列表是否可批量下载（最高支持1万的文件操作数量）

        POST https://webapi.115.com/files/extract_folders

        :payload:
            - pick_code: str
            - full_dir_name: str  💡 多个用逗号 "," 隔开
            - full_file_name: str 💡 多个用逗号 "," 隔开
        """
        api = complete_webapi("/files/extract_folders", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def extract_info(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_info(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取压缩文件的文件列表，推荐直接用封装函数 `extract_list`

        GET https://webapi.115.com/files/extract_info

        :payload:
            - pick_code: str
            - file_name: str = "" 💡 在压缩包中的相对路径
            - next_marker: str = ""
            - page_count: int | str = 999 💡 分页大小，介于 1-999
            - paths: str = "文件" 💡 省略即可
        """
        api = complete_webapi("/files/extract_info", base_url=base_url)
        if isinstance(payload, str):
            payload = {"paths": "文件", "page_count": 999, "next_marker": "", "file_name": "", "pick_code": payload}
        else:
            payload = {"paths": "文件", "page_count": 999, "next_marker": "", "file_name": "", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def extract_list(
        self, 
        /, 
        pickcode: str, 
        path: str, 
        next_marker: str, 
        page_count: int, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_list(
        self, 
        /, 
        pickcode: str, 
        path: str, 
        next_marker: str, 
        page_count: int, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_list(
        self, 
        /, 
        pickcode: str, 
        path: str = "", 
        next_marker: str = "", 
        page_count: int = 999, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取压缩文件的文件列表，此方法是对 `extract_info` 的封装，推荐使用
        """
        if not 1 <= page_count <= 999:
            page_count = 999
        payload = {
            "pick_code": pickcode, 
            "file_name": path.strip("/"), 
            "paths": "文件", 
            "next_marker": next_marker, 
            "page_count": page_count, 
        }
        return self.extract_info(payload, async_=async_, **request_kwargs)

    @overload
    def extract_progress(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_progress(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_progress(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取 解压缩到目录 任务的进度

        GET https://webapi.115.com/files/add_extract_file

        :payload:
            - extract_id: str
        """
        api = complete_webapi("/files/add_extract_file", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"extract_id": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def extract_push(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_push(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_push(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """推送一个解压缩任务给服务器，完成后，就可以查看压缩包的文件列表了

        .. warning::
            只能云解压 20GB 以内文件，不支持云解压分卷压缩包，只支持 .zip、.rar 和 .7z 等

        POST https://webapi.115.com/files/push_extract

        :payload:
            - pick_code: str
            - secret: str = "" 💡 解压密码
        """
        api = complete_webapi("/files/push_extract", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pick_code": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def extract_push_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_push_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_push_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """推送一个解压缩任务给服务器，完成后，就可以查看压缩包的文件列表了

        .. warning::
            只能云解压 20GB 以内文件，不支持云解压分卷压缩包，只支持 .zip、.rar 和 .7z 等

        POST https://proapi.115.com/android/2.0/ufile/push_extract

        :payload:
            - pick_code: str
            - secret: str = "" 💡 解压密码
        """
        api = complete_proapi("/2.0/ufile/push_extract", base_url, app)
        if isinstance(payload, str):
            payload = {"pick_code": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def extract_push_progress(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_push_progress(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_push_progress(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """查询解压缩任务的进度

        GET https://webapi.115.com/files/push_extract

        :payload:
            - pick_code: str
        """
        api = complete_webapi("/files/push_extract", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pick_code": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def extract_push_progress_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def extract_push_progress_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def extract_push_progress_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """查询解压缩任务的进度

        GET https://proapi.115.com/android/2.0/ufile/push_extract

        :payload:
            - pick_code: str
        """
        api = complete_proapi("/2.0/ufile/push_extract", base_url, app)
        if isinstance(payload, str):
            payload = {"pick_code": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    ########## File System API ##########

    @overload
    def fs_albumlist(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_albumlist(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_albumlist(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """相册列表

        GET https://webapi.115.com/photo/albumlist

        :payload:
            - offset: int = 0
            - limit: int = 1150
            - album_type: int = 1
        """
        api = complete_webapi("/photo/albumlist", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"album_type": 1, "limit": 1150, "offset": payload}
        else:
            payload = {"album_type": 1, "limit": 1150, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_batch_edit(
        self, 
        payload: list | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_batch_edit(
        self, 
        payload: list | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_batch_edit(
        self, 
        payload: list | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """批量设置文件或目录（显示时长等）

        POST https://webapi.115.com/files/batch_edit

        :payload:
            - show_play_long[{fid}]: 0 | 1 = 1 💡 设置或取消显示时长
        """
        api = complete_webapi("/files/batch_edit", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_batch_edit_app(
        self, 
        payload: list | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_batch_edit_app(
        self, 
        payload: list | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_batch_edit_app(
        self, 
        payload: list | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """批量设置文件或目录（显示时长等）

        POST https://proapi.115.com/android/files/batch_edit

        :payload:
            - show_play_long[{fid}]: 0 | 1 = 1 💡 设置或取消显示时长
        """
        api = complete_proapi("/files/batch_edit", base_url, app)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_category_get(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_category_get(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_category_get(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """显示属性，可获取文件或目录的统计信息（提示：但得不到根目录的统计信息，所以 cid 为 0 时无意义）

        GET https://webapi.115.com/category/get

        :payload:
            - cid: int | str
            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
        """
        api = complete_webapi("/category/get", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"cid": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_category_get_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_category_get_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_category_get_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """显示属性，可获取文件或目录的统计信息（提示：但得不到根目录的统计信息，所以 cid 为 0 时无意义）

        GET https://proapi.115.com/android/2.0/category/get

        :payload:
            - cid: int | str
            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
        """
        api = complete_proapi("/2.0/category/get", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"cid": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_category_shortcut(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_category_shortcut(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_category_shortcut(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """快捷入口列表（罗列所有的快捷入口）

        GET https://webapi.115.com/category/shortcut

        :payload:
            - offset: int = 0
            - limit: int = 1150
        """
        if isinstance(payload, (int, str)):
            payload = {"limit": 1150, "offset": payload}
        else:
            payload = {"limit": 1150, "offset": 0, **payload}
        api = complete_webapi("/category/shortcut", base_url=base_url)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_category_shortcut_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        set: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_category_shortcut_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        set: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_category_shortcut_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        set: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """把一个目录设置或取消为快捷入口（快捷入口需要是目录）

        POST https://webapi.115.com/category/shortcut

        :payload:
            - file_id: int | str 目录 id，多个用逗号 "," 隔开
            - op: "add" | "delete" | "top" = "add" 操作代码

              - "add":    添加
              - "delete": 删除
              - "top":    置顶
        """
        api = complete_webapi("/category/shortcut", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload, "op": ("delete", "add")[set]}
        elif not isinstance(payload, dict):
            payload = {"file_id": ",".join(map(str, payload)), "op": ("delete", "add")[set]}
        else:
            payload = {"op": ("delete", "add")[set], **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_copy(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_copy(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_copy(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """复制文件或目录

        POST https://webapi.115.com/files/copy

        :payload:
            - fid: int | str 💡 文件或目录 id，只接受单个 id
            - fid[]: int | str
            - ...
            - fid[0]: int | str
            - fid[1]: int | str
            - ...
            - pid: int | str = 0 💡 目标目录 id
        """
        api = complete_webapi("/files/copy", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"fid": payload}
        elif isinstance(payload, dict):
            payload = dict(payload)
        else:
            payload = {f"fid[{i}]": fid for i, fid in enumerate(payload)}
            if not payload:
                return {"state": False, "message": "no op"}
        payload.setdefault("pid", pid)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_copy_app(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_copy_app(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_copy_app(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """复制文件或目录

        POST https://proapi.115.com/android/files/copy

        :payload:
            - fid: int | str 💡 文件或目录的 id，多个用逗号 "," 隔开
            - pid: int | str = 0 💡 目标目录 id
        """
        api = complete_proapi("/files/copy", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"fid": payload}
        elif isinstance(payload, dict):
            payload = dict(payload)
        else:
            payload = {"fid": ",".join(map(str, payload))}
        if not payload.get("fid"):
            return {"state": False, "message": "no op"}
        payload = cast(dict, payload)
        payload.setdefault("pid", pid)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_cover_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        fid_cover: int | str,
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_cover_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        fid_cover: int | str,
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_cover_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        fid_cover: int | str = 0,
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """修改封面，可以设置目录的封面，此接口是对 `fs_edit` 的封装
        """
        return self._fs_edit_set(payload, "fid_cover", fid_cover, async_=async_, **request_kwargs)

    @overload
    def fs_cover_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        fid_cover: int | str, 
        app: str = "android", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_cover_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        fid_cover: int | str, 
        app: str = "android", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_cover_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        fid_cover: int | str = 0, 
        app: str = "android", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """修改封面，可以设置目录的封面，此接口是对 `fs_edit` 的封装
        """
        return self._fs_edit_set_app(payload, "fid_cover", fid_cover, app=app, async_=async_, **request_kwargs)

    @overload
    def fs_delete(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_delete(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_delete(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除文件或目录

        POST https://webapi.115.com/rb/delete

        .. note::
            删除和（从回收站）还原是互斥的，同时最多只允许执行一个操作

        :payload:
            - fid: int | str 💡 文件或目录的 id，多个用逗号 "," 隔开
            - fid[]: int | str
            - ...
            - fid[0]: int | str
            - fid[1]: int | str
            - ...
            - ignore_warn: 0 | 1 = <default>
        """
        api = complete_webapi("/rb/delete", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"fid": payload}
        elif not isinstance(payload, dict):
            payload = {f"fid[{i}]": fid for i, fid in enumerate(payload)}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_delete_app(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_delete_app(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_delete_app(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除文件或目录

        POST https://proapi.115.com/android/rb/delete

        :payload:
            - file_ids: int | str 💡 文件或目录的 id，多个用逗号 "," 隔开
            - user_id: int | str = <default> 💡 不用管
        """
        api = complete_proapi("/rb/delete", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"file_ids": payload, "user_id": self.user_id}
        elif isinstance(payload, dict):
            payload = dict(payload, user_id=self.user_id)
        else:
            payload = {"file_ids": ",".join(map(str, payload)), "user_id": self.user_id}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_desc(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_desc(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_desc(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取文件或目录的备注

        GET https://webapi.115.com/files/desc

        :payload:
            - file_id: int | str
            - field: str = <default> 💡 可取示例值："pass"
            - format: str = "json"
            - compat: 0 | 1 = 1
            - new_html: 0 | 1 = <default>
        """
        api = complete_webapi("/files/desc", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"format": "json", "compat": 1, "file_id": payload}
        else:
            payload = {"format": "json", "compat": 1, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_desc_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_desc_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_desc_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取文件或目录的备注

        GET https://proapi.115.com/android/files/desc

        :payload:
            - file_id: int | str
            - field: str = <default> 💡 可取示例值："pass"
            - format: str = "json"
            - compat: 0 | 1 = 1
            - new_html: 0 | 1 = <default>
        """
        api = complete_proapi("/android/files/desc", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"format": "json", "compat": 1, "file_id": payload}
        else:
            payload = {"format": "json", "compat": 1, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_desc_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        desc: str = "", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_desc_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        desc: str = "", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_desc_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        desc: str = "", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """为文件或目录设置备注，最多允许 65535 个字节 (64 KB 以内)，此接口是对 `fs_edit` 的封装

        .. hint::
            修改文件备注会更新文件的更新时间，即使什么也没改或者改为空字符串
        """
        return self._fs_edit_set(payload, "file_desc", desc, async_=async_, **request_kwargs)

    @overload
    def fs_desc_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        desc: str = "", 
        app: str = "android", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_desc_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        desc: str = "", 
        app: str = "android", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_desc_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        desc: str = "", 
        app: str = "android", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """为文件或目录设置备注，最多允许 65535 个字节 (64 KB 以内)，此接口是对 `fs_edit` 的封装

        .. hint::
            修改文件备注会更新文件的更新时间，即使什么也没改或者改为空字符串
        """
        return self._fs_edit_set_app(payload, "file_desc", desc, app=app, async_=async_, **request_kwargs)

    @overload
    def fs_dir_getid(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_dir_getid(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_dir_getid(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """由路径获取对应的 id（但只能获取目录，不能获取文件）

        GET https://webapi.115.com/files/getid

        :payload:
            - path: str
        """
        api = complete_webapi("/files/getid", base_url=base_url)
        if isinstance(payload, str):
            payload = {"path": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_dir_getid_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_dir_getid_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_dir_getid_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """由路径获取对应的 id（但只能获取目录，不能获取文件）

        GET https://proapi.115.com/android/files/getid

        :payload:
            - path: str
        """
        api = complete_proapi("/files/getid", base_url, app)
        if isinstance(payload, str):
            payload = {"path": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_document(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_document(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_document(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取图片的各种链接

        GET https://webapi.115.com/files/document

        .. note::
            即使文件格式不正确或者是一个目录，也可返回一些信息（包括 parent_id）

        :payload:
            - pickcode: str
        """
        api = complete_webapi("/files/document", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_document_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_document_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_document_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取图片的各种链接

        GET https://proapi.115.com/android/files/document

        .. note::
            即使文件格式不正确或者是一个目录，也可返回一些信息（包括 parent_id）

        :payload:
            - pickcode: str
        """
        api = complete_proapi("/files/document", base_url, app)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_edit(
        self, 
        payload: list | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_edit(
        self, 
        payload: list | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_edit(
        self, 
        payload: list | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """设置文件或目录（备注、标签等）

        POST https://webapi.115.com/files/edit

        :payload:
            - fid: int | str
            - fid[]: int | str
            - ...
            - file_desc: str = <default> 💡 可以用 html
            - file_label: int | str = <default> 💡 标签 id，多个用逗号 "," 隔开
            - fid_cover: int | str = <default> 💡 封面图片的文件 id，多个用逗号 "," 隔开，如果要删除，值设为 0 即可
            - show_play_long: 0 | 1 = <default> 💡 文件名称显示时长
            - ...
        """
        api = complete_webapi("/files/edit", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_edit_app(
        self, 
        payload: int | str | tuple[int | str] | list | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_edit_app(
        self, 
        payload: int | str | tuple[int | str] | list | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_edit_app(
        self, 
        payload: int | str | tuple[int | str] | list | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """设置文件或目录（备注、标签等）

        POST https://proapi.115.com/android/files/update

        :payload:
            - file_id: int | str
            - file_id[]: int | str
            ...
            - file_id[0]: int | str
            - file_id[1]: int | str
            - ...
            - file_desc: str = <default> 💡 可以用 html
            - file_label: int | str = <default> 💡 标签 id，多个用逗号 "," 隔开
            - fid_cover: int | str = <default> 💡 封面图片的文件 id，多个用逗号 "," 隔开，如果要删除，值设为 0 即可
            - show_play_long: 0 | 1 = <default> 💡 文件名称显示时长
            - ...
        """
        api = complete_proapi("/files/update", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload}
        elif isinstance(payload, tuple):
            payload = {f"file_id[i]": p for i, p in enumerate(payload)}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def _fs_edit_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        attr: str, 
        default: Any = "", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def _fs_edit_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        attr: str, 
        default: Any = "", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def _fs_edit_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        attr: str, 
        default: Any = "", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """批量设置文件或目录（备注、标签等），此接口是对 `fs_edit` 的封装
        """
        if isinstance(payload, (int, str)):
            payload = [("fid", payload), (attr, default)]
        elif isinstance(payload, list):
            if not any(a[0] == attr for a in payload):
                payload.append((attr, default))
        elif isinstance(payload, dict):
            payload.setdefault(attr, default)
        else:
            payload = [("fid[]", fid) for fid in payload]
            if not payload:
                return {"state": False, "message": "no op"}
            payload.append((attr, default))
        return self.fs_edit(payload, async_=async_, **request_kwargs)

    @overload
    def _fs_edit_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        attr: str, 
        default: Any = "", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def _fs_edit_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        attr: str, 
        default: Any = "", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def _fs_edit_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        attr: str, 
        default: Any = "", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """批量设置文件或目录（备注、标签等），此接口是对 `fs_edit` 的封装
        """
        if isinstance(payload, (int, str)):
            payload = [("file_id", payload), (attr, default)]
        elif isinstance(payload, list):
            if not any(a[0] == attr for a in payload):
                payload.append((attr, default))
        elif isinstance(payload, dict):
            payload.setdefault(attr, default)
        else:
            payload = [(f"file_id[{i}]", fid) for i, fid in enumerate(payload)]
            if not payload:
                return {"state": False, "message": "no op"}
            payload.append((attr, default))
        return self.fs_edit(payload, async_=async_, **request_kwargs)

    @overload
    def fs_export_dir(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_export_dir(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_export_dir(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """导出目录树

        POST https://webapi.115.com/files/export_dir

        :payload:
            - file_ids: int | str   💡 多个用逗号 "," 隔开
            - target: str = "U_1_0" 💡 导出目录树到这个目录
            - layer_limit: int = <default> 💡 层级深度，自然数
        """
        api = complete_webapi("/files/export_dir", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"target": "U_1_0", "file_ids": payload}
        else:
            payload = {"target": "U_1_0", **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_export_dir_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_export_dir_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_export_dir_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """导出目录树

        POST https://proapi.115.com/android/2.0/ufile/export_dir

        :payload:
            - file_ids: int | str   💡 多个用逗号 "," 隔开
            - target: str = "U_1_0" 💡 导出目录树到这个目录
            - layer_limit: int = <default> 💡 层级深度，自然数
        """
        api = complete_proapi("/2.0/ufile/export_dir", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"target": "U_1_0", "file_ids": payload}
        else:
            payload = {"target": "U_1_0", **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_export_dir_status(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_export_dir_status(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_export_dir_status(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取导出目录树的完成情况

        GET https://webapi.115.com/files/export_dir

        :payload:
            - export_id: int | str = 0 💡 任务 id
        """
        api = complete_webapi("/files/export_dir", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"export_id": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_export_dir_status_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_export_dir_status_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_export_dir_status_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取导出目录树的完成情况

        GET https://proapi.115.com/android/2.0/ufile/export_dir

        :payload:
            - export_id: int | str = 0 💡 任务 id
        """
        api = complete_proapi("/2.0/ufile/export_dir", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"export_id": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_file(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_file(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_file(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取文件或目录的基本信息

        GET https://webapi.115.com/files/get_info

        :payload:
            - file_id: int | str 💡 文件或目录的 id，不能为 0，只能传 1 个 id，如果有多个只采用第一个
        """
        api = complete_webapi("/files/get_info", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_file_skim(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_file_skim(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_file_skim(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取文件或目录的简略信息

        GET https://webapi.115.com/files/file

        .. note::
            如果需要查询到 id 特别多，请指定 `method="POST"`

        :payload:
            - file_id: int | str 💡 文件或目录的 id，不能为 0，多个用逗号 "," 隔开
        """
        api = complete_webapi("/files/file", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload}
        elif not isinstance(payload, dict):
            payload = {"file_id": ",".join(map(str, payload))}
        if request_kwargs.get("method", "get").lower() == "post":
            request_kwargs.update(data=payload)
        else:
            request_kwargs.update(params=payload)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def fs_files(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_files(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_files(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取目录中的文件列表和基本信息

        GET https://webapi.115.com/files

        .. hint::
            指定如下条件中任一，且 cur = 0 （默认），即可遍历搜索所在目录树

            1. cid=0 且 star=1
            2. suffix 为非空的字符串
            3. type 为正整数
            4. show_dir=0 且 cur=0（或不指定 cur）

        .. hint::
            如果仅指定 natsort=1&show_dir=1，以及一个可选的 cid，则当文件数不大于 1150 时可仅统计某个目录内的文件或目录总数，而不返回具体的文件信息，超过那个数值时，则会返回完整的文件列表

            但如果不指定或者指定的 cid 不存在，则会视为 cid=0 进行处理

        .. hint::
            当一个 cookies 被另一个更新的登录所失效，并不意味着这个 cookies 就直接不可用了。

            如果你使用的是 `proapi` 下的接口，则会让你重新登录。但是 `webapi`、`aps` 等之下的接口，却依然可以正常使用。具体哪些失效，哪些还正常，请自行试验总结。这就意味着可以设计一种同一设备多 cookies 做池的分流策略。

        .. hint::
            对于普通的文件系统，我们只允许任何一个目录中不可有相同的名字，但是 115 网盘中却可能有重复：

            - 目录和文件同名：文件和目录同名在 115 中不算是一个冲突
            - 相同的目录名：转存可以导致同一目录下有多个相同名字的目录
            - 相同的文件名：转存、离线和上传等，可以导致同一目录下有多个相同名字的文件

        .. hint::
            如果文件或目录被置顶，会在整个文件列表的最前面

            在根目录下且 `fc_mix=0` 且是特殊名字 ("我的接收", "手机相册", "云下载", "我的时光记录")（即 sys_dir），会在整个文件列表的最前面但在置顶之后，这时可从返回信息的 "sys_count" 字段知道数目

        .. note::
            当 type=1 时，suffix_type 的取值的含义：

                - (不填): 全部
                - 1: 文字（word，即 doc 和 docx 等）
                - 2: 表格（excel，即 xls 和 xlsx 等）
                - 3: 演示（ppt，即 ppt 和 pptx 等）
                - 4: pdf
                - 5: txt
                - 6: xmind
                - 7: 其它

        :payload:
            - cid: int | str = 0 💡 目录 id
            - limit: int = 32 💡 分页大小，目前最大值是 1,150，以前是没限制的
            - offset: int = 0 💡 分页开始的索引，索引从 0 开始计算

            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
            - asc: 0 | 1 = <default> 💡 是否升序排列。0:降序 1:升序
            - code: int | str = <default>
            - count_folders: 0 | 1 = 1 💡 统计文件数和目录数
            - cur: 0 | 1 = <default> 💡 是否只搜索当前目录
            - custom_order: 0 | 1 = <default> 💡 启用自定义排序，如果指定了 "asc"、"fc_mix"、"o" 中其一，则此参数会被自动设置为 1
            - date: str = <default> 💡 筛选日期
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - fields: str = <default>
            - format: str = "json" 💡 返回格式，默认即可
            - is_q: 0 | 1 = <default>
            - is_share: 0 | 1 = <default>
            - min_size: int = 0 💡 最小的文件大小
            - max_size: int = 0 💡 最大的文件大小
            - natsort: 0 | 1 = <default> 💡 是否执行自然排序(natural sorting) 💡 natural sorting
            - nf: str = <default> 💡 不要显示文件（即仅显示目录），但如果 show_dir=0，则此参数无效
            - o: str = <default> 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_utime": 修改时间
              - "user_ptime": 创建时间
              - "user_otime": 上一次打开时间

            - oof_token: str = <default>
            - qid: int | str = <default>
            - r_all: 0 | 1 = <default>
            - record_open_time: 0 | 1 = 1 💡 是否要记录目录的打开时间
            - scid: int | str = <default>
            - show_dir: 0 | 1 = 1
            - snap: 0 | 1 = <default>
            - source: str = <default>
            - sys_dir: int | str = <default>
            - star: 0 | 1 = <default> 💡 是否星标文件
            - stdir: 0 | 1 = <default>
            - suffix: str = <default> 💡 后缀名（优先级高于 `type`）
            - suffix_type: int = <default>
            - type: int = <default> 💡 文件类型

              - 0: 全部（仅当前目录）
              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍
              - 8: 其它
              - 9: 相当于 8
              - 10: 相当于 8
              - 11: 相当于 8
              - 12: ？？？
              - 13: 相当于 3
              - 14: ？？？
              - 15: 图片和视频，相当于 2 和 4
              - 16: ？？？
              - 17~98: 相当于 8
              - 99: 仅文件
              - >=100: 相当于 8
        """
        api = complete_webapi("/files", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {
                "aid": 1, "count_folders": 1, "limit": 32, "offset": 0, 
                "record_open_time": 1, "show_dir": 1, "cid": payload, 
            }
        else:
            payload = {
                "aid": 1, "count_folders": 1, "limit": 32, "offset": 0, 
                "record_open_time": 1, "show_dir": 1, "cid": 0, **payload, 
            }
        if payload.keys() & frozenset(("asc", "fc_mix", "o")):
            payload["custom_order"] = 1
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_files_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_files_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_files_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取目录中的文件列表和基本信息

        GET https://proapi.115.com/android/2.0/ufile/files

        .. hint::
            如果要遍历获取所有文件，需要指定 show_dir=0 且 cur=0（或不指定 cur），这个接口并没有 type=99 时获取所有文件的意义

        .. note::
            如果 `app` 为 "wechatmini" 或 "alipaymini"，则相当于 `P115Client.fs_files_app2`

        .. caution::
            这个接口有些问题，当 custom_order=1 时：
            
                1. 如果设定 limit=1 可能会报错
                2. fc_mix 无论怎么设置，都和 fc_mix=0 的效果相同（即目录总是置顶），但设置为 custom_order=2 就好了

        .. hint::
            置顶无效，但可以知道是否置顶了。

            在根目录下且 fc_mix=0 且是特殊名字 ("我的接收", "手机相册", "云下载", "我的时光记录")，会在整个文件列表的最前面，这时可从返回信息的 "sys_count" 字段知道数目

        :payload:
            - cid: int | str = 0 💡 目录 id
            - limit: int = 32 💡 分页大小，最大值不一定，看数据量，7,000 应该总是安全的，10,000 有可能报错，但有时也可以 20,000 而成功
            - offset: int = 0 💡 分页开始的索引，索引从 0 开始计算

            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
            - asc: 0 | 1 = <default> 💡 是否升序排列。0:降序 1:升序
            - code: int | str = <default>
            - count_folders: 0 | 1 = 1 💡 统计文件数和目录数
            - cur: 0 | 1 = <default>   💡 是否只显示当前目录
            - custom_order: 0 | 1 | 2 = <default> 💡 是否使用记忆排序。0:使用记忆排序（自定义排序失效） 1:使用自定义排序（不使用记忆排序） 2:自定义排序（非目录置顶）。如果指定了 "asc"、"fc_mix"、"o" 中其一，则此参数会被自动设置为 2
            - date: str = <default> 💡 筛选日期
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - fields: str = <default>
            - for: str = <default> 💡 文件格式，例如 "doc"
            - format: str = "json" 💡 返回格式，默认即可
            - hide_data: str = <default>
            - is_q: 0 | 1 = <default>
            - is_share: 0 | 1 = <default>
            - min_size: int = 0 💡 最小的文件大小
            - max_size: int = 0 💡 最大的文件大小
            - natsort: 0 | 1 = <default> 💡 是否执行自然排序(natural sorting)
            - nf: str = <default> 💡 不要显示文件（即仅显示目录），但如果 show_dir=0，则此参数无效
            - o: str = <default> 💡 用某字段排序（未定义的值会被视为 "user_utime"）

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_etime": 事件时间（无效，效果相当于 "user_utime"）
              - "user_utime": 修改时间
              - "user_ptime": 创建时间（无效，效果相当于 "user_utime"）
              - "user_otime": 上一次打开时间（无效，效果相当于 "user_utime"）

            - r_all: 0 | 1 = <default>
            - record_open_time: 0 | 1 = 1 💡 是否要记录目录的打开时间
            - scid: int | str = <default>
            - show_dir: 0 | 1 = 1 💡 是否展示目录：1:展示 0:不展示
            - snap: 0 | 1 = <default>
            - source: str = <default>
            - sys_dir: int | str = <default> 💡 系统通用目录
            - star: 0 | 1 = <default> 💡 是否星标文件
            - stdir: 0 | 1 = <default>
            - suffix: str = <default> 💡 后缀名（优先级高于 `type`）
            - type: int = <default> 💡 文件类型

              - 0: 全部（仅当前目录）
              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍
              - 8: 其它
              - 9: 相当于 8
              - 10: 相当于 8
              - 11: 相当于 8
              - 12: ？？？
              - 13: ？？？
              - 14: ？？？
              - 15: 图片和视频，相当于 2 和 4
              - >= 16: 相当于 8
        """
        api = complete_proapi("/2.0/ufile/files", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {
                "aid": 1, "count_folders": 1, "limit": 32, "offset": 0, 
                "record_open_time": 1, "show_dir": 1, "cid": payload, 
            }
        else:
            payload = {
                "aid": 1, "count_folders": 1, "limit": 32, "offset": 0, 
                "record_open_time": 1, "show_dir": 1, "cid": 0, **payload, 
            }
        if payload.keys() & frozenset(("asc", "fc_mix", "o")):
            payload["custom_order"] = 2
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_files_app2(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_files_app2(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_files_app2(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取目录中的文件列表和基本信息

        GET https://proapi.115.com/android/files

        .. hint::
            如果要遍历获取所有文件，需要指定 show_dir=0 且 cur=0（或不指定 cur），这个接口并没有 type=99 时获取所有文件的意义

        .. caution::
            这个接口有些问题，当 custom_order=1 时：

                1. 如果设定 limit=1 可能会报错
                2. fc_mix 无论怎么设置，都和 fc_mix=0 的效果相同（即目录总是置顶），设置为 custom_order=2 也没用

        :payload:
            - cid: int | str = 0 💡 目录 id
            - limit: int = 32 💡 分页大小，最大值不一定，看数据量，7,000 应该总是安全的，10,000 有可能报错，但有时也可以 20,000 而成功
            - offset: int = 0 💡 分页开始的索引，索引从 0 开始计算

            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
            - asc: 0 | 1 = <default> 💡 是否升序排列。0:降序 1:升序
            - code: int | str = <default>
            - count_folders: 0 | 1 = 1 💡 统计文件数和目录数
            - cur: 0 | 1 = <default> 💡 是否只搜索当前目录
            - custom_order: 0 | 1 | 2 = <default> 💡 启用自定义排序，如果指定了 "asc"、"fc_mix"、"o" 中其一，则此参数会被自动设置为 2
            - date: str = <default> 💡 筛选日期
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - fields: str = <default>
            - for: str = <default> 💡 文件格式，例如 "doc"
            - format: str = "json" 💡 返回格式，默认即可
            - hide_data: str = <default>
            - is_q: 0 | 1 = <default>
            - is_share: 0 | 1 = <default>
            - min_size: int = 0 💡 最小的文件大小
            - max_size: int = 0 💡 最大的文件大小
            - natsort: 0 | 1 = <default> 💡 是否执行自然排序(natural sorting)
            - nf: str = <default> 💡 不要显示文件（即仅显示目录），但如果 show_dir=0，则此参数无效
            - o: str = <default> 💡 用某字段排序（未定义的值会被视为 "user_utime"）

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_etime": 事件时间（无效，效果相当于 "user_utime"）
              - "user_utime": 修改时间
              - "user_ptime": 创建时间（无效，效果相当于 "user_utime"）
              - "user_otime": 上一次打开时间（无效，效果相当于 "user_utime"）

            - r_all: 0 | 1 = <default>
            - record_open_time: 0 | 1 = 1 💡 是否要记录目录的打开时间
            - scid: int | str = <default>
            - show_dir: 0 | 1 = 1
            - snap: 0 | 1 = <default>
            - source: str = <default>
            - sys_dir: int | str = <default>
            - star: 0 | 1 = <default> 💡 是否星标文件
            - stdir: 0 | 1 = <default>
            - suffix: str = <default> 💡 后缀名（优先级高于 `type`）
            - type: int = <default> 💡 文件类型

              - 0: 全部（仅当前目录）
              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍
              - 8: 其它
              - 9: 相当于 8
              - 10: 相当于 8
              - 11: 相当于 8
              - 12: ？？？
              - 13: ？？？
              - 14: ？？？
              - 15: 图片和视频，相当于 2 和 4
              - >= 16: 相当于 8
        """
        api = complete_proapi("/files", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {
                "aid": 1, "count_folders": 1, "limit": 32, "offset": 0, 
                "record_open_time": 1, "show_dir": 1, "cid": payload, 
            }
        else:
            payload = {
                "aid": 1, "count_folders": 1, "limit": 32, "offset": 0, 
                "record_open_time": 1, "show_dir": 1, "cid": 0, **payload, 
            }
        if payload.keys() & frozenset(("asc", "fc_mix", "o")):
            payload["custom_order"] = 2
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_files_aps(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_files_aps(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_files_aps(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取目录中的文件列表和基本信息

        GET https://aps.115.com/natsort/files.php

        .. caution::
            这个函数最多获取任何一种排序条件下的前 1201 条数据，当你的 `offset < 1201` 时，最多获取 `min(1201 - offset, limit)` 条数据

            `o` 参数无效，效果只等于 "file_name"，而 `fc_mix` 和 `asc` 可用。从技术上来讲最多获取 2402 个文件和 2402 个目录，即你可以通过 asc 取 0 或者 1，来最多获取两倍于数量上限的不同条目，然后通过指定 `show_dir=0&cur=1` 和 `show_dir=1&nf=1` 来分别只获取文件或目录。但如果有置顶的条目，置顶条目总是出现，因此会使能获取到的不同条目总数变少

            当 `offset` >= 1201 或 >= 当前条件下的条目总数时，则相当于 `offset=0&fc_mix=1`，且置顶项不会置顶，且最多获取 1200 条数据

        .. hint::
            文件或目录最多分别获取 max(1201, 2402 - 此类型被置顶的个数) 个，但对于文件，如果利用 type 或 suffix 进行筛选，则可以获得更多

            不过在我看来，只要一个目录内的节点数超过 2,400 个，则大概就没必要使用此接口

        :payload:
            - cid: int | str = 0 💡 目录 id
            - limit: int = 32 💡 分页大小，最大值是 1,200
            - offset: int = 0 💡 分页开始的索引，索引从 0 开始计算

            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
            - asc: 0 | 1 = <default> 💡 是否升序排列。0:降序 1:升序
            - code: int | str = <default>
            - count_folders: 0 | 1 = 1 💡 统计文件数和目录数
            - cur: 0 | 1 = <default> 💡 是否只搜索当前目录
            - custom_order: 0 | 1 = <default> 💡 启用自定义排序，如果指定了 "asc"、"fc_mix" 中其一，则此参数会被自动设置为 1
            - date: str = <default> 💡 筛选日期
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - fields: str = <default>
            - format: str = "json" 💡 返回格式，默认即可
            - hide_data: str = <default>
            - is_asc: 0 | 1 = <default>
            - is_q: 0 | 1 = <default>
            - is_share: 0 | 1 = <default>
            - min_size: int = 0 💡 最小的文件大小
            - max_size: int = 0 💡 最大的文件大小
            - natsort: 0 | 1 = <default>
            - order: str = <default>
            - r_all: 0 | 1 = <default>
            - record_open_time: 0 | 1 = 1 💡 是否要记录目录的打开时间
            - scid: int | str = <default>
            - show_dir: 0 | 1 = 1
            - snap: 0 | 1 = <default>
            - source: str = <default>
            - sys_dir: int | str = <default>
            - star: 0 | 1 = <default> 💡 是否星标文件
            - stdir: 0 | 1 = <default>
            - suffix: str = <default> 💡 后缀名（优先级高于 `type`）
            - type: int = <default> 💡 文件类型

              - 0: 全部（仅当前目录）
              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍
              - 8: 其它
              - 9: 相当于 8
              - 10: 相当于 8
              - 11: 相当于 8
              - 12: ？？？
              - 13: 相当于 3
              - 14: ？？？
              - 15: 图片和视频，相当于 2 和 4
              - 16: ？？？
              - 17~98: 相当于 8
              - 99: 仅文件
              - >=100: 相当于 8
        """
        api = complete_api("/natsort/files.php", "aps", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {
                "aid": 1, "count_folders": 1, "limit": 32, "offset": 0, 
                "record_open_time": 1, "show_dir": 1, "cid": payload, 
            }
        else:
            payload = {
                "aid": 1, "count_folders": 1, "limit": 32, "offset": 0, 
                "record_open_time": 1, "show_dir": 1, "cid": 0, **payload, 
            }
        if payload.keys() & frozenset(("asc", "fc_mix")):
            payload["custom_order"] = 1
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_files_blank_document(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_files_blank_document(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_files_blank_document(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """新建空白 office 文件

        POST https://webapi.115.com/files/blank_document

        :payload:
            - file_name: str      💡 文件名，不含后缀
            - pid: int | str = 0  💡 目录 id
            - type: 1 | 2 | 3 = 1 💡 1:Word文档(.docx) 2:Excel表格(.xlsx) 3:PPT文稿(.pptx)
        """
        api = complete_webapi("/files/blank_document", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pid": 0, "type": 1, "file_name": payload}
        else:
            payload = {"pid": 0, "type": 1, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_files_history(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_files_history(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_files_history(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取文件的观看历史，主要用于视频

        GET https://webapi.115.com/files/history

        :payload:
            - pick_code: str
            - fetch: str = "one"
            - category: int = <default>
            - share_id: int | str = <default>
        """
        api = complete_webapi("/files/history", base_url=base_url)
        if isinstance(payload, str):
            payload = {"fetch": "one", "pick_code": payload}
        else:
            payload = {"fetch": "one", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_files_history_set(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_files_history_set(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_files_history_set(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """更新文件的观看历史，主要用于视频

        POST https://webapi.115.com/files/history

        :payload:
            - pick_code: str     💡 文件的提取码
            - op: str = "update" 💡 操作类型，具体有哪些还需要再研究
            - category: int = <default>
            - definition: int = <default> 💡 视频清晰度
            - share_id: int | str = <default>
            - time: int = <default> 💡 播放时间点（用来向服务器同步播放进度）
            - ...（其它未找全的参数）
        """
        api = complete_webapi("/files/history", base_url=base_url)
        if isinstance(payload, str):
            payload = {"op": "update", "pick_code": payload}
        else:
            payload = {"op": "update", **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_files_second_type(
        self, 
        payload: Literal[1,2,3,4,5,6,7] | dict = 1, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_files_second_type(
        self, 
        payload: Literal[1,2,3,4,5,6,7] | dict = 1, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_files_second_type(
        self, 
        payload: Literal[1,2,3,4,5,6,7] | dict = 1, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取目录中某个文件类型的扩展名的（去重）列表

        GET https://webapi.115.com/files/get_second_type

        :payload:
            - cid: int | str = 0 💡 目录 id
            - type: int = 1 💡 文件类型

              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍

            - file_label: int | str = <default> 💡 标签 id，多个用逗号 "," 隔开
        """
        api = complete_webapi("/files/get_second_type", base_url=base_url)
        if isinstance(payload, int):
            payload = {"cid": 0, "type": payload}
        else:
            payload = {"cid": 0, "type": 1, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_top_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        top: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_top_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        top: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_top_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        top: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """文件或目录置顶

        POST https://webapi.115.com/files/top

        :payload:
            - file_id: int | str 💡 文件或目录的 id，多个用逗号 "," 隔开
            - top: 0 | 1 = 1
        """
        api = complete_webapi("/files/top", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload, "top": int(top)}
        elif not isinstance(payload, dict):
            payload = {"file_id": ",".join(map(str, payload)), "top": int(top)}
        else:
            payload = {"top": int(top), **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_folder_playlong(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_folder_playlong(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_folder_playlong(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取目录内文件总的播放时长

        POST https://aps.115.com/getFolderPlaylong

        :payload:
            - folder_ids: int | str 💡 目录 id，多个用逗号 "," 隔开
        """
        api = complete_api("/getFolderPlaylong", "aps", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"folder_ids": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_folder_playlong_set(
        self, 
        /, 
        ids: int | str | Iterable[int | str], 
        is_set: Literal[0, 1] = 1, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_folder_playlong_set(
        self, 
        /, 
        ids: int | str | Iterable[int | str], 
        is_set: Literal[0, 1] = 1, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_folder_playlong_set(
        self, 
        /, 
        ids: int | str | Iterable[int | str], 
        is_set: Literal[0, 1] = 1, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """显示或取消目录内文件总的播放时长，此接口是对 `fs_batch_edit` 的封装

        :param ids: 一个或多个文件或目录的 id
        :param is_set: 是否显示时长

        :return: 返回成功状态
        """
        if isinstance(ids, (int, str)):
            payload = {f"show_play_long[{ids}]": is_set}
        else:
            payload = {f"show_play_long[{id}]": is_set for id in ids}
        return self.fs_batch_edit(payload, async_=async_, **request_kwargs)

    @overload
    def fs_hide(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_hide(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_hide(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """隐藏或者取消隐藏某些文件或目录

        POST https://webapi.115.com/files/hiddenfiles

        :payload:
            - fid[0]: int | str
            - fid[1]: int | str
            - ...
            - hidden: 0 | 1 = 1
        """
        api = complete_webapi("/files/hiddenfiles", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"hidden": 1, "fid[0]": payload}
        elif isinstance(payload, dict):
            payload = {"hidden": 1, **payload}
        else:
            payload = {f"fid[{i}]": f for i, f in enumerate(payload)}
            if not payload:
                return {"state": False, "message": "no op"}
            payload["hidden"] = 1
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_hide_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_hide_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_hide_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """隐藏或者取消隐藏某些文件或目录

        POST https://proapi.115.com/android/files/hiddenfiles

        :payload:
            - fid: int | str 💡 文件或目录的 id，多个用逗号 "," 隔开
            - hidden: 0 | 1 = 1
        """
        api = complete_proapi("/files/hiddenfiles", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"hidden": 1, "fid[0]": payload}
        elif isinstance(payload, dict):
            payload = {"hidden": 1, **payload}
        else:
            payload = cast(dict, {"fid": ",".join(map(str, payload))})
            if not payload:
                return {"state": False, "message": "no op"}
            payload["hidden"] = 1
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_hidden_switch(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_hidden_switch(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_hidden_switch(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """切换隐藏模式

        POST https://115.com/?ct=hiddenfiles&ac=switching

        :payload:
            - safe_pwd: str = "" 💡 密码，如果需要进入隐藏模式，请传递此参数
            - show: 0 | 1 = 1
            - valid_type: int = 1
        """
        api = complete_api("/?ct=hiddenfiles&ac=switching", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"valid_type": 1, "show": 1, "safe_pwd": payload}
        else:
            payload = {"valid_type": 1, "show": 1, "safe_pwd": "", **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_hidden_switch_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_hidden_switch_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_hidden_switch_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """切换隐藏模式

        GET https://proapi.115.com/android/files/hiddenswitch

        .. caution::
            直接调用这个接口，似乎并不能直接进入隐藏模式，需要先调用如下接口验证一下密码

            > POST https://passportapi.115.com/app/1.0/android/1.0/user/security_key_check

        :payload:
            - safe_pwd: str = "" 💡 密码，如果需要进入隐藏模式，请传递此参数（值为密码的 md5 摘要）
            - show: 0 | 1 = 1    💡 0: 退出 1:进入
        """
        api = complete_proapi("/files/hiddenswitch", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"show": 1, "safe_pwd": md5(str(payload).encode("ascii")).hexdigest()}
        else:
            payload = {"show": 1, "safe_pwd": "", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取历史记录

        GET https://webapi.115.com/history

        :payload:
            - pick_code: str
            - action: str = "get_one" 💡 可用的值："get_one"、"update"、...
            - category: int = <default>
            - from: int = <default>
            - time: int = <default>
        """
        api = complete_webapi("/history", base_url=base_url)
        if isinstance(payload, str):
            payload = {"action": "get_one", "pick_code": payload}
        else:
            payload = {"action": "get_one", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取历史记录

        GET https://proapi.115.com/android/history

        :payload:
            - pick_code: str
            - action: str = "get_one" 💡 可用的值："get_one"、"update"、...
            - category: int = <default>
            - from: int = <default>
            - time: int = <default>
        """
        api = complete_proapi("/history", base_url, app)
        if isinstance(payload, str):
            payload = {"action": "get_one", "pick_code": payload}
        else:
            payload = {"action": "get_one", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history_clean(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history_clean(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history_clean(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """清空历史记录

        POST https://webapi.115.com/history/clean

        :payload:
            - type: int | str = 0 💡 类型（？？表示还未搞清楚），多个用逗号 "," 隔开

              - 全部: 0
              - ？？: 1
              - 离线下载: 2
              - 播放视频: 3
              - 上传: 4
              - ？？: 5
              - ？？: 6
              - 接收: 7
              - 移动: 8

            - with_file: 0 | 1 = 0
        """
        api = complete_webapi("/history/clean", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"with_file": 0, "type": payload}
        else:
            payload = {"with_file": 0, "type": 0, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history_delete(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history_delete(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history_delete(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除历史记录

        POST https://webapi.115.com/history/delete

        :payload:
            - id: int | str 💡 多个用逗号 "," 隔开
            - with_file: 0 | 1 = 0
        """
        api = complete_webapi("/history/delete", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"with_file": 0, "id": payload}
        else:
            payload = {"with_file": 0, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history_delete_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history_delete_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history_delete_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除历史记录

        POST https://proapi.115.com/android/history/delete

        :payload:
            - id: int | str 💡 多个用逗号 "," 隔开
            - with_file: 0 | 1 = 0
        """
        api = complete_proapi("/history/delete", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"with_file": 0, "id": payload}
        else:
            payload = {"with_file": 0, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history_clean_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history_clean_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history_clean_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """清空历史记录

        POST https://proapi.115.com/android/history/clean

        :payload:
            - type: int | str = 0 💡 类型（？？表示还未搞清楚），多个用逗号 "," 隔开

              - 全部: 0
              - ？？: 1
              - 离线下载: 2
              - 播放视频: 3
              - 上传: 4
              - ？？: 5
              - ？？: 6
              - 接收: 7
              - 移动: 8

            - with_file: 0 | 1 = 0
        """
        api = complete_proapi("/history/clean", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"with_file": 0, "type": payload}
        else:
            payload = {"with_file": 0, "type": 0, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """历史记录列表

        GET https://webapi.115.com/history/list

        :payload:
            - offset: int = 0
            - limit: int = 1150
            - played_end: 0 | 1 = <default>
            - type: int = <default> 💡 类型（？？表示还未搞清楚），多个用逗号 "," 隔开

              - 全部: 0
              - ？？: 1
              - 离线下载: 2
              - 播放视频: 3
              - 上传: 4
              - ？？: 5
              - ？？: 6
              - 接收: 7
              - 移动: 8
        """
        api = complete_webapi("/history/list", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"limit": 1150, "offset": payload}
        else:
            payload = {"limit": 1150, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history_list_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history_list_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history_list_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """历史记录列表

        GET https://proapi.115.com/android/history/list

        :payload:
            - offset: int = 0
            - limit: int = 1150
            - played_end: 0 | 1 = <default>
            - type: int = <default> 💡 类型（？？表示还未搞清楚），多个用逗号 "," 隔开

              - 全部: 0
              - ？？: 1
              - 离线下载: 2
              - 播放视频: 3
              - 上传: 4
              - ？？: 5
              - ？？: 6
              - 接收: 7
              - 移动: 8
        """
        api = complete_proapi("/history/list", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"limit": 1150, "offset": payload}
        else:
            payload = {"limit": 1150, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history_move_target_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history_move_target_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history_move_target_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """移动列表

        GET https://webapi.115.com/history/move_target_list

        :payload:
            - offset: int = 0
            - limit: int = 1150
        """
        api = complete_webapi("/history/move_target_list", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"limit": 1150, "offset": payload}
        else:
            payload = {"limit": 1150, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history_receive_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history_receive_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history_receive_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """接收列表

        GET https://webapi.115.com/history/receive_list

        :payload:
            - offset: int = 0
            - limit: int = 1150
        """
        api = complete_webapi("/history/receive_list", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"limit": 1150, "offset": payload}
        else:
            payload = {"limit": 1150, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_history_receive_list_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_history_receive_list_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_history_receive_list_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """接收列表

        GET https://proapi.115.com/android/history/receive_list

        :payload:
            - offset: int = 0
            - limit: int = 1150
        """
        api = complete_proapi("/history/receive_list", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"limit": 1150, "offset": payload}
        else:
            payload = {"limit": 1150, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_image(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_image(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_image(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取图片的各种链接

        GET https://webapi.115.com/files/image

        :payload:
            - pickcode: str
        """
        api = complete_webapi("/files/image", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_imagedata(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_imagedata(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_imagedata(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取图片的分辨率等信息

        POST https://imgjump.115.com/getimgdata_url

        :payload:
            - imgurl: str 💡 图片的访问链接，以 "http://thumb.115.com" 开头
        """
        api = "https://imgjump.115.com/getimgdata_url"
        if isinstance(payload, str):
            payload = {"imgurl": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_imglist(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_imglist(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_imglist(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取目录中的图片列表和基本信息

        GET https://webapi.115.com/files/imglist

        .. danger::
            这个函数大概是有 bug 的，不推荐使用

        .. attention::
            只能获取直属于 `cid` 所在目录的图片，不会遍历整个目录树

        :payload:
            - cid: int | str     💡 目录 id
            - file_id: int | str 💡 不能是 0，可以不同于 `cid`，必须是任何一个有效的 id（单纯是被检查一下）
            - limit: int = <default> 💡 最多返回数量
            - offset: int = 0    💡 索引偏移，索引从 0 开始计算
            - is_asc: 0 | 1 = <default> 💡 是否升序排列
            - next: 0 | 1 = <default>
            - order: str = <default> 💡 用某字段排序            

              - 文件名："file_name"
              - 文件大小："file_size"
              - 文件种类："file_type"
              - 修改时间："user_utime"
              - 创建时间："user_ptime"
              - 上一次打开时间："user_otime"
        """
        api = complete_webapi("/files/imglist", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"limit": 32, "offset": 0, "cid": payload}
        else:
            payload = {"limit": 32, "offset": 0, "cid": 0, **payload}
        if cid := payload.get("cid"):
            payload.setdefault("file_id", cid)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_imglist_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_imglist_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_imglist_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取目录中的图片列表和基本信息

        GET https://proapi.115.com/android/files/imglist

        :payload:
            - cid: int | str = 0 💡 目录 id
            - limit: int = 32    💡 一页大小，建议控制在 <= 9000，不然会报错
            - offset: int = 0    💡 索引偏移，索引从 0 开始计算

            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
            - asc: 0 | 1 = <default> 💡 是否升序排列
            - cur: 0 | 1 = <default> 💡 只罗列当前目录
            - o: str = <default> 💡 用某字段排序

              - 文件名："file_name"
              - 文件大小："file_size"
              - 文件种类："file_type"
              - 修改时间："user_utime"
              - 创建时间："user_ptime"
              - 上一次打开时间："user_otime"
        """
        api = complete_proapi("/files/imglist", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"limit": 32, "offset": 0, "aid": 1, "cid": payload}
        else:
            payload = {"limit": 32, "offset": 0, "aid": 1, "cid": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_index_info(
        self, 
        payload: Literal[0, 1] | bool | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_index_info(
        self, 
        payload: Literal[0, 1] | bool | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_index_info(
        self, 
        payload: Literal[0, 1] | bool | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取当前已用空间、可用空间、登录设备等信息

        GET https://webapi.115.com/files/index_info

        :payload:
            - count_space_nums: 0 | 1 = 0 💡 如果为 0，包含各种类型文件的数量统计；如果为 1，包含登录设备列表
        """
        api = complete_webapi("/files/index_info", base_url=base_url)
        if not isinstance(payload, dict):
            payload = {"count_space_nums": int(payload)}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_label_add(
        self, 
        payload: str | Iterable[str] | dict | list[tuple], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_add(
        self, 
        payload: str | Iterable[str] | dict | list[tuple], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_add(
        self, 
        payload: str | Iterable[str] | dict | list[tuple], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """添加标签（可以接受多个）

        POST https://webapi.115.com/label/add_multi

        :payload:
            - name[] 💡 格式为 "{label_name}" 或 "{label_name}\x07{color}"，例如 "tag\x07#FF0000"（中间有个 "\\x07"）
            - ...
        """
        api = complete_webapi("/label/add_multi", base_url=base_url)
        if isinstance(payload, str):
            payload = [("name[]", payload)]
        elif not isinstance(payload, dict) or not isinstance(payload, list) and payload and not isinstance(payload[0], tuple):
            payload = [("name[]", label) for label in payload if label]
            if not payload:
                return {"state": False, "message": "no op"}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_label_add_app(
        self, 
        payload: str | Iterable[str] | dict | list[tuple], 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_add_app(
        self, 
        payload: str | Iterable[str] | dict | list[tuple], 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_add_app(
        self, 
        payload: str | Iterable[str] | dict | list[tuple], 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """添加标签（可以接受多个）

        POST https://proapi.115.com/android/label/add_multi

        :payload:
            - name[] 💡 格式为 "{label_name}" 或 "{label_name}\x07{color}"，例如 "tag\x07#FF0000"（中间有个 "\\x07"）
            - ...
        """
        api = complete_proapi("/label/add_multi", base_url, app)
        if isinstance(payload, str):
            payload = [("name[]", payload)]
        elif not isinstance(payload, dict) or not isinstance(payload, list) and payload and not isinstance(payload[0], tuple):
            payload = [("name[]", label) for label in payload if label]
            if not payload:
                return {"state": False, "message": "no op"}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_label_del(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_del(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_del(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除标签

        POST https://webapi.115.com/label/delete

        :payload:
            - id: int | str 💡 标签 id，多个用逗号 "," 隔开
        """
        api = complete_webapi("/label/delete", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"id": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_label_del_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_del_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_del_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除标签

        POST https://proapi.115.com/android/label/delete

        :payload:
            - id: int | str 💡 标签 id，多个用逗号 "," 隔开
        """
        api = complete_proapi("/label/delete", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"id": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_label_edit(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_edit(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_edit(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """编辑标签

        POST https://webapi.115.com/label/edit

        :payload:
            - id: int | str 💡 标签 id
            - name: str = <default>  💡 标签名
            - color: str = <default> 💡 标签颜色，支持 css 颜色语法
            - sort: int = <default>  💡 序号
        """
        api = complete_webapi("/label/edit", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_label_edit_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_edit_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_edit_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """编辑标签

        POST https://proapi.115.com/android/label/edit

        :payload:
            - id: int | str 💡 标签 id
            - name: str = <default>  💡 标签名
            - color: str = <default> 💡 标签颜色，支持 css 颜色语法
            - sort: int = <default>  💡 序号
        """
        api = complete_proapi("/label/edit", base_url, app)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_label_list(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_list(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_list(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列标签列表（如果要获取做了标签的文件列表，用 `fs_search` 接口）

        GET https://webapi.115.com/label/list

        :payload:
            - offset: int = 0 💡 索引偏移，从 0 开始
            - limit: int = 11500 💡 最多返回数量
            - keyword: str = <default> 💡 搜索关键词
            - sort: "name" | "update_time" | "create_time" = <default> 💡 排序字段

              - 名称: "name"
              - 创建时间: "create_time"
              - 更新时间: "update_time"

            - order: "asc" | "desc" = <default> 💡 排序顺序："asc"(升序), "desc"(降序)
        """
        api = complete_webapi("/label/list", base_url=base_url)
        if isinstance(payload, str):
            payload = {"offset": 0, "limit": 11500, "keyword": payload}
        else:
            payload = {"offset": 0, "limit": 11500, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_label_list_app(
        self, 
        payload: str | dict = "", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_list_app(
        self, 
        payload: str | dict = "", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_list_app(
        self, 
        payload: str | dict = "", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列标签列表（如果要获取做了标签的文件列表，用 `fs_search` 接口）

        GET https://proapi.115.com/android/label/list

        :payload:
            - offset: int = 0 💡 索引偏移，从 0 开始
            - limit: int = 11500 💡 最多返回数量
            - keyword: str = <default> 💡 搜索关键词
            - sort: "name" | "update_time" | "create_time" = <default> 💡 排序字段

              - 名称: "name"
              - 创建时间: "create_time"
              - 更新时间: "update_time"

            - order: "asc" | "desc" = <default> 💡 排序顺序："asc"(升序), "desc"(降序)
        """
        api = complete_proapi("/label/list", base_url, app)
        if isinstance(payload, str):
            payload = {"offset": 0, "limit": 11500, "keyword": payload}
        else:
            payload = {"offset": 0, "limit": 11500, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_label_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        label: int | str = "", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        label: int | str = "", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        label: int | str = "", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """为文件或目录设置标签，此接口是对 `fs_edit` 的封装

        .. attention::
            这个接口会把标签列表进行替换，而不是追加

        .. hint::
            为单个文件或目录，设置一个不存在的标签 id，比如 1，会清空标签，但可产生事件（批量设置时无事件，可能是 bug）

            .. code:: python
                client.fs_label_set(id, 1)
        """
        return self._fs_edit_set(payload, "file_label", label, async_=async_, **request_kwargs)

    @overload
    def fs_label_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        label: int | str = "", 
        app: str = "android", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        label: int | str = "", 
        app: str = "android", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        label: int | str = "", 
        app: str = "android", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """为文件或目录设置标签，此接口是对 `fs_edit_app` 的封装

        .. attention::
            这个接口会把标签列表进行替换，而不是追加
        """
        return self._fs_edit_set_app(payload, "file_label", label, app=app, async_=async_, **request_kwargs)

    @overload
    def fs_label_batch(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_batch(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_batch(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """批量设置标签

        POST https://webapi.115.com/files/batch_label

        :payload:
            - action: "add" | "remove" | "reset" | "replace" 💡 操作名

              - "add": 添加
              - "remove": 移除
              - "reset": 重设
              - "replace": 替换

            - file_ids: int | str 💡 文件或目录 id，多个用逗号 "," 隔开
            - file_label: int | str = <default> 💡 标签 id，多个用逗号 "," 隔开
            - file_label[{file_label}]: int | str = <default> 💡 action 为 replace 时使用此参数，file_label[{原标签id}]: {目标标签id}，例如 file_label[123]: 456，就是把 id 是 123 的标签替换为 id 是 456 的标签
        """
        api = complete_webapi("/files/batch_label", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_label_batch_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_label_batch_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_label_batch_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """批量设置标签

        POST https://proapi.115.com/android/files/batch_label

        :payload:
            - action: "add" | "remove" | "reset" | "replace" 💡 操作名

              - "add": 添加
              - "remove": 移除
              - "reset": 重设
              - "replace": 替换

            - file_ids: int | str 💡 文件或目录 id，多个用逗号 "," 隔开
            - file_label: int | str = <default> 💡 标签 id，多个用逗号 "," 隔开
            - file_label[{file_label}]: int | str = <default> 💡 action 为 replace 时使用此参数，file_label[{原标签id}]: {目标标签id}，例如 file_label[123]: 456，就是把 id 是 123 的标签替换为 id 是 456 的标签
        """
        api = complete_proapi("/android/files/batch_label", base_url, app)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_makedirs_app(
        self, 
        payload: str | dict, 
        /, 
        pid: int = 0, 
        app: str = "chrome", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_makedirs_app(
        self, 
        payload: str | dict, 
        /, 
        pid: int = 0, 
        app: str = "chrome", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_makedirs_app(
        self, 
        payload: str | dict, 
        /, 
        pid: int = 0, 
        app: str = "chrome", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """新建目录（会尝试创建所有的中间节点）

        POST http://proapi.115.com/app/chrome/add_path

        .. note::
            1. 目录层级最多 25 级（不算文件节点的话）
            2. 名字不能包含 3 个字符之一 "<>，如果包含，则会被替换为 _

        .. attention::
            这个方法并不产生 115 生活的操作事件

        :payload:
            - path: str
            - parent_id: int | str = 0
        """
        if app == "chrome":
            api = complete_proapi("/app/chrome/add_path", base_url)
        else:
            api = complete_proapi("/2.0/ufile/add_path", base_url, app)
        if isinstance(payload, str):
            payload = {"parent_id": pid, "path": payload}
        else:
            payload = {"parent_id": pid, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_mkdir(
        self, 
        payload: str | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_mkdir(
        self, 
        payload: str | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_mkdir(
        self, 
        payload: str | dict, 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """新建目录

        POST https://webapi.115.com/files/add

        .. note::
            1. 目录层级最多 25 级（不算文件节点的话）
            2. 名字不能包含 3 个字符之一 "<>，但是文件可以通过上传来突破此限制

        :payload:
            - cname: str
            - pid: int | str = 0
        """
        api = complete_webapi("/files/add", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pid": pid, "cname": payload}
        else:
            payload = {"pid": pid, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_mkdir_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_mkdir_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_mkdir_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """新建目录

        .. todo::
            - name: str 💡 目录名
            待破解

        POST https://proapi.115.com/android/1.0/folder/update
        """
        api = complete_proapi("/folder/update", base_url, app)
        payload = dict(payload, user_id=self.user_id)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_move(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_move(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_move(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """移动文件或目录

        POST https://webapi.115.com/files/move

        .. caution::
            你可以把文件或目录移动到其它目录 id 下，即使是不存在的 id

            因此，我定义了一个概念，悬空节点，此节点的 aid=1，但它有一个祖先节点，要么不存在，要么 aid != 1

            你可以用 `P115Client.tool_space` 方法，使用【校验空间】功能，把所有悬空节点找出来，放到根目录下的【修复文件】目录，此接口一天只能用一次

        :payload:
            - fid: int | str 💡 文件或目录 id，只接受单个 id
            - fid[]: int | str
            - ...
            - fid[0]: int | str
            - fid[1]: int | str
            - ...
            - pid: int | str = 0 💡 目标目录 id
            - move_proid: str = <default> 💡 任务 id
        """
        api = complete_webapi("/files/move", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"fid": payload}
        elif isinstance(payload, dict):
            payload = dict(payload)
        else:
            payload = {f"fid[{i}]": fid for i, fid in enumerate(payload)}
            if not payload:
                return {"state": False, "message": "no op"}
        payload.setdefault("pid", pid)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_move_app(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_move_app(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_move_app(
        self, 
        payload: int | str | dict | Iterable[int | str], 
        /, 
        pid: int = 0, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """移动文件或目录

        POST https://proapi.115.com/android/files/move

        :payload:
            - ids: int | str    💡 文件或目录 id，多个用逗号 "," 隔开
            - to_cid: int | str 💡 目标目录 id
            - user_id: int | str = <default> 💡 不用管
        """
        api = complete_proapi("/files/move", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"ids": payload, "user_id": self.user_id}
        elif isinstance(payload, dict):
            payload = dict(payload, user_id=self.user_id)
        else:
            payload = {f"fid[{i}]": fid for i, fid in enumerate(payload)}
            if not payload:
                return {"state": False, "message": "no op"}
            payload["user_id"] = self.user_id
        payload.setdefault("pid", pid)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_move_progress(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_move_progress(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_move_progress(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """移动任务的进度

        GET https://webapi.115.com/files/move_progress

        :payload:
            - move_proid: str = <default> 💡 任务 id
        """
        api = complete_webapi("/files/move_progress", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"move_proid": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取音乐信息（其实只有一个下载链接）

        GET https://webapi.115.com/files/music

        :payload:
            - pickcode: str 💡 提取码
            - topic_id: int = <default>
            - music_id: int = <default>
            - download: int = <default>
        """
        api = complete_webapi("/files/music", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        if not request_kwargs.get("request"):
            request_kwargs["follow_redirects"] = False
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取音乐信息

        GET https://proapi.115.com/android/music/musicplay

        .. note::
            即使文件格式不正确或者过大（超过 200MB），也可返回一些信息（包括 parent_id），但如果是目录则信息匮乏（但由此也可判定一个目录）

        :payload:
            - pickcode: str 💡 提取码
            - format: str = "json"
            - music_id: int = <default>
            - topic_id: int = <default>
        """
        api = complete_proapi("/music/musicplay", base_url, app)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_file_exist(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_file_exist(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_file_exist(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """检查音乐文件是否存在

        GET https://webapi.115.com/files/music_file_exist

        :payload:
            - pickcode: str 💡 提取码
            - topic_id: int = <default>
            - music_id: int = <default>
            - download: int = <default>
        """
        api = complete_webapi("/files/music_file_exist", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_fond_list(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_fond_list(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_fond_list(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列星标听单

        GET https://webapi.115.com/files/music_fond_list
        """
        api = complete_webapi("/files/music_fond_list", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def fs_music_fond_list_app(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_fond_list_app(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_fond_list_app(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列星标听单

        GET https://proapi.115.com/android/music/music_fond_list
        """
        api = complete_proapi("/music/music_fond_list", base_url, app)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def fs_music_fond_set(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_fond_set(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_fond_set(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """给听单加减星标

        POST https://webapi.115.com/files/music_topic_fond

        :payload:
            - topic_id: int
            - fond: 0 | 1 = 1
        """
        api = complete_webapi("/files/music_topic_fond", base_url=base_url)
        if isinstance(payload, int):
            payload = {"fond": 1, "topic_id": payload}
        else:
            payload = {"fond": 1, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_include_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_include_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_include_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """包含音乐的目录列表（专属文件）

        GET https://webapi.115.com/files/include_music_list

        :payload:
            - asc: 0 | 1 = 0
            - limit: int = 1150
            - offset: int = 0
            - order: str = "user_etime"
        """
        api = complete_webapi("/files/include_music_list", base_url=base_url)
        if isinstance(payload, int):
            payload = {"asc": 0, "limit": 1150, "order": "user_etime", "offset": payload}
        else:
            payload = {"asc": 0, "limit": 1150, "order": "user_etime", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_include_list_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_include_list_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_include_list_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """包含音乐的目录列表（专属文件）

        GET https://proapi.115.com/android/music/include_music_list

        :payload:
            - asc: 0 | 1 = 0
            - limit: int = 1150
            - offset: int = 0
            - order: str = "user_etime"
        """
        api = complete_proapi("/music/include_music_list", base_url, app)
        if isinstance(payload, int):
            payload = {"asc": 0, "limit": 1150, "order": "user_etime", "offset": payload}
        else:
            payload = {"asc": 0, "limit": 1150, "order": "user_etime", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取音乐封面等信息

        GET https://webapi.115.com/files/music_info

        :payload:
            - pickcode: str 💡 提取码
        """
        api = complete_webapi("/files/music_info", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_info_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_info_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_info_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取音乐封面等信息

        GET https://proapi.115.com/android/music/musicdetail

        :payload:
            - pickcode: str 💡 提取码
        """
        api = complete_proapi("/music/musicdetail", base_url, app)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_list(
        self, 
        payload: int | dict = 1, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_list(
        self, 
        payload: int | dict = 1, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_list(
        self, 
        payload: int | dict = 1, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列听单中的文件

        GET https://webapi.115.com/files/music_list

        :payload:
            - topic_id: int = 1 💡 听单 id。-1:星标 1:最近听过 2:最近接收 678469:临时听单(?)
            - start: int = 0
            - limit: int = 1150
        """
        api = complete_webapi("/files/music_list", base_url=base_url)
        if isinstance(payload, int):
            payload = {"start": 0, "limit": 1150, "topic_id": payload}
        else:
            payload = {"start": 0, "limit": 1150, "topic_id": 1, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_list_app(
        self, 
        payload: int | dict = 1, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_list_app(
        self, 
        payload: int | dict = 1, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_list_app(
        self, 
        payload: int | dict = 1, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列听单中的文件

        GET https://proapi.115.com/android/music/music_list

        :payload:
            - topic_id: int = 1 💡 听单 id。-1:星标 1:最近听过 2:最近接收 678469:临时听单(?)
            - start: int = 0
            - limit: int = 1150
        """
        api = complete_proapi("/music/music_list", base_url, app)
        if isinstance(payload, int):
            payload = {"start": 0, "limit": 1150, "topic_id": payload}
        else:
            payload = {"start": 0, "limit": 1150, "topic_id": 1, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_new(
        self, 
        payload: int | dict = 1, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_new(
        self, 
        payload: int | dict = 1, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_new(
        self, 
        payload: int | dict = 1, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列听单或听单中的文件

        GET https://webapi.115.com/files/musicnew

        :payload:
            - topic_id: int = 1 💡 听单 id。-1:星标 1:最近听过 2:最近接收 678469:临时听单(?)
            - type: 0 | 1 = 0   💡 类型：0:文件 1:目录
            - start: int = 0
            - limit: int = 1150
        """
        api = complete_webapi("/files/musicnew", base_url=base_url)
        if isinstance(payload, int):
            payload = {"start": 0, "limit": 1150, "type": 0, "topic_id": payload}
        else:
            payload = {"start": 0, "limit": 1150, "type": 0, "topic_id": 1, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_new_app(
        self, 
        payload: int | dict = 1, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_new_app(
        self, 
        payload: int | dict = 1, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_new_app(
        self, 
        payload: int | dict = 1, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列听单或听单中的文件

        GET https://proapi.115.com/android/music/musicnew

        :payload:
            - topic_id: int = 1 💡 听单 id。-1:星标 1:最近听过 2:最近接收 678469:临时听单(?)
            - type: 0 | 1 = 0   💡 类型：0:文件 1:目录
        """
        api = complete_proapi("/music/musicnew", base_url, app)
        if isinstance(payload, int):
            payload = {"type": 0, "topic_id": payload}
        else:
            payload = {"type": 0, "topic_id": 1, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_set(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_set(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_set(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """从听单添加或移除音乐，或者给音乐加减星标

        POST https://webapi.115.com/files/music

        :payload:
            - file_id: int      💡 文件 id，多个用逗号 "," 隔开（op 为 "add" 和 "delete" 时需要）
            - music_id: int = 1 💡 音乐 id（op 为 "fond" 时需要）
            - topic_id: int = 1 💡 听单 id
            - op: str = "add"   💡 操作类型："add": 添加到听单, "delete": 从听单删除, "fond": 设置星标
            - fond: 0 | 1 = 1   💡 是否星标（op 为 "fond" 时需要），这个星标和 music_id 有关，和 file_id 无关
        """
        api = complete_webapi("/files/music", base_url=base_url)
        if isinstance(payload, int):
            payload = {"op": "add", "topic_id": 1, "file_id": payload}
        else:
            payload = {"op": "add", "fond": 1, "music_id": 1, "topic_id": 1, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_status(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_status(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_status(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """音乐状态

        GET https://webapi.115.com/files/music_status

        :payload:
            - pickcode: str 💡 提取码
        """
        api = complete_webapi("/files/music_status", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_topic_listnew(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_topic_listnew(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_topic_listnew(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列听单

        GET https://webapi.115.com/files/music_topic_listnew

        .. caution::
            似乎查询参数并没有效果

        :payload:
            - fond: 0 | 1 = 0   💡 是否星标
            - start: int = 0    💡 开始索引
            - limit: int = 1150 💡 最多返回数量
        """
        api = complete_webapi("/files/music_topic_listnew", base_url=base_url)
        if isinstance(payload, int):
            payload = {"fond": 0, "limit": 1150, "start": payload}
        else:
            payload = {"fond": 0, "limit": 1150, "start": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_topic_listnew_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_topic_listnew_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_topic_listnew_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列听单

        GET https://proapi.115.com/android/music/musiclistnew

        .. caution::
            似乎查询参数并没有效果

        :payload:
            - fond: 0 | 1 = 0   💡 是否星标
            - start: int = 0    💡 开始索引
            - limit: int = 1150 💡 最多返回数量
        """
        api = complete_proapi("/music/musiclistnew", base_url, app)
        if isinstance(payload, int):
            payload = {"fond": 0, "limit": 1150, "start": payload}
        else:
            payload = {"fond": 0, "limit": 1150, "start": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_music_topic_set(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_music_topic_set(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_music_topic_set(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """修改听单

        POST https://webapi.115.com/files/music_topic

        :payload:
            - op: "edit" | "delete" | "add" 💡 操作类型："edit":改名 "delete":删除 "add":添加
            - topic_id: int = <default> 💡 听单 id（op 不为 "add" 时需要）
            - topic_name: str = <default> 💡 听单名字（op 为 "add" 和 "edit" 时需要）
        """
        api = complete_webapi("/files/music_topic", base_url=base_url)
        if isinstance(payload, str):
            payload = {"op": "add", "topic_name": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_order_set(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_order_set(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_order_set(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """设置某个目录内文件的默认排序

        POST https://webapi.115.com/files/order

        :payload:
            - user_order: str 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_utime": 修改时间
              - "user_ptime": 创建时间
              - "user_otime": 上一次打开时间

            - file_id: int | str = 0 💡 目录 id
            - user_asc: 0 | 1 = <default> 💡 是否升序排列
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - module: str = <default> 💡 "label_search" 表示用于搜索的排序
        """
        api = complete_webapi("/files/order", base_url=base_url)
        if isinstance(payload, str):
            payload = {"file_id": 0, "user_asc": 1, "user_order": payload}
        else:
            payload = {"file_id": 0, "user_asc": 1, "user_order": "user_ptime", **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_order_set_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_order_set_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_order_set_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """设置某个目录内文件的默认排序

        POST https://proapi.115.com/android/2.0/ufile/order

        .. error::
            这个接口暂时并不能正常工作，应该是参数构造有问题，暂时请用 `P115Client.fs_order_set`

        :payload:
            - user_order: str 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_utime": 修改时间
              - "user_ptime": 创建时间
              - "user_otime": 上一次打开时间

            - file_id: int | str = 0 💡 目录 id
            - user_asc: 0 | 1 = <default> 💡 是否升序排列
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - module: str = <default> 💡 "label_search" 表示用于搜索的排序
        """
        api = complete_proapi("/2.0/ufile/order", base_url, app)
        if isinstance(payload, str):
            payload = {"file_id": 0, "user_asc": 1, "user_order": payload}
        else:
            payload = {"file_id": 0, "user_asc": 1, "user_order": "user_ptime", **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_rename(
        self, 
        payload: tuple[int | str, str] | dict | Iterable[tuple[int | str, str]], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_rename(
        self, 
        payload: tuple[int | str, str] | dict | Iterable[tuple[int | str, str]], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_rename(
        self, 
        payload: tuple[int | str, str] | dict | Iterable[tuple[int | str, str]], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """重命名文件或目录

        POST https://webapi.115.com/files/batch_rename

        :payload:
            - files_new_name[{file_id}]: str 💡 值为新的文件名（basename）
        """
        api = complete_webapi("/files/batch_rename", base_url=base_url)
        if isinstance(payload, tuple) and len(payload) == 2 and isinstance(payload[0], (int, str)):
            payload = {f"files_new_name[{payload[0]}]": payload[1]}
        elif not isinstance(payload, dict):
            payload = {f"files_new_name[{fid}]": name for fid, name in payload}
        if not payload:
            return {"state": False, "message": "no op"}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_rename_app(
        self, 
        payload: tuple[int | str, str] | dict | Iterable[tuple[int | str, str]], 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_rename_app(
        self, 
        payload: tuple[int | str, str] | dict | Iterable[tuple[int | str, str]], 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_rename_app(
        self, 
        payload: tuple[int | str, str] | dict | Iterable[tuple[int | str, str]], 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """重命名文件或目录

        POST https://proapi.115.com/android/files/batch_rename

        :payload:
            - files_new_name[{file_id}]: str 💡 值为新的文件名（basename）
        """
        api = complete_proapi("/files/batch_rename", base_url, app)
        if isinstance(payload, tuple) and len(payload) == 2 and isinstance(payload[0], (int, str)):
            payload = {f"files_new_name[{payload[0]}]": payload[1]}
        elif not isinstance(payload, dict):
            payload = {f"files_new_name[{fid}]": name for fid, name in payload}
        if not payload:
            return {"state": False, "message": "no op"}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_rename_set_names(
        self, 
        payload: dict | list[tuple[str, str | int]], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_rename_set_names(
        self, 
        payload: dict | list[tuple[str, str | int]], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_rename_set_names(
        self, 
        payload: dict | list[tuple[str, str | int]], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """提交模拟批量重命名请求（提示：较为复杂，自己抓包研究）

        POST https://aps.115.com/rename/set_names.php
        """
        api = complete_api("/rename/set_names.php", "aps", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_rename_reset_names(
        self, 
        payload: dict | list[tuple[str, str | int]], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_rename_reset_names(
        self, 
        payload: dict | list[tuple[str, str | int]], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_rename_reset_names(
        self, 
        payload: dict | list[tuple[str, str | int]], 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取批量重命名的模拟结果（提示：较为复杂，自己抓包研究）

        POST https://aps.115.com/rename/reset_names.php
        """
        api = complete_api("/rename/reset_names.php", "aps", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_repeat_sha1(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_repeat_sha1(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_repeat_sha1(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """查找重复文件（罗列除此以外的 sha1 相同的文件）

        GET https://webapi.115.com/files/get_repeat_sha

        :payload:
            - file_id: int | str
            - offset: int = 0
            - limit: int = 1150
            - source: str = ""
            - format: str = "json"
        """
        api = complete_webapi("/files/get_repeat_sha", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"offset": 0, "limit": 1150, "format": "json", "file_id": payload}
        else:
            payload = {"offset": 0, "limit": 1150, "format": "json", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_repeat_sha1_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_repeat_sha1_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_repeat_sha1_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """查找重复文件（罗列除此以外的 sha1 相同的文件）

        GET https://proapi.115.com/android/2.0/ufile/get_repeat_sha

        :payload:
            - file_id: int | str
            - offset: int = 0
            - limit: int = 1150
            - source: str = ""
            - format: str = "json"
        """
        api = complete_proapi("/2.0/ufile/get_repeat_sha", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"offset": 0, "limit": 1150, "format": "json", "file_id": payload}
        else:
            payload = {"offset": 0, "limit": 1150, "format": "json", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_score_set(
        self, 
        file_id: int | str | Iterable[int | str], 
        /, 
        score: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_score_set(
        self, 
        file_id: int | str | Iterable[int | str], 
        /, 
        score: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_score_set(
        self, 
        file_id: int | str | Iterable[int | str], 
        /, 
        score: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """给文件或目录评分

        POST https://webapi.115.com/files/score

        :payload:
            - file_id: int | str 💡 文件或目录 id，多个用逗号 "," 隔开
            - score: int = 0     💡 0 为删除评分
        """
        api = complete_webapi("/files/score", base_url=base_url)
        if not isinstance(file_id, (int, str)):
            file_id = ",".join(map(str, file_id))
        payload = {"file_id": file_id, "score": score}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_search(
        self, 
        payload: str | dict = ".", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_search(
        self, 
        payload: str | dict = ".", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_search(
        self, 
        payload: str | dict = ".", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """搜索文件或目录

        GET https://webapi.115.com/files/search

        .. attention::
            最多只能取回前 10,000 条数据，也就是 limit + offset <= 10_000

            这个接口实际上不支持在查询中直接设置排序，只能由 `P115Client.fs_order_set` 设置

        .. note::
            搜索接口甚至可以把上级 id 关联错误的文件或目录都搜索出来。一般是因为把文件或目录移动到了一个不存在的 id 下，你可以用某些关键词把他们搜索出来，然后移动到一个存在的目录中，就可以恢复他们了，或者使用 `P115Client.tool_space` 接口来批量恢复

        .. important::
            一般使用的话，要提供 "search_value" 或 "file_label"，不然返回数据里面看不到任何一条数据，即使你指定了其它参数

            下面指定的很多参数其实是一点效果都没有的，具体可以实际验证

        :payload:
            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
            - asc: 0 | 1 = <default> 💡 是否升序排列
            - cid: int | str = 0 💡 目录 id
            - count_folders: 0 | 1 = <default> 💡 是否统计目录数，这样就会增加 "folder_count" 和 "file_count" 字段作为统计
            - date: str = <default> 💡 筛选日期，格式为 YYYY-MM-DD（或者 YYYY-MM 或 YYYY），具体可以看文件信息中的 "t" 字段的值
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - file_label: int | str = <default> 💡 标签 id
            - format: str = "json" 💡 输出格式（不用管）
            - limit: int = 32 💡 一页大小，意思就是 page_size
            - o: str = <default> 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_utime": 修改时间
              - "user_ptime": 创建时间
              - "user_otime": 上一次打开时间

            - offset: int = 0  💡 索引偏移，索引从 0 开始计算
            - pick_code: str = <default> 💡 是否查询提取码，如果该值为 1 则查询提取码为 `search_value` 的文件
            - search_value: str = "." 💡 搜索文本，可以是 sha1
            - show_dir: 0 | 1 = 1     💡 是否显示目录
            - source: str = <default> 💡 来源
            - star: 0 | 1 = <default> 💡 是否打星标
            - suffix: str = <default> 💡 文件后缀（扩展名），优先级高于 `type`
            - type: int = <default>   💡 文件类型

              - 0: 全部（仅当前目录）
              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍
              - 99: 仅文件
        """
        api = complete_webapi("/files/search", base_url=base_url)
        if isinstance(payload, str):
            payload = {
                "aid": 1, "cid": 0, "format": "json", "limit": 32, "offset": 0, 
                "show_dir": 1, "search_value": payload, 
            }
        else:
            payload = {
                "aid": 1, "cid": 0, "format": "json", "limit": 32, "offset": 0, 
                "show_dir": 1, "search_value": ".", **payload, 
            }
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_search_app(
        self, 
        payload: str | dict = ".", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_search_app(
        self, 
        payload: str | dict = ".", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_search_app(
        self, 
        payload: str | dict = ".", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """搜索文件或目录（提示：好像最多只能罗列前 10,000 条数据，也就是 limit + offset <= 10_000）

        GET https://proapi.115.com/android/files/search

        .. attention::
            最多只能取回前 10,000 条数据，也就是 limit + offset <= 10_000

        :payload:
            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
            - asc: 0 | 1 = <default> 💡 是否升序排列
            - cid: int | str = 0 💡 目录 id。cid=-1 时，表示不返回列表任何内容
            - count_folders: 0 | 1 = <default>
            - date: str = <default> 💡 筛选日期
            - fc: 0 | 1 = <default> 💡 只显示文件或目录。1:只显示目录 2:只显示文件
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - file_label: int | str = <default> 💡 标签 id
            - format: str = "json" 💡 输出格式（不用管）
            - limit: int = 32 💡 一页大小，意思就是 page_size
            - o: str = <default> 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_utime": 修改时间
              - "user_ptime": 创建时间
              - "user_otime": 上一次打开时间

            - offset: int = 0  💡 索引偏移，索引从 0 开始计算
            - pick_code: str = <default> 💡 是否查询提取码，如果该值为 1 则查询提取码为 `search_value` 的文件
            - search_value: str = "." 💡 搜索文本，可以是 sha1
            - show_dir: 0 | 1 = 1
            - source: str = <default>
            - star: 0 | 1 = <default>
            - suffix: str = <default>
            - type: int = <default> 💡 文件类型

              - 0: 全部（仅当前目录）
              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍
              - 99: 仅文件

            - version: str = <default> 💡 版本号，比如 3.1
        """
        api = complete_proapi("/files/search", base_url, app)
        if isinstance(payload, str):
            payload = {
                "aid": 1, "cid": 0, "format": "json", "limit": 32, "offset": 0, 
                "show_dir": 1, "search_value": payload, 
            }
        else:
            payload = {
                "aid": 1, "cid": 0, "format": "json", "limit": 32, "offset": 0, 
                "show_dir": 1, "search_value": ".", **payload, 
            }
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_search_app2(
        self, 
        payload: str | dict = ".", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_search_app2(
        self, 
        payload: str | dict = ".", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_search_app2(
        self, 
        payload: str | dict = ".", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """搜索文件或目录（提示：好像最多只能罗列前 10,000 条数据，也就是 limit + offset <= 10_000）

        GET https://proapi.115.com/android/2.0/ufile/search

        .. attention::
            最多只能取回前 10,000 条数据，也就是 limit + offset <= 10_000

        :payload:
            - aid: int | str = 1 💡 area_id。1:正常文件 7:回收站文件 12:瞬间文件 120:彻底删除文件、简历附件
            - asc: 0 | 1 = <default> 💡 是否升序排列
            - cid: int | str = 0 💡 目录 id。cid=-1 时，表示不返回列表任何内容
            - count_folders: 0 | 1 = <default>
            - date: str = <default> 💡 筛选日期
            - fc: 0 | 1 = <default> 💡 只显示文件或目录。1:只显示目录 2:只显示文件
            - fc_mix: 0 | 1 = <default> 💡 是否目录和文件混合，如果为 0 则目录在前（目录置顶）
            - file_label: int | str = <default> 💡 标签 id
            - format: str = "json" 💡 输出格式（不用管）
            - gte_day: str 💡 搜索结果匹配的开始时间；格式：YYYY-MM-DD
            - limit: int = 32 💡 一页大小，意思就是 page_size
            - lte_day: str 💡 搜索结果匹配的结束时间；格式：YYYY-MM-DD
            - o: str = <default> 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_utime": 修改时间
              - "user_ptime": 创建时间
              - "user_otime": 上一次打开时间

            - offset: int = 0  💡 索引偏移，索引从 0 开始计算
            - pick_code: str = <default> 💡 是否查询提取码，如果该值为 1 则查询提取码为 `search_value` 的文件
            - search_value: str = "." 💡 搜索文本，可以是 sha1
            - show_dir: 0 | 1 = 1
            - source: str = <default>
            - star: 0 | 1 = <default>
            - suffix: str = <default>
            - type: int = <default> 💡 文件类型

              - 0: 全部（仅当前目录）
              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍
              - 99: 仅文件

            - version: str = <default> 💡 版本号，比如 3.1
        """
        api = complete_proapi("/2.0/ufile/search", base_url, app)
        if isinstance(payload, str):
            payload = {
                "aid": 1, "cid": 0, "format": "json", "limit": 32, "offset": 0, 
                "show_dir": 1, "search_value": payload, 
            }
        else:
            payload = {
                "aid": 1, "cid": 0, "format": "json", "limit": 32, "offset": 0, 
                "show_dir": 1, "search_value": ".", **payload, 
            }
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_shasearch(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_shasearch(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_shasearch(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """通过 sha1 搜索文件

        GET https://webapi.115.com/files/shasearch

        :payload:
            - sha1: str
        """
        api = complete_webapi("/files/shasearch", base_url=base_url)
        if isinstance(payload, str):
            payload = {"sha1": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_show_play_long_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        show: bool = True, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_show_play_long_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        show: bool = True, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_show_play_long_set(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        show: bool = True, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """为目录设置显示时长，此接口是对 `fs_edit` 的封装
        """
        return self._fs_edit_set(payload, "show_play_long", int(show), async_=async_, **request_kwargs)

    @overload
    def fs_show_play_long_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        show: bool = True, 
        app: str = "android", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_show_play_long_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        show: bool = True, 
        app: str = "android", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_show_play_long_set_app(
        self, 
        payload: int | str | Iterable[int | str] | list[tuple] | dict, 
        /, 
        show: bool = True, 
        app: str = "android", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """为目录设置显示时长，此接口是对 `fs_edit` 的封装
        """
        return self._fs_edit_set_app(payload, "show_play_long", int(show), app=app, async_=async_, **request_kwargs)

    @overload
    def fs_space_info(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_space_info(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_space_info(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取使用空间的统计数据（较为简略，如需更详细，请用 `P115Client.fs_index_info()`）

        GET https://proapi.115.com/android/user/space_info
        """
        api = complete_proapi("/user/space_info", base_url, app)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def fs_space_report(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_space_report(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_space_report(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取数据报告（截至月末数据，分组聚合）

        GET https://webapi.115.com/user/report

        :payload:
            - month: str 💡 年月，格式为 YYYYMM
        """
        api = complete_webapi("/user/report", base_url=base_url)
        if not payload:
            now = datetime.now()
            year, month = now.year, now.month
            if month == 1:
                ym = f"{year-1}12"
            else:
                ym = f"{year}{month-1:02d}"
            payload = {"month": ym}
        elif isinstance(payload, str):
            payload = {"month": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_space_summury(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_space_summury(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_space_summury(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取数据报告（当前数据，分组聚合）

        POST https://webapi.115.com/user/space_summury
        """
        api = complete_webapi("/user/space_summury", base_url=base_url)
        return self.request(url=api, method="POST", async_=async_, **request_kwargs)

    @overload
    def fs_star_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        star: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_star_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        star: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_star_set(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        star: bool = True, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """为文件或目录设置或取消星标

        POST https://webapi.115.com/files/star

        .. note::
            如果其中任何一个 id 目前已经被删除，则会直接返回错误信息

        :payload:
            - file_id: int | str 💡 文件或目录 id，多个用逗号 "," 隔开
            - star: 0 | 1 = 1
        """
        api = complete_webapi("/files/star", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload, "star": int(star)}
        elif not isinstance(payload, dict):
            payload = {"file_id": ",".join(map(str, payload)), "star": int(star)}
        else:
            payload = {"star": int(star), **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_star_set_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        star: bool = True, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_star_set_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        star: bool = True, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_star_set_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        star: bool = True, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """为文件或目录设置或取消星标

        POST https://proapi.115.com/android/files/star

        .. note::
            如果其中任何一个 id 目前已经被删除，则会直接返回错误信息

        :payload:
            - ids: int | str 💡 文件或目录 id，多个用逗号 "," 隔开
            - star: 0 | 1 = 1
            - user_id: int | str = <default> 💡 不用管
        """
        api = complete_proapi("/files/star", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"ids": payload, "star": int(star)}
        elif not isinstance(payload, dict):
            payload = {"ids": ",".join(map(str, payload)), "star": int(star)}
        else:
            payload = {"star": int(star), **payload}
        payload["user_id"] = self.user_id
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_storage_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_storage_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_storage_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取使用空间的统计数据（最简略，如需更详细，请用 `fs.fs_space_info()`）

        GET https://115.com/index.php?ct=ajax&ac=get_storage_info
        """
        api = complete_api("/index.php?ct=ajax&ac=get_storage_info", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def fs_supervision(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_supervision(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_supervision(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """通过 pickcode 获取文件信息

        POST https://webapi.115.com/files/supervision

        :payload:
            - pickcode: str
            - preview_type: str = "file" 💡 file:文件 doc:文档 video:视频 music:音乐 pic:图片
            - module: int = 10
        """
        api = complete_webapi("/files/supervision", base_url=base_url)
        if isinstance(payload, str):
            payload = {"preview_type": "file", "module": 10, "pickcode": payload}
        else:
            payload = {"preview_type": "file", "module": 10, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_supervision_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_supervision_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_supervision_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """通过 pickcode 获取文件信息

        POST https://proapi.115.com/android/files/supervision

        :payload:
            - pickcode: str
            - preview_type: str = "file" 💡 file:文件 doc:文档 video:视频 music:音乐 pic:图片
            - module: int = 10
        """
        api = complete_proapi("/files/supervision", base_url, app)
        if isinstance(payload, str):
            payload = {"preview_type": "file", "module": 10, "pickcode": payload}
        else:
            payload = {"preview_type": "file", "module": 10, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_sys_dir(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_sys_dir(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_sys_dir(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取系统目录（在根目录下，使用 `fs_files` 接口罗列时，数目体现在返回值的 `sys_count` 字段）

        GET https://proapi.115.com/android/files/getpackage

        :payload:
            - sys_dir: int 💡 0:我的接收 1:手机相册 2:云下载 3:我的时光记录 4,10,20,21,22,30,40,50,60,70:(未知)
        """
        api = complete_proapi("/files/getpackage", base_url, app)
        if isinstance(payload, int):
            payload = {"sys_dir": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_video(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_video(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_video(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取视频信息和 m3u8 链接列表

        GET https://webapi.115.com/files/video

        .. important::
            仅这几种设备可用：`harmony`, `web`, `desktop`, **wechatmini**, **alipaymini**, **tv**

            但是如果要获取 m3u8 文件，则要提供 web 设备的 cookies，否则返回空数据

        :payload:
            - pickcode: str 💡 提取码
            - share_id: int | str = <default> 💡 分享 id
            - local: 0 | 1 = <default> 💡 是否本地，如果为 1，则不包括 m3u8
        """
        api = complete_webapi("/files/video", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_video_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_video_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_video_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取视频信息和 m3u8 链接列表

        POST https://proapi.115.com/android/2.0/video/play

        .. important::
            网页端设备，即 `harmony`, `web`, `desktop` 不可用此接口，实际上任何 `proapi` 接口都不可用

            也就是说仅这几种设备可用：`115android`, `115ios`, `115ipad`, `android`, `ios`, `qandroid`, `qios`, **wechatmini**, **alipaymini**, **tv**

        :payload:
            - pickcode: str 💡 提取码
            - share_id: int | str = <default> 💡 分享 id
            - local: 0 | 1 = <default> 💡 是否本地，如果为 1，则不包括 m3u8
            - user_id: int = <default> 💡 不用管
        """
        api = complete_proapi("/2.0/video/play", base_url, app)
        if isinstance(payload, str):
            payload = {"pickcode": payload, "user_id": self.user_id}
        else:
            payload = dict(payload, user_id=self.user_id)
        def parse(_, content: bytes, /) -> dict:
            json = json_loads(content)
            if json["state"] or json.get("errno") == 409:
                json["data"] = json_loads(rsa_decode(json["data"]))
            return json
        request_kwargs.setdefault("parse", parse)
        request_kwargs["data"] = {"data": rsa_encode(dumps(payload)).decode("ascii")}
        return self.request(
            url=api, 
            method="POST", 
            async_=async_, 
            **request_kwargs, 
        )

    @overload
    def fs_video_def_set(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_video_def_set(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_video_def_set(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """切换视频清晰度

        .. caution::
            暂时没搞清楚调用了以后，到底有什么效果，所以建议不要用，除非你知道

        GET https://webapi.115.com/files/video_def

        :payload:
            - definition: str
        """
        api = complete_webapi("/files/video_def", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"definition": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def fs_video_m3u8(
        self, 
        /, 
        pickcode: str, 
        definition: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> bytes:
        ...
    @overload
    def fs_video_m3u8(
        self, 
        /, 
        pickcode: str, 
        definition: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, bytes]:
        ...
    def fs_video_m3u8(
        self, 
        /, 
        pickcode: str, 
        definition: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> bytes | Coroutine[Any, Any, bytes]:
        """获取视频的 m3u8 文件列表，此接口必须使用 web 的 cookies

        GET http://115.com/api/video/m3u8/{pickcode}.m3u8?definition={definition}

        .. attention::
            这个接口只支持 web 的 cookies，其它设备会返回空数据，而且获取得到的 m3u8 里的链接，也是 m3u8，会绑定前一次请求时的 user-agent

        :param pickcode: 视频文件的 pickcode
        :params definition: 画质，默认列出所有画质。但可进行筛选，常用的为：
            - 0: 各种分辨率（默认）
            - 1: SD 标清（约为 480p）
            - 3: HD 超清（约为 720p）
            - 4: UD 1080P（约为 1080p）
            - 5: BD 4K
            - 100: 原画（尺寸和原始的相同）
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 接口返回值
        """
        api = complete_api(f"/api/video/m3u8/{pickcode}.m3u8?definition={definition}", base_url=base_url)
        request_kwargs.setdefault("parse", False)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def fs_video_subtitle(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_video_subtitle(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_video_subtitle(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取视频字幕

        GET https://webapi.115.com/movies/subtitle

        :payload:
            - pickcode: str
        """
        api = complete_webapi("/movies/subtitle", base_url=base_url)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def fs_video_subtitle_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def fs_video_subtitle_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def fs_video_subtitle_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取视频字幕

        GET https://proapi.115.com/android/2.0/video/subtitle

        :payload:
            - pickcode: str
        """
        api = complete_proapi("/2.0/video/subtitle", base_url, app)
        if isinstance(payload, str):
            payload = {"pickcode": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    ########## Life API ##########

    @overload
    def life_batch_delete(
        self, 
        payload: Iterable[dict] | dict, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def life_batch_delete(
        self, 
        payload: Iterable[dict] | dict, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def life_batch_delete(
        self, 
        payload: Iterable[dict] | dict, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """批量删除操作历史：批量删除 115 生活事件列表

        POST https://life.115.com/api/1.0/web/1.0/life/life_batch_delete

        :payload:
            - delete_data: str 💡 JSON array，每条数据格式为 {"relation_id": str, "behavior_type": str}
        """
        if not isinstance(payload, dict):
            payload = {"delete_data": (b"[%s]" % b",".join(map(dumps, payload))).decode("utf-8")}
        api = f"http://life.115.com/api/1.0/{app}/1.0/life/life_batch_delete"
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def life_behavior_detail(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def life_behavior_detail(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def life_behavior_detail(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *,
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取 life_list 操作记录明细

        GET https://webapi.115.com/behavior/detail

        .. attention::
            这个接口最多能拉取前 10_000 条数据，且响应速度也较差，请优先使用 `P115Client.life_behavior_detail_app`

        :payload:
            - type: str = "" 💡 操作类型，若不指定则是全部

              - "upload_image_file": 1 💡 上传图片
              - "upload_file":       2 💡 上传文件或目录
              - "star_image":        3 💡 给图片设置星标
              - "star_file":         4 💡 给文件或目录设置星标（不包括图片）
              - "move_image_file":   5 💡 移动图片
              - "move_file":         6 💡 移动文件或目录（不包括图片）
              - "browse_image":      7 💡 浏览图片
              - "browse_video":      8 💡 浏览视频
              - "browse_audio":      9 💡 浏览音频
              - "browse_document":  10 💡 浏览文档
              - "receive_files":    14 💡 接收文件
              - "new_folder":       17 💡 新增目录
              - "copy_folder":      18 💡 复制目录
              - "folder_label":     19 💡 目录设置标签
              - "folder_rename":    20 💡 目录改名
              - "delete_file":      22 💡 删除文件或目录
              - "copy_file":         ? 💡 复制文件（未实现）
              - "rename_file":       ? 💡 文件改名（未实现）

            - limit: int = 32          💡 最大值为 1_000
            - offset: int = 0
            - date: str = <default>    💡 日期，格式为 'YYYY-MM-DD'，若指定则只拉取这一天的数据
        """
        api = complete_webapi("/behavior/detail", base_url=base_url)
        if isinstance(payload, str):
            payload = {"limit": 32, "offset": 0, "type": payload}
        else:
            payload = {"limit": 32, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def life_behavior_detail_app(
        self, 
        payload: str | dict = "", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def life_behavior_detail_app(
        self, 
        payload: str | dict = "", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def life_behavior_detail_app(
        self, 
        payload: str | dict = "", 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *,
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取 life_list 操作记录明细

        GET https://proapi.115.com/android/behavior/detail

        :payload:
            - type: str = "" 💡 操作类型

              - "upload_image_file": 1 💡 上传图片
              - "upload_file":       2 💡 上传文件或目录
              - "star_image":        3 💡 给图片设置星标
              - "star_file":         4 💡 给文件或目录设置星标（不包括图片）
              - "move_image_file":   5 💡 移动图片
              - "move_file":         6 💡 移动文件或目录（不包括图片）
              - "browse_image":      7 💡 浏览图片
              - "browse_video":      8 💡 浏览视频
              - "browse_audio":      9 💡 浏览音频
              - "browse_document":  10 💡 浏览文档
              - "receive_files":    14 💡 接收文件
              - "new_folder":       17 💡 新增目录
              - "copy_folder":      18 💡 复制目录
              - "folder_label":     19 💡 目录设置标签
              - "folder_rename":    20 💡 目录改名
              - "delete_file":      22 💡 删除文件或目录
              - "copy_file":         ? 💡 复制文件（未实现）
              - "rename_file":       ? 💡 文件改名（未实现）

            - limit: int = 32          💡 最大值为 1_000
            - offset: int = 0
            - date: str = <default>    💡 日期，格式为 YYYY-MM-DD，若指定则只拉取这一天的数据
        """
        api = complete_proapi("/behavior/detail", base_url, app)
        if isinstance(payload, str):
            payload = {"limit": 32, "offset": 0, "type": payload}
        else:
            payload = {"limit": 32, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def life_calendar_getoption(
        self, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def life_calendar_getoption(
        self, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def life_calendar_getoption(
        self, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取 115 生活的开关设置

        GET https://life.115.com/api/1.0/web/1.0/calendar/getoption

        .. hint::
            app 可以是任意字符串，服务器并不做检查。其他可用 app="web" 的接口可能皆是如此
        """
        api = f"http://life.115.com/api/1.0/{app}/1.0/calendar/getoption"
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def life_calendar_setoption(
        self, 
        payload: Literal[0, 1] | dict = 1, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def life_calendar_setoption(
        self, 
        payload: Literal[0, 1] | dict = 1, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def life_calendar_setoption(
        self, 
        payload: Literal[0, 1] | dict = 1, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """设置 115 生活的开关选项

        POST https://life.115.com/api/1.0/web/1.0/calendar/setoption

        :payload:
            - locus: 0 | 1 = 1     💡 开启或关闭最近记录
            - open_life: 0 | 1 = 1 💡 显示或关闭
            - birthday: 0 | 1 = <default>
            - holiday: 0 | 1 = <default>
            - lunar: 0 | 1 = <default>
            - view: 0 | 1 = <default>
            - diary: 0 | 1 = <default>
            - del_notice_item: 0 | 1 = <default>
            - first_week: 0 | 1 = <default>
        """
        if isinstance(payload, dict):
            payload = {"locus": 1, "open_life": 1, **payload}
        else:
            payload = {"locus": 1, "open_life": payload}
        api = f"http://life.115.com/api/1.0/{app}/1.0/calendar/setoption"
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def life_clear_history(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def life_clear_history(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def life_clear_history(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """清空操作历史：清空 115 生活事件列表

        POST https://life.115.com/api/1.0/web/1.0/life/life_clear_history

        :payload:
            - tab_type: 0 | 1 = <default>
        """
        if isinstance(payload, int):
            payload = {"tab_type": 0}
        api = f"http://life.115.com/api/1.0/{app}/1.0/life/life_clear_history"
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def life_doc_behavior_post_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def life_doc_behavior_post_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def life_doc_behavior_post_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """推送事件：浏览文档 "browse_document"

        POST https://proapi.115.com/android/files/doc_behavior

        .. note::
            如果提供的是目录的 id，则会把其中（直属的）文档记为浏览

        :payload:
            - file_id: int | str
            - file_id[0]: int | str
            - file_id[1]: int | str
            - ...
        """
        api = complete_proapi("/files/doc_behavior", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload}
        elif not isinstance(payload, dict):
            payload = {f"file_id[{i}]": fid for i, fid in enumerate(payload)}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def life_has_data(
        self, 
        payload: int | dict = {}, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def life_has_data(
        self, 
        payload: int | dict = {}, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def life_has_data(
        self, 
        payload: int | dict = {}, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取有数据的那几天零点的时间戳

        GET https://life.115.com/api/1.0/web/1.0/life/life_has_data

        :payload:
            - end_time: int = <default>
            - show_note_cal: 0 | 1 = <default>
            - start_time: int = <default>
        """
        api = f"http://life.115.com/api/1.0/{app}/1.0/life/life_has_data"
        if isinstance(payload, int):
            payload = {"start_time": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def life_img_behavior_post_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def life_img_behavior_post_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def life_img_behavior_post_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """推送事件：浏览图片 "browse_image"

        POST https://proapi.115.com/android/files/img_behavior

        .. note::
            如果提供的是目录的 id，则会把其中（直属的）图片记为浏览

        :payload:
            - file_id: int | str
            - file_id[0]: int | str
            - file_id[1]: int | str
            - ...
        """
        api = complete_proapi("/files/img_behavior", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload}
        elif not isinstance(payload, dict):
            payload = {f"file_id[{i}]": fid for i, fid in enumerate(payload)}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def life_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def life_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def life_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列登录和增删改操作记录（最新几条）

        GET https://life.115.com/api/1.0/web/1.0/life/life_list

        .. note::
            为了实现分页拉取，需要指定 last_data 参数。只要上次返回的数据不为空，就会有这个值，直接使用即可

        .. hint::
            引用：https://cdnres.115.com/life/m_r/web/static_v11.0/homepage/lifetime.js

            - 'upload_file'          => '上传文件'   💡 上传文件(非图片) 文件类
            - 'upload_image_file'    => '上传图片'   💡 上传文件(图片)   文件类
            - 'backup_album'         => '备份相册'   💡 备份相册         文件类
            - 'sync_communication'   => '同步通讯录' 💡 同步通讯录       文件类
            - 'receive_files'        => '接收文件'   💡 接收文件         文件类
            - 'star_file'            => '星标文件'   💡 星标文件         文件类
            - 'radar_sharing'        => '雷达分享'   💡 雷达分享         文件类
            - 'file_search'          => '文件搜索'   💡 文件搜索         文件类
            - 'move_file'            => '移动文件'   💡 移动文件(非图片) 文件类
            - 'move_image_file'      => '移动图片'   💡 移动文件(图片)   文件类
            - 'browse_document'      => '浏览文档'   💡 浏览文档         信息预览类
            - 'browse_video'         => '浏览视频'   💡 浏览视频         信息预览类
            - 'browse_audio'         => '浏览音频'   💡 浏览音频         信息预览类
            - 'browse_image'         => '浏览图片'   💡 浏览图片         信息预览类
            - 'publish_record'       => '发布记录'   💡 发布记录         信息发布类
            - 'publish_calendar'     => '发布日程'   💡 发布日程         信息发布类
            - 'publish_home'         => '发布传说'   💡 发布传说         信息发布类
            - 'account_security'     => '账号安全'   💡 账号安全         账号安全类

            一些筛选条件::

                - 全部：type=0
                - 上传文件：type=1&file_behavior_type=1
                - 浏览文件：type=1&file_behavior_type=2
                - 星标文件：type=1&file_behavior_type=3
                - 移动文件：type=1&file_behavior_type=4
                - 目录：type=1&file_behavior_type=5
                - 备份：type=1&file_behavior_type=6
                - 删除文件：type=1&file_behavior_type=7
                - 账号安全：type=2
                - 通讯录：type=3
                - 其他：type=99

            一些类型分类::

                .. code:: python

                    {
                        'file':['upload_file', 'upload_image_file', 'backup_album', 'sync_communication', 
                                'receive_files', 'star_file', 'radar_sharing', 'file_search', 'move_file', 
                                'move_image_file', 'star_image', 'del_photo_image', 'del_similar_image', 
                                'generate_smart_albums', 'new_person_albums', 'del_person_albums', 
                                'generate_photo_story', 'share_photo', 'folder_rename', 'folder_label', 
                                'new_folder', 'copy_folder', 'delete_file'],
                        'review':['browse_video', 'browse_document', 'browse_audio', 'browse_image'],
                        'edit':['publish_record', 'publish_calendar', 'publish_home'],
                        'safe':['account_security'],
                        'cloud':[],
                        'share': ['share_contact']
                    }

        :payload:
            - start: int = 0
            - limit: int = 1_000
            - check_num: int = <default> 💡 选中记录数
            - del_data: str = <default> 💡 JSON array，删除时传给接口数据
            - end_time: int = <default> 💡 结束时间戳
            - file_behavior_type: int | str = <default> 💡 筛选类型，有多个则用逗号 ',' 隔开

                - 💡 0: 所有
                - 💡 1: 上传
                - 💡 2: 浏览
                - 💡 3: 星标
                - 💡 4: 移动
                - 💡 5: 标签
                - 💡 6: <UNKNOWN>
                - 💡 7: 删除

            - isPullData: 'true' | 'false' = <default> 💡 是否下拉加载数据
            - isShow: 0 | 1 = <default> 💡 是否显示
            - last_data: str = <default> 💡 JSON object, e.g. '{"last_time":1700000000,"last_count":1,"total_count":200}'
            - mode: str = <default> 💡 操作模式

                - 💡 "show" 展示列表模式
                - 💡 "select": 批量操作模式

            - selectedRecords: str = <default> 💡 JSON array，选中记录 id 数组
            - show_note_cal: 0 | 1 = <default>
            - show_type: int = 0 💡 筛选类型，有多个则用逗号 ',' 隔开

                - 💡 0: 所有
                - 💡 1: 增、删、改、移动、上传、接收、设置标签等文件系统操作
                - 💡 2: 浏览文件
                - 💡 3: <UNKNOWN>
                - 💡 4: account_security

            - start_time: int = <default> 💡 开始时间戳
            - tab_type: int = <default>
            - total_count: int = <default> 💡 列表所有项数
            - type: int = <default> 💡 类型
        """
        api = f"http://life.115.com/api/1.0/{app}/1.0/life/life_list"
        if isinstance(payload, (int, str)):
            payload = {"limit": 1_000, "show_type": 0, "start": payload}
        else:
            payload = {"limit": 1_000, "show_type": 0, "start": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    ########## Login API ##########

    @overload
    def login_app(
        self, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> None | str:
        ...
    @overload
    def login_app(
        self, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, None | str]:
        ...
    def login_app(
        self, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> None | str | Coroutine[Any, Any, None | str]:
        """获取当前的登录设备名，如果为 None，说明未能获得
        """
        def gen_step():
            ssoent = self.login_ssoent
            if ssoent is None:
                return None
            if ssoent in SSOENT_TO_APP:
                return SSOENT_TO_APP[ssoent]
            device = yield self.login_device(async_=async_, **request_kwargs)
            if device is None:
                return None
            return device["icon"]
        return run_gen_step(gen_step, async_=async_)

    @overload
    def login_check_sso(
        self, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def login_check_sso(
        self, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def login_check_sso(
        self, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """检查当前 cookies 的登录状态信息，并且自最近一次登录的 60 秒后，使当前设备下除最近一次登录外的所有 cookies 失效

        GET https://passportapi.115.com/app/1.0/web/1.0/check/sso
        """
        api = "https://passportapi.115.com/app/1.0/web/1.0/check/sso"
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def login_device(
        self, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> None | dict:
        ...
    @overload
    def login_device(
        self, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, None | dict]:
        ...
    def login_device(
        self, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> None | dict | Coroutine[Any, Any, None | dict]:
        """获取当前的登录设备的信息，如果为 None，也不代表当前的 cookies 被下线，只能说明有更晚的登录到同一设备
        """
        def parse(_, content: bytes, /) -> None | dict:
            login_devices = json_loads(content)
            if not login_devices["state"]:
                return None
            return next(filter(cast(Callable, itemgetter("is_current")), login_devices["data"]["list"]), None)
        request_kwargs.setdefault("parse", parse)
        return self.login_devices(async_=async_, **request_kwargs)

    @overload
    def login_devices(
        self, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def login_devices(
        self, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def login_devices(
        self, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取所有的已登录设备的信息，不过当前的 cookies 必须是登录状态（未退出或未失效）

        GET https://passportapi.115.com/app/1.0/web/1.0/login_log/login_devices
        """
        api = "https://passportapi.115.com/app/1.0/web/1.0/login_log/login_devices"
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def login_info(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def login_info(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def login_info(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取登录信息

        GET https://proapi.115.com/android/2.0/user/login_info
        """
        api = complete_proapi("/2.0/user/login_info", base_url, app)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def login_log(
        self, 
        payload: dict = {}, 
        /, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def login_log(
        self, 
        payload: dict = {}, 
        /, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def login_log(
        self, 
        payload: dict = {}, 
        /, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取登录信息日志列表

        GET https://passportapi.115.com/app/1.0/web/1.0/login_log/log

        :payload:
            - start: int = 0
            - limit: int = 100
        """
        api = "https://passportapi.115.com/app/1.0/web/1.0/login_log/log"
        payload = {"start": 0, "limit": 100, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def login_online(
        self, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def login_online(
        self, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def login_online(
        self, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """当前登录的设备总数和最近登录的设备

        GET https://passportapi.115.com/app/1.0/web/1.0/login_log/login_online
        """
        api = f"http://passportapi.115.com/app/1.0/{app}/1.0/login_log/login_online"
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def login_status(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> bool:
        ...
    @overload
    def login_status(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, bool]:
        ...
    def login_status(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> bool | Coroutine[Any, Any, bool]:
        """检查是否已登录

        GET https://my.115.com/?ct=guide&ac=status
        """
        api = complete_api("/?ct=guide&ac=status", "my", base_url=base_url)
        def parse(_, content: bytes, /) -> bool:
            try:
                return json_loads(content)["state"]
            except:
                return False
        request_kwargs.setdefault("parse", parse)
        return self.request(url=api, async_=async_, **request_kwargs)

    @property
    def login_ssoent(self, /) -> None | str:
        """获取当前的登录设备 ssoent，如果为 None，说明未能获得（会直接获取 Cookies 中名为 UID 字段的值，所以即使能获取，也不能说明登录未失效）
        """
        cookie_uid = self.cookies.get("UID")
        if cookie_uid:
            return cookie_uid.split("_")[1]
        else:
            return None

    ########## Logout API ##########

    @overload
    def logout_by_app(
        self, 
        /, 
        app: None | str = None, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> None:
        ...
    @overload
    def logout_by_app(
        self, 
        /, 
        app: None | str = None, 
        request: None | Callable = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, None]:
        ...
    def logout_by_app(
        self, 
        /, 
        app: None | str = None, 
        request: None | Callable = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> None | Coroutine[Any, Any, None]:
        """退出登录状态（可以把某个客户端下线，所有已登录设备可从 `login_devices` 获取）

        GET https://passportapi.115.com/app/1.0/{app}/1.0/logout/logout

        :param app: 退出登录的 app

        -----

        :设备列表如下:

        +-------+----------+------------+-------------------------+
        | No.   | ssoent   | app        | description             |
        +=======+==========+============+=========================+
        | 01    | A1       | web        | 网页版                  |
        +-------+----------+------------+-------------------------+
        | 02    | A2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 03    | A3       | ?          | 未知: iphone            |
        +-------+----------+------------+-------------------------+
        | 04    | A4       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 05    | B1       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 06    | D1       | ios        | 115生活(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 07    | D2       | ?          | 未知: ios               |
        +-------+----------+------------+-------------------------+
        | 08    | D3       | 115ios     | 115(iOS端)              |
        +-------+----------+------------+-------------------------+
        | 09    | F1       | android    | 115生活(Android端)      |
        +-------+----------+------------+-------------------------+
        | 10    | F2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 11    | F3       | 115android | 115(Android端)          |
        +-------+----------+------------+-------------------------+
        | 12    | H1       | ipad       | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 13    | H2       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 14    | H3       | 115ipad    | 115(iPad端)             |
        +-------+----------+------------+-------------------------+
        | 15    | I1       | tv         | 115网盘(Android电视端)  |
        +-------+----------+------------+-------------------------+
        | 16    | M1       | qandriod   | 115管理(Android端)      |
        +-------+----------+------------+-------------------------+
        | 17    | N1       | qios       | 115管理(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 18    | O1       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 19    | P1       | windows    | 115生活(Windows端)      |
        +-------+----------+------------+-------------------------+
        | 20    | P2       | mac        | 115生活(macOS端)        |
        +-------+----------+------------+-------------------------+
        | 21    | P3       | linux      | 115生活(Linux端)        |
        +-------+----------+------------+-------------------------+
        | 22    | R1       | wechatmini | 115生活(微信小程序)     |
        +-------+----------+------------+-------------------------+
        | 23    | R2       | alipaymini | 115生活(支付宝小程序)   |
        +-------+----------+------------+-------------------------+
        | 24    | S1       | harmony    | 115(Harmony端)          |
        +-------+----------+------------+-------------------------+
        """
        def gen_step():
            nonlocal app
            if app is None:
                app = yield self.login_app(async_=async_)
            if app == "desktop":
                app = "web"
            api = f"http://passportapi.115.com/app/1.0/{app}/1.0/logout/logout"
            request_kwargs["headers"] = {**(request_kwargs.get("headers") or {}), "Cookie": self.cookies_str}
            request_kwargs.setdefault("parse", ...)
            if request is None:
                return get_default_request()(url=api, async_=async_, **request_kwargs)
            else:
                return request(url=api, **request_kwargs)
        return run_gen_step(gen_step, async_=async_)

    @overload
    def logout_by_ssoent(
        self, 
        payload: None | str | dict = None, 
        /, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def logout_by_ssoent(
        self, 
        payload: None | str | dict = None, 
        /, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def logout_by_ssoent(
        self, 
        payload: None | str | dict = None, 
        /, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """退出登录状态（可以把某个客户端下线，所有已登录设备可从 `login_devices` 获取）

        POST https://passportapi.115.com/app/1.0/web/1.0/logout/mange

        :payload:
            - ssoent: str

        -----

        :设备列表如下:

        +-------+----------+------------+-------------------------+
        | No.   | ssoent   | app        | description             |
        +=======+==========+============+=========================+
        | 01    | A1       | web        | 网页版                  |
        +-------+----------+------------+-------------------------+
        | 02    | A2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 03    | A3       | ?          | 未知: iphone            |
        +-------+----------+------------+-------------------------+
        | 04    | A4       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 05    | B1       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 06    | D1       | ios        | 115生活(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 07    | D2       | ?          | 未知: ios               |
        +-------+----------+------------+-------------------------+
        | 08    | D3       | 115ios     | 115(iOS端)              |
        +-------+----------+------------+-------------------------+
        | 09    | F1       | android    | 115生活(Android端)      |
        +-------+----------+------------+-------------------------+
        | 10    | F2       | ?          | 未知: android           |
        +-------+----------+------------+-------------------------+
        | 11    | F3       | 115android | 115(Android端)          |
        +-------+----------+------------+-------------------------+
        | 12    | H1       | ipad       | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 13    | H2       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 14    | H3       | 115ipad    | 115(iPad端)             |
        +-------+----------+------------+-------------------------+
        | 15    | I1       | tv         | 115网盘(Android电视端)  |
        +-------+----------+------------+-------------------------+
        | 16    | M1       | qandriod   | 115管理(Android端)      |
        +-------+----------+------------+-------------------------+
        | 17    | N1       | qios       | 115管理(iOS端)          |
        +-------+----------+------------+-------------------------+
        | 18    | O1       | ?          | 未知: ipad              |
        +-------+----------+------------+-------------------------+
        | 19    | P1       | windows    | 115生活(Windows端)      |
        +-------+----------+------------+-------------------------+
        | 20    | P2       | mac        | 115生活(macOS端)        |
        +-------+----------+------------+-------------------------+
        | 21    | P3       | linux      | 115生活(Linux端)        |
        +-------+----------+------------+-------------------------+
        | 22    | R1       | wechatmini | 115生活(微信小程序)     |
        +-------+----------+------------+-------------------------+
        | 23    | R2       | alipaymini | 115生活(支付宝小程序)   |
        +-------+----------+------------+-------------------------+
        | 24    | S1       | harmony    | 115(Harmony端)          |
        +-------+----------+------------+-------------------------+
        """
        api = "https://passportapi.115.com/app/1.0/web/1.0/logout/mange"
        if payload is None:
            payload = {"ssoent": self.login_ssoent or ""}
        elif isinstance(payload, str):
            payload = {"ssoent": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    ########## Message API ##########

    @overload
    def msg_contacts_ls(
        self, 
        payload: int | str | dict = 0, 
        /, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def msg_contacts_ls(
        self, 
        payload: int | str | dict = 0, 
        /, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def msg_contacts_ls(
        self, 
        payload: int | str | dict = 0, 
        /, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取提示消息

        GET https://pmsg.115.com/api/1.0/app/1.0/contact/ls

        :payload:
            - limit: int = 115
            - skip: int = 0
            - t: 0 | 1 = 1
        """
        api = "https://pmsg.115.com/api/1.0/app/1.0/contact/ls"
        if isinstance(payload, (int, str)):
            payload = {"limit": 115, "t": 1, "skip": payload}
        else:
            payload = {"limit": 115, "t": 1, "skip": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def msg_contacts_notice(
        self, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def msg_contacts_notice(
        self, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def msg_contacts_notice(
        self, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取提示消息

        GET https://msg.115.com/?ct=contacts&ac=notice&client=web
        """
        api = "https://msg.115.com/?ct=contacts&ac=notice&client=web"
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def msg_get_websocket_host(
        self, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def msg_get_websocket_host(
        self, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def msg_get_websocket_host(
        self, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取 websocket 链接

        GET https://msg.115.com/?ct=im&ac=get_websocket_host
        """
        api = "https://msg.115.com/?ct=im&ac=get_websocket_host"
        return self.request(url=api, async_=async_, **request_kwargs)

    ########## Note API ##########

    @overload
    def note_bookmark_list(
        self, 
        payload: int | str | dict = "", 
        /, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_bookmark_list(
        self, 
        payload: int | str | dict = "", 
        /, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_bookmark_list(
        self, 
        payload: int | str | dict = "", 
        /, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列书签（网址收藏夹）

        GET https://bookmark.115.com/api/bookmark_list.php

        .. note::
            这个接口支持 GET 和 POST 请求方法

        :payload:
            - search_value: str = ""
            - parent_id: int = 0
            - limit: int = 1150
            - offset: int = 0
        """
        api = "https://bookmark.115.com/api/bookmark_list.php"
        if isinstance(payload, int):
            payload = {"limit": 1150, "offset": payload}
        elif isinstance(payload, str):
            payload = {"limit": 1150, "search_value": payload}
        else:
            payload = {"limit": 1150, **payload}
        if request_kwargs.get("method", "").upper() == "POST":
            return self.request(url=api, data=payload, async_=async_, **request_kwargs)
        else:
            return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def note_cate_add(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_cate_add(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_cate_add(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """添加记录分类

        POST https://note.115.com/?ct=note&ac=addcate

        :payload:
            - cname: str 💡 最多允许 20 个字符
        """
        api = "https://note.115.com/?ct=note&ac=addcate"
        if isinstance(payload, str):
            payload = {"cname": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def note_cate_del(
        self, 
        payload: int | dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_cate_del(
        self, 
        payload: int | dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_cate_del(
        self, 
        payload: int | dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除记录分类

        POST https://note.115.com/?ct=note&ac=delcate

        :payload:
            - cid: int 💡 分类 id
            - action: str = <default>
        """
        api = "https://note.115.com/?ct=note&ac=delcate"
        if isinstance(payload, int):
            payload = {"cid": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def note_cate_update(
        self, 
        payload: dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_cate_update(
        self, 
        payload: dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_cate_update(
        self, 
        payload: dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """改名记录分类

        POST https://note.115.com/?ct=note&ac=upcate

        :payload:
            - cid: int   💡 分类 id
            - cname: str 💡 分类名，最多 20 个字符
        """
        api = "https://note.115.com/?ct=note&ac=upcate"
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def note_cate_list(
        self, 
        payload: bool | dict = True, 
        /, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_cate_list(
        self, 
        payload: bool | dict = True, 
        /, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_cate_list(
        self, 
        payload: bool | dict = True, 
        /, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取记录分类列表

        GET https://note.115.com/?ct=note&ac=cate

        :payload:
            - has_picknews: 0 | 1 = 1 💡 是否显示 id 为负数的分类
        """
        api = "https://note.115.com/?ct=note&ac=cate"
        if isinstance(payload, bool):
            payload = {"has_picknews": int(payload)}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def note_del(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_del(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_del(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除记录

        POST https://note.115.com/?ct=note&ac=delete

        :payload:
            - nid: int | str 💡 记录 id，多个用逗号 "," 隔开
        """
        api = "https://note.115.com/?ct=note&ac=delete"
        if isinstance(payload, (int, str)):
            payload = {"nid": payload}
        elif not isinstance(payload, dict):
            payload = {"nid": ",".join(map(str, payload))}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def note_detail(
        self, 
        payload: int | dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_detail(
        self, 
        payload: int | dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_detail(
        self, 
        payload: int | dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取记录（笔记）数据

        GET https://note.115.com/?ct=note&ac=detail

        :payload:
            - nid: int 💡 记录 id
        """
        api = "https://note.115.com/?ct=note&ac=detail"
        if isinstance(payload, int):
            payload = {"nid": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def note_fav_list(
        self, 
        payload: int | dict = 0, 
        /, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_fav_list(
        self, 
        payload: int | dict = 0, 
        /, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_fav_list(
        self, 
        payload: int | dict = 0, 
        /, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取星标记录（笔记）列表

        GET https://note.115.com/?ct=note&ac=get_fav_note_list

        :payload:
            - start: int = 0    💡 开始索引，从 0 开始
            - limit: int = 1150 💡 最多返回数量
        """
        api = "https://note.115.com/?ct=note&ac=get_fav_note_list"
        if isinstance(payload, int):
            payload = {"limit": 1150, "start": payload}
        else:
            payload = {"limit": 1150, "start": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def note_fav_set(
        self, 
        payload: int | dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_fav_set(
        self, 
        payload: int | dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_fav_set(
        self, 
        payload: int | dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """给记录添加或去除星标

        POST https://note.115.com/?ct=note&ac=fav

        :payload:
            - note_id: int 💡 记录 id
            - op: "add" | "del" = "add" 💡 操作类型："add":添加 "del":去除
        """
        api = "https://note.115.com/?ct=note&ac=fav"
        if isinstance(payload, int):
            payload = {"op": "add", "note_id": payload}
        else:
            payload = {"op": "add", **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def note_is_fav(
        self, 
        payload: int | str | Iterable[int | str] |dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_is_fav(
        self, 
        payload: int | str | Iterable[int | str] |dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_is_fav(
        self, 
        payload: int | str | Iterable[int | str] |dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """检查记录是否被星标

        .. note::
            这个接口支持 GET 和 POST 请求方法

        GET https://note.115.com/api/2.0/api.php?ac=is_fav

        :payload:
            - note_id: int | str 💡 多个用逗号隔开
        """
        api = "https://note.115.com/api/2.0/api.php?ac=is_fav"
        if isinstance(payload, (int, str)):
            payload = {"note_id": payload}
        elif not isinstance(payload, dict):
            payload = {"note_id": ",".join(map(str, payload))}
        if request_kwargs.get("method", "").upper() == "POST":
            return self.request(url=api, data=payload, async_=async_, **request_kwargs)
        else:
            return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def note_list(
        self, 
        payload: int | dict = 0, 
        /, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_list(
        self, 
        payload: int | dict = 0, 
        /, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_list(
        self, 
        payload: int | dict = 0, 
        /, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取记录（笔记）列表

        GET https://note.115.com/?ct=note

        :payload:
            - ac: "" | "all" = "all"  💡 如果为 "all"，则显示完整信息，如果为 ""，则显示简要信息（只有标题，没有内容文本）
            - start: int = 0          💡 开始索引，从 0 开始
            - page_size: int = 1150   💡 分页大小，相当于 `limit`
            - cid: int = 0            💡 分类 id：0:全部 -10:云收藏 -15:消息备忘
            - has_picknews: 0 | 1 = 1 💡 是否显示 id 为负数的分类
            - keyword: str = <default>
            - recently: 0 | 1 = <default> 💡 是否为最近
        """
        api = "https://note.115.com/?ct=note"
        if isinstance(payload, int):
            payload = {"ac": "all", "cid": 0, "has_picknews": 1, "page_size": 1150, "start": payload}
        else:
            payload = {"ac": "all", "cid": 0, "has_picknews": 1, "page_size": 1150, "start": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def note_save(
        self, 
        payload: str | dict | list, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_save(
        self, 
        payload: str | dict | list, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_save(
        self, 
        payload: str | dict | list, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """保存记录（笔记）

        POST https://note.115.com/?ct=note&ac=save

        :payload:
            - content: str         💡 记录的文本，最多 50000 个字符
            - cid: int = 0         💡 分类 id
            - is_html: 0 | 1 = 0   💡 是否 HTML，如果为 1，则会自动加上标签（例如 <p>），以使内容成为合法的 HTML
            - nid: int = <default> 💡 记录 id，如果提供就是更新，否则就是新建
            - pickcodes: str = <default>
            - subject: str = <default> 💡 标题，最多 927 个字节，可以为空
            - toc_ids: int | str = <default>
            - tags: str = <default>    💡 标签文本
            - tags[]: str = <default>  💡 标签文本（多个用 "[]" 后缀）
            - ...
            - tags[0]: str = <default> 💡 标签文本（多个用 "[0]","[1]",... 后缀）
            - tags[1]: str = <default> 💡 标签文本
            - ...
        """
        api = "https://note.115.com/?ct=note&ac=save"
        if isinstance(payload, str):
            payload = {"content": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def note_search(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_search(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_search(
        self, 
        payload: str | dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """搜索记录（笔记）

        .. note::
            这个接口支持 GET 和 POST 请求方法

        GET https://note.115.com/api/2.0/api.php?ac=search

        :payload:
            - q: str 💡 搜索词
            - start: int = 0          💡 开始索引，从 0 开始
            - limit: int = 1150       💡 最多返回数量
            - count: int = <default>
            - cid: int = 0            💡 分类 id
            - has_picknews: 0 | 1 = 1 💡 是否显示 id 为负数的分类
            - create_time1: str = <default>
            - create_time2: str = <default>
            - start_time: str = <default>    💡 开始日期，格式为 YYYY-MM-DD
            - end_time: str = <default>      💡 结束日期（含），格式为 YYYY-MM-DD
            - tag_arr: str = <default>    💡 标签文本
            - tag_arr[]: str = <default>  💡 标签文本（多个用 "[]" 后缀）
            - ...
            - tag_arr[0]: str = <default> 💡 标签文本（多个用 "[0]","[1]",... 后缀）
            - tag_arr[1]: str = <default> 💡 标签文本
            - ...
        """
        api = "https://note.115.com/api/2.0/api.php?ac=search"
        if isinstance(payload, str):
            payload = {"has_picknews": 1, "limit": 1150, "start": 0, "q": payload}
        else:
            payload = {"has_picknews": 1, "limit": 1150, "start": 0, **payload}
        if request_kwargs.get("method", "").upper() == "POST":
            return self.request(url=api, data=payload, async_=async_, **request_kwargs)
        else:
            return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def note_tag_color(
        self, 
        payload: str | Iterable[str] | dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_tag_color(
        self, 
        payload: str | Iterable[str] | dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_tag_color(
        self, 
        payload: str | Iterable[str] | dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """上传标签，返回标签并提供颜色

        POST https://note.115.com/api/2.0/api.php?ac=get_tag_color

        :payload:
            - tags: str = <default>    💡 标签文本
            - tags[]: str = <default>  💡 标签文本（多个用 "[]" 后缀）
            - ...
            - tags[0]: str = <default> 💡 标签文本（多个用 "[0]","[1]",... 后缀）
            - tags[1]: str = <default> 💡 标签文本
            - ...
        """
        api = "https://note.115.com/api/2.0/api.php?ac=get_tag_color"
        if isinstance(payload, str):
            payload = {"tags": payload}
        elif payload and not isinstance(payload, dict) and not (isinstance(payload, Sequence) and not isinstance(payload[0], str)):
            payload = {f"tags[{i}]": t for i, t in enumerate(payload)}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def note_tag_latest(
        self, 
        payload: str | dict = "", 
        /, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_tag_latest(
        self, 
        payload: str | dict = "", 
        /, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_tag_latest(
        self, 
        payload: str | dict = "", 
        /, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取最近使用的标签

        .. note::
            这个接口支持 GET 和 POST 请求方法

        GET https://note.115.com/api/2.0/api.php?ac=get_latest_tags

        :payload:
            - q: str = ""                💡 搜索词
            - is_return_color: 0 | 1 = 1 💡 是否返回颜色
            - limit: int = 1150          💡 最多返回数量
        """
        api = "https://note.115.com/api/2.0/api.php?ac=get_latest_tags"
        if isinstance(payload, str):
            payload = {"is_return_color": 1, "limit": 1150, "q": payload}
        else:
            payload = {"is_return_color": 1, "limit": 1150, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def note_update_cate(
        self, 
        payload: dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def note_update_cate(
        self, 
        payload: dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def note_update_cate(
        self, 
        payload: dict, 
        /, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """修改记录的分类

        POST https://note.115.com/?ct=note&ac=update_note_cate

        :payload:
            - cid: int 💡 分类 id
            - nid: int | str 💡 记录 id，多个用逗号 "," 隔开
        """
        api = "https://note.115.com/?ct=note&ac=update_note_cate"
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    ########## Offline Download API ##########

    @overload
    def _offline_web_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def _offline_web_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def _offline_web_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        api = "http://lixian.115.com/web/lixian/"
        if ac:
            payload["ac"] = ac
        return self.request(
            url=api, 
            method="POST", 
            data=payload, 
            async_=async_, 
            **request_kwargs, 
        )

    @overload
    def _offline_lixian_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def _offline_lixian_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def _offline_lixian_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        api = "http://lixian.115.com/lixian/"
        if ac:
            payload["ac"] = ac
        request_kwargs["ecdh_encrypt"] = True
        return self.request(
            url=api, 
            method="POST", 
            data=payload, 
            async_=async_, 
            **request_kwargs, 
        )

    @overload
    def _offline_lixianssp_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def _offline_lixianssp_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def _offline_lixianssp_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        api = "http://lixian.115.com/lixianssp/"
        for k, v in payload.items():
            payload[k] = str(v)
        if ac:
            payload["ac"] = ac
        payload["app_ver"] = "99.99.99.99"
        request_kwargs["headers"] = {
            **(request_kwargs.get("headers") or {}), 
            "user-agent": "Mozilla/5.0 115disk/99.99.99.99 115Browser/99.99.99.99 115wangpan_android/99.99.99.99", 
        }
        request_kwargs["ecdh_encrypt"] = False
        def parse(_, content: bytes, /) -> dict:
            json = json_loads(content)
            if data := json.get("data"):
                try:
                    json["data"] = json_loads(rsa_decode(data))
                except Exception:
                    pass
            return json
        request_kwargs.setdefault("parse", parse)
        return self.request(
            url=api, 
            method="POST", 
            data={"data": rsa_encode(dumps(payload)).decode("ascii")}, 
            async_=async_, 
            **request_kwargs, 
        )

    @overload
    def _offline_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        use_web_api: bool = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def _offline_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        use_web_api: bool = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def _offline_post(
        self, 
        payload: dict, 
        /, 
        ac: str = "", 
        use_web_api: bool = False, 
        *, 
        async_: Literal[False, True] = False, 
        ecdh_encrypt: bool = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        if use_web_api:
            method = self._offline_web_post
        elif ecdh_encrypt:
            method = self._offline_lixian_post
        else:
            method = self._offline_lixianssp_post
        return method(payload, ac, async_=async_, ecdh_encrypt=ecdh_encrypt, **request_kwargs)

    @overload
    def offline_add_torrent(
        self, 
        payload: str | dict, 
        /, 
        use_web_api: bool = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_add_torrent(
        self, 
        payload: str | dict, 
        /, 
        use_web_api: bool = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_add_torrent(
        self, 
        payload: str | dict, 
        /, 
        use_web_api: bool = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """添加一个种子作为离线任务

        POST https://lixian.115.com/lixianssp/?ac=add_task_bt

        .. note::
            `client.offline_add_torrent(info_hash)` 相当于 `client.offline_add_url(f"magnet:?xt=urn:btih:{info_hash}")`

            但此接口的优势是允许选择要下载的文件

        :payload:
            - info_hash: str 💡 种子文件的 info_hash
            - wanted: str = <default> 💡 选择文件进行下载（是数字用 "," 分隔）
            - savepath: str = <default> 💡 保存到目录下的相对路径
            - wp_path_id: int | str = <default> 💡 保存到目录的 id
        """
        if isinstance(payload, str):
            payload = {"info_hash": payload}
        return self._offline_post(payload, "add_task_bt", use_web_api=use_web_api, async_=async_, **request_kwargs)

    @overload
    def offline_add_url(
        self, 
        payload: str | dict, 
        /, 
        use_web_api: bool = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_add_url(
        self, 
        payload: str | dict, 
        /, 
        use_web_api: bool = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_add_url(
        self, 
        payload: str | dict, 
        /, 
        use_web_api: bool = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """添加一个离线任务

        POST https://lixian.115.com/lixianssp/?ac=add_task_url

        :payload:
            - url: str 💡 链接，支持HTTP、HTTPS、FTP、磁力链和电驴链接
            - savepath: str = <default> 💡 保存到目录下的相对路径
            - wp_path_id: int | str = <default> 💡 保存到目录的 id
        """
        if isinstance(payload, str):
            payload = {"url": payload}
        return self._offline_post(payload, "add_task_url", use_web_api=use_web_api, async_=async_, **request_kwargs)

    @overload
    def offline_add_urls(
        self, 
        payload: str | Iterable[str] | dict, 
        /, 
        use_web_api: bool = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_add_urls(
        self, 
        payload: str | Iterable[str] | dict, 
        /, 
        use_web_api: bool = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_add_urls(
        self, 
        payload: str | Iterable[str] | dict, 
        /, 
        use_web_api: bool = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """添加一组离线任务

        POST https://lixian.115.com/lixianssp/?ac=add_task_urls

        :payload:
            - url[0]: str 💡 链接，支持HTTP、HTTPS、FTP、磁力链和电驴链接
            - url[1]: str
            - ...
            - savepath: str = <default> 💡 保存到目录下的相对路径
            - wp_path_id: int | str = <default> 💡 保存到目录的 id
        """
        if isinstance(payload, str):
            payload = payload.strip().split("\n")
        if not isinstance(payload, dict):
            payload = {f"url[{i}]": url for i, url in enumerate(payload)}
            if not payload:
                raise ValueError("no `url` specified")
        return self._offline_post(payload, "add_task_urls", use_web_api=use_web_api, async_=async_, **request_kwargs)

    @overload
    def offline_clear(
        self, 
        payload: int | dict, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_clear(
        self, 
        payload: int | dict, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_clear(
        self, 
        payload: int | dict = {"flag": 0}, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """清空离线任务列表

        POST https://115.com/web/lixian/?ct=lixian&ac=task_clear

        :payload:
            - flag: int = 0 💡 标识，用于对应某种情况

              - 0: 已完成
              - 1: 全部
              - 2: 已失败
              - 3: 进行中
              - 4: 已完成+删除源文件
              - 5: 全部+删除源文件
        """
        api = complete_lixian_api("?ct=lixian&ac=task_clear", base_url=base_url)
        if isinstance(payload, int):
            flag = payload
            if flag < 0:
                flag = 0
            elif flag > 5:
                flag = 5
            payload = {"flag": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def offline_download_path(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_download_path(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_download_path(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取当前默认的离线下载到的目录信息（可能有多个）

        GET https://webapi.115.com/offine/downpath
        """
        api = complete_webapi("/offine/downpath", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def offline_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取关于离线的限制的信息，以及 sign 和 time 字段（各个添加任务的接口需要）

        GET https://115.com/?ct=offline&ac=space
        """
        api = complete_api("/?ct=offline&ac=space", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def offline_list(
        self, 
        payload: int | dict = 1, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_list(
        self, 
        payload: int | dict, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_list(
        self, 
        payload: int | dict = 1, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取当前的离线任务列表

        POST https://lixian.115.com/lixian/?ct=lixian&ac=task_lists

        :payload:
            - page: int | str
        """
        api = complete_lixian_api("?ct=lixian&ac=task_lists", base_url=base_url)
        if isinstance(payload, int):
            payload = {"page": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def offline_quota_info(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_quota_info(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_quota_info(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取当前离线配额信息（简略）

        GET https://lixian.115.com/lixian/?ct=lixian&ac=get_quota_info
        """
        api = complete_lixian_api("?ct=lixian&ac=get_quota_info", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def offline_quota_package_array(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_quota_package_array(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_quota_package_array(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取当前离线配额信息（详细）

        GET https://lixian.115.com/lixian/?ct=lixian&ac=get_quota_package_array
        """
        api = complete_lixian_api("?ct=lixian&ac=get_quota_package_array", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def offline_quota_package_info(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_quota_package_info(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_quota_package_info(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取当前离线配额信息（详细）

        GET https://lixian.115.com/lixian/?ct=lixian&ac=get_quota_package_info
        """
        api = complete_lixian_api("?ct=lixian&ac=get_quota_package_info", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def offline_remove(
        self, 
        payload: str | dict, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_remove(
        self, 
        payload: str | dict, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_remove(
        self, 
        payload: str | dict, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除一组离线任务（无论是否已经完成）

        POST https://lixian.115.com/lixianssp/?ac=task_del

        :payload:
            - hash[0]: str
            - hash[1]: str
            - ...
            - flag: 0 | 1 = <default> 💡 是否删除源文件
        """
        api = complete_lixian_api("?ct=lixian&ac=task_del", base_url=base_url)
        if isinstance(payload, str):
            payload = {"hash[0]": payload}
        elif not isinstance(payload, dict):
            payload = {f"hash[{i}]": hash for i, hash in enumerate(payload)}
            if not payload:
                raise ValueError("no `hash` (info_hash) specified")
        return self.request(api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def offline_task_count(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_task_count(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_task_count(
        self, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取当前正在运行的离线任务数

        GET https://lixian.115.com/lixian/?ct=lixian&ac=get_task_cnt&flag=0
        """
        api = complete_lixian_api("?ct=lixian&ac=get_task_cnt&flag=0", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def offline_torrent_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_torrent_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_torrent_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: None | bool | str | Callable[[], str] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """查看种子的文件列表等信息

        POST https://lixian.115.com/lixian/?ct=lixian&ac=torrent

        :payload:
            - sha1: str
        """
        api = complete_lixian_api("?ct=lixian&ac=torrent", base_url=base_url)
        if isinstance(payload, str):
            payload = {"sha1": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def offline_upload_torrent_path(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def offline_upload_torrent_path(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def offline_upload_torrent_path(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取当前的种子上传到的目录，当你添加种子任务后，这个种子会在此目录中保存

        GET https://115.com/?ct=lixian&ac=get_id&torrent=1
        """
        api = complete_api("/?ct=lixian&ac=get_id&torrent=1", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    ########## Recyclebin API ##########

    @overload # type: ignore
    def recyclebin_clean(
        self, 
        payload: int | str | Iterable[int | str] | dict = {}, 
        /, 
        password: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def recyclebin_clean(
        self, 
        payload: int | str | Iterable[int | str] | dict = {}, 
        /, 
        password: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def recyclebin_clean(
        self, 
        payload: int | str | Iterable[int | str] | dict = {}, 
        /, 
        password: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """回收站：删除或清空

        POST https://webapi.115.com/rb/clean

        :payload:
            - rid[0]: int | str 💡 如果没有指定任一 rid，就是清空回收站
            - rid[1]: int | str
            - ...
            - password: int | str = <default> 💡 密码，是 6 位数字
        """
        api = complete_webapi("/rb/clean", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"rid[0]": payload}
        elif not isinstance(payload, dict):
            payload = {f"rid[{i}]": rid for i, rid in enumerate(payload)}
        if password:
            payload.setdefault("password", password)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def recyclebin_clean_app(
        self, 
        payload: int | str | Iterable[int | str] | dict = {}, 
        /, 
        password: str = "", 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def recyclebin_clean_app(
        self, 
        payload: int | str | Iterable[int | str] | dict = {}, 
        /, 
        password: str = "", 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def recyclebin_clean_app(
        self, 
        payload: int | str | Iterable[int | str] | dict = {}, 
        /, 
        password: str = "", 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """回收站：删除或清空

        POST https://proapi.115.com/android/rb/secret_del

        :payload:
            - tid: int | str 💡 多个用逗号 "," 隔开
            - password: int | str = <default> 💡 密码，是 6 位数字
            - user_id: int = <default> 💡 不用管
        """
        api = complete_proapi("/rb/secret_del", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"tid": payload, "user_id": self.user_id}
        elif isinstance(payload, dict):
            payload = dict(payload, user_id=self.user_id)
        else:
            payload = {"tid": ",".join(map(str, payload)), "user_id": self.user_id}
        if password:
            payload.setdefault("password", password)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def recyclebin_info(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def recyclebin_info(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def recyclebin_info(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """回收站：文件信息

        POST https://webapi.115.com/rb/rb_info

        :payload:
            - rid: int | str
        """
        api = complete_webapi("/rb/rb_info", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"rid": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def recyclebin_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def recyclebin_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def recyclebin_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """回收站：列表

        GET https://webapi.115.com/rb

        :payload:
            - aid: int | str = 7
            - cid: int | str = 0
            - limit: int = 32
            - offset: int = 0
            - format: str = "json"
            - source: str = <default>
        """ 
        api = complete_webapi("/rb", base_url=base_url)
        if isinstance(payload, int):
            payload = {"aid": 7, "cid": 0, "limit": 32, "format": "json", "offset": payload}
        else:
            payload = {"aid": 7, "cid": 0, "limit": 32, "format": "json", "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def recyclebin_list_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def recyclebin_list_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def recyclebin_list_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """回收站：列表

        GET https://proapi.115.com/android/rb

        :payload:
            - aid: int | str = 7
            - cid: int | str = 0
            - limit: int = 32
            - offset: int = 0
            - format: str = "json"
            - source: str = <default>
        """ 
        api = complete_proapi("/rb", base_url, app)
        if isinstance(payload, int):
            payload = {"aid": 7, "cid": 0, "limit": 32, "format": "json", "offset": payload}
        else:
            payload = {"aid": 7, "cid": 0, "limit": 32, "format": "json", "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def recyclebin_revert(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def recyclebin_revert(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def recyclebin_revert(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """回收站：还原

        POST https://webapi.115.com/rb/revert

        :payload:
            - rid[0]: int | str
            - rid[1]: int | str
            - ...
        """
        api = complete_webapi("/rb/revert", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"rid[0]": payload}
        elif not isinstance(payload, dict):
            payload = {f"rid[{i}]": rid for i, rid in enumerate(payload)}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def recyclebin_revert_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def recyclebin_revert_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def recyclebin_revert_app(
        self, 
        payload: int | str | Iterable[int | str] | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """回收站：还原

        POST https://proapi.115.com/android/rb/revert

        :payload:
            - tid: int | str 💡 多个用逗号 "," 隔开
            - user_id: int = <default> 💡 不用管
        """
        api = complete_proapi("/rb/revert", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"tid": payload}
        elif not isinstance(payload, dict):
            payload = {"tid": ",".join(map(str, payload))}
        payload.setdefault("user_id", self.user_id)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    ########## Share API ##########

    @overload
    def share_access_user_list(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_access_user_list(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_access_user_list(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """访问账号列表

        GET https://webapi.115.com/share/access_user_list

        :payload:
            - share_code: str
        """
        api = complete_webapi("/share/access_user_list", base_url=base_url)
        if isinstance(payload, str):
            payload = {"share_code": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_downlist(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_downlist(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_downlist(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取分享链接的某个目录中可下载的文件的列表（只含文件，不含目录，任意深度，简略信息）

        .. attention::
            cid 不能为 0

        GET https://webapi.115.com/share/downlist

        :payload:
            - share_code: str
            - receive_code: str
            - cid: int | str
        """
        api = complete_webapi("/share/downlist", base_url=base_url)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_downlist_app(
        self, 
        payload: dict, 
        /, 
        app: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_downlist_app(
        self, 
        payload: dict, 
        /, 
        app: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_downlist_app(
        self, 
        payload: dict, 
        /, 
        app: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取分享链接的某个目录中可下载的文件的列表（只含文件，不含目录，任意深度，简略信息）

        .. attention::
            cid 不能为 0

        GET https://proapi.115.com/app/share/downlist

        :payload:
            - share_code: str
            - receive_code: str
            - cid: int | str
        """
        if app:
            api = complete_proapi("/2.0/share/downlist", base_url, app)
        else:
            api = complete_proapi("/app/share/downlist", base_url)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_download_url(
        self, 
        payload: int | str | dict, 
        /, 
        url: str = "", 
        strict: bool = True, 
        use_web_api: bool = False, 
        app: str = "", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> P115URL:
        ...
    @overload
    def share_download_url(
        self, 
        payload: int | str | dict, 
        /, 
        url: str = "", 
        strict: bool = True, 
        use_web_api: bool = False, 
        app: str = "", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, P115URL]:
        ...
    def share_download_url(
        self, 
        payload: int | str | dict, 
        /, 
        url: str = "", 
        strict: bool = True, 
        use_web_api: bool = False, 
        app: str = "", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> P115URL | Coroutine[Any, Any, P115URL]:
        """获取分享链接中某个文件的下载链接

        :param payload: 请求参数，如果为 int 或 str，则视为 `file_id`

            - file_id: int | str 💡 文件 id
            - receive_code: str  💡 接收码（也就是密码）
            - share_code: str    💡 分享码

        :param url: 分享链接，如果提供的话，会被拆解并合并到 `payload` 中，优先级较高
        :param strict: 如果为 True，当目标是目录时，会抛出 IsADirectoryError 异常
        :param use_web_api: 是否使用网页版接口执行请求（优先级高于 `app`）
        :param app: 使用此设备的接口
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 下载链接
        """
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload}
        else:
            payload = dict(payload)
        if url:
            from .tool import share_extract_payload
            share_payload = share_extract_payload(url)
            payload["share_code"] = share_payload["share_code"]
            payload["receive_code"] = share_payload["receive_code"] or ""
        if use_web_api:
            resp = self.share_download_url_web(payload, async_=async_, **request_kwargs)
        else:
            resp = self.share_download_url_app(payload, app=app, async_=async_, **request_kwargs)
        def get_url(resp: dict, /) -> P115URL:
            info = check_response(resp)["data"]
            file_id = payload["file_id"]
            if not info:
                raise FileNotFoundError(
                    ENOENT, 
                    f"no such id: {file_id!r}, with response {resp}", 
                )
            url = info["url"]
            if strict and not url:
                raise IsADirectoryError(
                    EISDIR, 
                    f"{file_id} is a directory, with response {resp}", 
                )
            return P115URL(
                url["url"] if url else "", 
                id=int(info["fid"]), 
                name=info["fn"], 
                size=int(info["fs"]), 
                sha1=info.get("sha1", ""), 
                is_directory=not url, 
            )
        if async_:
            async def async_request() -> P115URL:
                return get_url(await cast(Coroutine[Any, Any, dict], resp)) 
            return async_request()
        else:
            return get_url(cast(dict, resp))

    @overload
    def share_download_url_app(
        self, 
        payload: dict, 
        /, 
        app: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_download_url_app(
        self, 
        payload: dict, 
        /, 
        app: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_download_url_app(
        self, 
        payload: dict, 
        /, 
        app: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取分享链接中某个文件的下载链接

        POST https://proapi.115.com/app/share/downurl

        :payload:
            - file_id: int | str
            - receive_code: str
            - share_code: str
        """
        if app:
            api = complete_proapi("/2.0/share/downurl", base_url, app)
            return self.request(url=api, params=payload, async_=async_, **request_kwargs)
        else:
            api = complete_proapi("/app/share/downurl", base_url)
            def parse(resp, content: bytes, /) -> dict:
                resp = json_loads(content)
                if resp["state"]:
                    resp["data"] = json_loads(rsa_decode(resp["data"]))
                return resp
            request_kwargs.setdefault("parse", parse)
            payload = {"data": rsa_encode(dumps(payload)).decode()}
            return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def share_download_url_web(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_download_url_web(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_download_url_web(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取分享链接中某个文件的下载链接（网页版接口，不推荐使用）

        GET https://webapi.115.com/share/downurl

        :payload:
            - file_id: int | str
            - receive_code: str
            - share_code: str
        """
        api = complete_webapi("/share/downurl", base_url=base_url)
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_info(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取（自己的）分享信息

        GET https://webapi.115.com/share/shareinfo

        :payload:
            - share_code: str
        """
        api = complete_webapi("/share/shareinfo", base_url=base_url)
        if isinstance(payload, str):
            payload = {"share_code": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_info_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_info_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_info_app(
        self, 
        payload: str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取（自己的）分享信息

        GET https://proapi.115.com/android/2.0/share/shareinfo

        :payload:
            - share_code: str
        """
        api = complete_proapi("/2.0/share/shareinfo", base_url, app)
        if isinstance(payload, str):
            payload = {"share_code": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列（自己的）分享信息列表

        GET https://webapi.115.com/share/slist

        :payload:
            - limit: int = 32
            - offset: int = 0
        """
        api = complete_webapi("/share/slist", base_url=base_url)
        if isinstance(payload, int):
            payload = {"limit": 32, "offset": payload}
        else:
            payload = {"limit": 32, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_list_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_list_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_list_app(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """罗列（自己的）分享信息列表

        GET https://proapi.115.com/android/2.0/share/slist

        :payload:
            - limit: int = 32
            - offset: int = 0
        """
        api = complete_proapi("/2.0/share/slist", base_url, app)
        if isinstance(payload, int):
            payload = {"limit": 32, "offset": payload}
        else:
            payload = {"limit": 32, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_receive(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_receive(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_receive(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """接收分享链接的某些文件或目录

        POST https://webapi.115.com/share/receive

        :payload:
            - share_code: str
            - receive_code: str
            - file_id: int | str         💡 有多个时，用逗号 "," 分隔
            - cid: int | str = <default> 💡 这是你网盘的目录 cid
            - is_check: 0 | 1 = <default>
        """
        api = complete_webapi("/share/receive", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def share_receive_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_receive_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_receive_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """接收分享链接的某些文件或目录

        POST https://proapi.115.com/android/2.0/share/receive

        :payload:
            - share_code: str
            - receive_code: str
            - file_id: int | str         💡 有多个时，用逗号 "," 分隔
            - cid: int | str = <default> 💡 这是你网盘的目录 cid
            - is_check: 0 | 1 = <default>
        """
        api = complete_proapi("/2.0/share/receive", base_url, app)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def share_send(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_send(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_send(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """创建（自己的）分享

        POST https://webapi.115.com/share/send

        :payload:
            - file_ids: int | str 💡 文件列表，有多个用逗号 "," 隔开
            - is_asc: 0 | 1 = 1 💡 是否升序排列
            - order: str = "file_name" 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_utime": 修改时间
              - "user_ptime": 创建时间
              - "user_otime": 上一次打开时间

            - ignore_warn: 0 | 1 = 1 💡 忽略信息提示，传 1 就行了
        """
        api = complete_webapi("/share/send", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"ignore_warn": 1, "is_asc": 1, "order": "file_name", "file_ids": payload}
        else:
            payload = {"ignore_warn": 1, "is_asc": 1, "order": "file_name", **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def share_send_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_send_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_send_app(
        self, 
        payload: int | str | dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """创建（自己的）分享

        POST https://proapi.115.com/android/2.0/share/send

        :payload:
            - file_ids: int | str 💡 文件列表，有多个用逗号 "," 隔开
            - is_asc: 0 | 1 = 1 💡 是否升序排列
            - order: str = "file_name" 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "file_type": 文件种类
              - "user_utime": 修改时间
              - "user_ptime": 创建时间
              - "user_otime": 上一次打开时间

            - ignore_warn: 0 | 1 = 1 💡 忽略信息提示，传 1 就行了
        """
        api = complete_proapi("/2.0/share/send", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"ignore_warn": 1, "is_asc": 1, "order": "file_name", "file_ids": payload}
        else:
            payload = {"ignore_warn": 1, "is_asc": 1, "order": "file_name", **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def share_search(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_search(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_search(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """从分享链接搜索文件或目录

        GET https://webapi.115.com/share/search

        .. attention::
            最多只能取回前 10,000 条数据，也就是 limit + offset <= 10_000

        :payload:
            - share_code: str    💡 分享码
            - receive_code: str  💡 接收码（即密码）
            - cid: int | str = 0 💡 目录 id
            - limit: int = 32    💡 一页大小，意思就是 page_size
            - offset: int = 0   💡 索引偏移，索引从 0 开始计算
            - search_value: str = "." 💡 搜索文本，仅支持搜索文件名
            - suffix: str = <default> 💡 文件后缀（扩展名），优先级高于 `type`
            - type: int = <default>   💡 文件类型

              - 0: 全部
              - 1: 文档
              - 2: 图片
              - 3: 音频
              - 4: 视频
              - 5: 压缩包
              - 6: 软件/应用
              - 7: 书籍
              - 99: 仅文件
        """
        api = complete_webapi("/share/search", base_url=base_url)
        payload = {"cid": 0, "limit": 32, "offset": 0, "search_value": ".", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_skip_login_check(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_skip_login_check(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_skip_login_check(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """检查是否可免登录下载

        POST https://webapi.115.com/share/is_skip_login

        :payload:
            - share_code: str        💡 分享码
            - receive_code: str      💡 接收码（访问密码）
            - file_id: int | str = 1 💡 文件 id（可以随便填一个非 0 的值）
        """
        api = complete_webapi("/share/is_skip_login", base_url=base_url)
        payload.setdefault("file_id", 1)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def share_skip_login_down(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_skip_login_down(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_skip_login_down(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """开启或关闭免登录下载

        POST https://webapi.115.com/share/skip_login_down

        :payload:
            - share_code: str       💡 分享码
            - skip_login: 0 | 1 = 1 💡 是否开启
        """
        api = complete_webapi("/share/skip_login_down", base_url=base_url)
        if isinstance(payload, str):
            payload = {"skip_login": 1, "share_code": payload}
        else:
            payload = {"skip_login": 1, **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def share_skip_login_download_url(
        self: int | str | dict | P115Client, 
        payload: None | int | str | dict = None, 
        /, 
        url: str = "", 
        strict: bool = True, 
        use_web_api: bool = False, 
        app: str = "", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> P115URL:
        ...
    @overload
    def share_skip_login_download_url(
        self: int | str | dict | P115Client, 
        payload: None | int | str | dict = None, 
        /, 
        url: str = "", 
        strict: bool = True, 
        use_web_api: bool = False, 
        app: str = "", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, P115URL]:
        ...
    def share_skip_login_download_url(
        self: int | str | dict | P115Client, 
        payload: None | int | str | dict = None, 
        /, 
        url: str = "", 
        strict: bool = True, 
        use_web_api: bool = False, 
        app: str = "", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> P115URL | Coroutine[Any, Any, P115URL]:
        """获取分享链接中某个文件的下载链接

        .. important::
            这个函数可以作为 staticmethod 使用，只要 `self` 不是 P115Client 类型，此时不需要登录

        :param payload: 请求参数，如果为 int 或 str，则视为 `file_id`

            - file_id: int | str 💡 文件 id
            - receive_code: str  💡 接收码（访问密码）
            - share_code: str    💡 分享码

        :param url: 分享链接，如果提供的话，会被拆解并合并到 `payload` 中，优先级较高
        :param strict: 如果为 True，当目标是目录时，会抛出 IsADirectoryError 异常
        :param use_web_api: 是否使用网页版接口执行请求（优先级高于 `app`）
        :param app: 使用此设备的接口
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 下载链接
        """
        if isinstance(self, P115Client):
            assert payload is not None
            inst: P115Client | type[P115Client] = self
        else:
            payload = self
            inst = __class__ # type: ignore
        if isinstance(payload, (int, str)):
            payload = {"file_id": payload}
        else:
            payload = dict(payload)
        if url:
            from .tool import share_extract_payload
            share_payload = share_extract_payload(url)
            payload["share_code"] = share_payload["share_code"]
            payload["receive_code"] = share_payload["receive_code"] or ""
        if use_web_api:
            resp = inst.share_skip_login_download_url_web(payload, async_=async_, **request_kwargs)
        else:
            resp = inst.share_skip_login_download_url_app(payload, app=app, async_=async_, **request_kwargs)
        def get_url(resp: dict, /) -> P115URL:
            info = check_response(resp)["data"]
            file_id = payload["file_id"]
            if not info:
                raise FileNotFoundError(
                    ENOENT, 
                    f"no such id: {file_id!r}, with response {resp}", 
                )
            url = info["url"]
            if strict and not url:
                raise IsADirectoryError(
                    EISDIR, 
                    f"{file_id} is a directory, with response {resp}", 
                )
            return P115URL(
                url["url"] if url else "", 
                id=int(info["fid"]), 
                name=info["fn"], 
                size=int(info["fs"]), 
                sha1=info.get("sha1", ""), 
                is_directory=not url, 
            )
        if async_:
            async def async_request() -> P115URL:
                return get_url(await cast(Coroutine[Any, Any, dict], resp)) 
            return async_request()
        else:
            return get_url(cast(dict, resp))

    @overload
    def share_skip_login_download_url_app(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        app: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_skip_login_download_url_app(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        app: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_skip_login_download_url_app(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        app: str = "", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取免登录下载链接

        POST https://proapi.115.com/app/share/skip_login_downurl

        .. important::
            这个函数可以作为 staticmethod 使用，只要 `self` 不是 P115Client 类型，此时不需要登录

        :payload:
            - file_id: int | str
            - receive_code: str
            - share_code: str
        """
        if isinstance(self, dict):
            payload = self
        else:
            assert payload is not None
        if app:
            api = complete_proapi("/2.0/share/skip_login_downurl", base_url, app)
        else:
            api = complete_proapi("/app/share/skip_login_downurl", base_url)
            def parse(resp, content: bytes, /) -> dict:
                resp = json_loads(content)
                if resp["state"]:
                    resp["data"] = json_loads(rsa_decode(resp["data"]))
                return resp
            request_kwargs.setdefault("parse", parse)
            payload = {"data": rsa_encode(dumps(payload)).decode()}
        if isinstance(self, P115Client):
            return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)
        else:
            request_kwargs.setdefault("parse", default_parse)
            request = request_kwargs.pop("request", None)
            if request is None:
                return get_default_request()(url=api, method="POST", data=payload, async_=async_, **request_kwargs)
            else:
                return request(url=api, method="POST", data=payload, **request_kwargs)

    @overload
    def share_skip_login_download_url_web(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_skip_login_download_url_web(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_skip_login_download_url_web(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取免登录下载链接

        POST https://webapi.115.com/share/skip_login_downurl

        .. important::
            这个函数可以作为 staticmethod 使用，只要 `self` 不是 P115Client 类型，此时不需要登录

        :payload:
            - share_code: str    💡 分享码
            - receive_code: str  💡 接收码（访问密码）
            - file_id: int | str 💡 文件 id
        """
        api = complete_webapi("/share/skip_login_downurl", base_url=base_url)
        if isinstance(self, dict):
            payload = self
        else:
            assert payload is not None
        if isinstance(self, P115Client):
            return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)
        else:
            request_kwargs.setdefault("parse", default_parse)
            request = request_kwargs.pop("request", None)
            if request is None:
                return get_default_request()(url=api, method="POST", data=payload, async_=async_, **request_kwargs)
            else:
                return request(url=api, method="POST", data=payload, **request_kwargs)

    @overload
    def share_skip_login_down_first(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_skip_login_down_first(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_skip_login_down_first(
        self, 
        payload: str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """免登录下载信息

        GET https://webapi.115.com/share/skip_login_down_first

        :payload:
            - share_code: str 💡 分享码
        """
        api = complete_webapi("/share/skip_login_down_first", base_url=base_url)
        if isinstance(payload, str):
            payload = {"share_code": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_skip_login_down_details(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_skip_login_down_details(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_skip_login_down_details(
        self, 
        payload: str | dict = "", 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """流量消耗明细

        GET https://webapi.115.com/share/skip_login_down_details

        :payload:
            - start_time: str = <default> 💡 开始时间，格式为 "YYYY-MM-DD hh:mm:ss"，默认为今天零点
            - end_time: str = <default>   💡 结束时间（含），默认为明天零点
            - share_code: str = ""        💡 分享码，如果为空则统计所有分享
            - offset: int = 0
            - limit: int = 32
        """
        api = complete_webapi("/share/skip_login_down_details", base_url=base_url)
        today = date.today()
        default_start_time = f"{today} 00:00:00"
        default_end_time = f"{today + timedelta(days=1)} 00:00:00"
        if isinstance(payload, str):
            payload = {"share_code": "", "limit": 32, "offset": 0, "start_time": payload or default_start_time, "end_time": default_end_time}
        else:
            payload = {"share_code": "", "limit": 32, "offset": 0, "start_time": default_start_time, "end_time": default_end_time, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def share_snap(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_snap(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_snap(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取分享链接的某个目录中的文件和子目录的列表（包含详细信息）

        GET https://webapi.115.com/share/snap

        .. important::
            这个函数可以作为 staticmethod 使用，只要 `self` 不是 P115Client 类型，此时不需要登录

            否则，就是登录状态，但如果这个分享是你自己的，则可以不提供 receive_code，而且即使还在审核中，也能获取文件列表

        :payload:
            - share_code: str
            - receive_code: str
            - cid: int | str = 0
            - limit: int = 32
            - offset: int = 0
            - asc: 0 | 1 = <default> 💡 是否升序排列
            - o: str = <default> 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "user_ptime": 创建时间/修改时间
        """
        api = complete_webapi("/share/snap", base_url=base_url)
        if isinstance(self, dict):
            payload = self
        else:
            assert payload is not None
        payload = {"cid": 0, "limit": 32, "offset": 0, **payload}
        if isinstance(self, P115Client):
            return self.request(url=api, params=payload, async_=async_, **request_kwargs)
        else:
            request_kwargs.setdefault("parse", default_parse)
            request = request_kwargs.pop("request", None)
            if request is None:
                return get_default_request()(url=api, params=payload, async_=async_, **request_kwargs)
            else:
                return request(url=api, params=payload, **request_kwargs)

    @overload
    def share_snap_app(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        request: None | Callable = None, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_snap_app(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        request: None | Callable = None, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_snap_app(
        self: dict | P115Client, 
        payload: None | dict = None, 
        /, 
        request: None | Callable = None, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取分享链接的某个目录中的文件和子目录的列表（包含详细信息）

        GET https://proapi.115.com/android/2.0/share/snap

        .. important::
            这个函数可以作为 staticmethod 使用，只要 `self` 不是 P115Client 类型，此时不需要登录

            否则，就是登录状态，但如果这个分享是你自己的，则可以不提供 receive_code，而且即使还在审核中，也能获取文件列表

        :payload:
            - share_code: str
            - receive_code: str
            - cid: int | str = 0
            - limit: int = 32
            - offset: int = 0
            - asc: 0 | 1 = <default> 💡 是否升序排列
            - o: str = <default> 💡 用某字段排序

              - "file_name": 文件名
              - "file_size": 文件大小
              - "user_ptime": 创建时间/修改时间
        """
        api = complete_proapi("/2.0/share/snap", base_url, app)
        if isinstance(self, dict):
            payload = self
        else:
            assert payload is not None
        payload = {"cid": 0, "limit": 32, "offset": 0, **payload}
        if isinstance(self, P115Client):
            return self.request(url=api, params=payload, async_=async_, **request_kwargs)
        else:
            request_kwargs.setdefault("parse", default_parse)
            request = request_kwargs.pop("request", None)
            if request is None:
                return get_default_request()(url=api, params=payload, async_=async_, **request_kwargs)
            else:
                return request(url=api, params=payload, **request_kwargs)

    @overload
    def share_update(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_update(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_update(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """变更（自己的）分享的配置（例如改访问密码，取消分享）

        POST https://webapi.115.com/share/updateshare

        :payload:
            - share_code: str
            - receive_code: str = <default>         💡 接收码（访问密码）
            - share_duration: int = <default>       💡 分享天数: n（填入指定天数），-1(长期)
            - is_custom_code: 0 | 1 = <default>     💡 用户自定义口令（不用管）
            - auto_fill_recvcode: 0 | 1 = <default> 💡 分享链接自动填充口令（不用管）
            - share_channel: int = <default>        💡 分享渠道代码（不用管）
            - action: str = <default>               💡 操作: 取消分享 "cancel"
            - skip_login_down_flow_limit: "" | int  = <default> 💡 设置免登录下载限制流量，如果为 "" 则不限，单位: 字节
            - access_user_ids = int | str = <default> 💡 设置访问账号，多个用逗号 "," 隔开
            - receive_user_limit: int = <default> 💡 接收次数
            - reset_receive_user: 0 | 1 = <default> 💡 重置接收次数
        """
        api = complete_webapi("/share/updateshare", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def share_update_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def share_update_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def share_update_app(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """变更（自己的）分享的配置（例如改访问密码，取消分享）

        POST https://proapi.115.com/android/2.0/share/updateshare

        :payload:
            - share_code: str
            - receive_code: str = <default>         💡 接收码（访问密码）
            - share_duration: int = <default>       💡 分享天数: n（填入指定天数），-1(长期)
            - is_custom_code: 0 | 1 = <default>     💡 用户自定义口令（不用管）
            - auto_fill_recvcode: 0 | 1 = <default> 💡 分享链接自动填充口令（不用管）
            - share_channel: int = <default>        💡 分享渠道代码（不用管）
            - action: str = <default>               💡 操作: 取消分享 "cancel"
            - skip_login_down_flow_limit: "" | int  = <default> 💡 设置免登录下载限制流量，如果为 "" 则不限，单位: 字节
            - access_user_ids = int | str = <default> 💡 设置访问账号，多个用逗号 "," 隔开
            - receive_user_limit: int = <default> 💡 接收次数
            - reset_receive_user: 0 | 1 = <default> 💡 重置接收次数
        """
        api = complete_proapi("/2.0/share/updateshare", base_url, app)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    ########## Tool API ##########

    @overload
    def tool_clear_empty_folder(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def tool_clear_empty_folder(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def tool_clear_empty_folder(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除空目录

        GET https://115.com/?ct=tool&ac=clear_empty_folder
        """
        api = complete_api("/?ct=tool&ac=clear_empty_folder", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def tool_repeat(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def tool_repeat(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def tool_repeat(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """开始一键排重任务

        POST https://aps.115.com/repeat/repeat.php

        :payload:
            - folder_id: int | str 💡 目录 id
        """
        api = complete_api("/repeat/repeat.php", "aps", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"folder_id": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def tool_repeat_delete(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def tool_repeat_delete(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def tool_repeat_delete(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除重复文件

        POST https://aps.115.com/repeat/repeat_delete.php

        :payload:
            - filter_field: "parents" | "file_name" | "" | "" = <default> 💡 保留条件（1. 用于批量删除）

              - "file_name": 文件名（按长度）
              - "parents": 所在目录路径（按长度）
              - "user_utime": 操作时间
              - "user_ptime": 创建时间

            - filter_order: "asc" | "desc" = <default> 💡 排序（2. 用于批量删除）

              - "asc": 升序，从小到大，取最小
              - "desc": 降序，从大到小，取最大

            - batch: 0 | 1 = <default> 💡 是否批量操作（3. 用于批量删除）
            - sha1s[{sha1}]: int | str = <default> 💡 文件 id，多个用逗号 "," 隔开（1. 用于手动指定删除对象）
        """
        api = complete_api("/repeat/repeat_delete.php", "aps", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def tool_repeat_delete_status(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def tool_repeat_delete_status(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def tool_repeat_delete_status(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """删除重复文件进度和统计信息（status 为 False 表示进行中，为 True 表示完成）

        GET https://aps.115.com/repeat/delete_status.php
        """
        api = complete_api("/repeat/delete_status.php", "aps", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def tool_repeat_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def tool_repeat_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def tool_repeat_list(
        self, 
        payload: int | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取重复文件列表

        GET https://aps.115.com/repeat/repeat_list.php

        :payload:
            - s: int = 0 💡 offset，从 0 开始
            - l: int = 100 💡 limit
        """
        api = complete_api("/repeat/repeat_list.php", "aps", base_url=base_url)
        if isinstance(payload, int):
            payload = {"l": 100, "s": payload}
        else:
            payload = {"s": 0, "l": 100, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def tool_repeat_status(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def tool_repeat_status(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def tool_repeat_status(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """查询一键排重任务进度和统计信息（status 为 False 表示进行中，为 True 表示完成）

        GET https://aps.115.com/repeat/repeat_status.php
        """
        api = complete_api("/repeat/repeat_status.php", "aps", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def tool_space(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def tool_space(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def tool_space(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """检验空间

        GET https://115.com/?ct=tool&ac=space

        .. hint::
            1. 校验空间需全局进行扫描，请谨慎操作;
            2. 扫描出无父目录的文件将统一放入到"/修复文件"的目录中;
            3. "/修复文件"的目录若超过存放文件数量限制，将创建多个目录存放，避免无法操作。
            4. 此接口一天只能使用一次
        """
        api = complete_api("/?ct=tool&ac=space", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    ########## Upload API ##########

    @overload
    def upload_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取和上传有关的各种服务信息

        GET https://proapi.115.com/app/uploadinfo
        """
        api = complete_proapi("/app/uploadinfo", base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload # type: ignore
    def upload_init(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_init(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_init(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """秒传接口，参数的构造较为复杂，所以请不要直接使用

        POST https://uplb.115.com/4.0/initupload.php
        """
        api = complete_api("/4.0/initupload.php", "uplb", base_url=base_url)
        return self.request(url=api, method="POST", async_=async_, **request_kwargs)

    @overload
    def upload_key(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_key(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_key(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取 user_key

        GET https://proapi.115.com/android/2.0/user/upload_key
        """
        api = complete_proapi("/2.0/user/upload_key", base_url, app)
        def gen_step():
            resp = yield self.request(url=api, async_=async_, **request_kwargs)
            if resp["state"]:
                self.user_key = resp["data"]["userkey"]
            return resp
        return run_gen_step(gen_step, async_=async_)

    @overload
    def upload_resume(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_resume(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_resume(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取恢复断点续传所需信息

        POST https://uplb.115.com/3.0/resumeupload.php

        :payload:
            - fileid: str   💡 文件的 sha1 值
            - filesize: int 💡 文件大小，单位是字节
            - target: str   💡 上传目标，默认为 "U_1_0"，格式为 f"U_{aid}_{pid}"
            - pickcode: str 💡 提取码
            - userid: int = <default> 💡 不用管
        """
        api = complete_api("/3.0/resumeupload.php", "uplb", base_url=base_url)
        payload = dict(payload, userid=self.user_id)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def upload_sample_init(
        self, 
        /, 
        filename: str, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_sample_init(
        self, 
        /, 
        filename: str, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_sample_init(
        self, 
        /, 
        filename: str, 
        pid: int = 0, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """网页端的上传接口的初始化，注意：不支持秒传

        POST https://uplb.115.com/3.0/sampleinitupload.php
        """
        api = complete_api("/3.0/sampleinitupload.php", "uplb", base_url=base_url)
        payload = {"filename": filename, "target": f"U_1_{pid}"}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload # type: ignore
    @staticmethod
    def upload_gettoken(
        request: None | Callable = None, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @staticmethod
    def upload_gettoken(
        request: None | Callable = None, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def upload_gettoken(
        request: None | Callable = None, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取阿里云 OSS 的 token（上传凭证）

        GET https://uplb.115.com/3.0/gettoken.php
        """
        api = complete_api("/3.0/gettoken.php", "uplb", base_url=base_url)
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, async_=async_, **request_kwargs)
        else:
            return request(url=api, **request_kwargs)

    @property
    def upload_token(self, /) -> dict:
        token = self.__dict__.get("upload_token", {})
        if not token or token["Expiration"] < (datetime.now() - timedelta(hours=7, minutes=30)).strftime("%FT%XZ"):
            while True:
                if token.get("StatusCode") == "200":
                    break
                token = self.__dict__["upload_token"] = self.upload_gettoken()
        return token

    @overload
    @staticmethod
    def upload_url(
        request: None | Callable = None, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @staticmethod
    def upload_url(
        request: None | Callable = None, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def upload_url(
        request: None | Callable = None, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取用于上传的一些 http 接口，此接口具有一定幂等性，请求一次，然后把响应记下来即可

        GET https://uplb.115.com/3.0/getuploadinfo.php

        :response:

            - endpoint: 此接口用于上传文件到阿里云 OSS 
            - gettokenurl: 上传前需要用此接口获取 token
        """
        api = complete_api("/3.0/getuploadinfo.php", "uplb", base_url=base_url)
        request_kwargs.setdefault("parse", default_parse)
        if request is None:
            return get_default_request()(url=api, async_=async_, **request_kwargs)
        else:
            return request(url=api, **request_kwargs)

    # NOTE: 下列是关于上传功能的封装方法

    @overload
    def _upload_file_init(
        self, 
        /, 
        filename: str, 
        filesize: int, 
        filesha1: str, 
        target: str = "U_1_0", 
        sign_key: str = "", 
        sign_val: str = "", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def _upload_file_init(
        self, 
        /, 
        filename: str, 
        filesize: int, 
        filesha1: str, 
        target: str = "U_1_0", 
        sign_key: str = "", 
        sign_val: str = "", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def _upload_file_init(
        self, 
        /, 
        filename: str, 
        filesize: int, 
        filesha1: str, 
        target: str = "U_1_0", 
        sign_key: str = "", 
        sign_val: str = "", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """秒传接口，此接口是对 `upload_init` 的封装

        :param filename: 文件名
        :param filesize: 文件大小
        :param filesha1: 文件的 sha1
        :param target: 保存到目录，格式为 f"U_{area_id}_{parent_id}"
        :param sign_key: 二次验证时读取文件的范围
        :param sign_val: 二次验证的签名值
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 接口响应
        """
        data = {
            "appid": 0, 
            "appversion": "99.99.99.99", 
            "fileid": filesha1, 
            "filename": filename, 
            "filesize": filesize, 
            "sign_key": sign_key, 
            "sign_val": sign_val, 
            "target": target, 
            "topupload": 1, 
            "userid": self.user_id, 
            "userkey": self.user_key, 
        }
        request_kwargs.update(make_upload_payload(data))
        request_kwargs["headers"] = {
            **(request_kwargs.get("headers") or {}), 
            "Content-Type": "application/x-www-form-urlencoded", 
            "user-agent": "Mozilla/5.0 115disk/99.99.99.99 115Browser/99.99.99.99 115wangpan_android/99.99.99.99", 
        }
        request_kwargs.setdefault("parse", parse_upload_init_response)
        return self.upload_init(async_=async_, **request_kwargs)

    @overload # type: ignore
    def upload_file_init(
        self, 
        /, 
        filename: str, 
        filesize: int, 
        filesha1: str, 
        read_range_bytes_or_hash: None | Callable[[str], str | Buffer] = None, 
        pid: int = 0, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_file_init(
        self, 
        /, 
        filename: str, 
        filesize: int, 
        filesha1: str, 
        read_range_bytes_or_hash: None | Callable[[str], str | Buffer] = None, 
        pid: int = 0, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_file_init(
        self, 
        /, 
        filename: str, 
        filesize: int, 
        filesha1: str, 
        read_range_bytes_or_hash: None | Callable[[str], str | Buffer] = None, 
        pid: int = 0, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """秒传接口，此接口是对 `upload_init` 的封装。

        .. note::

            - 文件大小 和 sha1 是必需的，只有 sha1 是没用的。
            - 如果文件大于等于 1 MB (1048576 B)，就需要 2 次检验一个范围哈希，就必须提供 `read_range_bytes_or_hash`

        :param filename: 文件名
        :param filesize: 文件大小
        :param filesha1: 文件的 sha1
        :param read_range_bytes_or_hash: 调用以获取二次验证的数据或计算 sha1，接受一个数据范围，格式符合 `HTTP Range Requests <https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests>`_，返回值如果是 str，则视为计算好的 sha1，如果为 Buffer，则视为数据（之后会被计算 sha1）
        :param pid: 上传文件到此目录的 id
        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 接口响应
        """
        filesha1 = filesha1.upper()
        target = f"U_1_{pid}"
        def gen_step():
            resp = yield self._upload_file_init(
                filename, 
                filesize, 
                filesha1, 
                target, 
                async_=async_, 
                **request_kwargs, 
            )
            # NOTE: 当文件大于等于 1 MB (1048576 B)，需要 2 次检验 1 个范围哈希，它会给出此文件的 1 个范围区间
            #       ，你读取对应的数据计算 sha1 后上传，以供 2 次检验
            if resp["status"] == 7 and resp["statuscode"] == 701:
                if read_range_bytes_or_hash is None:
                    raise ValueError("filesize >= 1 MB, thus need pass the `read_range_bytes_or_hash` argument")
                sign_key: str = resp["sign_key"]
                sign_check: str = resp["sign_check"]
                data: str | Buffer
                if async_:
                    data = yield ensure_async(read_range_bytes_or_hash)(sign_check)
                else:
                    data = read_range_bytes_or_hash(sign_check)
                if isinstance(data, str):
                    sign_val = data.upper()
                else:
                    sign_val = sha1(data).hexdigest().upper()
                resp = yield self._upload_file_init(
                    filename, 
                    filesize, 
                    filesha1, 
                    target, 
                    sign_key=sign_key, 
                    sign_val=sign_val, 
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
            resp["state"] = True
            resp["data"] = {
                "target": target, 
                "file_name": filename, 
                "file_size": filesize, 
                "sha1": filesha1, 
                "cid": pid, 
                "pickcode": resp["pickcode"], 
            }
            return resp
        return run_gen_step(gen_step, async_=async_)

    @overload
    def upload_file_sample(
        self, 
        /, 
        file: Buffer | SupportsRead[Buffer] | Iterable[Buffer], 
        filename: str, 
        filesize: int = -1, 
        pid: int = 0, 
        make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any]] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_file_sample(
        self, 
        /, 
        file: Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer],  
        filename: str, 
        filesize: int = -1, 
        pid: int = 0, 
        make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any]] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_file_sample(
        self, 
        /, 
        file: Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer],  
        filename: str, 
        filesize: int = -1, 
        pid: int = 0, 
        make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any]] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """网页端的上传接口，注意：不支持秒传，但也不需要文件大小和 sha1

        :param file: 待上传的文件，只接受二进制数据或者迭代器
        :param filename: 文件名
        :param filesize: 文件大小，如果为 -1，则会自动确定
        :param pid: 上传文件到此目录的 id
        :param make_reporthook: 调用以推送上传进度

            .. note::
                - 如果为 None，则不推送进度
                - 否则，必须是 Callable。可接受 int 或 None 作为总文件大小，如果为 None 或者不传，则不确定文件大小。返回值作为实际的更新器，暂名为 `update`，假设一次的更新值为 `step`

                    - 如果返回值为 Callable，则更新时调用 `update(step)`
                    - 如果返回值为 Generator，则更新时调用 `update.send(step)`
                    - 如果返回值为 AsyncGenerator，则更新时调用 `await update.asend(step)`

                1. 你可以直接用第三方的进度条

                    .. code:: python

                        from tqdm import tqdm

                        make_report = lambda total=None: tqdm(total=total).update

                2. 或者你也可以自己写一个进度条

                    .. code:: python

                        from collections import deque
                        from time import perf_counter

                        def make_report(total: None | int = None):
                            dq: deque[tuple[int, float]] = deque(maxlen=64)
                            push = dq.append
                            read_num = 0
                            push((read_num, perf_counter()))
                            while True:
                                read_num += yield
                                cur_t = perf_counter()
                                speed = (read_num - dq[0][0]) / 1024 / 1024 / (cur_t - dq[0][1])
                                if total:
                                    percentage = read_num / total * 100
                                    print(f"\\r\\x1b[K{read_num} / {total} | {speed:.2f} MB/s | {percentage:.2f} %", end="", flush=True)
                                else:
                                    print(f"\\r\\x1b[K{read_num} | {speed:.2f} MB/s", end="", flush=True)
                                push((read_num, cur_t))

        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 接口响应
        """
        def gen_step():
            dataiter: Iterator[Buffer] | AsyncIterator[Buffer] = make_dataiter(file, async_=async_) # type: ignore
            if callable(make_reporthook):
                if async_:
                    dataiter = progress_bytes_async_iter(
                        cast(AsyncIterable[Buffer], dataiter), 
                        make_reporthook, 
                        None if filesize < 0 else filesize, 
                    )
                else:
                    dataiter = progress_bytes_iter(
                        cast(Iterable[Buffer], dataiter), 
                        make_reporthook, 
                        None if filesize < 0 else filesize, 
                    )
            resp = yield self.upload_sample_init(
                filename, 
                pid=pid, 
                async_=async_, 
                **request_kwargs, 
            )
            api = resp["host"]
            data = {
                "name": filename, 
                "key": resp["object"], 
                "policy": resp["policy"], 
                "OSSAccessKeyId": resp["accessid"], 
                "success_action_status": "200", 
                "callback": resp["callback"], 
                "signature": resp["signature"], 
            }
            if async_:
                headers, request_kwargs["data"] = encode_multipart_data_async(data, {"file": dataiter})
            else:
                headers, request_kwargs["data"] = encode_multipart_data(data, {"file": dataiter})
            request_kwargs["headers"] = {**request_kwargs.get("headers", {}), **headers}
            return self.request(
                url=api, 
                method="POST", 
                async_=async_, 
                **request_kwargs, 
            )
        return run_gen_step(gen_step, async_=async_)

    @overload # type: ignore
    def upload_file(
        self, 
        /, 
        file: ( str | PathLike | URL | SupportsGeturl | 
                Buffer | SupportsRead[Buffer] | Iterable[Buffer] ), 
        filename: None | str = None, 
        pid: int = 0, 
        filesize: int = -1, 
        filesha1: str = "", 
        partsize: int = 0, 
        upload_directly: None | bool = False, 
        multipart_resume_data: None | MultipartResumeData = None, 
        collect_resume_data: None | Callable[[MultipartResumeData], Any] = None, 
        make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any]] = None, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def upload_file(
        self, 
        /, 
        file: ( str | PathLike | URL | SupportsGeturl | 
                Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer] ), 
        filename: None | str = None, 
        pid: int = 0, 
        filesize: int = -1, 
        filesha1: str = "", 
        partsize: int = 0, 
        upload_directly: None | bool = False, 
        multipart_resume_data: None | MultipartResumeData = None, 
        collect_resume_data: None | Callable[[MultipartResumeData], Any] = None, 
        make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any]] = None, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def upload_file(
        self, 
        /, 
        file: ( str | PathLike | URL | SupportsGeturl | 
                Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer] ), 
        filename: None | str = None, 
        pid: int = 0, 
        filesize: int = -1, 
        filesha1: str = "", 
        partsize: int = 0, 
        upload_directly: None | bool = False, 
        multipart_resume_data: None | MultipartResumeData = None, 
        collect_resume_data: None | Callable[[MultipartResumeData], Any] = None, 
        make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any]] = None, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """文件上传，这是高层封装，推荐使用

        :param file: 待上传的文件

            - 如果为 `collections.abc.Buffer`，则作为二进制数据上传
            - 如果为 `filewrap.SupportsRead` (`pip install python-filewrap`)，则作为文件上传
            - 如果为 `str` 或 `os.PathLike`，则视为路径，打开后作为文件上传
            - 如果为 `yarl.URL` 或 `http_request.SupportsGeturl` (`pip install python-http_request`)，则视为超链接，打开后作为文件上传
            - 如果为 `collections.abc.Iterable[collections.abc.Buffer]` 或 `collections.abc.AsyncIterable[collections.abc.Buffer]`，则迭代以获取二进制数据，逐步上传

        :param filename: 文件名，如果为 None，则会自动确定
        :param pid: 上传文件到此目录的 id
        :param filesize: 文件大小，如果为 -1，则会自动确定
        :param filesha1: 文件的 sha1，如果未提供，则会自动确定
        :param partsize: 分块上传的分块大小，如果 <= 0，则不进行分块上传
        :param upload_directly: 如果为 True，则使用网页版接口直接上传（优先级高于 `partsize`）
        :param multipart_resume_data: 如果不为 None，则断点续传，并且恢复相关参数（优先级高于 `upload_directly`）
        :param collect_resume_data: 如果不为 None，则调用以输出分块上传的恢复数据（用于下次继续执行）
        :param make_reporthook: 调用以推送上传进度

            .. note::
                - 如果为 None，则不推送进度
                - 否则，必须是 Callable。可接受 int 或 None 作为总文件大小，如果为 None 或者不传，则不确定文件大小。返回值作为实际的更新器，暂名为 `update`，假设一次的更新值为 `step`

                    - 如果返回值为 Callable，则更新时调用 `update(step)`
                    - 如果返回值为 Generator，则更新时调用 `update.send(step)`
                    - 如果返回值为 AsyncGenerator，则更新时调用 `await update.asend(step)`

                1. 你可以直接用第三方的进度条

                    .. code:: python

                        from tqdm import tqdm

                        make_report = lambda total=None: tqdm(total=total).update

                2. 或者你也可以自己写一个进度条

                    .. code:: python

                        from collections import deque
                        from time import perf_counter

                        def make_report(total: None | int = None):
                            dq: deque[tuple[int, float]] = deque(maxlen=64)
                            push = dq.append
                            read_num = 0
                            push((read_num, perf_counter()))
                            while True:
                                read_num += yield
                                cur_t = perf_counter()
                                speed = (read_num - dq[0][0]) / 1024 / 1024 / (cur_t - dq[0][1])
                                if total:
                                    percentage = read_num / total * 100
                                    print(f"\\r\\x1b[K{read_num} / {total} | {speed:.2f} MB/s | {percentage:.2f} %", end="", flush=True)
                                else:
                                    print(f"\\r\\x1b[K{read_num} | {speed:.2f} MB/s", end="", flush=True)
                                push((read_num, cur_t))

        :param async_: 是否异步
        :param request_kwargs: 其它请求参数

        :return: 接口响应
        """
        def gen_step():
            nonlocal file, filename, filesize, filesha1
            def do_upload(file):
                return self.upload_file(
                    file=file, 
                    filename=filename, 
                    pid=pid, 
                    filesize=filesize, 
                    filesha1=filesha1, 
                    partsize=partsize, 
                    upload_directly=upload_directly, 
                    collect_resume_data=collect_resume_data, 
                    make_reporthook=make_reporthook, # type: ignore
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
            if filesize == 0:
                filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
            need_calc_filesha1 = not filesha1 and not upload_directly and multipart_resume_data is None
            read_range_bytes_or_hash: None | Callable = None
            try:
                file = getattr(file, "getbuffer")()
            except (AttributeError, TypeError):
                pass
            if isinstance(file, Buffer):
                filesize = buffer_length(file)
                if filesize == 0:
                    filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
                elif need_calc_filesha1:
                    filesha1 = sha1(file).hexdigest()
                if not upload_directly and multipart_resume_data is None and filesize >= 1 << 20:
                    view = memoryview(file)
                    def read_range_bytes_or_hash(sign_check: str, /) -> memoryview:
                        start, end = map(int, sign_check.split("-"))
                        return view[start:end+1]
            elif isinstance(file, SupportsRead):
                seek = getattr(file, "seek", None)
                seekable = False   
                curpos = 0
                if callable(seek):
                    if async_:
                        seek = ensure_async(seek, threaded=True)
                    try:
                        seekable = getattr(file, "seekable")()
                    except (AttributeError, TypeError):
                        try:
                            curpos = yield seek(0, 1)
                            seekable = True
                        except Exception:
                            seekable = False
                if need_calc_filesha1:
                    if not seekable:
                        fsrc = file
                        file = TemporaryFile()
                        if async_:
                            yield copyfileobj_async(fsrc, file)
                        else:
                            copyfileobj(fsrc, file)
                        file.seek(0)
                        return do_upload(file)
                    try:
                        if async_:
                            filesize, filesha1_obj = yield file_digest_async(file, "sha1")
                        else:
                            filesize, filesha1_obj = file_digest(file, "sha1")
                    finally:
                        yield seek(curpos)
                    filesha1 = filesha1_obj.hexdigest()
                if filesize < 0:
                    try:
                        fileno = getattr(file, "fileno")()
                        filesize = fstat(fileno).st_size - curpos
                    except (AttributeError, TypeError, OSError):
                        try:
                            filesize = len(file) - curpos # type: ignore
                        except TypeError:
                            if seekable:
                                try:
                                    filesize = (yield seek(0, 2)) - curpos
                                finally:
                                    yield seek(curpos)
                if filesize == 0:
                    filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
                elif not upload_directly and multipart_resume_data is None and filesize >= 1 << 20:
                    read: Callable[[int], Buffer] | Callable[[int], Awaitable[Buffer]]
                    if seekable:
                        if async_:
                            async_read = ensure_async(file.read, threaded=True)
                            async def read_range_bytes_or_hash(sign_check: str, /):
                                start, end = map(int, sign_check.split("-"))
                                await seek(curpos + start)
                                return await async_read(end - start + 1)
                        else:
                            read = cast(Callable[[int], Buffer], file.read)
                            def read_range_bytes_or_hash(sign_check: str, /):
                                start, end = map(int, sign_check.split("-"))
                                seek(curpos + start)
                                return read(end - start + 1)
            elif isinstance(file, (URL, SupportsGeturl)):
                if isinstance(file, URL):
                    url: str = str(file)
                else:
                    url = file.geturl()
                if async_:
                    from httpfile import AsyncHttpxFileReader
                    async def request():
                        file = await AsyncHttpxFileReader.new(url, headers={"user-agent": ""})
                        async with file:
                            return await do_upload(file)
                    return request
                else:
                    with HTTPFileReader(url, headers={"user-agent": ""}) as file:
                        return do_upload(file)
            elif isinstance(file, (str, PathLike)):
                path = fsdecode(file)
                if not filename:
                    filename = ospath.basename(path)
                if async_:
                    async def request():
                        from aiofile import async_open
                        async with async_open(path, "rb") as file:
                            setattr(file, "fileno", file.file.fileno)
                            setattr(file, "seekable", lambda: True)
                            return await do_upload(file)
                    return request
                else:
                    return do_upload(open(path, "rb"))
            else:
                if need_calc_filesha1:
                    if async_:
                        file = bytes_iter_to_async_reader(file) # type: ignore
                    else:
                        file = bytes_iter_to_reader(file) # type: ignore
                    return do_upload(file)
            if multipart_resume_data is not None:
                bucket = multipart_resume_data["bucket"]
                object = multipart_resume_data["object"]
                url    = cast(str, multipart_resume_data.get("url", ""))
                if not url:
                    url = self.upload_endpoint_url(bucket, object)
                callback_var = loads(multipart_resume_data["callback"]["callback_var"])
                yield self.upload_resume(
                    {
                        "fileid": object, 
                        "filesize": multipart_resume_data["filesize"], 
                        "target": callback_var["x:target"], 
                        "pickcode": callback_var["x:pick_code"], 
                    }, 
                    async_=async_, 
                    **request_kwargs, 
                )
                return oss_multipart_upload(
                    self.request, 
                    file, # type: ignore
                    url=url, 
                    bucket=bucket, 
                    object=object, 
                    token=self.upload_token, 
                    callback=multipart_resume_data["callback"], 
                    upload_id=multipart_resume_data["upload_id"], 
                    partsize=multipart_resume_data["partsize"], 
                    filesize=multipart_resume_data.get("filesize", filesize), 
                    collect_resume_data=collect_resume_data, 
                    make_reporthook=make_reporthook, # type: ignore
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
            if not filename:
                filename = getattr(file, "name", "")
                filename = ospath.basename(filename)
            if filename:
                filename = filename.translate(NAME_TANSTAB_FULLWIDH)
            else:
                filename = str(uuid4())
            if filesize < 0:
                filesize = getattr(file, "length", 0)
            if upload_directly:
                return self.upload_file_sample(
                    file, # type: ignore
                    filename=filename, 
                    filesize=filesize, 
                    pid=pid, 
                    make_reporthook=make_reporthook, # type: ignore
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
            resp = yield self.upload_file_init(
                filename=filename, 
                filesize=filesize, 
                filesha1=filesha1, 
                read_range_bytes_or_hash=read_range_bytes_or_hash, 
                pid=pid, 
                async_=async_, # type: ignore
                **request_kwargs, 
            )
            status = resp["status"]
            statuscode = resp.get("statuscode", 0)
            if status == 2 and statuscode == 0:
                return resp
            elif status == 1 and statuscode == 0:
                bucket, object, callback = resp["bucket"], resp["object"], resp["callback"]
            else:
                raise P115OSError(EINVAL, resp)
            url = self.upload_endpoint_url(bucket, object)
            token = self.upload_token
            if partsize <= 0:
                return oss_upload(
                    self.request, 
                    file, # type: ignore
                    url=url, 
                    bucket=bucket, 
                    object=object, 
                    callback=callback, 
                    token=token, 
                    filesize=filesize, 
                    make_reporthook=make_reporthook, # type: ignore
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
            else:
                return oss_multipart_upload(
                    self.request, 
                    file, # type: ignore
                    url=url, 
                    bucket=bucket, 
                    object=object, 
                    callback=callback, 
                    token=token, 
                    partsize=partsize, 
                    filesize=filesize, 
                    collect_resume_data=collect_resume_data, 
                    make_reporthook=make_reporthook, # type: ignore
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
        return run_gen_step(gen_step, async_=async_)

    ########## User API ##########

    @overload
    def user_card(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_card(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_card(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取用户信息

        GET https://proapi.115.com/android/user/card
        """
        api = complete_proapi("/user/card", base_url, app)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    @staticmethod
    def user_face_code(
        request: None | Callable = None, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    @staticmethod
    def user_face_code(
        request: None | Callable = None, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    @staticmethod
    def user_face_code(
        request: None | Callable = None, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取表情包

        GET http://my.115.com/api/face_code.js
        """
        api = complete_api("/api/face_code.js", "my", base_url=base_url)
        request_kwargs.setdefault("parse", lambda _, b, /: default_parse(_, b[25:-1]))
        if request is None:
            return get_default_request()(url=api, async_=async_, **request_kwargs)
        else:
            return request(url=api, **request_kwargs)

    @overload
    def user_fingerprint(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_fingerprint(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_fingerprint(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取截图时嵌入的水印

        GET https://webapi.115.com/user/fingerprint
        """
        api = complete_webapi("/user/fingerprint", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload # type: ignore
    def user_info(
        self: int | str | dict | P115Client, 
        payload: None | int | str | dict = None, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_info(
        self: int | str | dict | P115Client, 
        payload: None | int | str | dict = None, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_info(
        self: int | str | dict | P115Client, 
        payload: None | int | str | dict = None, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取用户信息

        GET https://my.115.com/proapi/3.0/index.php?method=user_info

        .. important::
            这个函数可以作为 staticmethod 使用，只要 `self` 不是 P115Client 类型，此时不需要登录

        :payload:
            - uid: int | str
        """
        api = complete_api("/proapi/3.0/index.php", "my", base_url=base_url)
        if isinstance(self, P115Client):
            if payload is None:
                payload = self.user_id
        else:
            payload = self
        if isinstance(payload, (int, str)):
            payload = {"uid": payload, "method": "user_info"}
        else:
            payload = {"method": "user_info", **payload}
        if isinstance(self, P115Client):
            return self.request(url=api, params=payload, async_=async_, **request_kwargs)
        else:
            request_kwargs.setdefault("parse", default_parse)
            request = request_kwargs.pop("request", None)
            if request is None:
                return get_default_request()(url=api, params=payload, async_=async_, **request_kwargs)
            else:
                return request(url=api, params=payload, **request_kwargs)

    @overload
    def user_my(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_my(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_my(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取此用户信息

        GET https://my.115.com/?ct=ajax&ac=nav
        """
        api = complete_api("/?ct=ajax&ac=nav", "my", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def user_my_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_my_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_my_info(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取此用户信息（更全）

        GET https://my.115.com/?ct=ajax&ac=get_user_aq
        """
        api = complete_api("/?ct=ajax&ac=get_user_aq", "my", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def user_points_balance(
        self, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_points_balance(
        self, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_points_balance(
        self, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """剩余的签到积分

        GET https://points.115.com/api/1.0/web/1.0/user/balance
        """
        api = f"http://points.115.com/api/1.0/{app}/1.0/user/balance"
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def user_points_sign(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_points_sign(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_points_sign(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取签到信息

        GET https://proapi.115.com/android/2.0/user/points_sign
        """
        api = complete_proapi("/2.0/user/points_sign", base_url, app)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def user_points_sign_post(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_points_sign_post(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_points_sign_post(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """每日签到（注意：不要用 web，即浏览器，的 cookies，会失败）

        POST https://proapi.115.com/android/2.0/user/points_sign
        """
        api = complete_proapi("/2.0/user/points_sign", base_url, app)
        t = int(time())
        payload = {
            "token": sha1(b"%d-Points_Sign@#115-%d" % (self.user_id, t)).hexdigest(), 
            "token_time": t, 
        }
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def user_points_transaction(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_points_transaction(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_points_transaction(
        self, 
        payload: int | dict = 0, 
        /, 
        app: str = "web", 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """签到记录

        GET https://points.115.com/api/1.0/web/1.0/user/transaction

        payload:
            - start: int = 0
            - limit: int = 32
            - month: str = <default> 💡 月份，格式为 YYYYMM
        """
        if isinstance(payload, int):
            payload = {"limit": 32, "start": payload}
        else:
            payload = {"limit": 32, **payload}
        api = f"http://points.115.com/api/1.0/{app}/1.0/user/transaction"
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def user_setting(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_setting(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_setting(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取此账户的设置

        GET https://115.com/?ac=setting&even=saveedit&is_wl_tpl=1
        """
        api = complete_api("/?ac=setting&even=saveedit&is_wl_tpl=1", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def user_setting2(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_setting2(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_setting2(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取此账户的设置

        GET https://115.com/?ct=user_setting&ac=get
        """
        api = complete_api("/?ct=user_setting&ac=get", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def user_setting_set(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_setting_set(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_setting_set(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """修改此账户的网页版设置（提示：较为复杂，自己抓包研究）

        POST https://115.com/?ac=setting&even=saveedit&is_wl_tpl=1
        """
        api = complete_api("/?ac=setting&even=saveedit&is_wl_tpl=1", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def user_setting_web(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_setting_web(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_setting_web(
        self, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取此账户的 app 版设置（提示：较为复杂，自己抓包研究）

        GET https://webapi.115.com/user/setting
        """
        api = complete_webapi("/user/setting", base_url=base_url)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def user_setting_web_set(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_setting_web_set(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_setting_web_set(
        self, 
        payload: dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取（并可修改）此账户的网页版设置（提示：较为复杂，自己抓包研究）

        POST https://webapi.115.com/user/setting
        """
        api = complete_webapi("/user/setting", base_url=base_url)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def user_setting_app(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_setting_app(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_setting_app(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取此账户的 app 版设置（提示：较为复杂，自己抓包研究）

        GET https://proapi.115.com/android/1.0/user/setting
        """
        api = complete_proapi("/1.0/user/setting", base_url, app)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def user_setting_app_set(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_setting_app_set(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_setting_app_set(
        self, 
        payload: dict, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取（并可修改）此账户的网页版设置（提示：较为复杂，自己抓包研究）

        POST https://proapi.115.com/android/1.0/user/setting
        """
        api = complete_proapi("/1.0/user/setting", base_url, app)
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def user_vip_check_spw(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_vip_check_spw(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_vip_check_spw(
        self, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取用户积分、余额等信息

        GET https://proapi.115.com/android/vip/check_spw
        """
        api = complete_proapi("/vip/check_spw", base_url, app)
        return self.request(url=api, async_=async_, **request_kwargs)

    @overload
    def user_vip_limit(
        self, 
        payload: int | dict = 2, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def user_vip_limit(
        self, 
        payload: int | dict = 2, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def user_vip_limit(
        self, 
        payload: int | dict = 2, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取 vip 的某些限制

        GET https://webapi.115.com/user/vip_limit

        :payload:
            - feature: int = 2
        """
        api = complete_webapi("/user/vip_limit", base_url=base_url)
        if isinstance(payload, int):
            payload = {"feature": payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    ########## User Share API ##########

    @overload
    def usershare_action(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def usershare_action(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def usershare_action(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取共享动态列表

        GET https://webapi.115.com/usershare/action

        :payload:
            - share_id: int | str
            - offset: int = 0
            - limit: int = 32
        """
        api = complete_webapi("/usershare/action", base_url=base_url)
        if isinstance(payload, int):
            payload = {"limit": 32, "offset": 0, "share_id": payload}
        else:
            payload = {"limit": 32, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def usershare_invite(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def usershare_invite(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def usershare_invite(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """获取共享链接

        POST https://webapi.115.com/usershare/invite

        :payload:
            - share_id: int | str
        """
        api = complete_webapi("/usershare/invite", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"share_id": payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)

    @overload
    def usershare_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def usershare_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def usershare_list(
        self, 
        payload: int | str | dict = 0, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """共享列表

        GET https://webapi.115.com/usershare/list

        :payload:
            - offset: int = 0
            - limit: int = 1150
            - all: 0 | 1 = 1
        """
        api = complete_webapi("/usershare/list", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"all": 1, "limit": 1150, "offset": payload}
        else:
            payload = {"all": 1, "limit": 1150, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def usershare_list_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def usershare_list_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def usershare_list_app(
        self, 
        payload: int | str | dict = 0, 
        /, 
        app: str = "android", 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """共享列表

        GET https://proapi.115.com/android/2.0/usershare/list

        :payload:
            - offset: int = 0
            - limit: int = 1150
            - all: 0 | 1 = 1
        """
        api = complete_proapi("/2.0/usershare/list", base_url, app)
        if isinstance(payload, (int, str)):
            payload = {"all": 1, "limit": 1150, "offset": payload}
        else:
            payload = {"all": 1, "limit": 1150, "offset": 0, **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def usershare_member(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def usershare_member(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def usershare_member(
        self, 
        payload: int | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """某共享的成员信息

        GET https://webapi.115.com/usershare/member

        :payload:
            - share_id: int | str
            - action: "member_list" | "member_info" | "noticeset" = "member_list"
            - notice_set: 0 | 1 = <default> 💡 action 为 "noticeset" 时可以设置
        """
        api = complete_webapi("/usershare/member", base_url=base_url)
        if isinstance(payload, int):
            payload = {"action": "member_list", "share_id": payload}
        else:
            payload = {"action": "member_list", **payload}
        return self.request(url=api, params=payload, async_=async_, **request_kwargs)

    @overload
    def usershare_share(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def usershare_share(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def usershare_share(
        self, 
        payload: int | str | dict, 
        /, 
        base_url: bool | str | Callable[[], str] = False, 
        *, 
        async_: Literal[False, True] = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        """设置共享

        POST https://webapi.115.com/usershare/share

        :payload:
            - file_id: int | str
            - share_opt: 1 | 2 = 1 💡 1: 设置 2: 取消
            - ignore_warn: 0 | 1 = 0
            - safe_pwd: str = "" 
        """
        api = complete_webapi("/usershare/share", base_url=base_url)
        if isinstance(payload, (int, str)):
            payload = {"ignore_warn": 0, "share_opt": 1, "safe_pwd": "", "file_id": payload}
        else:
            payload = {"ignore_warn": 0, "share_opt": 1, "safe_pwd": "", **payload}
        return self.request(url=api, method="POST", data=payload, async_=async_, **request_kwargs)


for name, method in P115Client.__dict__.items():
    if not (callable(method) and method.__doc__):
        continue
    match = CRE_CLIENT_API_search(method.__doc__)
    if match is not None:
        CLIENT_API_MAP[match[1]] = "P115Client." + name

# TODO: 提供一个可随时终止和暂停的上传功能，并且可以输出进度条和获取进度
# TODO: 更新一下，p115client._upload，做更多的封装，至少让断点续传更易于使用

