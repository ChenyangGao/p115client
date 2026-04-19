#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 9)
__all__ = [
    "upload_endpoint_url", "upload_url", "upload_token", "upload_token_open", 
    "upload_init", "upload_init_open", "upload_resume", "upload_resume_open", 
    "oss_upload_sign", "oss_upload_request", "oss_multipart_upload_url", 
    "oss_multipart_part_iter", "oss_multipart_upload_init", 
    "oss_multipart_upload_complete", "oss_multipart_upload_cancel", 
    "oss_multipart_upload_part", "oss_multipart_upload_part_iter", 
    "oss_upload_init", "oss_upload", "oss_multipart_upload", "upload", 
]

from asyncio import to_thread, Lock as AsyncLock
from base64 import b64encode
from collections import UserString
from collections.abc import (
    AsyncIterable, AsyncIterator, Buffer, Callable, 
    Coroutine, Iterable, Iterator, Mapping, Sequence, 
)
from datetime import datetime, timedelta
from email.utils import formatdate
from hashlib import sha1
from hmac import digest as hmac_digest
from inspect import isawaitable, iscoroutinefunction, signature
from itertools import count
from os import fsdecode, fstat, stat, PathLike
from threading import Lock
from typing import cast, overload, Any, Final, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4
from xml.etree.ElementTree import fromstring

from asynctools import ensure_async
from dicttools import iter_items, dict_update
from filewrap import (
    SupportsRead, buffer_length, 
    bio_chunk_iter, bio_chunk_async_iter, 
    bytes_iter_to_async_reader, bytes_iter_to_reader, 
    bytes_to_chunk_iter, bytes_to_chunk_async_iter, 
)
from hashtools import file_digest, file_digest_async
from http_request import complete_url, SupportsGeturl
from http_response import get_status_code, get_total_length, get_filename
from integer_tool import try_parse_int
from iterutils import (
    foreach, collect, peek_iter, run_gen_step, run_gen_step_iter, 
    wrap_iter, Yield, 
)
from orjson import loads
from p115cipher import ecdh_aes_decrypt, make_upload_payload
from p115pickcode import pickcode_to_id
from yarl import URL


_HEADERS: Final = {"user-agent": "", "accept-encoding": "identity"}
_UPLOAD_TOKEN: Final[dict[str, str]] = {}
_UPLOAD_TOKEN_LOCK: Final = Lock()
_UPLOAD_TOKEN_ASYNC_LOCK: Final = AsyncLock()


@overload
def _upload_token(
    refresh: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict[str, str]:
    ...
@overload
def _upload_token(
    refresh: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict[str, str]]:
    ...
def _upload_token(
    refresh: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict[str, str] | Coroutine[Any, Any, dict[str, str]]:
    request_kwargs["parse"] = parse_json
    request_kwargs.pop("headers", None)
    def gen_step():
        if async_:
            lock: AsyncLock | Lock = _UPLOAD_TOKEN_ASYNC_LOCK
        else:
            lock = _UPLOAD_TOKEN_LOCK
        try:
            yield lock.acquire()
            expiration = _UPLOAD_TOKEN.get("Expiration") or ""
            if refresh:
                deadline = datetime.now() - timedelta(hours=7, minutes=10)
            else:
                deadline = datetime.now() - timedelta(hours=7, minutes=59)
            if expiration < deadline.strftime("%FT%XZ"):
                while True:
                    try:
                        resp = yield upload_token(async_=async_, **request_kwargs)
                    except Exception:
                        continue
                    if resp.get("StatusCode") == "200":
                        break
                _UPLOAD_TOKEN.update(resp)
        finally:
            lock.release()
        return _UPLOAD_TOKEN
    return run_gen_step(gen_step, async_)


def to_base64(s: Buffer | str | UserString, /) -> str:
    if isinstance(s, (str, UserString)):
        s = s.encode("utf-8")
    return str(b64encode(s), "ascii")


def parse_json(_, content: Buffer, /):
    return loads(memoryview(content))


def parse_upload_id(_, content: bytes, /) -> str:
    return getattr(fromstring(content).find("UploadId"), "text")


def get_request(
    request_kwargs: dict, 
    async_: Literal[False, True] = False, 
):
    request = request_kwargs.pop("request", None)
    request_kwargs.setdefault("parse", parse_json)
    if request is None:
        from httpcore_request import request
        request_kwargs["async_"] = async_
    else:
        def has_keyword_async(request: Callable, /) -> bool:
            try:
                sig = signature(request)
            except (ValueError, TypeError):
                return False
            params = sig.parameters
            param = params.get("async_")
            return bool(param and param.kind in (param.POSITIONAL_OR_KEYWORD, param.KEYWORD_ONLY))
        if iscoroutinefunction(request):
            async_ = True
        if async_ is not None and has_keyword_async(request):
            request_kwargs["async_"] = async_
    return request


def determine_partsize(
    size: int, 
    max_part_count: int = 10 ** 4, 
) -> int:
    """确定分片上传（multipart upload）时的分片大小

    :param size: 数据大小
    :param min_part_size:  用户期望的分片大小
    :param max_part_count: 最大的分片个数

    :return: 分片大小
    """
    min_part_size = 1024 * 1024 * 10
    if size <= min_part_size:
        return min_part_size
    n = -(-size // max_part_count)
    partsize = min_part_size
    while partsize < n:
        partsize <<= 1
    return partsize


def upload_endpoint_url(
    object: str, 
    bucket: str = "fhnfile", 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
) -> str:
    """构造上传时的 url

    :param bucket: 存储桶
    :param object: 存储对象 id
    :param endpoint: 上传目的网址

    :return: 上传时所用的 url
    """
    urlp = urlsplit(endpoint)
    return f"{urlp.scheme}://{bucket}.{urlp.netloc}/{object}"


@overload
def upload_url(
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_url(
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_url(
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取上传目的网址和获取 ``token`` 的网址

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 网址的字典，"endpoint" 是上传目的网址，"gettokenurl" 是获取 ``token`` 的网址
    """
    api = "https://uplb.115.com/3.0/getuploadinfo.php"
    return get_request(request_kwargs, async_=async_)(url=api, **request_kwargs)


@overload
def upload_token(
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_token(
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_token(
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取上传用到的令牌信息（字典）

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 令牌信息（字典）
    """
    api = "https://uplb.115.com/3.0/gettoken.php"
    return get_request(request_kwargs, async_=async_)(url=api, **request_kwargs)


@overload
def upload_token_open(
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_token_open(
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_token_open(
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取上传用到的令牌信息（字典）

    .. caution::
        需要携带 "authorization" 请求头

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 令牌信息（字典）
    """
    api = "https://proapi.115.com/open/upload/get_token"
    return get_request(request_kwargs, async_=async_)(url=api, **request_kwargs)


@overload
def upload_init(
    payload: dict, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_init(
    payload: dict, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_init(
    payload: dict, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """上传初始化

    :param payload: 请求参数

        - userid: int | str     💡 用户 id
        - userkey: str          💡 用户的 key
        - fileid: str           💡 文件的 sha1
        - filename: str         💡 文件名
        - filesize: int         💡 文件大小
        - target: str = "U_1_0" 💡 保存目标，格式为 f"U_{aid}_{pid}"
        - sign_key: str = ""    💡 2 次验证的 key
        - sign_val: str = ""    💡 2 次验证的值
        - topupload: int | str = "true" 💡 上传调度文件类型调度标记

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    api = "https://uplb.115.com/4.0/initupload.php"
    data = {
        "appid": 0, 
        "target": "U_1_0", 
        "sign_key": "", 
        "sign_val": "", 
        "topupload": "true", 
        **payload, 
        "appversion": "99.99.99.99", 
    }
    request_kwargs["method"] = "POST"
    request_kwargs["headers"] = dict_update(
        dict(request_kwargs.get("headers") or ()), 
        {
            "content-type": "application/x-www-form-urlencoded", 
            "user-agent": "Mozilla/5.0 115disk/99.99.99.99 115Browser/99.99.99.99 115wangpan_android/99.99.99.99", 
        }, 
    )
    request_kwargs.update(make_upload_payload(data))
    def parse_upload_init_response(_, content: bytes, /) -> dict:
        data = ecdh_aes_decrypt(content, decompress=True)
        return parse_json(None, data)
    request_kwargs.setdefault("parse", parse_upload_init_response)
    return get_request(request_kwargs, async_=async_)(url=api, **request_kwargs)


@overload
def upload_init_open(
    payload: dict, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_init_open(
    payload: dict, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_init_open(
    payload: dict, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """上传初始化（开放接口）

    .. caution::
        需要携带 "authorization" 请求头

    :param payload: 请求参数

        - fileid: str              💡 文件的 sha1
        - file_name: str           💡 文件名
        - file_size: int           💡 文件大小
        - target: str = "U_1_0"    💡 保存目标，格式为 f"U_{aid}_{pid}"
        - sign_key: str = ""       💡 2 次验证的 key
        - sign_val: str = ""       💡 2 次验证的值
        - topupload: int | str = 1 💡 上传调度文件类型调度标记

            -  0: 单文件上传任务标识 1 条单独的文件上传记录
            -  1: 目录任务调度的第 1 个子文件上传请求标识 1 次目录上传记录
            -  2: 目录任务调度的其余后续子文件不作记作单独上传的上传记录 
            - -1: 没有该参数

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    api = "https://proapi.115.com/open/upload/init"
    request_kwargs.update(
        method="POST", 
        data={"target": "U_1_0", "topupload": 1, **payload}, 
    )
    return get_request(request_kwargs, async_=async_)(url=api, **request_kwargs)


@overload
def upload_resume(
    payload: dict, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_resume(
    payload: dict, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_resume(
    payload: dict, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """恢复上传（主要用于分块上传）

    .. note::
        ``payload`` 中包含 "callback" 或 "callback_var" 字段，则可以被自动处理（即使相关字段缺失）

        即使你仅保存了 ``upload_id`` 和 ``callback``，也能让你断点续传

    :param payload: 需要接受下面这些参数

        - pickcode: str 💡 提取码
        - userid: int   💡 用户 id
        - target: str   💡 上传目标，默认为 "U_1_0"，格式为 f"U_{aid}_{pid}"
        - fileid: str   💡 文件的 sha1 值（⚠️ 可以是任意值）
        - filesize: int 💡 文件大小，单位是字节（⚠️ 可以是任意值）

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    api = "https://uplb.115.com/3.0/resumeupload.php"
    data: dict = dict(payload)
    if "pickcode" not in data:
        if "callback_var" in data:
            callback_var = loads(data["callback_var"])
        elif "callback" in data:
            callback_var = loads(data["callback"]["callback_var"])
        else:
            raise ValueError(f"invalid payload: {payload!r}")
        data.update(
            pickcode=callback_var["x:pick_code"], 
            target=callback_var["x:target"], 
            userid=callback_var["x:user_id"]
        )
    data.setdefault("fileid", "0" * 40)
    data.setdefault("filesize", 1)
    data.setdefault("target", "U_1_0")
    request_kwargs.update(method="POST", data=data)
    return get_request(request_kwargs, async_=async_)(url=api, **request_kwargs)


@overload
def upload_resume_open(
    payload: dict | str, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_resume_open(
    payload: dict | str, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_resume_open(
    payload: dict | str, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """恢复上传（主要用于分块上传）

    .. caution::
        需要携带 "authorization" 请求头

    .. note::
        ``payload`` 中包含 "callback" 或 "callback_var" 字段，则可以被自动处理（即使相关字段缺失）

        即使你仅保存了 ``upload_id`` 和 ``callback``，也能让你断点续传

    :param payload: 需要接受下面这些参数

        - pick_code: str 💡 提取码
        - target: str    💡 上传目标，默认为 "U_1_0"，格式为 f"U_{aid}_{pid}"
        - fileid: str    💡 文件的 sha1 值（⚠️ 可以是任意值）
        - file_size: int 💡 文件大小，单位是字节（⚠️ 可以是任意值）

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    api = "https://proapi.115.com/open/upload/resume"
    if isinstance(payload, str):
        data: dict = {"pick_code": payload}
    else:
        data = dict(payload)
        if "pick_code" not in data:
            if "callback_var" in data:
                callback_var = loads(data["callback_var"])
            elif "callback" in data:
                callback_var = loads(data["callback"]["callback_var"])
            else:
                raise ValueError(f"invalid payload: {payload!r}")
            data.update(
                pick_code=callback_var["x:pick_code"], 
                target=callback_var["x:target"], 
            )
    data.setdefault("fileid", "0" * 40)
    data.setdefault("file_size", 1)
    data.setdefault("target", "U_1_0")
    request_kwargs.update(method="POST", data=data)
    return get_request(request_kwargs, async_=async_)(url=api, **request_kwargs)


@overload
def oss_upload_sign(
    url: str, 
    method: str = "POST", 
    headers: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
    token: None | dict = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_upload_sign(
    url: str, 
    method: str = "POST", 
    headers: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
    token: None | dict = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> dict:
    ...
def oss_upload_sign(
    url: str, 
    method: str = "POST", 
    headers: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
    token: None | dict = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict:
    """计算然后返回带认证信息的请求头

    :param token: 上传用到的令牌信息（字典）
    :param method: HTTP 请求方法
    :param url: HTTP 请求链接
    :param headers: 默认的请求头
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 带认证信息的请求头
    """
    # subresource_keys = (
    #     "accessPoint", "accessPointPolicy", "acl", "append", "asyncFetch", "bucketArchiveDirectRead", 
    #     "bucketInfo", "callback", "callback-var", "cname", "comp", "continuation-token", "cors", 
    #     "delete", "encryption", "endTime", "group", "httpsConfig", "inventory", "inventoryId", 
    #     "lifecycle", "link", "live", "location", "logging", "metaQuery", "objectInfo", "objectMeta", 
    #     "partNumber", "policy", "position", "publicAccessBlock", "qos", "qosInfo", "qosRequester", 
    #     "redundancyTransition", "referer", "regionList", "replication", "replicationLocation", 
    #     "replicationProgress", "requestPayment", "requesterQosInfo", "resourceGroup", "resourcePool", 
    #     "resourcePoolBuckets", "resourcePoolInfo", "response-cache-control", "response-content-disposition", 
    #     "response-content-encoding", "response-content-language", "response-content-type", "response-expires", 
    #     "restore", "security-token", "sequential", "startTime", "stat", "status", "style", "styleName", 
    #     "symlink", "tagging", "transferAcceleration", "uploadId", "uploads", "versionId", "versioning", 
    #     "versions", "vod", "website", "worm", "wormExtend", "wormId", "x-oss-ac-forward-allow", 
    #     "x-oss-ac-source-ip", "x-oss-ac-subnet-mask", "x-oss-ac-vpc-id", "x-oss-access-point-name", 
    #     "x-oss-async-process", "x-oss-process", "x-oss-redundancy-transition-taskid", "x-oss-request-payer", 
    #     "x-oss-target-redundancy-type", "x-oss-traffic-limit", "x-oss-write-get-object-response", 
    # )
    def gen_step():
        nonlocal headers, token
        if not token:
            token = yield _upload_token(async_=async_, **request_kwargs)
        urlp = urlsplit(url)
        bucket = cast(str, urlp.hostname).partition(".")[0]
        headers = {k.lower(): v for k, v in iter_items(headers or ())}
        headers["x-oss-security-token"] = token["SecurityToken"]
        date = headers["date"] = headers.get("x-oss-date") or headers.get("date") or formatdate(usegmt=True)
        signature = to_base64(hmac_digest(
            bytes(token["AccessKeySecret"], "utf-8"), 
            f"""\
{method.upper()}
{headers.setdefault("content-md5", "")}
{headers.setdefault("content-type", "")}
{date}
{"\n".join(map(
    "%s:%s".__mod__, 
    sorted(e for e in headers.items() if e[0].startswith("x-oss-"))
))}
/{bucket}{urlunsplit(urlp._replace(scheme="", netloc=""))}""".encode("utf-8"), 
            "sha1", 
        ))
        headers["authorization"] = "OSS {0}:{1}".format(token["AccessKeyId"], signature)
        return headers
    return run_gen_step(gen_step, async_)


def oss_upload_request(
    url: str, 
    method: str = "POST", 
    params: None | str | Mapping | Sequence[tuple[Any, Any]] = None, 
    token: None | dict = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """请求阿里云 OSS 的公用函数
    """
    assert url
    if not url.strip("1234567890abcdef"):
        url = "http://fhnfile.oss-cn-shenzhen.aliyuncs.com/" + url
    url = complete_url(url, params=params)
    def gen_step():
        nonlocal token
        if not token:
            token = yield _upload_token(async_=async_, **request_kwargs)
        request_kwargs["headers"] = oss_upload_sign(
            url, 
            method=method, 
            headers=request_kwargs.get("headers"), 
            token=token, 
        )
        return get_request(request_kwargs, async_=async_)(
            url=url, 
            method=method, 
            **request_kwargs, 
        )
    return run_gen_step(gen_step, async_)


@overload
def oss_multipart_upload_url(
    url: str, 
    upload_id: int | str, 
    part_number: int = 1, 
    token: None | dict = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> tuple[str, dict]:
    ...
@overload
def oss_multipart_upload_url(
    url: str, 
    upload_id: int | str, 
    part_number: int = 1, 
    token: None | dict = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, tuple[str, dict]]:
    ...
def oss_multipart_upload_url(
    url: str, 
    upload_id: int | str, 
    part_number: int = 1, 
    token: None | dict = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> tuple[str, dict] | Coroutine[Any, Any, tuple[str, dict]]:
    """获取分块上传的链接和请求头

    :param url: HTTP 请求链接
    :param upload_id: 上传任务的 id
    :param part_number: 分块编号（从 1 开始）
    :param token: 上传用到的令牌信息（字典）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数   

    :return: 上传链接 和 请求头 的 2 元组
    """
    assert url
    if not url.strip("1234567890abcdef"):
        url = "http://fhnfile.oss-cn-shenzhen.aliyuncs.com/" + url
    url = complete_url(url, params={"partNumber": part_number, "uploadId": upload_id})
    def gen_step():
        nonlocal token
        if not token:
            token = yield _upload_token(refresh=True, async_=async_, **request_kwargs)
        headers = yield oss_upload_sign(
            url=url, 
            method="PUT", 
            token=token, 
            async_=async_, 
            **request_kwargs, 
        )
        return url, headers
    return run_gen_step(gen_step, async_)


@overload
def oss_multipart_part_iter(
    url: str, 
    upload_id: str, 
    token: None | dict = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def oss_multipart_part_iter(
    url: str, 
    upload_id: str, 
    token: None | dict = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def oss_multipart_part_iter(
    url: str, 
    upload_id: str, 
    token: None | dict = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """罗列某个分块上传任务，已经上传的分块

    :param url: HTTP 请求链接
    :param upload_id: 上传任务的 id
    :param token: 上传用到的令牌信息（字典）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数    

    :return: 上传完成分块信息的迭代器
    """
    request_kwargs.update(
        method="GET", 
        params={"uploadId": upload_id}, 
        parse=False, 
    )
    def gen_step():
        params = request_kwargs["params"]
        while True:
            content = yield oss_upload_request(
                url=url, 
                token=token, 
                async_=async_, 
                **request_kwargs, 
            )
            etree = fromstring(content)
            for el in etree.iterfind("Part"):
                yield Yield({sel.tag: try_parse_int(sel.text) for sel in el})
            if getattr(etree.find("IsTruncated"), "text") == "false":
                break
            params["part-number-marker"] = getattr(etree.find("NextPartNumberMarker"), "text")
    return run_gen_step_iter(gen_step, async_)


@overload
def oss_multipart_upload_init(
    url: str, 
    token: None | dict = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> str:
    ...
@overload
def oss_multipart_upload_init(
    url: str, 
    token: None | dict = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, str]:
    ...
def oss_multipart_upload_init(
    url: str, 
    token: None | dict = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> str | Coroutine[Any, Any, str]:
    """初始化，以获取分块上传任务的 id

    :param url: HTTP 请求链接
    :param token: 上传用到的令牌信息（字典）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 分块上传任务的 id
    """
    request_kwargs.update(
        method="POST", 
        params={"sequential": "1", "uploads": "1"}, 
    )
    request_kwargs.setdefault("parse", parse_upload_id)
    return oss_upload_request(
        url=url, 
        token=token, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_complete(
    url: str, 
    callback: dict, 
    upload_id: str, 
    parts: None | list[dict] = None, 
    token: None | dict = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_multipart_upload_complete(
    url: str, 
    callback: dict, 
    upload_id: str, 
    parts: None | list[dict] = None, 
    token: None | dict = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_multipart_upload_complete(
    url: str, 
    callback: dict, 
    upload_id: str, 
    parts: None | list[dict] = None, 
    token: None | dict = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """完成分块上传任务

    :param url: HTTP 请求链接
    :param callback: 回调数据
    :param upload_id: 上传任务 id
    :pamra parts: 已完成的分块信息列表
    :param token: 上传用到的令牌信息（字典）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    def gen_step():
        nonlocal parts
        if parts is None:
            parts = yield collect(oss_multipart_part_iter(
                url=url, 
                upload_id=upload_id, 
                token=token, 
                async_=async_, 
                **request_kwargs, 
            ))
        request_kwargs.update(
            method="POST", 
            params={"uploadId": upload_id}, 
            data=b"".join((
                b"<CompleteMultipartUpload>", 
                *map(
                    b"<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>".__mod__, 
                    ((part["PartNumber"], bytes(part["ETag"], "ascii")) for part in parts), 
                ), 
                b"</CompleteMultipartUpload>", 
            )), 
            headers=dict_update(
                dict(request_kwargs.get("headers") or ()), 
                {
                    "x-oss-callback": to_base64(callback["callback"]), 
                    "x-oss-callback-var": to_base64(callback["callback_var"]), 
                    "content-type": "text/xml", 
                }, 
            ), 
        )
        return oss_upload_request(
            url=url, 
            token=token, 
            async_=async_, 
            **request_kwargs, 
        )
    return run_gen_step(gen_step, async_)


@overload
def oss_multipart_upload_cancel(
    url: str, 
    upload_id: str, 
    token: None | dict = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> bool:
    ...
@overload
def oss_multipart_upload_cancel(
    url: str, 
    upload_id: str, 
    token: None | dict = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, bool]:
    ...
def oss_multipart_upload_cancel(
    url: str, 
    upload_id: str, 
    token: None | dict = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> bool | Coroutine[Any, Any, bool]:
    """取消分块上传任务

    :param url: HTTP 请求链接
    :param upload_id: 上传任务 id
    :param token: 上传用到的令牌信息（字典）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 是否成功
    """
    request_kwargs.update(
        method="DELETE", 
        params={"uploadId": upload_id}, 
        raise_for_status=False, 
    )
    request_kwargs.setdefault(
        "parse", 
        lambda resp: (code := get_status_code(resp)) == 404 or 200 <= code < 300, 
    )
    return oss_upload_request(
        url=url, 
        token=token, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_part(
    url: str, 
    file: Buffer | SupportsRead | Iterable[Buffer], 
    upload_id: str, 
    part_number: int, 
    token: None | dict = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_multipart_upload_part(
    url: str, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    upload_id: str, 
    part_number: int, 
    token: None | dict = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_multipart_upload_part(
    url: str, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    upload_id: str, 
    part_number: int, 
    token: None | dict = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """上传一个分块

    :param url: HTTP 请求链接
    :param file: 文件数据
    :param upload_id: 上传任务 id
    :param part_number: 分块编号（从 1 开始）
    :param token: 上传用到的令牌信息（字典）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 上传完成的分块的信息字典，包含如下字段：

        .. code:: python

            {
                "PartNumber": int,    # 分块序号，从 1 开始计数
                "LastModified": str,  # 最近更新时间
                "ETag": str,          # ETag 值，判断资源是否发生变化
                "HashCrc64ecma": int, # 校验码
                "Size": int,          # 分块大小
            }
    """
    count_in_bytes = 0
    if isinstance(file, Buffer):
        count_in_bytes = buffer_length(file)
    else:
        if isinstance(file, SupportsRead):
            if async_:
                file = bio_chunk_async_iter(file)
            else:
                file = bio_chunk_iter(cast(SupportsRead, file))
        def acc(chunk: Buffer, /):
            nonlocal count_in_bytes
            count_in_bytes += buffer_length(chunk)
        file = wrap_iter(file, callnext=acc)
    def parse_upload_part(resp, _, /) -> dict:
        headers = resp.headers
        return {
            "PartNumber": part_number, 
            "LastModified": datetime.strptime(headers["date"], "%a, %d %b %Y %H:%M:%S GMT").strftime("%FT%X.%f")[:-3] + "Z", 
            "ETag": headers["ETag"], 
            "HashCrc64ecma": int(headers["x-oss-hash-crc64ecma"]), 
            "Size": count_in_bytes, 
        }
    request_kwargs.update(
        method="PUT", 
        params={"partNumber": part_number, "uploadId": upload_id}, 
        data=file, 
    )
    request_kwargs.setdefault("parse", parse_upload_part)
    return oss_upload_request(
        url=url, 
        token=token, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_part_iter(
    url: str, 
    file: Buffer | SupportsRead | Iterable[Buffer], 
    upload_id: str, 
    partsize: int, 
    part_number_start: int = 1, 
    token: None | dict = None, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def oss_multipart_upload_part_iter(
    url: str, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    upload_id: str, 
    partsize: int, 
    part_number_start: int = 1, 
    token: None | dict = None, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def oss_multipart_upload_part_iter(
    url: str, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    upload_id: str, 
    partsize: int, 
    part_number_start: int = 1, 
    token: None | dict = None, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代器，迭代一次会上传一个分块

    .. attention::
        如果需要跳过一定的数据，请提前处理好，这个不管数据是否被重复上传

    :param url: HTTP 请求链接
    :param file: 文件数据
    :param upload_id: 上传任务 id
    :param partsize: 分块大小
    :param part_number_start: 开始的分块编号（从 1 开始）
    :param token: 上传用到的令牌信息（字典）
    :param reporthook: 回调函数，可以用来统计已上传的数据量或者展示进度条
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 上传完成的分块信息的迭代器
    """
    if isinstance(file, (Buffer, SupportsRead)):
        pass
    elif async_:
        file = bytes_iter_to_async_reader(file)
    else:
        file = bytes_iter_to_reader(cast(Iterable, file))
    def gen_step():
        chunk: Buffer | Iterator[Buffer] | AsyncIterator[Buffer]
        end_with_reporthook = reporthook is not None and isinstance(file, Buffer)
        for i, part_number in enumerate(count(part_number_start)):
            if isinstance(file, Buffer):
                chunk = memoryview(file)[i*partsize:(i+1)*partsize]
                if not chunk:
                    break
            else:
                if async_:
                    chunk = bio_chunk_async_iter(file, partsize)
                else:
                    chunk = bio_chunk_iter(cast(SupportsRead, file), partsize)
                chunk = yield peek_iter(chunk)
                if not chunk:
                    break
                chunk = cast(Iterator[Buffer] | AsyncIterator[Buffer], chunk)
                if reporthook is not None:
                    chunk = wrap_iter(chunk, callnext=lambda b: reporthook(buffer_length(b)))
            part = yield Yield(oss_multipart_upload_part(
                url=url, 
                file=chunk, # type: ignore
                upload_id=upload_id, 
                part_number=part_number, 
                token=token, 
                async_=async_, # type: ignore
                **request_kwargs, 
            ))
            if end_with_reporthook:
                reporthook(buffer_length(chunk)) # type: ignore
            if part["Size"] < partsize:
                break
    return run_gen_step_iter(gen_step, async_)


@overload
def oss_upload_init(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_upload_init(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_upload_init(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """准备分块上传，获取必要信息

    .. note::
        如果你并没有同时提供 user_id 和 user_key，则视为调用 open 接口，需要携带 "authorization" 请求头

    :param file: 待上传的文件或其路径
    :param pid: 上传文件到目录的 id
    :param filename: 文件名，若为空则自动确定
    :param filesha1: 文件的 sha1 摘要，若为空则自动计算
    :param filesize: 文件大小，若为负数则自动计算
    :param user_id: 用户 id
    :param user_key: 用户的 key
    :param endpoint: 上传目的网址
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 如果秒传成功，则返回响应信息（有 "status" 字段），否则返回上传配置信息（可用于断点续传）
    """
    use_open = not (user_id and user_key)
    def gen_step():
        nonlocal file, filename, filesha1, filesize
        upload_data: dict = {}
        if not use_open:
            upload_data["user_id"] = user_id
            upload_data["user_key"] = user_key
        read_range: Callable
        try:
            file = getattr(file, "getbuffer")()
        except (AttributeError, TypeError):
            pass
        if isinstance(file, Buffer):
            data = file
            filesize = buffer_length(data)
            if filesize == 0:
                filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
            elif not filesha1:
                filesha1 = sha1(data).hexdigest()
            def read_range(sign_check: str, /) -> bytes:
                start, end = map(int, sign_check.split("-"))
                return memoryview(data)[start:end+1].tobytes()
        elif isinstance(file, SupportsRead):
            if not filename:
                from os.path import basename
                filename = getattr(file, "name", "")
                filename = basename(filename)
            if not filesha1:
                if filesize == 0:
                    filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
                else:
                    if async_:
                        filesize, filesha1_obj = yield file_digest_async(file, "sha1")
                    else:
                        filesize, filesha1_obj = file_digest(file, "sha1")
                    filesha1 = filesha1_obj.hexdigest()
            if filesize < 0:
                try:
                    fileno = getattr(file, "fileno")()
                    filesize = fstat(fileno).st_size
                except (AttributeError, TypeError, OSError):
                    for attr in ("length", "getlength", "__len__"):
                        if hasattr(file, attr):
                            length = getattr(file, attr)
                            if callable(length):
                                length = length()
                            if async_ and isawaitable(length):
                                length = yield length
                            filesize = length
                            break
                    else:
                        seek = getattr(file, "seek")
                        if async_:
                            filesize = yield ensure_async(seek, threaded=True)(0, 2)
                        else:
                            filesize = seek(0, 2)
            reader: Any = file
            if async_:
                async def read_range(sign_check: str, /) -> bytes:
                    start, end = map(int, sign_check.split("-"))
                    await ensure_async(reader.seek, threaded=True)(start)
                    return await ensure_async(reader.read, threaded=True)(end - start + 1)
            else:
                def read_range(sign_check: str, /) -> bytes:
                    start, end = map(int, sign_check.split("-"))
                    reader.seek(start)
                    return reader.read(end - start + 1)
        else:
            path = file
            is_url = False
            if isinstance(path, str):
                is_url = path.startswith(("http://", "https://"))
            elif isinstance(path, (URL, SupportsGeturl)):
                is_url = True
                if isinstance(path, URL):
                    path = str(path)
                else:
                    path = path.geturl()
            else:
                path = fsdecode(path)
            path = cast(str, path)
            if not filesha1:
                if filesize == 0:
                    filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
                else:
                    if is_url:
                        if async_:
                            from httpfile import AsyncHTTPFileReader
                            async def process():
                                reader = await AsyncHTTPFileReader.new(path, headers=_HEADERS)
                                async with reader:
                                    return await file_digest_async(reader, "sha1")
                            filesize, filesha1_obj = yield process()
                        else:
                            from httpfile import HTTPFileReader
                            with HTTPFileReader(path, headers=_HEADERS) as reader:
                                filesize, filesha1_obj = file_digest(reader, "sha1")
                    else:
                        def make_hash(path, /):
                            with open(path, "rb") as file:
                                return file_digest(file, "sha1")
                        if async_:
                            filesize, filesha1_obj = yield to_thread(make_hash, path)
                        else:
                            filesize, filesha1_obj = make_hash(path)
                filesha1 = filesha1_obj.hexdigest()
            if filesize < 0:
                if is_url:
                    from http_client_request import request
                    if async_:
                        response = yield to_thread(request, path)
                    else:
                        response = request(path)
                    if not filename:
                        filename = get_filename(response)
                    with response:
                        length = get_total_length(response)
                        if length is None:
                            raise ValueError(f"can't get file size: {path!r}")
                        filesize = length
                else:
                    filesize = stat(path).st_size
            if not filename:
                if is_url:
                    from posixpath import basename
                    from urllib.parse import unquote
                    filename = basename(unquote(urlsplit(path).path))
                else:
                    from os.path import basename
                    filename = basename(path)
            def read_range(sign_check: str, /) -> bytes:
                if is_url:
                    from http_client_request import request
                    headers: dict = {**_HEADERS, "range": "bytes="+sign_check}
                    with request(path, headers=headers) as response:
                        return response.read()
                else:
                    start, end = map(int, sign_check.split("-"))
                    with open(path, "rb") as reader:
                        reader.seek(start)
                        return reader.read(end - start + 1)
        if not filename:
            filename = str(uuid4())
        filesha1 = filesha1.upper()
        if isinstance(pid, str) and pid.startswith("U_"):
            target = pid
        else:
            target = f"U_1_{pid or 0}"
        upload_data.update(filename=filename, filesha1=filesha1, filesize=filesize, target=target)
        if use_open:
            payload = {
                "fileid": filesha1, 
                "file_name": filename, 
                "file_size": filesize, 
                "target": target, 
            }
            do_upload_init = upload_init_open
        else:
            payload = {
                "fileid": filesha1, 
                "filename": filename, 
                "filesize": filesize, 
                "target": target, 
                "userid": user_id, 
                "userkey": user_key, 
            }
            do_upload_init = upload_init
        resp = data = yield do_upload_init(payload, async_=async_, **request_kwargs)
        if use_open:
            if not resp["state"]:
                return resp
            data = resp["data"]
        status = data["status"]
        if status == 7:
            sign_key: str = data["sign_key"]
            sign_check: str = data["sign_check"]
            payload["sign_key"] = sign_key
            if async_:
                read_range = ensure_async(read_range, threaded=True)
            data = yield read_range(sign_check)
            payload["sign_val"] = sha1(data).hexdigest().upper()
            resp = data = yield do_upload_init(payload, async_=async_, **request_kwargs)
            if use_open:
                if not resp["state"]:
                    return resp
                data = resp["data"]
            status = data["status"]
        if status == 2:
            if use_open:
                pickcode = data["pick_code"]
            else:
                pickcode = resp["pickcode"]
            upload_data["pickcode"] = pickcode
            upload_data["id"] = pickcode_to_id(pickcode)
            resp["state"] = True
            resp["reuse"] = True
        elif status == 1:
            resp["state"] = True
            resp["reuse"] = False
            upload_data["callback"] = data["callback"]
            upload_data["bucket"] = data["bucket"]
            upload_data["object"] = data["object"]
            upload_data["url"] = upload_endpoint_url(data["object"], data["bucket"], endpoint=endpoint)
            resp["data"] = upload_data
        else:
            resp["state"] = False
            resp["reuse"] = False
        if use_open:
            data.update(upload_data)
        else:
            resp["data"] = upload_data
        return resp
    return run_gen_step(gen_step, async_)


@overload
def oss_upload(
    file: Buffer | SupportsRead | Iterable[Buffer], 
    callback: dict, 
    url: str = "", 
    token: None | dict = None, 
    reporthook: None | Callable[[int], Any] = None, 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_upload(
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    callback: dict, 
    url: str = "", 
    token: None | dict = None, 
    reporthook: None | Callable[[int], Any] = None, 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_upload(
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    callback: dict, 
    url: str = "", 
    token: None | dict = None, 
    reporthook: None | Callable[[int], Any] = None, 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """一次性上传文件到阿里云 OSS

    :param file: 文件数据
    :param callback: 回调数据
    :param url: HTTP 请求链接
    :param token: 上传用到的令牌信息（字典）
    :param reporthook: 回调函数，可以用来统计已上传的数据量或者展示进度条
    :param endpoint: 上传目的网址（如果未提供 url 的话）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    if reporthook is not None:
        if isinstance(file, Buffer):
            if async_:
                file = bytes_to_chunk_async_iter(file)
            else:
                file = bytes_to_chunk_iter(file)
        elif isinstance(file, SupportsRead):
            if async_:
                file = bio_chunk_async_iter(file)
            else:
                file = bio_chunk_iter(file)
        file = wrap_iter(file, callnext=lambda b: reporthook(buffer_length(b)))
    def gen_step():
        nonlocal url
        if not url:
            resp = yield upload_resume(callback, async_=async_, **request_kwargs)
            if resp["status"] != 1:
                resp["state"] = False
                return resp
            url = upload_endpoint_url(resp["object"], resp["bucket"], endpoint=endpoint)
        elif not url.startswith(("http://", "https://")):
            url = upload_endpoint_url(url, endpoint=endpoint)
        request_kwargs.update(
            method="PUT", 
            data=file, 
            headers=dict_update(
            dict(request_kwargs.get("headers") or ()), 
                {
                    "x-oss-callback": to_base64(callback["callback"]), 
                    "x-oss-callback-var": to_base64(callback["callback_var"]), 
                }, 
            ), 
        )
        return oss_upload_request(
            url=url, 
            token=token, 
            async_=async_, 
            **request_kwargs, 
        )
    return run_gen_step(gen_step, async_)


@overload
def oss_multipart_upload(
    file: Buffer | SupportsRead | Iterable[Buffer], 
    callback: dict, 
    url: str = "", 
    upload_id: None | str = None, 
    partsize: int = 1024 * 1024 * 10, 
    parts: None | list[dict] = None, 
    token: None | dict = None, 
    reporthook: None | Callable[[int], Any] = None, 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_multipart_upload(
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    callback: dict, 
    url: str = "", 
    upload_id: None | str = None, 
    partsize: int = 1024 * 1024 * 10, 
    parts: None | list[dict] = None, 
    token: None | dict = None, 
    reporthook: None | Callable[[int], Any] = None, 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_multipart_upload(
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    callback: dict, 
    url: str = "", 
    upload_id: None | str = None, 
    partsize: int = 1024 * 1024 * 10, 
    parts: None | list[dict] = None, 
    token: None | dict = None, 
    reporthook: None | Callable[[int], Any] = None, 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """分块上传文件到阿里云 OSS

    .. attention::
        如果需要跳过一定的数据，请提前处理好，这个不管数据是否被重复上传    

    :param file: 文件数据
    :param callback: 回调数据
    :param url: HTTP 请求链接
    :param upload_id: 上传任务 id
    :param partsize: 分块大小
    :pamra parts: 已完成的分块信息列表
    :param token: 上传用到的令牌信息（字典）
    :param reporthook: 回调函数，可以用来统计已上传的数据量或者展示进度条
    :param endpoint: 上传目的网址（如果未提供 url 的话）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    if partsize <= 0:
        partsize = 1024 * 1024 * 10
    def gen_step():
        nonlocal url, upload_id, parts
        if not url or upload_id:
            resp = yield upload_resume(callback, async_=async_, **request_kwargs)
            if resp["status"] != 1:
                resp["state"] = False
                return resp
            if not url or not url.startswith(("http://", "https://")):
                url = upload_endpoint_url(resp["object"], resp["bucket"], endpoint=endpoint)
        if not url.startswith(("http://", "https://")):
            url = upload_endpoint_url(url, endpoint=endpoint)
        if not upload_id:
            upload_id = yield oss_multipart_upload_init(
                url=url, 
                token=token, 
                async_=async_, 
                **request_kwargs, 
            )
            upload_id = cast(str, upload_id)
            if parts is None:
                parts = []
            else:
                assert not parts
        elif parts is None:
            parts = []
            yield foreach(
                parts.append, 
                oss_multipart_part_iter(
                    url=url, 
                    upload_id=upload_id, 
                    token=token, 
                    async_=async_, 
                    **request_kwargs, 
                ), 
            )
        yield foreach(
            parts.append, 
            oss_multipart_upload_part_iter(
                url=url, 
                file=file, # type: ignore
                upload_id=upload_id, 
                partsize=partsize, 
                part_number_start=len(parts)+1, 
                token=token, 
                reporthook=reporthook, 
                async_=async_, # type: ignore
                **request_kwargs, 
            ), 
        )
        return (yield oss_multipart_upload_complete(
            url=url, 
            callback=callback, 
            upload_id=upload_id, 
            parts=parts, 
            token=token, 
            async_=async_, 
            **request_kwargs, 
        ))
    return run_gen_step(gen_step, async_)


@overload
def upload(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    partsize: int = 0, 
    callback: None | dict = None, 
    upload_id: str = "", 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    partsize: int = 0, 
    callback: None | dict = None, 
    upload_id: str = "", 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    partsize: int = 0, 
    callback: None | dict = None, 
    upload_id: str = "", 
    endpoint: str = "http://oss-cn-shenzhen.aliyuncs.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """上传文件

    .. note::
        如果提供了 ``callback``，则强制为分块上传。
        此时，最好提供一下 ``upload_id``，否则就是从头开始。
        此时可以省略 ``pid``、``filename``、``filesha1``、``filesize``、``user_id``、``user_key``、``partsize``

    .. caution::
        ``partsize > 0`` 时，不要把 ``partsize`` 设置得太小，起码得 10 MB (10485760) 以上

    :param file: 待上传的文件或其路径
    :param pid: 上传文件到目录的 id
    :param filename: 文件名，若为空则自动确定
    :param filesha1: 文件的 sha1 摘要，若为空则自动计算
    :param filesize: 文件大小，若为负数则自动计算
    :param user_id: 用户 id
    :param user_key: 用户的 key
    :param partsize: 分块大小（如果为 0，则不是分块上传；如果 <0，则自动确定）
    :param callback: 回调数据
    :param upload_id: 上传任务 id
    :param endpoint: 上传目的网址
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    def gen_step():
        nonlocal file, partsize, callback
        parts: None | list[dict] = None
        skip_size = 0
        if callback:
            resp = yield upload_resume(callback, async_=async_, **request_kwargs)
            if not resp["state"]:
                return resp
            url = upload_endpoint_url(resp["object"], resp["bucket"], endpoint=endpoint)
            if upload_id:
                parts = []
                yield foreach(
                    parts.append, 
                    oss_multipart_part_iter(
                        url=url, 
                        upload_id=upload_id, 
                        async_=async_, 
                        **request_kwargs, 
                    ), 
                )
                skip_size = sum(p["Size"] for p in parts)
        else:
            resp = yield oss_upload_init(
                file=file, 
                pid=pid, 
                filename=filename, 
                filesha1=filesha1, 
                filesize=filesize, 
                user_id=user_id, 
                user_key=user_key, 
                endpoint=endpoint, 
                async_=async_, 
                **request_kwargs, 
            )
            if not resp["state"] or resp["reuse"]:
                return resp
            upload_data = resp["data"]
            url = upload_data["url"]
            callback = upload_data["callback"]
            if partsize:
                if partsize < 0:
                    partsize = determine_partsize(upload_data["filesize"])
            else:
                if isinstance(file, SupportsRead):
                    seek = getattr(file, "seek")
                    if async_:
                        yield ensure_async(seek, threaded=True)(0)
                    else:
                        seek(0)
                elif not isinstance(file, Buffer):
                    path = file
                    is_url = False
                    if isinstance(path, str):
                        is_url = path.startswith(("http://", "https://"))
                    elif isinstance(path, (URL, SupportsGeturl)):
                        is_url = True
                        if isinstance(path, URL):
                            path = str(path)
                        else:
                            path = path.geturl()
                    else:
                        path = fsdecode(path)
                    path = cast(str, path)
                    if is_url:
                        if async_:
                            from httpfile import AsyncHTTPFileReader
                            async def process():
                                return await AsyncHTTPFileReader.new(cast(str, path), headers=_HEADERS)
                            file = yield process()
                        else:
                            from httpfile import HTTPFileReader
                            file = HTTPFileReader(path, headers=_HEADERS)
                    else:
                        file = open(path, "rb")
                file = cast(Buffer | SupportsRead, file)
                return oss_upload(
                    file, 
                    callback=callback, 
                    url=url, 
                    async_=async_, 
                    **request_kwargs, 
                )
        if isinstance(file, SupportsRead):
            seek = getattr(file, "seek")
            if async_:
                yield ensure_async(seek, threaded=True)(skip_size)
            else:
                seek(skip_size)
        elif not isinstance(file, Buffer):
            path = file
            is_url = False
            if isinstance(path, str):
                is_url = path.startswith(("http://", "https://"))
            elif isinstance(path, (URL, SupportsGeturl)):
                is_url = True
                if isinstance(path, URL):
                    path = str(path)
                else:
                    path = path.geturl()
            else:
                path = fsdecode(path)
            path = cast(str, path)
            if is_url:
                if async_:
                    from httpfile import AsyncHTTPFileReader
                    async def process():
                        return await AsyncHTTPFileReader.new(path, headers=_HEADERS, start=skip_size)
                    file = yield process()
                else:
                    from httpfile import HTTPFileReader
                    file = HTTPFileReader(path, headers=_HEADERS, start=skip_size)
            else:
                file = open(path, "rb")
                if skip_size:
                    file.seek(skip_size)
        file = cast(Buffer | SupportsRead, file)
        return oss_multipart_upload(
            file=file, 
            callback=callback, 
            url=url, 
            upload_id=upload_id, 
            partsize=partsize, 
            parts=parts, 
            async_=async_, 
            **request_kwargs, 
        )
    return run_gen_step(gen_step, async_)

# TODO: 先用着，如果发现分块上传用断点续传，而有些已经上传的分块因为中途失败，导致上传的块太小，导致最后合并时报错，那么以后就要跳过这些分块（这是 partsize 会有一个限制的最小值，例如 64 KB，小于此值，则分块会被忽略）
