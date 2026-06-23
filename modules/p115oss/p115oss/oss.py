#!/usr/bin/env python3
# encoding: utf-8

# NOTE: 参考代码: https://github.com/aliyun/aliyun-oss-python-sdk

__all__ = [
    "oss_request", "oss_multipart_upload_init", "oss_upload_url", 
    "oss_multipart_upload_url", "oss_multipart_upload_cancel", 
    "oss_multipart_upload_complete", "oss_multipart_list_parts", 
    "oss_multipart_part_iter", "oss_upload", "oss_multipart_upload_part", 
    "oss_multipart_upload_part_iter", "oss_multipart_upload", 
]

from base64 import b64encode
from collections import UserString
from collections.abc import (
    AsyncIterable, AsyncIterator, Buffer, Callable, 
    Coroutine, Iterable, Iterator, Mapping, 
)
from datetime import datetime
from email.utils import formatdate
from hashlib import md5
from hmac import digest as hmac_digest
from inspect import isawaitable
from itertools import count
from typing import cast, overload, Any, Final, Literal
from urllib.parse import urlsplit, parse_qsl, urlencode
from xml.etree.ElementTree import fromstring

from dicttools import iter_items, dict_update
from filewrap import (
    SupportsRead, buffer_length, 
    bio_chunk_iter, bio_chunk_async_iter, 
    bytes_iter_to_async_reader, bytes_iter_to_reader, 
    bytes_to_chunk_iter, bytes_to_chunk_async_iter, 
)
from http_request import complete_url
from http_response import get_status_code
from integer_tool import try_parse_int
from iterutils import (
    foreach, peek_iter, run_gen_step, run_gen_step_iter, 
    wrap_iter, Yield, YieldFrom, 
)


SUBRESOURCE_KEYS: Final = {
    "accessPoint", "accessPointPolicy", "acl", "append", "asyncFetch", "bucketArchiveDirectRead", 
    "bucketInfo", "callback", "callback-var", "cname", "comp", "continuation-token", "cors", 
    "delete", "encryption", "endTime", "group", "httpsConfig", "inventory", "inventoryId", 
    "lifecycle", "link", "live", "location", "logging", "metaQuery", "objectInfo", "objectMeta", 
    "partNumber", "policy", "position", "publicAccessBlock", "qos", "qosInfo", "qosRequester", 
    "redundancyTransition", "referer", "regionList", "replication", "replicationLocation", 
    "replicationProgress", "requestPayment", "requesterQosInfo", "resourceGroup", "resourcePool", 
    "resourcePoolBuckets", "resourcePoolInfo", "response-cache-control", "response-content-disposition", 
    "response-content-encoding", "response-content-language", "response-content-type", "response-expires", 
    "restore", "security-token", "sequential", "startTime", "stat", "status", "style", "styleName", 
    "symlink", "tagging", "transferAcceleration", "uploadId", "uploads", "versionId", "versioning", 
    "versions", "vod", "website", "worm", "wormExtend", "wormId", "x-oss-ac-forward-allow", 
    "x-oss-ac-source-ip", "x-oss-ac-subnet-mask", "x-oss-ac-vpc-id", "x-oss-access-point-name", 
    "x-oss-async-process", "x-oss-process", "x-oss-redundancy-transition-taskid", "x-oss-request-payer", 
    "x-oss-target-redundancy-type", "x-oss-traffic-limit", "x-oss-write-get-object-response", 
}
DEFAULT_ENDPOINT: Final = "http://oss-cn-shenzhen.aliyuncs.com"
DEFAULT_BUCKET: Final = "fhnfile"


def to_base64(s: Buffer | str | UserString, /) -> str:
    """帮助函数：把数据转化为 Base64 编码的文本
    """
    if isinstance(s, (str, UserString)):
        s = s.encode("utf-8")
    return str(b64encode(s), "ascii")


def parse_upload_id(_, content: Buffer, /) -> str:
    """帮助函数：从响应中提取 "UploadId"
    """
    return getattr(fromstring(content).find("UploadId"), "text")


def parse_list_parts(_, content: Buffer, /) -> dict:
    """帮助函数：从响应中提取分块信息
    """
    etree = fromstring(content)
    result = {
        "parts": [
            {sel.tag: try_parse_int(sel.text) for sel in el} 
            for el in etree.iterfind("Part")
        ]
    }
    for el in etree:
        if el.tag == "Part":
            break
        result[el.tag] = try_parse_int(el.text)
    return result


def oss_url(
    url_or_key: str = "", 
    /, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    request_kwargs: None | dict = None, 
) -> str:
    """帮助函数：构建实际请求的 URL

    :param url_or_key: url 或 key (或称 object)
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param request_kwargs: 其它请求参数
    """
    if url_or_key.startswith(("http://", "https://")):
        url = url_or_key
    else:
        if bucket is DEFAULT_BUCKET and endpoint is DEFAULT_ENDPOINT:
            url = "http://fhnfile.oss-cn-shenzhen.aliyuncs.com/"
        else:
            urlp = urlsplit(endpoint)
            host = urlp.hostname or "oss-cn-shenzhen"
            if "." not in host:
                host += ".aliyuncs.com"
            url = f"{urlp.scheme or "http"}://{bucket}.{host}/"
        if url_or_key:
            url += url_or_key
    if request_kwargs and (params := request_kwargs.pop("params", None)):
        url = complete_url(url, params=params)
    return url


def oss_sign(
    token: dict, 
    method: str, 
    url: str, 
    headers: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
) -> dict:
    """计算然后返回带认证信息的请求头

    :param token: 令牌信息
    :param method: HTTP 请求方法
    :param url: HTTP 请求链接
    :param headers: HTTP 请求头

    :return: 带认证信息的请求头
    """
    urlp = urlsplit(url)
    bucket = cast(str, urlp.hostname).partition(".")[0]
    headers = {k.lower(): v for k, v in iter_items(headers or ())}
    headers["x-oss-security-token"] = token["SecurityToken"]
    date = headers["date"] = headers.get("x-oss-date") or headers.get("date") or formatdate(usegmt=True)
    path = urlp.path or "/"
    if query := urlp.query or "":
        query = urlencode(sorted((k, v) for k, v in parse_qsl(query) if k in SUBRESOURCE_KEYS))
    if query:
        query = "?" + query
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
/{bucket}{path}{query}""".encode("utf-8"), 
        "sha1", 
    ))
    headers["authorization"] = "OSS {0}:{1}".format(token["AccessKeyId"], signature)
    return headers


def oss_request(
    url_or_key: str = "", 
    /, 
    method: str = "GET", 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    request: None | Callable = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """请求阿里云 OSS 的公用函数

    :param url_or_key: url 或 key (或称 object)
    :param method: HTTP 请求方法
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param request: 调用以执行 HTTP 请求
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口返回数据
    """
    request_kwargs.setdefault("parse", True)
    def gen_step():
        nonlocal endpoint, request, token
        if request is None:
            from urllib3_future_request import request
            request = cast(Callable, request)
        if not endpoint:
            from .api import upload_url
            resp = yield upload_url(request=request, async_=async_)
            endpoint = resp["endpoint"]
        url = oss_url(
            url_or_key, 
            bucket=bucket, 
            endpoint=endpoint, 
            request_kwargs=request_kwargs, 
        )
        if not token:
            from .api import _upload_token
            token = yield _upload_token(request=request, async_=async_)
        request_kwargs["headers"] = oss_sign(
            token=token, 
            method=method, 
            url=url, 
            headers=request_kwargs.get("headers"), 
        )
        return request(
            url=url, 
            method=method, 
            **request_kwargs, 
        )
    return run_gen_step(gen_step, async_)


def oss_upload_url(
    url_or_key: str, 
    /, 
    callback: dict, 
    token: dict, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
) -> dict:
    """获取分块上传的方法、链接和请求头

    :param url_or_key: url 或 key (或称 object)
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址

    :return: 字典，包含 "method"、"url" 和 "headers"
    """
    url = oss_url(
        url_or_key, 
        bucket=bucket, 
        endpoint=endpoint, 
    )
    headers = oss_sign(token, "PUT", url)
    headers["x-oss-callback"] = to_base64(callback["callback"])
    headers["x-oss-callback-var"] = to_base64(callback["callback_var"])
    return {
        "method": "PUT", 
        "url": url, 
        "headers": headers, 
    }


def oss_multipart_upload_url(
    url_or_key: str, 
    /, 
    upload_id: int | str, 
    token: dict, 
    part_number: int = 1, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
) -> dict:
    """获取分块上传的方法、链接和请求头

    :param url_or_key: url 或 key (或称 object)
    :param upload_id: 上传任务的 id
    :param token: 令牌信息
    :param part_number: 分块编号（从 1 开始）
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址

    :return: 字典，包含 "method"、"url" 和 "headers"
    """
    url = oss_url(
        url_or_key, 
        bucket=bucket, 
        endpoint=endpoint, 
    )
    url = complete_url(url, params={"partNumber": part_number, "uploadId": upload_id})
    return {
        "method": "PUT", 
        "url": url, 
        "headers": oss_sign(token, "PUT", url)
    }


@overload
def oss_multipart_upload_init(
    url_or_key: str, 
    /, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> str:
    ...
@overload
def oss_multipart_upload_init(
    url_or_key: str, 
    /, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, str]:
    ...
def oss_multipart_upload_init(
    url_or_key: str, 
    /, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> str | Coroutine[Any, Any, str]:
    """初始化，以获取分块上传任务的 id

    :param url_or_key: url 或 key (或称 object)
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 分块上传任务的 id
    """
    request_kwargs.setdefault("params", {"sequential": "1", "uploads": "1"})
    request_kwargs.setdefault("parse", parse_upload_id)
    return oss_request(
        url_or_key, 
        method="POST", 
        token=token, 
        bucket=bucket, 
        endpoint=endpoint, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_cancel(
    url_or_key: str, 
    /, 
    upload_id: str, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> bool:
    ...
@overload
def oss_multipart_upload_cancel(
    url_or_key: str, 
    /, 
    upload_id: str, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, bool]:
    ...
def oss_multipart_upload_cancel(
    url_or_key: str, 
    /, 
    upload_id: str, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> bool | Coroutine[Any, Any, bool]:
    """取消分块上传任务

    :param url_or_key: url 或 key (或称 object)
    :param upload_id: 上传任务 id
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 是否成功
    """
    request_kwargs.setdefault("raise_for_status", False)
    request_kwargs.setdefault(
        "parse", 
        lambda resp, _: (code := get_status_code(resp)) == 404 or 200 <= code < 300, 
    )
    return oss_request(
        url_or_key, 
        method="DELETE", 
        params={"uploadId": upload_id}, 
        token=token, 
        bucket=bucket, 
        endpoint=endpoint, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_complete(
    url_or_key: str, 
    /, 
    upload_id: str, 
    parts: list[dict], 
    callback: dict, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_multipart_upload_complete(
    url_or_key: str, 
    /, 
    upload_id: str, 
    parts: list[dict], 
    callback: dict, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_multipart_upload_complete(
    url_or_key: str, 
    /, 
    upload_id: str, 
    parts: list[dict], 
    callback: dict, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """完成分块上传任务

    :param url_or_key: url 或 key (或称 object)
    :param upload_id: 上传任务 id
    :pamra parts: 分块信息列表
    :param callback: 回调数据
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    request_kwargs.update(
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
    return oss_request(
        url_or_key, 
        method="POST", 
        token=token, 
        bucket=bucket, 
        endpoint=endpoint, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_list_parts(
    key: str, 
    params: str | dict, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def oss_multipart_list_parts(
    key: str, 
    params: str | dict, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def oss_multipart_list_parts(
    key: str, 
    params: str | dict, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """罗列某个分块上传任务的分块信息

    :param url_or_key: url 或 key (或称 object)
    :param params: 请求参数

        - uploadId: str 💡 上传 id
        - part-number-marker: int = 0 💡 从这个序号开始（不含）
        - max-parts: int = 1000 💡 最多获取数据条数，取值范围是 1~1000

    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数    

    :return: 接口返回信息为 XML 文本，被转化成 dict
    """
    if not isinstance(params, dict):
        params = {"uploadId": params}
    request_kwargs.setdefault("parse", parse_list_parts)
    return oss_request(
        key, 
        params=params, 
        bucket=bucket, 
        endpoint=endpoint, 
        token=token, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_part_iter(
    url_or_key: str, 
    /, 
    upload_id: str, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def oss_multipart_part_iter(
    url_or_key: str, 
    /, 
    upload_id: str, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def oss_multipart_part_iter(
    url_or_key: str, 
    /, 
    upload_id: str, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """罗列某个分块上传任务的所有分块信息

    :param url_or_key: url 或 key (或称 object)
    :param upload_id: 上传任务的 id
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数    

    :return: 分块信息的迭代器
    """
    def gen_step():
        url = oss_url(
            url_or_key, 
            bucket=bucket, 
            endpoint=endpoint, 
            request_kwargs=request_kwargs, 
        )
        last_maker = 0
        while True:
            result = yield oss_multipart_list_parts(
                url, 
                {"uploadId": upload_id, "part-number-marker": last_maker}, 
                token=token, 
                async_=async_, 
                **request_kwargs, 
            )
            yield YieldFrom(result["parts"])
            if not result["IsTruncated"]:
                break
            last_maker = result["NextPartNumberMarker"]
    return run_gen_step_iter(gen_step, async_)


@overload
def oss_upload(
    url_or_key: str, 
    /, 
    file: Buffer | SupportsRead | Iterable[Buffer], 
    callback: dict, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_upload(
    url_or_key: str, 
    /, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    callback: dict, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_upload(
    url_or_key: str, 
    /, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    callback: dict, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """整个文件一次上传

    :param url_or_key: url 或 key (或称 object)
    :param file: 文件数据
    :param callback: 回调数据
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param reporthook: 回调函数，可以用来统计已上传的数据量或者展示进度条
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
    headers = request_kwargs["headers"] = dict(request_kwargs.get("headers") or ())
    headers["x-oss-callback"] = to_base64(callback["callback"])
    headers["x-oss-callback-var"] = to_base64(callback["callback_var"])
    return oss_request(
        url_or_key, 
        method="PUT", 
        data=file, 
        token=token, 
        bucket=bucket, 
        endpoint=endpoint, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_part(
    url_or_key: str, 
    /, 
    upload_id: str, 
    file: Buffer | SupportsRead | Iterable[Buffer], 
    part_number: int = 1, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_multipart_upload_part(
    url_or_key: str, 
    /, 
    upload_id: str, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    part_number: int = 1, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_multipart_upload_part(
    url_or_key: str, 
    /, 
    upload_id: str, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    part_number: int = 1, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """上传一个分块

    :param url_or_key: url 或 key (或称 object)
    :param upload_id: 上传任务 id
    :param file: 文件数据
    :param part_number: 分块编号（从 1 开始）
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param reporthook: 回调函数，可以用来统计已上传的数据量或者展示进度条
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
    count_in_bytes = 0
    hashobj = md5()
    def acc(chunk: Buffer, /):
        nonlocal count_in_bytes
        count_in_bytes += buffer_length(chunk)
        hashobj.update(chunk)
        if reporthook is not None:
            return reporthook(count_in_bytes)
    file = wrap_iter(file, callnext=acc)
    def parse_upload_part(resp, _, /) -> dict:
        headers = resp.headers
        md5 = hashobj.hexdigest().upper()
        server_md5 = headers["ETag"].strip('"')
        if md5 != server_md5:
            raise OSError(5, f"the server side failed to submit data, because of the md5 does not match {md5!r} != {server_md5!r}")
        return {
            "PartNumber": part_number, 
            "LastModified": datetime.strptime(headers["date"], "%a, %d %b %Y %H:%M:%S GMT").strftime("%FT%X.%f")[:-3] + "Z", 
            "ETag": headers["ETag"], 
            "HashCrc64ecma": int(headers["x-oss-hash-crc64ecma"]), 
            "Size": count_in_bytes, 
        }
    request_kwargs.setdefault("parse", parse_upload_part)
    return oss_request(
        url_or_key, 
        method="PUT", 
        params={"partNumber": part_number, "uploadId": upload_id}, 
        data=file, 
        token=token, 
        bucket=bucket, 
        endpoint=endpoint, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_part_iter(
    url_or_key: str, 
    /, 
    upload_id: str, 
    file: Buffer | SupportsRead | Iterable[Buffer], 
    part_number_start: int = 1, 
    partsize: int = 1024 * 1024 * 100, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def oss_multipart_upload_part_iter(
    url_or_key: str, 
    /, 
    upload_id: str, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    part_number_start: int = 1, 
    partsize: int = 1024 * 1024 * 100, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def oss_multipart_upload_part_iter(
    url_or_key: str, 
    /, 
    upload_id: str, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    part_number_start: int = 1, 
    partsize: int = 1024 * 1024 * 100, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代器，迭代一次会上传一个分块

    .. attention::
        如果需要跳过一定的数据，请提前处理好，这个不管数据是否被重复上传

    :param url_or_key: url 或 key (或称 object)
    :param upload_id: 上传任务 id
    :param file: 文件数据
    :param part_number_start: 开始的分块编号（从 1 开始）
    :param partsize: 分块大小
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param reporthook: 回调函数，可以用来统计已上传的数据量或者展示进度条
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 上传完成的分块信息的迭代器
    """
    def gen_step():
        nonlocal file
        if isinstance(file, Buffer):
            file = memoryview(file)
        elif not isinstance(file, SupportsRead):
            if async_:
                file = bytes_iter_to_async_reader(file)
            else:
                file = bytes_iter_to_reader(cast(Iterable, file))
        chunk: memoryview | Iterator[Buffer] | AsyncIterator[Buffer]
        for part_number in count(part_number_start):
            if isinstance(file, memoryview):
                chunk = file[:partsize]
                if not chunk:
                    break
                file = file[partsize:]
            else:
                if async_:
                    chunk = bio_chunk_async_iter(file, partsize)
                else:
                    chunk = bio_chunk_iter(cast(SupportsRead, file), partsize)
                chunk = yield peek_iter(chunk)
                if chunk is None:
                    break
                if reporthook is not None:
                    chunk = wrap_iter(
                        chunk, # type: ignore[arg-type]
                        callnext=lambda b, /: reporthook(buffer_length(b)), 
                    )
            part = yield oss_multipart_upload_part(
                url_or_key, 
                upload_id=upload_id, 
                file=chunk, # type: ignore[arg-type]
                part_number=part_number, 
                token=token, 
                bucket=bucket, 
                endpoint=endpoint, 
                async_=async_, # type: ignore[arg-type]
                **request_kwargs, 
            )
            if reporthook is not None and isinstance(chunk, memoryview):
                ret = reporthook(len(chunk))
                if async_ and isawaitable(ret):
                    yield ret
            yield Yield(part)
            size = part["Size"]
            if size < partsize:
                break
    return run_gen_step_iter(gen_step, async_)


@overload
def oss_multipart_upload(
    url_or_key: str, 
    /, 
    upload_id: str, 
    file: Buffer | SupportsRead | Iterable[Buffer], 
    callback: dict, 
    partsize: int = 1024 * 1024 * 100, 
    parts: None | list[dict] = None, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_multipart_upload(
    url_or_key: str, 
    /, 
    upload_id: str, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    callback: dict, 
    partsize: int = 1024 * 1024 * 100, 
    parts: None | list[dict] = None, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_multipart_upload(
    url_or_key: str, 
    /, 
    upload_id: str, 
    file: Buffer | SupportsRead | Iterable[Buffer] | AsyncIterable[Buffer], 
    callback: dict, 
    partsize: int = 1024 * 1024 * 100, 
    parts: None | list[dict] = None, 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """分块上传文件

    .. attention::
        如果需要跳过一定的数据，请提前处理好，这个不管数据是否被重复上传    

    .. note::
        1. 允许每次上传的分块大小不同
        2. 最后提交分块的时候（即 ``oss_multipart_upload_complete`` 的 ``parts`` 参数），可以只选择其中一些分块信息进行提交（而忽略掉那些有问题的分块，因为后面又有重新上传了）
        3. 除了最后一个分块，其它分块上传的大小必须 >= 100 KB，如果不足，那么即使成功上传，此分块也要被忽略，否则是会报错的

    :param url_or_key: url 或 key (或称 object)
    :param upload_id: 上传任务 id
    :param file: 文件数据
    :param callback: 回调数据
    :param partsize: 分块大小
    :pamra parts: 已完成的分块信息列表
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param reporthook: 回调函数，可以用来统计已上传的数据量或者展示进度条
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    if partsize <= 0:
        partsize = 1024 * 1024 * 100
    else:
        partsize = max(partsize, 1024 * 100)
    def gen_step():
        nonlocal parts
        if parts is None:
            parts = []
            yield foreach(
                parts.append, 
                oss_multipart_part_iter(
                    url_or_key, 
                    upload_id=upload_id, 
                    token=token, 
                    bucket=bucket, 
                    endpoint=endpoint, 
                    async_=async_, 
                    **request_kwargs, 
                ), 
            )
        yield foreach(
            parts.append, 
            oss_multipart_upload_part_iter(
                url_or_key, 
                upload_id=upload_id, 
                file=file, # type: ignore[arg-type]
                part_number_start=len(parts)+1, 
                partsize=partsize, 
                token=token, 
                bucket=bucket, 
                endpoint=endpoint, 
                reporthook=reporthook, 
                async_=async_, # type: ignore[arg-type]
                **request_kwargs, 
            ), 
        )
        parts = [*(p for p in parts[:-1] if p["Size"] >= 1024 * 100), parts[-1]]
        return oss_multipart_upload_complete(
            url_or_key, 
            upload_id=upload_id, 
            parts=parts, 
            callback=callback, 
            token=token, 
            bucket=bucket, 
            endpoint=endpoint, 
            async_=async_, 
            **request_kwargs, 
        )
    return run_gen_step(gen_step, async_)

