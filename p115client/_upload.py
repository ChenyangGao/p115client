#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "make_dataiter", "oss_upload_sign", "oss_upload_request", "oss_multipart_upload_init", 
    "oss_multipart_upload_complete", "oss_multipart_upload_cancel", "oss_multipart_upload_part", 
    "oss_multipart_upload_part_iter", "oss_multipart_part_iter", "oss_upload", "oss_multipart_upload", 
]

from base64 import b64encode
from collections.abc import (
    AsyncGenerator, AsyncIterable, AsyncIterator, Awaitable, Buffer, Callable, 
    Coroutine, Generator, ItemsView, Iterable, Iterator, Mapping, Sequence, Sized, 
)
from datetime import datetime
from email.utils import formatdate
from functools import partial
from hmac import digest as hmac_digest
from inspect import iscoroutinefunction
from itertools import count
from typing import cast, overload, Any, Literal
from urllib.parse import urlencode
from xml.etree.ElementTree import fromstring

from asynctools import ensure_aiter, ensure_async
from filewrap import (
    SupportsRead, buffer_length, 
    bio_chunk_iter, bio_chunk_async_iter, 
    bio_skip_iter, bio_skip_async_iter, 
    bytes_iter_to_async_reader, bytes_iter_to_reader, 
    bytes_to_chunk_iter, bytes_to_chunk_async_iter, 
    progress_bytes_iter, progress_bytes_async_iter, 
)
from iterutils import (
    foreach, async_through, through, run_gen_step, 
    run_gen_step_iter, wrap_iter, wrap_aiter, Yield, 
)

from .exception import MultipartUploadAbort
from .type import MultipartResumeData


def to_base64(s: Buffer | str, /) -> str:
    if isinstance(s, str):
        s = bytes(s, "utf-8")
    return str(b64encode(s), "ascii")


def maybe_integer(n: int | str, /) -> int | str:
    if isinstance(n, str) and n.isdecimal():
        n = int(n)
    return n


def parse_upload_id(resp, content: bytes, /) -> str:
    return getattr(fromstring(content).find("UploadId"), "text")


@overload
def make_dataiter(
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer], 
    /, 
    read_size: int = -1, 
    callback: None | Callable[[Buffer], Any] = None, 
    *, 
    async_: Literal[False] = False, 
) -> Iterator[Buffer]:
    ...
@overload
def make_dataiter(
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer], 
    /, 
    read_size: int = -1, 
    callback: None | Callable[[Buffer], Any] = None, 
    *, 
    async_: Literal[True], 
) -> AsyncIterator[Buffer]:
    ...
def make_dataiter(
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer], 
    /, 
    read_size: int = -1, 
    callback: None | Callable[[Buffer], Any] = None, 
    *, 
    async_: Literal[False, True] = False, 
) -> Iterator[Buffer] | AsyncIterator[Buffer]:
    try:
        file = getattr(file, "getbuffer")()
    except (AttributeError, TypeError):
        pass
    dataiter: Iterable[Buffer] | AsyncIterable[Buffer]
    if isinstance(file, Buffer):
        if async_:
            dataiter = bytes_to_chunk_async_iter(file)
        else:
            dataiter = bytes_to_chunk_iter(file)
    elif isinstance(file, SupportsRead):
        if not async_ and iscoroutinefunction(file.read):
            raise TypeError(f"{file!r} with async read in non-async mode")
        if async_:
            dataiter = bio_chunk_async_iter(file, read_size)
        else:
            dataiter = bio_chunk_iter(file, read_size)
    else:
        if not async_ and isinstance(file, AsyncIterable):
            raise TypeError(f"async iterable {file!r} in non-async mode")
        if read_size >= 0:
            count_in_bytes = 0
            def acc(chunk: Buffer, /):
                nonlocal count_in_bytes
                count_in_bytes += buffer_length(chunk)
                if count_in_bytes >= read_size:
                    raise StopIteration
            if async_:
                dataiter = wrap_aiter(file, callnext=acc)
            else:
                dataiter = wrap_iter(cast(Iterable, file), callnext=acc)
        elif async_:
            dataiter = ensure_aiter(file)
        else:
            dataiter = file
    if callback is not None:
        if async_:
            dataiter = wrap_aiter(dataiter, callnext=callback)
        else:
            dataiter = wrap_iter(cast(Iterable, dataiter), callnext=callback)
    return dataiter # type: ignore


def oss_upload_sign(
    bucket: str, 
    object: str, 
    token: dict, 
    method: str = "PUT", 
    params: None | str | Mapping | Sequence[tuple[Any, Any]] = None, 
    headers: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
) -> tuple[dict, str]:
    """计算认证信息，返回带认证信息的请求头
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
    date = formatdate(usegmt=True)
    if params is None:
        params = ""
    elif not isinstance(params, str):
        params = urlencode(params)
    if params and not params.startswith("?"):
        params = "?" + params
    if headers:
        if isinstance(headers, Mapping):
            headers = ItemsView(headers)
        headers = {k.lower(): v for k, v in headers}
    else:
        headers = {}
    header_pairs = [(k, v) for k, v in headers.items() if k.startswith("x-oss-")]
    if header_pairs:
        header_pairs.sort()
        headers_str = "\n".join(map("%s:%s".__mod__, header_pairs))
    else:
        headers_str = ""
    content_md5 = headers.setdefault("content-md5", "")
    content_type = headers.setdefault("content-type", "")
    date = headers.get("x-oss-date") or headers.get("date") or ""
    if not date:
        date = headers["date"] = formatdate(usegmt=True)
    signature_data = f"""\
{method.upper()}
{content_md5}
{content_type}
{date}
{headers_str}
/{bucket}/{object}{params}""".encode("utf-8")
    signature = to_base64(hmac_digest(bytes(token["AccessKeySecret"], "utf-8"), signature_data, "sha1"))
    headers["authorization"] = "OSS {0}:{1}".format(token["AccessKeyId"], signature)
    return headers, params


def oss_upload_request[T](
    request: Callable[..., T], 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    method: str = "PUT", 
    params: None | str | Mapping | Sequence[tuple[Any, Any]] = None, 
    headers: None | Mapping[str, str] | Iterable[tuple[str, str]] = None, 
    async_: bool = False, 
    **request_kwargs, 
) -> T:
    """请求阿里云 OSS 的公用函数
    """
    headers, params = oss_upload_sign(
        bucket, 
        object, 
        token, 
        method=method, 
        params=params, 
        headers=headers, 
    )
    return request(
        url=url+params, 
        headers=headers, 
        method=method, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_part_iter(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str,
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def oss_multipart_part_iter(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str,
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def oss_multipart_part_iter(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str,
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """罗列某个分块上传任务，已经上传的分块
    """
    request_kwargs.update(
        method="GET", 
        params={"uploadId": upload_id}, 
        headers={"x-oss-security-token": token["SecurityToken"]}, 
    )
    request_kwargs.setdefault("parse", lambda _, content: fromstring(content))
    def gen_step():
        params = request_kwargs["params"]
        while True:
            etree = yield oss_upload_request(
                request, 
                url=url, 
                bucket=bucket, 
                object=object, 
                token=token, 
                async_=async_, 
                **request_kwargs, 
            )
            for el in etree.iterfind("Part"):
                yield Yield({sel.tag: maybe_integer(sel.text) for sel in el})
            if getattr(etree.find("IsTruncated"), "text") == "false":
                break
            params["part-number-marker"] = getattr(etree.find("NextPartNumberMarker"), "text")
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def oss_multipart_upload_init(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> str:
    ...
@overload
def oss_multipart_upload_init(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, str]:
    ...
def oss_multipart_upload_init(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> str | Coroutine[Any, Any, str]:
    """分块上传的初始化，获取 upload_id
    """
    request_kwargs.update(
        method="POST", 
        params={"sequential": "1", "uploads": "1"}, 
        headers={"x-oss-security-token": token["SecurityToken"]}, 
    )
    request_kwargs.setdefault("parse", parse_upload_id)
    return oss_upload_request(
        request, 
        url=url, 
        bucket=bucket, 
        object=object, 
        token=token, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_complete(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    callback: dict, 
    token: dict, 
    upload_id: str, 
    parts: list[dict], 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_multipart_upload_complete(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    callback: dict, 
    token: dict, 
    upload_id: str, 
    parts: list[dict], 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_multipart_upload_complete(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    callback: dict, 
    token: dict, 
    upload_id: str, 
    parts: list[dict], 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """完成分块上传任务，会在请求头中包含回调数据，请求体中包含分块信息
    """
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
        headers={
            "x-oss-security-token": token["SecurityToken"], 
            "x-oss-callback": to_base64(callback["callback"]), 
            "x-oss-callback-var": to_base64(callback["callback_var"]), 
            "content-type": "text/xml", 
        }, 
    )
    return oss_upload_request(
        request, 
        url=url, 
        bucket=bucket, 
        object=object, 
        token=token, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_cancel(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> bool:
    ...
@overload
def oss_multipart_upload_cancel(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, bool]:
    ...
def oss_multipart_upload_cancel(
    request: Callable, 
    /, 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> bool | Coroutine[Any, Any, bool]:
    """取消分块上传任务，返回成功与否
    """
    request_kwargs.update(
        method="DELETE", 
        params={"uploadId": upload_id}, 
        headers={"x-oss-security-token": token["SecurityToken"]}, 
    )
    request_kwargs.setdefault("parse", lambda resp: 200 <= resp.status_code < 300 or resp.status_code == 404)
    return oss_upload_request(
        request, 
        url=url, 
        bucket=bucket, 
        object=object, 
        token=token, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_part(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str, 
    part_number: int, 
    partsize: int = 1 << 24, 
    reporthook: None | Callable = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_multipart_upload_part(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str, 
    part_number: int, 
    partsize: int = 1 << 24, 
    reporthook: None | Callable = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_multipart_upload_part(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str, 
    part_number: int, 
    partsize: int = 1 << 24, # default to: 16 MB
    reporthook: None | Callable = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """上传一个分片，返回一个字典，包含如下字段：

    .. code:: python

        {
            "PartNumber": int,    # 分块序号，从 1 开始计数
            "LastModified": str,  # 最近更新时间
            "ETag": str,          # ETag 值，判断资源是否发生变化
            "HashCrc64ecma": int, # 校验码
            "Size": int,          # 分片大小
        }
    """
    count_in_bytes = 0
    def acc(chunk: Buffer, /):
        nonlocal count_in_bytes
        count_in_bytes += buffer_length(chunk)
    def parse_upload_part(resp, /) -> dict:
        headers = resp.headers
        return {
            "PartNumber": part_number, 
            "LastModified": datetime.strptime(headers["date"], "%a, %d %b %Y %H:%M:%S GMT").strftime("%FT%X.%f")[:-3] + "Z", 
            "ETag": headers["ETag"], 
            "HashCrc64ecma": int(headers["x-oss-hash-crc64ecma"]), 
            "Size": count_in_bytes, 
        }
    request_kwargs.setdefault("parse", parse_upload_part)
    request_kwargs["params"] = {"partNumber": part_number, "uploadId": upload_id}
    request_kwargs["headers"] = {"x-oss-security-token": token["SecurityToken"]}
    dataiter: Iterator[Buffer] | AsyncIterator[Buffer] = make_dataiter(file, partsize, callback=acc, async_=async_) # type: ignore
    if reporthook is not None:
        if async_:
            reporthook = ensure_async(reporthook)
            async def reporthook_wrap(b: Buffer, /):
                await reporthook(buffer_length(b))
            dataiter = wrap_aiter(dataiter, callnext=reporthook_wrap)
        else:
            dataiter = wrap_iter(cast(Iterable, dataiter), callnext=lambda b: reporthook(buffer_length(b)))
    request_kwargs["data"] = dataiter
    return oss_upload_request(
        request, 
        url=url, 
        bucket=bucket, 
        object=object, 
        token=token, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload_part_iter(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str, 
    part_number_start: int, 
    partsize: int, 
    reporthook: None | Callable = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def oss_multipart_upload_part_iter(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | SupportsRead[Awaitable[Buffer]] | Iterable[Buffer] | AsyncIterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str, 
    part_number_start: int, 
    partsize: int, 
    reporthook: None | Callable = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def oss_multipart_upload_part_iter(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | SupportsRead[Awaitable[Buffer]] | Iterable[Buffer] | AsyncIterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    token: dict, 
    upload_id: str, 
    part_number_start: int, 
    partsize: int, 
    reporthook: None | Callable = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代器，迭代一次会上传一个分片
    """
    def gen_step():
        nonlocal file
        try:
            file = getattr(file, "getbuffer")()
        except (AttributeError, TypeError):
            pass
        if isinstance(file, Buffer):
            file = memoryview(file)
        elif isinstance(file, SupportsRead):
            pass
        elif async_:
            file = bytes_iter_to_async_reader(file)
        else:
            file = bytes_iter_to_reader(cast(Iterable, file))
        if skipsize := partsize * (part_number_start - 1):
            if isinstance(file, memoryview):
                reporthook and reporthook(skipsize)
            elif async_:
                through(bio_skip_iter(
                    file, # type: ignore
                    skipsize, 
                    callback=reporthook, 
                ))
            else:
                yield async_through(bio_skip_async_iter(file, skipsize, callback=reporthook))
        chunk: Buffer | Iterator[Buffer] | AsyncIterator[Buffer]
        for i, part_number in enumerate(count(part_number_start)):
            if isinstance(file, memoryview):
                chunk = file[i*partsize:(i+1)*partsize]
            elif isinstance(file, SupportsRead):
                if async_:
                    chunk = bio_chunk_async_iter(file, partsize)
                else:
                    chunk = bio_chunk_iter(
                        file, # type: ignore
                        partsize, 
                    )
            part = yield Yield(oss_multipart_upload_part(
                request, 
                file=chunk, # type: ignore
                url=url, 
                bucket=bucket, 
                object=object, 
                token=token, 
                upload_id=upload_id, 
                part_number=part_number, 
                partsize=partsize, 
                reporthook=reporthook, 
                async_=async_, # type: ignore
                **request_kwargs, 
            ))
            if part["Size"] < partsize:
                break
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def oss_upload(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    callback: dict, 
    token: dict, 
    filesize: int = -1, 
    make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any]] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_upload(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    callback: dict, 
    token: dict, 
    filesize: int = -1, 
    make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any]] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_upload(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    callback: dict, 
    token: dict, 
    filesize: int = -1, 
    make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any]] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """帮助函数：上传文件到阿里云 OSS，一次上传全部（即不进行分片）
    """
    request_kwargs["headers"] = {
        "x-oss-security-token": token["SecurityToken"], 
        "x-oss-callback": to_base64(callback["callback"]), 
        "x-oss-callback-var": to_base64(callback["callback_var"]), 
    }
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
    request_kwargs["data"] = dataiter
    return oss_upload_request(
        request, 
        url=url, 
        bucket=bucket, 
        object=object, 
        token=token, 
        async_=async_, 
        **request_kwargs, 
    )


@overload
def oss_multipart_upload(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    callback: dict, 
    token: dict, 
    upload_id: None | str = None, 
    partsize: int = 10 * 1 << 20, 
    parts: None | list[dict] = None, 
    filesize: int = -1, 
    collect_resume_data: None | Callable[[MultipartResumeData], Any] = None, 
    make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any]] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def oss_multipart_upload(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    callback: dict, 
    token: dict, 
    upload_id: None | str = None, 
    partsize: int = 10 * 1 << 20, 
    parts: None | list[dict] = None, 
    filesize: int = -1, 
    collect_resume_data: None | Callable[[MultipartResumeData], Any] = None, 
    make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any]] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def oss_multipart_upload(
    request: Callable, 
    /, 
    file: Buffer | SupportsRead[Buffer] | Iterable[Buffer] | AsyncIterable[Buffer], 
    url: str, 
    bucket: str, 
    object: str, 
    callback: dict, 
    token: dict, 
    upload_id: None | str = None, 
    partsize: int = 10 * 1 << 20, # default to: 10 MB
    parts: None | list[dict] = None, 
    filesize: int = -1, 
    collect_resume_data: None | Callable[[MultipartResumeData], Any] = None, 
    make_reporthook: None | Callable[[None | int], Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any]] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    def gen_step():
        nonlocal make_reporthook, parts, upload_id
        if parts is None:
            parts = []
            add_part = parts.append
            if upload_id:
                if async_:
                    async def async_request():
                        async for part in oss_multipart_part_iter(
                            request, 
                            url=url, 
                            bucket=bucket, 
                            object=object, 
                            token=token, 
                            upload_id=cast(str, upload_id), 
                            async_=True, 
                            **request_kwargs, 
                        ):
                            if part["Size"] != partsize:
                                break
                            add_part(part)
                    yield async_request()
                else:
                    for part in oss_multipart_part_iter(
                        request, 
                        url=url, 
                        bucket=bucket, 
                        object=object, 
                        token=token, 
                        upload_id=cast(str, upload_id), 
                        **request_kwargs, 
                    ):
                        if part["Size"] != partsize:
                            break
                        add_part(part)
            else:
                upload_id = yield oss_multipart_upload_init(
                    request, 
                    url=url, 
                    bucket=bucket, 
                    object=object, 
                    token=token, 
                    async_=async_, 
                    **request_kwargs, 
                )
        else:
            parts = parts.copy()
            add_part = parts.append
        upload_id = cast(str, upload_id)
        reporthook: None | Callable[[int], Any] | Generator[int, Any, Any] | AsyncGenerator[int, Any] = None
        close_reporthook: None | Callable = None
        if callable(make_reporthook):
            reporthook = make_reporthook(None if filesize < 0 else filesize)
            if isinstance(reporthook, Generator):
                close_reporthook = reporthook.close
                reporthook = reporthook.send
                reporthook(None)
            elif isinstance(reporthook, AsyncGenerator):
                close_reporthook = reporthook.aclose
                reporthook = reporthook.asend
                yield reporthook(None)
        try:
            resume_data: MultipartResumeData = {
                "bucket": bucket, "object": object, "token": token, "callback": callback, 
                "upload_id": upload_id, "partsize": partsize, "filesize": filesize, "parts": parts, 
            }
            if collect_resume_data is not None:
                yield collect_resume_data(resume_data)
            yield foreach(
                add_part, 
                oss_multipart_upload_part_iter(
                    request, 
                    file, # type: ignore
                    url=url, 
                    bucket=bucket, 
                    object=object, 
                    token=token, 
                    upload_id=upload_id, 
                    part_number_start=len(parts)+1, 
                    partsize=partsize, 
                    reporthook=reporthook, # type: ignore
                    async_=async_, # type: ignore
                    **request_kwargs, 
                ), 
            )
            return (yield oss_multipart_upload_complete(
                request, 
                url=url, 
                bucket=bucket, 
                object=object, 
                callback=callback, 
                token=token, 
                upload_id=upload_id, 
                parts=parts, 
                async_=async_, # type: ignore
                **request_kwargs, 
            ))
        except BaseException as e:
            raise MultipartUploadAbort(resume_data) from e
        finally:
            if close_reporthook is not None:
                yield close_reporthook()
    return run_gen_step(gen_step, may_call=False, async_=async_)


# class MultipartUploader:
#     def __init__
#     def __del__
#     async def __aiter__
#     def __iter__
#     async def __aenter__
#     async def __aexit__
#     def __enter__
#     def __exit__
#     # 0. 应该设计 1 个类，支持同步和异步，实例化不会进行初始化（为了对异步进行适配）
#     # 1. 可以作为上下文管理器或者迭代器使用
#     # 2. 上下文管理器也返回迭代器（迭代器迭代时，如果未打开文件或者没有上传信息，则会初始化以获取）
#     # 3. 中途可以暂停或取消
#     # 4. seekable: path, url (支持 range request), file reader (seekable)
#     # 5. 支持进度条
#     # 6. 设计一个工具函数，放到 p115client.tool.upload 模块中
#     ...

