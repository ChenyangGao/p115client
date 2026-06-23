#!/usr/bin/env python3
# encoding: utf-8

__all__ = ["upload_file_init", "upload_file", "MultipartUploadAbort"]

from asyncio import to_thread
from collections.abc import Buffer, Callable, Coroutine
from hashlib import sha1
from inspect import isawaitable
from os import fsdecode, fstat, stat, PathLike
from re import compile as re_compile
from typing import cast, overload, Any, Final, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from asynctools import ensure_async
from filewrap import SupportsRead, buffer_length
from hashtools import file_digest, file_digest_async
from http_request import SupportsGeturl
from http_response import get_total_length, get_filename
from iterutils import foreach, run_gen_step
from p115pickcode import pickcode_to_id
from yarl import URL

from .api import upload_init, upload_init_open, upload_resume
from .oss import (
    DEFAULT_BUCKET, DEFAULT_ENDPOINT, oss_multipart_part_iter, oss_upload, 
    oss_multipart_upload_init, oss_multipart_upload, oss_multipart_upload_complete, 
)


CRE_UID_in_COOKIE_search: Final = re_compile(r"(?<=\bUID=)\w+").search


class MultipartUploadAbort(OSError):
    ...


def urlopen(
    url: str, 
    /, 
    bytes_range: str = "", 
    async_: bool = False, 
):
    from urllib3_future_request import request
    headers: dict = {"accept-encoding": "identity"}
    if bytes_range:
        headers["range"] = "bytes=" + bytes_range
    return request(
        url, 
        headers=headers, 
        async_=async_, # type: ignore
    )


def determine_partsize(
    size: int, 
    max_part_count: int = 10 ** 4, 
) -> int:
    """确定分片上传（multipart upload）时的分片大小

    .. note::
        分块大小至少 100 KB

    :param size: 数据大小
    :param min_part_size:  用户期望的分片大小
    :param max_part_count: 最大的分片个数

    :return: 分片大小
    """
    min_part_size = 1024 * 100
    if size <= min_part_size:
        return min_part_size
    n = -(-size // max_part_count)
    partsize = min_part_size
    while partsize < n:
        partsize <<= 1
    return partsize


@overload
def upload_file_init(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_file_init(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_file_init(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """准备分块上传，获取必要信息

    .. note::
        如果你并没有同时提供 ``user_id`` 和 ``user_key``，则视为调用 open 接口，需要携带 "authorization" 请求头

    :param file: 待上传的文件或其路径
    :param pid: 上传文件到目录的 id
    :param filename: 文件名，若为空则自动确定
    :param filesha1: 文件的 sha1 摘要，若为空则自动计算
    :param filesize: 文件大小，若为负数则自动计算
    :param user_id: 用户 id
    :param user_key: 用户的 key
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 如果秒传成功，则返回响应信息（有 "status" 字段），否则返回上传配置信息（可用于断点续传）
    """
    def gen_step():
        nonlocal file, filename, filesha1, filesize
        upload_data: dict = {}
        use_open = not (user_id and user_key)
        if not use_open:
            upload_data["user_id"] = user_id
            upload_data["user_key"] = user_key
        read_range: Callable
        try:
            file = getattr(file, "getbuffer")()
        except (AttributeError, TypeError):
            pass
        if isinstance(file, Buffer):
            filesize = buffer_length(file)
            if filesize == 0:
                filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
            elif not filesha1:
                filesha1 = sha1(file).hexdigest()
            def read_range(sign_check: str, /, data=file) -> bytes:
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
                            async def process():
                                async with urlopen(path, async_=True):
                                    return await file_digest_async(reader, "sha1")
                            filesize, filesha1_obj = yield process()
                        else:
                            with urlopen(path) as reader:
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
                    if async_:
                        response = yield to_thread(urlopen, path)
                    else:
                        response = urlopen(path)
                    with response:
                        if not filename:
                            filename = get_filename(response)
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
            if async_:
                async def read_range(sign_check: str, /) -> bytes:
                    if is_url:
                        async with urlopen(path, bytes_range=sign_check, async_=True) as response:
                            return await response.read()
                    else:
                        start, end = map(int, sign_check.split("-"))
                        with open(path, "rb") as reader:
                            reader.seek(start)
                            return await to_thread(reader.read, end - start + 1)
            else:
                def read_range(sign_check: str, /) -> bytes:
                    if is_url:
                        with urlopen(path, bytes_range=sign_check) as response:
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
        upload_data.update(
            filename=filename, 
            filesha1=filesha1, 
            filesize=filesize, 
            target=target, 
        )
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
            if use_open:
                pickcode = data["pick_code"]
            else:
                pickcode = resp["pickcode"]
            upload_data["pickcode"] = pickcode
            upload_data["callback"] = data["callback"]
            upload_data["bucket"] = data["bucket"]
            upload_data["object"] = data["object"]
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
def upload_file(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    partsize: int = 0, 
    callback: None | str | dict = None, 
    upload_id: str = "", 
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
def upload_file(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    partsize: int = 0, 
    callback: None | str | dict = None, 
    upload_id: str = "", 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_file(
    file: Buffer | str | PathLike | URL | SupportsGeturl | SupportsRead, 
    pid: int | str = 0, 
    filename: str = "", 
    filesha1: str = "", 
    filesize: int = -1, 
    user_id: int | str = "", 
    user_key: str = "", 
    partsize: int = 0, 
    callback: None | str | dict = None, 
    upload_id: str = "", 
    token: None | dict = None, 
    bucket: str = DEFAULT_BUCKET, 
    endpoint: str = DEFAULT_ENDPOINT, 
    reporthook: None | Callable[[int], Any] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """上传文件

    .. note::
        如果想要断点续传，需要提供 ``callback`` 和 ``upload_id``

    :param file: 待上传的文件或其路径
    :param pid: 上传文件到目录的 id
    :param filename: 文件名，若为空则自动确定
    :param filesha1: 文件的 sha1 摘要，若为空则自动计算
    :param filesize: 文件大小，若为负数则自动计算
    :param user_id: 用户 id
    :param user_key: 用户的 key
    :param partsize: 分块大小（如果为 0，则不是分块上传；如果 <0，则自动确定）
    :param callback: 回调数据或者上传的 pickcode
    :param upload_id: 上传任务 id
    :param token: 令牌信息
    :param bucket: 存储桶名字
    :param endpoint: 服务器地址
    :param reporthook: 回调函数，可以用来统计已上传的数据量或者展示进度条
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    if upload_id and partsize >= 0:
        partsize = max(partsize, 1024 * 100)
    def gen_step():
        nonlocal file, partsize, callback, upload_id
        parts: list[dict] = []
        skip_size = 0
        try:
            if callback:
                if isinstance(callback, str) and user_id:
                    params: Any = {"callback": callback, "userid": user_id}
                else:
                    params = callback
                resp = yield upload_resume(
                    params, 
                    async_=async_, 
                    **request_kwargs, 
                )
                key = resp["object"]
                if not resp.get("state", True):
                    return resp
                callback = cast(dict, resp["callback"])
                if upload_id:
                    yield foreach(
                        parts.append, 
                        oss_multipart_part_iter(
                            key, 
                            upload_id=upload_id, 
                            token=token, 
                            bucket=bucket, 
                            endpoint=endpoint, 
                            async_=async_, 
                            **request_kwargs, 
                        ), 
                    )
                    skip_size = sum(p["Size"] for p in parts if p["Size"] >= 1024 * 100)
                    if filesize >= 0:
                        if skip_size > filesize:
                            raise OSError(5, "excessive uploads have been detected, please re-upload")
                        if parts:
                            last_part_size = parts[-1]["Size"]
                            if last_part_size < 1024 * 100 and skip_size + last_part_size == filesize:
                                skip_size == filesize
                    if skip_size and reporthook is not None:
                        ret = reporthook(skip_size)
                        if async_ and isawaitable(ret):
                            yield ret
            else:
                upload_id = ""
                resp = yield upload_file_init(
                    file=file, 
                    pid=pid, 
                    filename=filename, 
                    filesha1=filesha1, 
                    filesize=filesize, 
                    user_id=user_id, 
                    user_key=user_key, 
                    async_=async_, 
                    **request_kwargs, 
                )
                if not resp["state"] or resp["reuse"]:
                    return resp
                upload_data = resp["data"]
                key = upload_data["object"]
                callback = cast(dict, upload_data["callback"])
                if partsize:
                    if partsize < 0:
                        partsize = determine_partsize(upload_data["filesize"])
                    else:
                        partsize = max(partsize, 1024 * 100)
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
                                file = yield urlopen(path, async_=True)
                            else:
                                file = urlopen(path)
                        else:
                            file = open(path, "rb")
                    file = cast(Buffer | SupportsRead, file)
                    return oss_upload(
                        key, 
                        file, 
                        callback=callback, 
                        token=token, 
                        bucket=bucket, 
                        endpoint=endpoint, 
                        reporthook=reporthook, 
                        async_=async_, 
                        **request_kwargs, 
                    )
            if not upload_id or filesize < 0 or skip_size < filesize:
                if not upload_id:
                    upload_id = yield oss_multipart_upload_init(
                        key, 
                        token, 
                        bucket=bucket, 
                        endpoint=endpoint, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                if isinstance(file, SupportsRead):
                    if skip_size:
                        seek = getattr(file, "seek")
                        if async_:
                            yield ensure_async(seek, threaded=True)(skip_size)
                        else:
                            seek(skip_size)
                elif isinstance(file, Buffer):
                    if skip_size:
                        file = memoryview(file)[skip_size:]
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
                    if is_url:
                        if async_:
                            file = yield urlopen(path, bytes_range=f"{skip_size}-", async_=True)
                        else:
                            file = urlopen(path, bytes_range=f"{skip_size}-")
                    else:
                        file = open(path, "rb")
                        if skip_size:
                            file.seek(skip_size)
                file = cast(Buffer | SupportsRead, file)
                return oss_multipart_upload(
                    key, 
                    upload_id=upload_id, 
                    file=file, 
                    callback=callback, 
                    partsize=partsize, 
                    parts=parts, 
                    token=token, 
                    bucket=bucket, 
                    endpoint=endpoint, 
                    reporthook=reporthook, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                return oss_multipart_upload_complete(
                    key, 
                    upload_id=upload_id, 
                    parts=parts, 
                    callback=callback, 
                    token=token, 
                    bucket=bucket, 
                    endpoint=endpoint, 
                    async_=async_, 
                    **request_kwargs, 
                )
        except BaseException as e:
            data = locals()
            raise MultipartUploadAbort({k: data[k] for k in (
                "pid", "filename", "filesha1", "filesize", "user_id", 
                "user_key", "partsize", "callback", "upload_id", 
            )}) from e
    return run_gen_step(gen_step, async_)

