#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "iter_115_to_115", "iter_115_to_115_resume", "multipart_upload_init", 
    "multipart_upload_url", "multipart_upload_complete", 
]
__doc__ = "这个模块提供了一些和上传有关的函数"

import errno

from asyncio import to_thread
from collections.abc import AsyncIterator, Callable, Coroutine, Iterator
from itertools import dropwhile
from os import fsdecode, stat, PathLike
from typing import cast, overload, Any, Literal
from urllib.parse import unquote, urlsplit
from uuid import uuid4

from asynctools import to_list
from concurrenttools import threadpool_map, taskgroup_map, Return
from hashtools import file_digest, file_digest_async
from http_request import SupportsGeturl
from http_response import get_total_length
from iterutils import (
    as_gen_step, collect, run_gen_step, run_gen_step_iter, 
    with_iter_next, YieldFrom, 
)
from orjson import loads
from p115client import check_response, normalize_attr_simple, P115Client, P115OpenClient
from p115client.exception import OperationalError
from p115client._upload import (
    oss_multipart_part_iter, oss_multipart_upload_init, 
    oss_multipart_upload_url, oss_multipart_upload_complete, 
)
from p115pickcode import to_id
from urlopen import urlopen
from yarl import URL

from .download import iter_download_files
from .iterdir import iterdir, iter_files_with_path, unescape_115_charref
from .util import determine_part_size


ALIYUN_DOMAIN = "oss-cn-shenzhen.aliyuncs.com"


# TODO: 支持 open 接口
@overload
def iter_115_to_115(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int | str = 0, 
    to_pid: int | str = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    use_iter_files: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_115_to_115(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int | str = 0, 
    to_pid: int | str = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    use_iter_files: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_115_to_115(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int | str = 0, 
    to_pid: int | str = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    use_iter_files: bool = False, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """从 115 传到 115

    :param from_client: 来源 115 客户端对象
    :param to_client: 去向 115 客户端对象
    :param from_cid: 来源 115 的目录 id 或 pickcode
    :param to_pid: 去向 115 的父目录 id 或 pickcode
    :param max_workers: 最大并发数
    :param with_root: 是否保留 `from_cid` 对应的目录名（如果为 False，则会少 1 级目录）
    :param use_iter_files: 如果为 True，则调用 iter_files_with_path，否则调用 iter_download_files
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生转移结果，有 3 种类型："good"、"fail" 和 "skip"
    """
    from_cid = to_id(from_cid)
    to_pid = to_id(to_pid)
    @as_gen_step
    def upload(attr: dict, pid: int, /):
        @as_gen_step
        def read_range_bytes_or_hash(sign_check: str, /):
            if attr["is_collect"]:
                url = yield from_client.download_url(
                    attr["pickcode"], 
                    use_web_api=True, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                url = yield from_client.download_url(
                    attr["pickcode"], 
                    app="android", 
                    async_=async_, 
                    **request_kwargs, 
                )
            return from_client.request(
                url, 
                headers=dict(url["headers"], Range="bytes="+sign_check), 
                parse=False, 
                async_=async_, 
                **request_kwargs, 
            )
        try:
            if not use_iter_files:
                resp = yield from_client.fs_supervision(
                    attr["pickcode"], 
                    async_=async_, 
                    **request_kwargs, 
                )
                check_response(resp)
                info = resp["data"]
                attr.update(
                    id=int(info["file_id"]), 
                    name=info["file_name"], 
                    sha1=info["file_sha1"], 
                    size=int(info["file_size"]), 
                    is_collect=int(info["is_collect"]), 
                    file_type=int(info["file_type"]), 
                )
                if attr["is_collect"] and attr["size"] >= 1024 * 1024 * 115:
                    return {"type": "skip", "attr": attr, "resp": None}
            resp = yield to_client.upload_file_init(
                filename=attr["name"], 
                filesize=attr["size"], 
                filesha1=attr["sha1"], 
                pid=pid, 
                read_range_bytes_or_hash=read_range_bytes_or_hash, 
                base_url=True, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            if resp.get("statuscode"):
                return {"type": "fail", "attr": attr, "resp": resp}
            else:
                return {"type": "good", "attr": attr, "resp": resp}
        except BaseException as e:
            if isinstance(e, OSError) and len(e.args) == 2 and isinstance(e.args[1], dict):
                return {"type": "fail", "attr": attr, "resp": e.args[1], "exc": e}
            else:
                return {"type": "fail", "attr": attr, "resp": None, "exc": e}
    key_of_id = "id" if with_root else "parent_id"
    @as_gen_step
    def get_pid(attr: dict, /):
        if use_iter_files:
            if attr["is_collect"] and attr["size"] >= 1024 * 1024 * 115:
                return Return({"type": "skip", "attr": attr, "resp": None})
            if from_cid:
                dir_ = "/".join(a["name"] for a in dropwhile(
                    lambda a: a[key_of_id] != from_cid, 
                    attr["ancestors"][1:-1], 
                ))
            else:
                dir_ = "/".join(a["name"] for a in attr["ancestors"][1:-1])
        else:
            if from_cid:
                dir_ = "/".join(a["name"] for a in dropwhile(
                    lambda a: a[key_of_id] != from_cid, 
                    attr["dir_ancestors"][1:], 
                ))
            else:
                dir_ = attr["dirname"][1:]
        if dir_ in dir_to_cid:
            return dir_to_cid[dir_]
        else:
            resp = yield to_client.fs_makedirs_app(
                dir_, 
                to_pid, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            pid = dir_to_cid[dir_] = resp["cid"]
            return pid
    dir_to_cid = {"": 0}
    if use_iter_files:
        it = iter_files_with_path(
            from_client, 
            from_cid, 
            normalize_attr=normalize_attr_simple, 
            async_=async_, 
            **request_kwargs, 
        )
    else:
        it = iter_download_files(
            from_client, 
            from_cid, 
            async_=async_, 
            **request_kwargs, 
        )
    if async_:
        return taskgroup_map(upload, it, arg_func=get_pid, max_workers=max_workers)
    else:
        return threadpool_map(upload, it, arg_func=get_pid, max_workers=max_workers)


# TODO: 支持一次性把所有文件找完，也支持慢慢处理（可能会风控）
# TODO: 支持 open 接口
@overload
def iter_115_to_115_resume(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int | str = 0, 
    to_pid: int | str = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_115_to_115_resume(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int | str = 0, 
    to_pid: int | str = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_115_to_115_resume(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int | str = 0, 
    to_pid: int | str = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """从 115 传到 115（可以跳过已经存在的文件）

    :param from_client: 来源 115 客户端对象
    :param to_client: 去向 115 客户端对象
    :param from_cid: 来源 115 的目录 id 或 pickcode（文件数最好控制在 100 万以内，太多的话，里面多个子文件夹分别传即可）
    :param to_pid: 去向 115 的父目录 id 或 pickcode
    :param max_workers: 最大并发数
    :param with_root: 是否保留 `from_cid` 对应的目录名（如果为 False，则会少 1 级目录）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生转移结果，有 3 种类型："good"、"fail" 和 "skip"
    """
    from_cid = to_id(from_cid)
    to_pid = to_id(to_pid)
    @as_gen_step
    def upload(attr: dict, pid: int, /):
        @as_gen_step
        def read_range_bytes_or_hash(sign_check: str, /):
            if attr["is_collect"]:
                url = yield from_client.download_url(
                    attr["pickcode"], 
                    use_web_api=True, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                url = yield from_client.download_url(
                    attr["pickcode"], 
                    app="android", 
                    async_=async_, 
                    **request_kwargs, 
                )
            return from_client.request(
                url, 
                headers=dict(url["headers"], Range="bytes="+sign_check), 
                parse=False, 
                async_=async_, 
                **request_kwargs, 
            )
        try:
            resp = yield to_client.upload_file_init(
                filename=attr["name"], 
                filesize=attr["size"], 
                filesha1=attr["sha1"], 
                pid=pid, 
                read_range_bytes_or_hash=read_range_bytes_or_hash, 
                base_url=True, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            if resp.get("statuscode"):
                return {"type": "fail", "attr": attr, "resp": resp}
            else:
                return {"type": "good", "attr": attr, "resp": resp}
        except BaseException as e:
            if isinstance(e, OSError) and len(e.args) == 2 and isinstance(e.args[1], dict):
                return {"type": "fail", "attr": attr, "resp": e.args[1], "exc": e}
            else:
                return {"type": "fail", "attr": attr, "resp": None, "exc": e}
    dirt_to_cid: dict[tuple[str, ...], int] = {}
    key_of_id = "id" if with_root else "parent_id"
    @as_gen_step
    def get_pid(attr: dict, /):
        if attr["is_collect"] and attr["size"] >= 1024 * 1024 * 115:
            return Return({"type": "skip", "attr": attr, "resp": None})
        dirt = tuple(a["name"] for a in dropwhile(
            lambda a: a[key_of_id] != from_cid, 
            attr["ancestors"][1:-1], 
        ))
        try:
            return dirt_to_cid[dirt]
        except KeyError:
            pid = dirt_to_cid[()]
            for i, name in enumerate(dirt, 1):
                p_dirt = dirt[:i]
                if p_dirt in dirt_to_cid:
                    pid = dirt_to_cid[p_dirt]
                else:
                    resp = yield to_client.fs_mkdir(
                        name, 
                        pid, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    check_response(resp)
                    pid = dirt_to_cid[p_dirt] = int(resp["cid"])
            return pid
    def gen_step():
        from_files: Any = iter_files_with_path(
            from_client, 
            from_cid, 
            normalize_attr=normalize_attr_simple, 
            async_=async_, 
            **request_kwargs, 
        )
        if from_cid:
            resp = yield from_client.fs_file_skim(
                from_cid, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            name = unescape_115_charref(resp["data"][0]["file_name"])
            resp = yield to_client.fs_mkdir(
                name, 
                to_pid, 
                async_=async_, 
                **request_kwargs, 
            )
            if resp.get("errno") == 20004:
                if "/" in name:
                    with with_iter_next(iterdir(
                        to_client, 
                        to_pid, 
                        normalize_attr=normalize_attr_simple, 
                        ensure_file=False, 
                        async_=async_, 
                        **request_kwargs, 
                    )) as get_next:
                        while True:
                            attr = yield get_next()
                            if attr["name"] == name:
                                to_cid = attr["id"]
                                break
                else:
                    resp = yield to_client.fs_makedirs_app(
                        name, 
                        to_pid, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    check_response(resp)
                    to_cid = int(resp["cid"])
                dirt_to_cid[()] = to_cid
                id_to_dirnode: dict[int, tuple[str, int]] = {}
                to_files: Any = iter_files_with_path(
                    to_client, 
                    to_cid, 
                    id_to_dirnode=id_to_dirnode, 
                    normalize_attr=normalize_attr_simple, 
                    async_=async_, 
                    **request_kwargs, 
                )
                if async_:
                    from_files, to_files = yield to_list(
                        taskgroup_map(to_list, (from_files, to_files), max_workers=2))
                else:
                    from_files, to_files = threadpool_map(list, (from_files, to_files), max_workers=2)
                while to_cid:
                    _, to_cid = id_to_dirnode.pop(to_cid)
                cid_to_dirt: dict[int, tuple[str, ...]] = {}
                def get_dirt(cid: int, /) -> tuple[str, ...]:
                    if cid not in id_to_dirnode:
                        return ()
                    name, pid = id_to_dirnode[cid]
                    if pid in cid_to_dirt:
                        p_dirt = cid_to_dirt[pid]
                    else:
                        p_dirt = get_dirt(pid)
                    dirt = (*p_dirt, name)
                    dirt_to_cid[dirt] = cid
                    cid_to_dirt[cid] = dirt
                    return dirt
                for cid, (name, pid) in id_to_dirnode.items():
                    if cid not in cid_to_dirt:
                        get_dirt(cid)
                del cid_to_dirt, id_to_dirnode
                to_cid = dirt_to_cid[()]
                seen = {
                    tuple(a["name"] for a in dropwhile(
                        lambda a: a["parent_id"] != to_cid, 
                        attr["ancestors"][1:], 
                    )) for attr in to_files
                }
                from_files = [
                    attr for attr in from_files
                    if tuple(a["name"] for a in dropwhile(
                        lambda a: a["parent_id"] != from_cid, 
                        attr["ancestors"][1:], 
                    )) not in seen
                ]
                del to_files, seen
            else:
                check_response(resp)
                dirt_to_cid[()] = int(resp["cid"])
        else:
            dirt_to_cid[()] = 0
        if async_:
            return YieldFrom(taskgroup_map(
                upload, 
                from_files, 
                arg_func=get_pid, 
                max_workers=max_workers, 
            ))
        else:
            return YieldFrom(threadpool_map(
                upload, 
                from_files, 
                arg_func=get_pid, 
                max_workers=max_workers, 
            ))
    return run_gen_step_iter(gen_step, async_)


@overload
def multipart_upload_init(
    client: str | P115Client | P115OpenClient, 
    path: str | PathLike | URL | SupportsGeturl, 
    pid: int | str = 0, 
    filename: str = "", 
    filesize: int = -1, 
    filesha1: str = "", 
    partsize: int = -1, 
    upload_data: None | dict = None, 
    domain: str = ALIYUN_DOMAIN, 
    use_open_api: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def multipart_upload_init(
    client: str | P115Client | P115OpenClient, 
    path: str | PathLike | URL | SupportsGeturl, 
    pid: int | str = 0, 
    filename: str = "", 
    filesize: int = -1, 
    filesha1: str = "", 
    partsize: int = -1, 
    upload_data: None | dict = None, 
    domain: str = ALIYUN_DOMAIN, 
    use_open_api: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def multipart_upload_init(
    client: str | P115Client | P115OpenClient, 
    path: str | PathLike | URL | SupportsGeturl, 
    pid: int | str = 0, 
    filename: str = "", 
    filesize: int = -1, 
    filesha1: str = "", 
    partsize: int = -1, 
    upload_data: None | dict = None, 
    domain: str = ALIYUN_DOMAIN, 
    use_open_api: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """准备分块上传，获取必要信息

    :param client: 115 客户端或 cookies
    :param path: 路径 或 链接（仅支持 GET 请求，http(s)协议）
    :param pid: 上传文件到此目录的 id 或 pickcode
    :param filename: 文件名，若为空则自动确定
    :param filesize: 文件大小，若为负数则自动计算
    :param filesha1: 文件的 sha1 摘要，若为空则自动计算
    :param partsize: 分块大小，若不为正数则自动确定
    :param upload_data: 上传相关信息，可用于以后的断点续传
    :param domain: 上传到指定的阿里云集群的网址（netloc）
    :param use_open_api: 是否使用 open 接口，如果本身就是 P115OpenClient （而不是其子类）的实例，此值强制为 True
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 如果秒传成功，则返回响应信息（有 "status" 字段），否则返回上传配置信息（可用于断点续传）
    """
    pid = to_id(pid)
    if not domain:
        domain = ALIYUN_DOMAIN
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if type(client) is P115OpenClient:
        use_open_api = True
    if use_open_api:
        upload_file_init = client.upload_file_init_open
        upload_resume = client.upload_resume_open
    else:
        upload_file_init = client.upload_file_init
        upload_resume = client.upload_resume
    def gen_step():
        nonlocal upload_data, path, filename, filesha1, filesize, partsize
        if upload_data is None:
            upload_data = {}
            if isinstance(path, str):
                is_path = not path.startswith(("http://", "https://"))
            elif isinstance(path, URL):
                path = str(path)
                is_path = False
            elif isinstance(path, SupportsGeturl):
                path = path.geturl()
                is_path = False
            else:
                path = fsdecode(path)
                is_path = True
            path = cast(str, path)
            if not filename:
                if is_path:
                    from os.path import basename
                    filename = basename(path)
                else:
                    from posixpath import basename
                    filename = basename(unquote(urlsplit(path).path))
                if not filename:
                    filename = str(uuid4())
            file: Any
            if not filesha1:
                if filesize == 0:
                    filesha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
                else:
                    if is_path:
                        if async_:
                            from aiofile import async_open
                            async def request():
                                async with async_open(path, "rb") as file:
                                    return await file_digest_async(file, "sha1") # type: ignore
                            filesize, filesha1_obj = yield request
                        else:
                            with open(path, "rb") as file:
                                filesize, filesha1_obj = file_digest(file, "sha1")
                    else:
                        if async_:
                            from httpfile import AsyncHttpxFileReader
                            async def request():
                                file = await AsyncHttpxFileReader.new(path, headers={"user-agent": ""})
                                async with file:
                                    return await file_digest_async(file, "sha1")
                            filesize, filesha1_obj = yield request
                        else:
                            from httpfile import HTTPFileReader
                            with HTTPFileReader(path, headers={"user-agent": ""}) as file:
                                filesize, filesha1_obj = file_digest(file, "sha1")
                filesha1 = filesha1_obj.hexdigest()
            if filesize < 0:
                if is_path:
                    filesize = stat(path).st_size
                else:
                    if async_:
                        file = yield to_thread(urlopen, path)
                    else:
                        file = urlopen(path)
                    try:
                        filesize = get_total_length(file) or 0
                    finally:
                        file.close()
            if partsize <= 0:
                partsize = determine_part_size(filesize)
            read_range_bytes_or_hash: Callable
            if async_:
                async def read_range_bytes_or_hash(sign_check: str, /) -> bytes:
                    file: Any
                    if is_path:
                        from aiofile import async_open
                        start, end = map(int, sign_check.split("-"))
                        async with async_open(path, "rb") as file:
                            file.seek(start)
                            return await file.read(end - start + 1)
                    else:
                        file = await to_thread(
                            urlopen, 
                            path, 
                            headers={"Range": "bytes="+sign_check}, 
                        )
                        with file:
                            return await to_thread(file.read)
            else:
                def read_range_bytes_or_hash(sign_check: str, /) -> bytes:
                    if is_path:
                        start, end = map(int, sign_check.split("-"))
                        with open(path, "rb") as file:
                            file.seek(start)
                            return file.read(end - start + 1)
                    else:
                        with urlopen(path, headers={"Range": "bytes="+sign_check}) as file:
                            return file.read()
            resp = yield upload_file_init(
                filename=filename, 
                filesize=filesize, 
                filesha1=filesha1, 
                read_range_bytes_or_hash=read_range_bytes_or_hash, # type: ignore
                pid=pid, 
                async_=async_, # type: ignore
                **request_kwargs, 
            )
            if use_open_api:
                check_response(resp)
                data = resp["data"]
                match data["status"]:
                    case 2:
                        return resp
                    case 1:
                        bucket, object, callback = data["bucket"], data["object"], data["callback"]
                    case _:
                        raise OperationalError(errno.EINVAL, resp)
            else:
                status = resp["status"]
                statuscode = resp.get("statuscode", 0)
                if status == 2 and statuscode == 0:
                    return resp
                elif status == 1 and statuscode == 0:
                    bucket, object, callback = resp["bucket"], resp["object"], resp["callback"]
                else:
                    raise OperationalError(errno.EINVAL, resp)
            upload_data["bucket"] = bucket
            upload_data["object"] = object
            upload_data["callback"] = callback
            upload_data["filename"] = filename
            upload_data["filesha1"] = filesha1
            upload_data["filesize"] = filesize
            upload_data["partsize"] = partsize
            upload_data["part_count"] = partsize and -(-filesize // partsize)
            upload_data["pid"] = pid
        else:
            bucket = upload_data["bucket"]
            object = upload_data["object"]
            callback_var = loads(upload_data["callback"]["callback_var"])
            resp = yield upload_resume(
                {
                    "fileid": object, 
                    "file_size": upload_data["filesize"], 
                    "target": callback_var["x:target"], 
                    "pick_code": callback_var["x:pick_code"], 
                }, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
        url = f"http://{bucket}.{domain}/{object}"
        token = client.upload_token
        if upload_id := upload_data.get("upload_id"):
            parts = yield collect(oss_multipart_part_iter(
                client.request, 
                url, 
                bucket=bucket, 
                object=object, 
                upload_id=upload_id, 
                token=token, 
                async_=async_, 
                **request_kwargs, 
            ))
            if parts:
                upload_data["part_number_next"] = len(parts) + (int(parts[-1]["Size"]) == upload_data["partsize"])
            else:
                upload_data["part_number_next"] = 1
            upload_data["parts"] = parts
        else:
            upload_data["upload_id"] = yield oss_multipart_upload_init(
                client.request, 
                url, 
                bucket=bucket, 
                object=object, 
                token=token, 
                async_=async_, 
                **request_kwargs, 
            )
            upload_data["part_number_next"] = 1
            upload_data["parts"] = []
        upload_data["_upload_"] = None
        return upload_data
    return run_gen_step(gen_step, async_)


def multipart_upload_url(
    client: str | P115Client | P115OpenClient | dict, 
    upload_data: dict, 
    part_number: int = 1, 
    domain: str = ALIYUN_DOMAIN, 
) -> tuple[str, dict]:
    """用来获取 上传链接 和 请求头，然后文件需要你自己上传

    :param client: 115 客户端或 cookies，或者是 token（令牌）
    :param upload_data: 上传相关信息，可用于以后的断点续传
    :param part_number: 需要上传的分块编号，须从 1 开始递增
    :param domain: 上传到指定的阿里云集群的网址（netloc）

    :return: 上传链接 和 请求头 的 2 元组
    """
    if not domain:
        domain = ALIYUN_DOMAIN
    if isinstance(client, dict):
        token = client
    else:
        if isinstance(client, str):
            client = P115Client(client, check_for_relogin=True)
        token = client.upload_token
    return oss_multipart_upload_url(
        bucket=upload_data["bucket"], 
        object=upload_data["object"], 
        upload_id=upload_data["upload_id"], 
        part_number=part_number, 
        token=token, 
        domain=domain, 
    )


@overload
def multipart_upload_complete(
    client: str | P115Client | P115OpenClient, 
    upload_data: dict, 
    domain: str = ALIYUN_DOMAIN, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def multipart_upload_complete(
    client: str | P115Client | P115OpenClient, 
    upload_data: dict, 
    domain: str = ALIYUN_DOMAIN, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def multipart_upload_complete(
    client: str | P115Client | P115OpenClient, 
    upload_data: dict, 
    domain: str = ALIYUN_DOMAIN, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """完成分块上传

    :param client: 115 客户端或 cookies，或者是 token（令牌）
    :param upload_data: 上传相关信息，可用于以后的断点续传
    :param domain: 上传到指定的阿里云集群的网址（netloc）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应值

    :example:
        你可以构建自己的分块上传逻辑，下面是一个例子

        .. code:: python

            from pathlib import Path
            from p115client import *
            from p115client.tool import *

            client = P115Client(Path("~/115-cookies.txt").expanduser())
            #client.login_another_open(100195123, replace=True)

            # TODO: 这里填一个文件的路径
            path = "test.txt"

            upload_data = multipart_upload_init(
                client, 
                path, 
                pid = 0, 
                filename = "", 
                upload_data = None, 
            )
            if "_upload_" in upload_data:
                partsize = upload_data["partsize"]
                part_number_next = upload_data["part_number_next"]
                with open(path, "rb") as file:
                    if part_number_next > 1:
                        file.seek(partsize * (part_number_next - 1))
                    for part_number in range(part_number_next, upload_data["part_count"] + 1):
                        url, headers = multipart_upload_url(client, upload_data, part_number)
                        ## TODO: 你可以自己改写上传的逻辑
                        ## NOTE: 使用 urllib3
                        # from urllib3 import request
                        # request("PUT", url, body=file.read(partsize), headers=headers)
                        ## NOTE: 使用 requests
                        # from requests import request
                        # request("PUT", url, data=file.read(partsize), headers=headers)
                        client.request(url=url, method="PUT", data=file.read(partsize), headers=headers, parse=False)
                resp = multipart_upload_complete(client, upload_data)
            else:
                resp = upload_data
            print(resp)
    """
    if not domain:
        domain = ALIYUN_DOMAIN
    bucket = upload_data["bucket"]
    object = upload_data["object"]
    upload_id = upload_data["upload_id"]
    url = f"http://{bucket}.{domain}/{object}"
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    def gen_step():
        token = client.upload_token
        parts = yield collect(oss_multipart_part_iter(
            client.request, 
            url, 
            bucket=bucket, 
            object=object, 
            upload_id=upload_id, 
            token=token, 
            async_=async_, 
            **request_kwargs, 
        ))
        return oss_multipart_upload_complete(
            client.request, 
            url, 
            bucket=bucket, 
            object=object, 
            upload_id=upload_id, 
            token=token, 
            callback=upload_data["callback"], 
            parts=parts, 
            async_=async_, 
            **request_kwargs, 
        )
    return run_gen_step(gen_step, async_)

