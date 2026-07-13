#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "extract_push", "extract_push_progress", "extract_iterdir_raw", 
    "extract_file", "extract_progress", 
]
__doc__ = "这个模块提供了一些和压缩包的增删改查有关的函数"

from collections.abc import AsyncIterator, Callable, Coroutine, Iterable, Iterator, Mapping
from os import PathLike
from typing import cast, overload, Any, Literal

from dicttools import get_first
from iterutils import run_gen_step, run_gen_step_iter, YieldFrom

from ..client import P115Client, check_response


@overload
def extract_push(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    secret: str = "", 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def extract_push(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    secret: str = "", 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def extract_push(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    secret: str = "", 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """推送云解压任务

    .. warning::
        只能云解压 20GB 以内文件，也不支持云解压分卷压缩包，只支持 .zip、.rar 和 .7z 等。
        如果超出此限制，就要自己动手了，但如此的话，压缩包里面的单个文件往往就不支持随机定位了。

    .. note::
        响应信息里面有个 "unzip_status" 字段

        - 0: 未解压
        - 1: 解压中
        - 4: 解压成功
        - 6: 解压成功（重复提交已成功任务，但密码错误）

        .. code:: python

            from time import sleep
            from p115client import P115Client
            from p115client.tool import *
            client = P115Client.from_path()

            # NOTE: 待搜索的目录
            cid = 0
            # 罗列此目录内所有的压缩包
            files = list(iter_files(client, cid, type=5, use_media_api=True))

            for i, file in enumerate(files, 1):
                if not file:
                    continue
                # 只支持云解压不超过 20 GB 的压缩包
                if file["size"] > (1 << 30) * 20:
                    print(i, f"[SKIPPED] 文件过大: {file}\n\n")
                    continue
                # 推送解压任务
                try:
                    resp = extract_push(client, file, app="android")
                except FileNotFoundError:
                    print(i, f"[SKIPPED] 文件不存在: {file}\n\n")
                    continue
                unzip_status = resp["data"]["unzip_status"]
                if resp["data"]["unzip_status"] != 4:
                    print(i, f"[SKIPPED] unzip_status={unzip_status} 云解压未成: {file}\n\n")
                    continue
                print(i, "开始解压:", file)
                try:
                    task_id = extract_file(client, file["pickcode"], to_pid=file["parent_id"])
                except Exception as e:
                    print(i, f"[FAILED] 解压失败: {file} 异常: {e}\n\n")
                    continue
                while True:
                    try:
                        resp = extract_progress(client, task_id)
                    except Exception:
                        continue
                    percent = resp["data"]["percent"]
                    print(f"\r进度（百分比）: {percent}%", end="")
                    if percent == 100:
                        print()
                        break
                    sleep(1)
                client.fs_delete(file["id"])
                files[i-1] = None
                print(i, "[SUCCESS] 解压完成，文件已删除\n\n")

    :param client:   115 客户端或 cookies
    :param pickcode: 压缩包文件的 提取码、id
    :param secret:   解压密码，没有就不传
    :param app:      使用指定 app（设备）的接口
    :param async_:   是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app in ("", "web", "desktop", "aps"):
        extract_push: Callable = client.extract_push
    else:
        extract_push = client.extract_push_app
        request_kwargs["app"] = app
    if isinstance(pickcode, Mapping):
        pickcode = cast(str | int, get_first(pickcode, "pickcode", "id"))
    return check_response(extract_push(
        {"pick_code": client.to_pickcode(pickcode), "secret": secret}, 
        async_=async_, 
        **request_kwargs, 
    ))


@overload
def extract_push_progress(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def extract_push_progress(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def extract_push_progress(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取云解压任务进度

    .. warning::
        只能云解压 20GB 以内文件，也不支持云解压分卷压缩包，只支持 .zip、.rar 和 .7z 等。
        如果超出此限制，就要自己动手了，但如此的话，压缩包里面的单个文件往往就不支持随机定位了。

    .. note::
        响应信息里面有个 "unzip_status" 字段

        - 0: 未解压
        - 1: 解压中
        - 4: 解压成功
        - 6: 解压失败

    :param client:   115 客户端或 cookies
    :param pickcode: 压缩包文件的 提取码、id
    :param app:      使用指定 app（设备）的接口
    :param async_:   是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app in ("", "web", "desktop", "aps"):
        extract_push: Callable = client.extract_push_progress
    else:
        extract_push = client.extract_push_progress_app
        request_kwargs["app"] = app
    if isinstance(pickcode, Mapping):
        pickcode = cast(str | int, get_first(pickcode, "pickcode", "id"))
    return check_response(extract_push(
        {"pick_code": client.to_pickcode(pickcode)}, 
        async_=async_, 
        **request_kwargs, 
    ))


@overload
def extract_iterdir_raw(
    client: str | PathLike | P115Client, 
    pickcode: str, 
    path: str = "", 
    page_size: int = 999, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def extract_iterdir_raw(
    client: str | PathLike | P115Client, 
    pickcode: str, 
    path: str = "", 
    page_size: int = 999, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def extract_iterdir_raw(
    client: str | PathLike | P115Client, 
    pickcode: str, 
    path: str = "", 
    page_size: int = 999, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """对压缩包迭代目录，获取（原始的）文件信息

    .. note::
        你可以使用 ``p115client.tool.extract_iterdir`` 作为替代，以获取经过处理的信息

    :param client:    115 客户端或 cookies
    :param pickcode:  压缩包文件的 提取码、id
    :param path:      压缩包内（目录）路径，为空则是压缩包的根目录
    :param page_size: 分页大小，最大 999
    :param app:       使用指定 app（设备）的接口
    :param async_:    是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def gen_step():
        extract_list = client.extract_list
        next_marker = ""
        while True:
            resp = yield extract_list(
                pickcode, 
                path=path, 
                next_marker=next_marker, 
                page_count=page_size, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            data = resp["data"]
            yield YieldFrom(data["list"])
            if not (next_marker := data.get("next_marker")):
                break
    return run_gen_step_iter(gen_step, async_)


@overload
def extract_file(
    client: str | PathLike | P115Client, 
    pickcode: str, 
    files: str | Iterable[str] = "", 
    dirs: str | Iterable[str] = "", 
    dirname: str = "", 
    to_pid: int | str = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def extract_file(
    client: str | PathLike | P115Client, 
    pickcode: str, 
    files: str | Iterable[str] = "", 
    dirs: str | Iterable[str] = "", 
    dirname: str = "", 
    to_pid: int | str = 0, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def extract_file(
    client: str | PathLike | P115Client, 
    pickcode: str, 
    files: str | Iterable[str] = "", 
    dirs: str | Iterable[str] = "", 
    dirname: str = "", 
    to_pid: int | str = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """解压缩到某个网盘目录

    :param client:   115 客户端或 cookies
    :param pickcode: 压缩文件的提取码
    :param files:    待解压缩的文件路径（相对于 ``dirname``），如果以 "/" 结尾，则视为目录
    :param dirs:     待解压缩的文件路径（相对于 ``dirname``）
    :param dirname:  压缩包内路径，为空则是压缩包的根目录
    :param to_pid:   解压到网盘的目录 id
    :param app:      使用此设备的接口
    :param async_:   是否异步
    :param request_kwargs: 其它请求参数

    :return: 任务 id
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def gen_step():
        resp = yield client.extract_file(
            pickcode, 
            files=files, 
            dirs=dirs, 
            dirname=dirname, 
            to_pid=client.to_id(to_pid), 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )
        check_response(resp)
        return resp["data"]["extract_id"]
    return run_gen_step(gen_step, async_)


@overload
def extract_progress(
    client: str | PathLike | P115Client, 
    extract_id: int, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def extract_progress(
    client: str | PathLike | P115Client, 
    extract_id: int, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def extract_progress(
    client: str | PathLike | P115Client, 
    extract_id: int, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取【解压到网盘】任务进度

    :param client:     115 客户端或 cookies
    :param extract_id: 解压任务 id
    :param app:      使用此设备的接口
    :param async_:   是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app in ("", "web", "desktop", "aps"):
        extract_progress: Callable = client.extract_progress
    else:
        extract_progress = client.extract_progress_app
        request_kwargs["app"] = app
    return check_response(extract_progress(extract_id, async_=async_, **request_kwargs))

