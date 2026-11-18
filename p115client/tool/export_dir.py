#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "export_dir_parse_iter_depth_name", "export_dir_parse_iter_dict", 
    "export_dir_parse_iter_path", "export_dir_parse_iter_patht", 
    "export_dir_start", "export_dir_status", "export_dir_result", 
    "export_dir_parse_iter", "export_dir", 
]
__doc__ = "这个模块提供了一些和导出目录树有关的函数"

from asyncio import sleep as async_sleep
from collections.abc import (
    AsyncIterable, AsyncIterator, Awaitable, Buffer, Callable, 
    Coroutine, Iterable, Iterator, 
)
from inspect import iscoroutinefunction
from os import PathLike
from time import sleep, time
from typing import cast, overload, Any, Literal

from filewrap import SupportsRead
from iterutils import (
    run_gen_step, run_gen_step_iter, with_iter_next, Yield, YieldFrom, 
)
from p115pickcode import to_id

from ..client import check_response, P115Client
from ..exception import P115FileTooBig


def iter_line_utf16(
    chunks: Iterable[Buffer] | SupportsRead[Buffer], 
    /, 
    chunksize: int = 1 << 16, 
) -> Iterator[str]:
    # NOTE: NEWLINE = bytes("\n", "utf-16").removeprefix(bytes("", "utf-16"))
    NEWLINE = b"\n\x00"
    if hasattr(chunks, "read"):
        chunks = iter(
            cast(Callable[[], bytes], lambda read=chunks.read, /: read(chunksize)), 
            b"", 
        )
    buf = bytearray()
    absorb = bytearray.extend
    indexof = bytearray.index
    stop = 0
    for chunk in chunks:
        absorb(buf, chunk) # type: ignore
        view = memoryview(buf)
        start = 0
        try:
            while True:
                stop = indexof(buf, NEWLINE, stop) + 2
                if stop % 2 == 0:
                    yield str(view[start:stop], "utf-16")
                    start = stop
        except ValueError:
            pass
        del view
        if start:
            buf = buf[start:]
        stop = len(buf) & ~1
    if buf:
        yield str(buf, "utf-16")


async def aiter_line_utf16(
    chunks: AsyncIterable[Buffer] | SupportsRead[Awaitable[Buffer]], 
    /, 
    chunksize: int = 1 << 16, 
) -> AsyncIterator[str]:
    NEWLINE = b"\n\x00" 
    if hasattr(chunks, "read"):
        from itertools import repeat
        read = chunks.read
        chunks = (b for _ in repeat(None) if (b := await read(chunksize)))
    buf = bytearray()
    absorb = bytearray.extend
    indexof = bytearray.index
    stop = 0
    async for chunk in chunks:
        absorb(buf, chunk) # type: ignore
        view = memoryview(buf)
        start = 0
        try:
            while True:
                stop = indexof(buf, NEWLINE, stop) + 2
                if stop % 2 == 0:
                    yield str(view[start:stop], "utf-16")
                    start = stop
        except ValueError:
            pass
        del view
        if start:
            buf = buf[start:]
        stop = len(buf) & ~1
    if buf:
        yield str(buf, "utf-16")


def export_dir_parse_iter_depth_name_sync(
    iterable: Iterable[str], 
    /, 
) -> Iterator[tuple[int, str]]:
    count = str.count
    indexof = str.index
    startswith = str.startswith
    last_depth = 0
    last_line = ""
    for line in iterable:
        try:
            idx = indexof(line, "|-", 2)
            if startswith(line, "| "):
                q, r = divmod(idx, 2)
                if r == 0 and count(line, "| ", 0, idx) == q:
                    if last_depth == 0 and last_line == "根目录":
                        last_line = ""
                    yield last_depth, last_line
                    last_depth = q
                    last_line = line[idx+2:-1]
                    continue
        except ValueError:
            if not last_line and startswith(line, "|——"):
                last_line = line[3:-1]
                continue
        last_line += "\n" + line[:-1]
    if last_line:
        yield last_depth, last_line


async def export_dir_parse_iter_depth_name_async(
    iterable: AsyncIterable[str], 
    /, 
) -> AsyncIterator[tuple[int, str]]:
    count = str.count
    indexof = str.index
    startswith = str.startswith
    last_depth = 0
    last_line = ""
    async for line in iterable:
        try:
            idx = indexof(line, "|-", 2)
            if startswith(line, "| "):
                q, r = divmod(idx, 2)
                if r == 0 and count(line, "| ", 0, idx) == q:
                    if last_depth == 0 and last_line == "根目录":
                        last_line = ""
                    last_depth = q
                    last_line = line[idx+2:-1]
                    continue
        except ValueError:
            if not last_line and startswith(line, "|——"):
                last_line = line[3:-1]
                continue
        last_line += "\n" + line[:-1]
    if last_line:
        yield last_depth, last_line


@overload
def export_dir_iter_line(
    chunks: Iterable[Buffer] | SupportsRead[Buffer], 
    /, 
    chunksize: int = 1 << 16, 
) -> Iterator[str]:
    ...
@overload
def export_dir_iter_line(
    chunks: AsyncIterable[Buffer] | SupportsRead[Awaitable[Buffer]], 
    /, 
    chunksize: int = 1 << 16, 
) -> AsyncIterator[str]:
    ...
def export_dir_iter_line(
    chunks: Iterable[Buffer] | SupportsRead[Buffer] | AsyncIterable[Buffer] | SupportsRead[Awaitable[Buffer]], 
    /, 
    chunksize: int = 1 << 16, 
) -> Iterator[str] | AsyncIterator[str]:
    if isinstance(chunks, AsyncIterable) or iscoroutinefunction(getattr(chunks, "read", None)):
        return aiter_line_utf16(chunks, chunksize=chunksize) # type: ignore
    else:
        return iter_line_utf16(chunks, chunksize=chunksize) # type: ignore


@overload
def export_dir_parse_iter_depth_name(
    iterable: Iterable[str], 
    /, 
) -> Iterator[tuple[int, str]]:
    ...
@overload
def export_dir_parse_iter_depth_name(
    iterable: AsyncIterable[str], 
    /, 
) -> AsyncIterator[tuple[int, str]]:
    ...
def export_dir_parse_iter_depth_name(
    iterable: Iterable[str] | AsyncIterable[str], 
    /, 
) -> Iterator[tuple[int, str]] | AsyncIterator[tuple[int, str]]:
    if isinstance(iterable, AsyncIterable):
        return export_dir_parse_iter_depth_name_async(iterable)
    else:
        return export_dir_parse_iter_depth_name_sync(iterable)


@overload
def export_dir_parse_iter_dict(
    iterable: Iterable[str], 
    /, 
) -> Iterator[dict]:
    ...
@overload
def export_dir_parse_iter_dict(
    iterable: AsyncIterable[str], 
    /, 
) -> AsyncIterator[dict]:
    ...
def export_dir_parse_iter_dict(
    iterable: Iterable[str] | AsyncIterable[str], 
    /, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """解析 115 导出的目录树（可通过 P115Client.fs_export_dir 提交导出任务）

    :param iterable: 迭代器，每次返回一行

    :return: 把每一行解析为一个字典，迭代返回，格式为

        .. code:: python

            {
                "id":        int, # 序号
                "parent_id": int, # 上级目录的序号
                "depth":     int, # 深度
                "name":      str, # 名字
            }
    """
    def gen_step():
        stack: list[int] = []
        push = stack.append
        i = 1
        with with_iter_next(export_dir_parse_iter_depth_name(iterable)) as get_next:
            while True:
                depth, name = yield get_next()
                yield Yield({
                    "id": i, 
                    "parent_id": stack[depth-1] if depth else 0, 
                    "depth": depth, 
                    "name": name, 
                })
                try:
                    stack[depth] = i
                except IndexError:
                    push(i)
                i += 1
    return run_gen_step_iter(
        gen_step, 
        isinstance(iterable, AsyncIterable), # type: ignore
    )


@overload
def export_dir_parse_iter_path(
    iterable: Iterable[str], 
    /, 
    escape: None | bool | Callable[[str], str] = None, 
) -> Iterator[str]:
    ...
@overload
def export_dir_parse_iter_path(
    iterable: AsyncIterable[str], 
    /, 
    escape: None | bool | Callable[[str], str] = None, 
) -> AsyncIterator[str]:
    ...
def export_dir_parse_iter_path(
    iterable: Iterable[str] | AsyncIterable[str], 
    /, 
    escape: None | bool | Callable[[str], str] = None, 
) -> Iterator[str] | AsyncIterator[str]:
    """解析 115 导出的目录树（可通过 P115Client.fs_export_dir 提交导出任务）

    :param iterable: 迭代器，每次返回一行
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :return: 把每一行解析为一个路径，并逐次迭代返回
    """
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            from p115client.util import posix_escape_name as escape
    escape = cast(None | Callable[[str], str], escape)
    def gen_step():
        stack: list[str] = [""]
        push = stack.append
        with with_iter_next(export_dir_parse_iter_depth_name(iterable)) as get_next:
            while True:
                depth, name = yield get_next()
                if escape is not None:
                    name = escape(name)
                if depth:
                    path = stack[depth-1] + "/" + name
                else:
                    path = name
                yield Yield(path or "/")
                try:
                    stack[depth] = path
                except IndexError:
                    push(path)
    return run_gen_step_iter(
        gen_step, 
        isinstance(iterable, AsyncIterable), # type: ignore
    )


@overload
def export_dir_parse_iter_patht(
    iterable: Iterable[str], 
    /, 
) -> Iterator[list[str]]:
    ...
@overload
def export_dir_parse_iter_patht(
    iterable: AsyncIterable[str], 
    /, 
) -> AsyncIterator[list[str]]:
    ...
def export_dir_parse_iter_patht(
    iterable: Iterable[str] | AsyncIterable[str], 
    /, 
) -> Iterator[list[str]] | AsyncIterator[list[str]]:
    """解析 115 导出的目录树（可通过 P115Client.fs_export_dir 提交导出任务）

    :param iterable: 迭代器，每次返回一行

    :return: 把每一行解析为一个名字列表，并逐次迭代返回
    """
    def gen_step():
        stack = [""]
        push = stack.append
        with with_iter_next(export_dir_parse_iter_depth_name(iterable)) as get_next:
            while True:
                depth, name = yield get_next()
                try:
                    stack[depth] = name
                except IndexError:
                    push(name)
                yield Yield(stack[:depth+1])
    return run_gen_step_iter(
        gen_step, 
        isinstance(iterable, AsyncIterable), # type: ignore
    )


@overload
def export_dir_start(
    client: str | PathLike | P115Client, 
    file_ids: int | str | Iterable[int | str] = 0, 
    target: int | str = 0, 
    layer_limit: int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def export_dir_start(
    client: str | PathLike | P115Client, 
    file_ids: int | str | Iterable[int | str] = 0, 
    target: int | str = 0, 
    layer_limit: int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def export_dir_start(
    client: str | PathLike | P115Client, 
    file_ids: int | str | Iterable[int | str] = 0, 
    target: int | str = 0, 
    layer_limit: int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """开始【导出目录树】任务

    :param client: 115 客户端或 cookies
    :param file_ids: 待导出的目录 id 或 pickcode
    :param target: 导出到的目标目录 id 或 pickcode 或 target（格式为 f"U_{aid}_{pid}"）
    :param layer_limit: 层级深度，取值范围 0~25
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 返回任务 id，可用 `P115Client.fs_export_dir_status` 查询进度
    """
    if not isinstance(client, P115Client):
        client = P115Client(client)
    if isinstance(target, int):
        target = f"U_1_{target}"
    elif not target.startswith("U_"):
        target = f"U_1_{to_id(target)}"
    if isinstance(file_ids, str):
        if "," not in file_ids:
            file_ids = to_id(file_ids)
    elif not isinstance(file_ids, int):
        file_ids = ",".join(str(to_id(eid)) for eid in file_ids)
    if app in ("", "web", "desktop", "aps"):
        export_dir: Callable = client.fs_export_dir
    else:
        request_kwargs["app"] = app
        export_dir = client.fs_batch_edit_app
    def gen_step():
        payload = {"file_ids": file_ids, "target": target}
        if 0 < layer_limit <= 25:
            payload["layer_limit"] = layer_limit
        resp = yield export_dir(payload, async_=async_, **request_kwargs)
        check_response(resp)
        return resp["data"]["export_id"]
    return run_gen_step(gen_step, async_)


@overload
def export_dir_status(
    client: str | PathLike | P115Client, 
    export_id: int | str, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def export_dir_status(
    client: str | PathLike | P115Client, 
    export_id: int | str, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def export_dir_status(
    client: str | PathLike | P115Client, 
    export_id: int | str, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """【导出目录树】的任务状态

    :param client: 115 客户端或 cookies
    :param export_id: 任务 id，由 `P115Client.fs_export_dir` 接口调用产生
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口返回结果，如果任务完成，格式为

        .. code:: python

            {
                "export_id": str, # 任务 id
                "file_id":   str, # 导出文件的 id
                "file_name": str, # 导出文件的名字
                "pick_code": str  # 导出文件的提取码
            }
    """
    if not isinstance(client, P115Client):
        client = P115Client(client)
    if app in ("", "web", "desktop", "aps"):
        export_dir_status: Callable = client.fs_export_dir_status
    else:
        request_kwargs["app"] = app
        export_dir_status = client.fs_export_dir_status_app
    def gen_step():
        resp = yield export_dir_status(
            export_id, 
            async_=async_, 
            **request_kwargs, 
        )
        check_response(resp)
        if data := resp["data"]:
            return data
        return {"export_id": export_id}
    return run_gen_step(gen_step, async_)


@overload
def export_dir_result(
    client: str | PathLike | P115Client, 
    export_id: int | str, 
    timeout: None | int | float = None, 
    check_interval: int | float = 1, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def export_dir_result(
    client: str | PathLike | P115Client, 
    export_id: int | str, 
    timeout: None | int | float = None, 
    check_interval: int | float = 1, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def export_dir_result(
    client: str | PathLike | P115Client, 
    export_id: int | str, 
    timeout: None | int | float = None, 
    check_interval: int | float = 1, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取【导出目录树】的结果

    .. attention::
        如果指定超时时间为正数，则会在过期时抛出 TimeoutError，但这并不会取消远程正在执行的任务，而 115 同时只允许运行一个导出目录树的任务，所以如果要开始下一个导出任务，还需要此任务完成或者被 115 自动超时取消

    :param client: 115 客户端或 cookies
    :param export_id: 任务 id，由 `P115Client.fs_export_dir` 接口调用产生
    :param timeout: 超时秒数，如果为 None 或 小于等于 0，则相当于 float("inf")，即永不超时
    :param check_interval: 两次轮询之间的等待秒数，如果 <= 0，则不等待
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口返回结果，格式为

        .. code:: python

            {
                "export_id": str, # 任务 id
                "file_id":   str, # 导出文件的 id
                "file_name": str, # 导出文件的名字
                "pick_code": str  # 导出文件的提取码
            }
    """
    if not isinstance(client, P115Client):
        client = P115Client(client)
    if app in ("", "web", "desktop", "aps"):
        export_dir_status: Callable = client.fs_export_dir_status
    else:
        request_kwargs["app"] = app
        export_dir_status = client.fs_export_dir_status_app
    if check_interval < 0:
        check_interval = 0
    def gen_step():
        nonlocal timeout
        if timeout is None or timeout <= 0:
            timeout = float("inf")
        expired_t = time() + timeout
        while True:
            resp = yield export_dir_status(
                export_id, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            if data := resp["data"]:
                return data
            remaining_seconds = expired_t - time()
            if remaining_seconds <= 0:
                raise TimeoutError(export_id)
            if check_interval and (delta := min(check_interval, remaining_seconds)) >= 0:
                if async_:
                    yield async_sleep(delta)
                else:
                    sleep(delta)
    return run_gen_step(gen_step, async_)


@overload
def export_dir_parse_iter(
    client: str | PathLike | P115Client, 
    export_id: int | str = 0, 
    parse_iter: None | Literal["depth_name", "dict", "path", "patht"] | Callable[[Iterable[str]], Iterable] = "path", 
    delete: bool = False, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator:
    ...
@overload
def export_dir_parse_iter(
    client: str | PathLike | P115Client, 
    export_id: int | str = 0, 
    parse_iter: None | Literal["depth_name", "dict", "path", "patht"] | Callable[[AsyncIterable[str]], AsyncIterable] = "path", 
    delete: bool = False, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator:
    ...
def export_dir_parse_iter(
    client: str | PathLike | P115Client, 
    export_id: int | str = 0, 
    parse_iter: None | Literal["depth_name", "dict", "path", "patht"] | Callable[[Iterable[str]], Iterable] | Callable[[AsyncIterable[str]], AsyncIterable] = "path", 
    delete: bool = False, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator | AsyncIterator:
    """解析且按行遍历【导出目录树】生成的文件，并返回迭代器

    :param client: 115 客户端或 cookies
    :param export_id: 【导出目录树】的任务 id、文件 id 或 文件 pickcode
    :param parse_iter: 解析每一行目录树记录，并返回迭代器

        - None: 直接原样返回每一行
        - "depth_name": 使用 `export_dir_parse_iter_depth_name`
        - "dict": 使用 `export_dir_parse_dict`
        - "path": 使用 `export_dir_parse_iter_path`
        - "patht": 使用 `export_dir_parse_iter_patht`
        - Callable: 自定义解析函数

    :param delete: 是否在完成后删除文件

        - True: 删除
        - False: 保留

    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 解析目录树文件的迭代器
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if isinstance(parse_iter, str):
        parse_iter = cast(Callable, globals()["export_dir_parse_iter_" + parse_iter])
    def gen_step():
        nonlocal export_id
        export_id = to_id(export_id)
        if export_id < 1 << 60:
            result: dict = yield export_dir_result(
                client, 
                export_id, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
            fid = int(result["file_id"])
        else:
            fid = export_id
        try:
            try:
                url: str = yield client.download_url(
                    fid, 
                    app="web", 
                    async_=async_, 
                    **request_kwargs, 
                )
            except P115FileTooBig:
                url = yield client.download_url(
                    fid, 
                    app="android", 
                    async_=async_, 
                    **request_kwargs, 
                )
            file = yield client.open(url, async_=async_)
            try:
                it = export_dir_iter_line(file)
                if parse_iter is not None:
                    it = parse_iter(it)
                yield YieldFrom(it)
            finally:
                yield file.close()
        finally:
            if delete:
                if app in ("", "web", "desktop", "aps"):
                    fs_delete: Callable = client.fs_delete
                else:
                    request_kwargs["app"] = app
                    fs_delete = client.fs_delete_app
                yield fs_delete(
                    fid, 
                    async_=async_, 
                    **request_kwargs, 
                )
    return run_gen_step_iter(gen_step, async_)


@overload
def export_dir(
    client: str | PathLike | P115Client, 
    file_ids: int | str | Iterable[int | str], 
    target: int | str = 0, 
    layer_limit: int = 0, 
    parse_iter: None | Literal["depth_name", "dict", "path", "patht"] | Callable[[Iterable[str]], Iterable] = "path", 
    delete: bool = True, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator:
    ...
@overload
def export_dir(
    client: str | PathLike | P115Client, 
    file_ids: int | str | Iterable[int | str], 
    target: int | str = 0, 
    layer_limit: int = 0, 
    parse_iter: None | Literal["depth_name", "dict", "path", "patht"] | Callable[[AsyncIterable[str]], AsyncIterable] = "path", 
    delete: bool = True, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator:
    ...
def export_dir(
    client: str | PathLike | P115Client, 
    file_ids: int | str | Iterable[int | str], 
    target: int | str = 0, 
    layer_limit: int = 0, 
    parse_iter: None | Literal["depth_name", "dict", "path", "patht"] | Callable[[Iterable[str]], Iterable] | Callable[[AsyncIterable[str]], AsyncIterable] = "path", 
    delete: bool = True, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator | AsyncIterator:
    """执行【导出目录树】，读取产生的文件并返回按行解析的迭代器

    :param client: 115 客户端或 cookies
    :param file_ids: 待导出的目录 id 或 pickcode
    :param target: 导出到的目标目录 id 或 pickcode 或 target（格式为 f"U_{aid}_{pid}"）
    :param layer_limit: 层级深度，小于等于 0 时不限
    :param parse_iter: 解析每一行目录树记录，并返回迭代器

        - None: 直接原样返回每一行
        - "depth_name": 使用 `export_dir_parse_iter_depth_name`
        - "dict": 使用 `export_dir_parse_dict`
        - "path": 使用 `export_dir_parse_iter_path`
        - "patht": 使用 `export_dir_parse_iter_patht`
        - Callable: 自定义解析函数

    :param delete: 是否在完成后删除文件
 
        - True: 删除
        - False: 保留

    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 解析目录树文件的迭代器
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if isinstance(parse_iter, str):
        parse_iter = cast(Callable, globals()["export_dir_parse_iter_" + parse_iter])
    request_kwargs["app"] = app
    def gen_step():
        export_id = yield export_dir_start(
            client, 
            file_ids=file_ids, 
            target=target, 
            layer_limit=layer_limit, 
            async_=async_, 
            **request_kwargs, 
        )
        yield YieldFrom(export_dir_parse_iter(
            client, 
            export_id, 
            parse_iter=parse_iter, 
            delete=delete, 
            **request_kwargs, 
        ))
    return run_gen_step_iter(gen_step, async_)

