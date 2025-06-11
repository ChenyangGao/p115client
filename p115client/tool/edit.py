#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "update_abstract", "update_desc", "update_star", "update_label", "update_score", 
    "update_top", "update_show_play_long", "update_category_shortcut", "batch_unstar", 
]
__doc__ = "这个模块提供了一些和修改文件或目录信息有关的函数"

from collections.abc import AsyncIterable, AsyncIterator, Coroutine, Iterable, Iterator
from functools import partial
from typing import cast, overload, Any, Literal

from asynctools import to_list
from concurrenttools import taskgroup_map, threadpool_map
from iterutils import chunked, run_gen_step, foreach, through, async_through
from p115client import check_response, P115Client


@overload
def update_abstract(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    /, 
    method: str, 
    value: Any, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_abstract(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    method: str, 
    value: Any, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_abstract(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    method: str, 
    value: Any, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量设置文件或目录

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param method: 方法名
    :param value: 要设置的值
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if max_workers is None or max_workers <= 0:
        max_workers = 20 if async_ else None
    def gen_step():
        setter = partial(getattr(client, method), async_=async_, **request_kwargs)
        def call(batch, /):
            return check_response(setter(batch, value))
        if max_workers == 1:
            yield foreach(call, chunked(ids, batch_size))
        elif async_: 
            yield async_through(taskgroup_map(
                call, 
                chunked(ids, batch_size), 
                max_workers=max_workers, 
            ))
        else:
            through(threadpool_map(
                call, 
                chunked(ids, batch_size), 
                max_workers=max_workers
            ))
    return run_gen_step(gen_step, may_call=False, async_=async_)


@overload
def update_desc(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    /, 
    desc: str = "", 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_desc(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    desc: str = "", 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_desc(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    desc: str = "", 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给文件或目录设置备注，此举可更新此文件或目录的 mtime

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param desc: 备注文本
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if app in ("", "web", "desktop", "harmony"):
        method = "fs_desc_set"
    else:
        method = "fs_desc_set_app"
        request_kwargs["app"] = app
    return update_abstract(
        client, 
        ids, # type: ignore
        method=method, 
        value=desc, 
        batch_size=batch_size, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def update_star(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    /, 
    star: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_star(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    star: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_star(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    star: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给文件或目录设置星标

    .. note::
        如果一批中有任何一个 id 已经被删除，则这一批直接失败报错

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param star: 是否设置星标
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if not isinstance(client, P115Client) or app == "open":
        method = "fs_star_set_open"
    elif app in ("", "web", "desktop", "harmony"):
        method = "fs_star_set"
    else:
        method = "fs_star_set_app"
        request_kwargs["app"] = app
    return update_abstract(
        client, 
        ids, # type: ignore
        method=method, 
        value=star, 
        batch_size=batch_size, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def update_label(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    /, 
    label: int | str = 1, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_label(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    label: int | str = 1, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_label(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    label: int | str = 1, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给文件或目录设置标签

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param label: 标签 id，多个用逗号 "," 隔开，如果用一个根本不存在的 id，效果就是清空标签列表
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if app in ("", "web", "desktop", "harmony"):
        method = "fs_label_set"
    else:
        method = "fs_label_set_app"
        request_kwargs["app"] = app
    return update_abstract(
        client, 
        ids, # type: ignore
        method=method, 
        value=label, 
        batch_size=batch_size, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def update_score(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    /, 
    score: int = 0, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_score(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    score: int = 0, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_score(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    score: int = 0, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给文件或目录设置分数

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param score: 分数
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    return update_abstract(
        client, 
        ids, # type: ignore
        method="fs_score_set", 
        value=score, 
        batch_size=batch_size, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def update_top(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    /, 
    top: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_top(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    top: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_top(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    top: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给文件或目录设置置顶

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param score: 分数
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    return update_abstract(
        client, 
        ids, # type: ignore
        method="fs_top_set", 
        value=top, 
        batch_size=batch_size, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def update_show_play_long(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    /, 
    show: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_show_play_long(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    show: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_show_play_long(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    show: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给目录设置显示时长

    :param client: 115 客户端或 cookies
    :param ids: 一组目录的 id
    :param show: 是否显示时长
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if app in ("", "web", "desktop", "harmony"):
        method = "fs_show_play_long_set"
    else:
        method = "fs_show_play_long_set_app"
        request_kwargs["app"] = app
    return update_abstract(
        client, 
        ids, # type: ignore
        method=method, 
        value=show, 
        batch_size=batch_size, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def update_category_shortcut(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    /, 
    set: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_category_shortcut(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    set: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_category_shortcut(
    client: str | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    set: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给目录设置显示时长

    :param client: 115 客户端或 cookies
    :param ids: 一组目录的 id
    :param set: 是否设为快捷入口
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    return update_abstract(
        client, 
        ids, # type: ignore
        method="fs_category_shortcut_set", 
        value=set, 
        batch_size=batch_size, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def batch_unstar(
    client: str | P115Client, 
    /, 
    batch_size: int = 10_000, 
    ensure_file: None | bool = None, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def batch_unstar(
    client: str | P115Client, 
    /, 
    batch_size: int = 10_000, 
    ensure_file: None | bool = None, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def batch_unstar(
    client: str | P115Client, 
    /, 
    batch_size: int = 10_000, 
    ensure_file: None | bool = None, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量对一批文件或目录取消星标

    :param client: 115 客户端或 cookies
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param ensure_file: 是否确保为文件

        - True: 必须是文件
        - False: 必须是目录
        - None: 可以是目录或文件

    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    def get_id(info: dict, /) -> int:
        for k in ("file_id", "category_id", "fid", "cid"):
            if k in info:
                return int(info[k])
        raise KeyError
    def gen_step():
        from .iterdir import _iter_fs_files
        it = _iter_fs_files(
            client, 
            payload={"cid": 0, "count_folders": 1, "cur": 0, "fc_mix": 0, "offset": 0, "show_dir": 1, "star": 1}, 
            ensure_file=ensure_file, 
            app=app, 
            cooldown=0.5, 
            async_=async_, 
            **request_kwargs, 
        )
        if async_:
            ids: list[int] = yield to_list(get_id(info) async for info in cast(AsyncIterator[dict], it))
        else:
            ids = [get_id(info) for info in cast(Iterator[dict], it)]
        yield update_star(
            client, 
            ids, 
            star=False, 
            batch_size=batch_size, 
            max_workers=max_workers, 
            app=app, 
            async_=async_, # type: ignore
            **request_kwargs, 
        )
    return run_gen_step(gen_step, may_call=False, async_=async_)

