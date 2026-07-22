#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "update_abstract", "update_desc", "update_star", "update_label", "update_score", 
    "update_top", "update_show_play_long", "update_category_shortcut", "batch_unstar", 
    "update_name", "post_event", "makedir", "iter_batch_makedir", "batch_makedir", 
    "batch_copy", "batch_copy_files", "batch_delete", "batch_delete_files", 
    "batch_move", "batch_move_files", "batch_recyclebin_clean", "batch_recyclebin_revert", 
    "batch_hide", "copyfile", "renamefile", "transferfile", 
]
__doc__ = "这个模块提供了一些和修改文件或目录信息有关的函数"

from collections import defaultdict
from collections.abc import (
    AsyncIterable, AsyncIterator, Callable, Coroutine, Iterable, 
    Iterator, Mapping, MutableMapping, 
)
from contextlib import suppress
from functools import partial
from itertools import batched
from os import PathLike
from typing import cast, overload, Any, Literal
from types import EllipsisType

from concurrenttools import conmap
from iterutils import (
    chunked, collect, foreach, map as do_map, run_gen_step, as_gen_step, 
    through, 
)
from p115pickcode import to_id

from ..client import check_response, P115Client, P115OpenClient
from ..exception import P115BusyOSError
from ..type import P115URL


@overload
def update_abstract(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    /, 
    method: str, 
    value: Any, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_abstract(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    method: str, 
    value: Any, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_abstract(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    method: str, 
    value: Any, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量设置文件或目录

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param method: 方法名
    :param value: 要设置的值
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def gen_step():
        setter = partial(getattr(client, method), async_=async_, **request_kwargs)
        def call(batch, /):
            return check_response(setter(batch, value))
        yield through(conmap(
            call, 
            chunked(do_map(to_id, ids), batch_size), 
            max_workers=max_workers, 
            async_=async_, 
        ))
    return run_gen_step(gen_step, async_)


@overload
def update_desc(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    /, 
    desc: str = "", 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_desc(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    desc: str = "", 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_desc(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    desc: str = "", 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给文件或目录设置备注，此举可更新此文件或目录的 mtime

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param desc: 备注文本
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if app in ("", "web", "desktop", "aps"):
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
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: Iterable[int | str], 
    /, 
    star: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_star(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    star: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_star(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    star: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给文件或目录设置星标

    .. note::
        如果一批中有任何一个 id 已经被删除，则这一批直接失败报错

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param star: 是否设置星标
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app == "open" or not isinstance(client, P115Client):
        method = "fs_star_set_open"
    elif app in ("", "web", "desktop", "aps"):
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
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    /, 
    label: int | str = 1, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_label(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    label: int | str = 1, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_label(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    label: int | str = 1, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给文件或目录设置标签

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param label: 标签 id，多个用逗号 "," 隔开，如果用一个根本不存在的 id，效果就是清空标签列表
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if app in ("", "web", "desktop", "aps"):
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
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    /, 
    score: int = 0, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_score(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    score: int = 0, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_score(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    score: int = 0, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给文件或目录设置分数

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
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
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    /, 
    top: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_top(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    top: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_top(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    top: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给文件或目录设置置顶

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
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
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    /, 
    show: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_show_play_long(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    show: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_show_play_long(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    show: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给目录设置显示时长

    :param client: 115 客户端或 cookies
    :param ids: 一组目录的 id 或 pickcode
    :param show: 是否显示时长
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if app in ("", "web", "desktop", "aps"):
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
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    /, 
    set: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def update_category_shortcut(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    set: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def update_category_shortcut(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    set: bool = True, 
    batch_size: int = 10_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量给目录设置显示时长

    :param client: 115 客户端或 cookies
    :param ids: 一组目录的 id 或 pickcode
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
def update_name(
    client: str | PathLike | P115Client, 
    id_name_pairs: Iterable[tuple[int | str, str]], 
    /, 
    batch_size: int = 10_000, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def update_name(
    client: str | PathLike | P115Client, 
    id_name_pairs: Iterable[tuple[int | str, str]], 
    /, 
    batch_size: int = 10_000, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def update_name(
    client: str | PathLike | P115Client, 
    id_name_pairs: Iterable[tuple[int | str, str]], 
    /, 
    batch_size: int = 10_000, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """批量给文件或目录设置名字

    .. note::
        不支持 open，是因为它仅能一次修改一个名字，并不能批量

    :param client: 115 客户端或 cookies
    :param id_name_pairs: 一堆文件或目录的 id 到新名字的元组
    :param batch_size: 批次大小，分批次，每次提交的任务数
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 成功命名的 {id: name} 的字典
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app in ("", "web", "desktop", "aps"):
        method: Callable = client.fs_rename
    else:
        method = client.fs_rename_app
        request_kwargs["app"] = app
    def gen_step():
        mapping: dict[int, str] = {}
        for batch in batched(id_name_pairs, batch_size):
            resp = yield method(
                batch, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            if data := resp["data"]:
                for k, v in data.items():
                    mapping[int(k)] = v
        return mapping
    return run_gen_step(gen_step, async_)


@overload
def batch_unstar(
    client: str | PathLike | P115Client | P115OpenClient, 
    /, 
    batch_size: int = 0, 
    ensure_file: None | bool = None, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def batch_unstar(
    client: str | PathLike | P115Client | P115OpenClient, 
    /, 
    batch_size: int = 0, 
    ensure_file: None | bool = None, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def batch_unstar(
    client: str | PathLike | P115Client | P115OpenClient, 
    /, 
    batch_size: int = 0, 
    ensure_file: None | bool = None, 
    max_workers: None | int = 0, 
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
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def get_id(info: dict, /) -> int:
        for k in ("file_id", "category_id", "fid", "cid"):
            if k in info:
                return int(info[k])
        raise KeyError
    def gen_step():
        if max_workers == 0:
            from .fs_files import fs_files
            from .iterdir import overview_attr
            while True:
                resp = yield fs_files(
                    client, 
                    payload={"cid": 0, "cur": 0, "star": 1}, 
                    page_size=batch_size, 
                    ensure_file=ensure_file, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )
                if len(resp["data"]):
                    yield update_star(
                        client, 
                        (overview_attr(info).id for info in resp["data"]), 
                        star=False, 
                        batch_size=len(resp["data"]), 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                if not resp["has_next_page"]:
                    break
        else:
            from .iterdir import iter_stared
            ids: list[int] = []
            append = ids.append
            yield foreach(
                lambda a: append(get_id(a)), 
                iter_stared(
                    client, 
                    ensure_file=ensure_file, 
                    app=app, 
                    cooldown=0.5, 
                    async_=async_, 
                    **request_kwargs, 
                )
            )
            yield update_star(
                client, 
                ids, 
                star=False, 
                batch_size=batch_size or 10_000, 
                max_workers=max_workers, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
    return run_gen_step(gen_step, async_)


@overload
def post_event(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    /, 
    type: Literal["doc", "img"] = "doc", 
    batch_size: int = 1_000, 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> None:
    ...
@overload
def post_event(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    type: Literal["doc", "img"] = "doc", 
    batch_size: int = 1_000, 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def post_event(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str] | AsyncIterable[int | str], 
    /, 
    type: Literal["doc", "img"] = "doc", 
    batch_size: int = 1_000, 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> None | Coroutine:
    """批量将文件或目录推送事件

    .. todo::
        是否能批量推送 "browse_audio" 或 "browse_video" 事件？

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param type: 事件类型

        - "doc": 推送 "browse_document" 事件
        - "img": 推送 "browse_image" 事件

    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if type == "doc":
        post = client.life_behavior_doc_post_app
    else:
        post = client.life_behavior_img_post_app
    def call(batch, /):
        return check_response(post(
            batch, 
            app=app, 
            async_=async_, 
            request_kwargs=request_kwargs, 
        ))
    def gen_step():
        yield through(conmap(
            call, 
            chunked(do_map(to_id, ids), batch_size), 
            max_workers=max_workers, 
            async_=async_, 
        ))
    return run_gen_step(gen_step, async_)


@overload
def makedir(
    client: str | PathLike | P115Client | P115OpenClient, 
    name: str, 
    /, 
    pid: int | str = 0, 
    contain_dir: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def makedir(
    client: str | PathLike | P115Client | P115OpenClient, 
    name: str, 
    /, 
    pid: int | str = 0, 
    contain_dir: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def makedir(
    client: str | PathLike | P115Client | P115OpenClient, 
    name: str, 
    /, 
    pid: int | str = 0, 
    contain_dir: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """创建目录

    :param client: 115 客户端或 cookies
    :param name: 名称 或 路径（如果 `contain_dir` 为 True）
    :param pid: 目录的 id 或 pickcode，如果输入的是 **名字或相对路径**，则创建在此目录下
    :param contain_dir: 如果为 True，则要创建的是相对路径（文件存在也能正确返回），否则就是一个文件（即使其中包含 "/"，但文件存在时会报错）
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 目录 id
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app == "open" or not isinstance(client, P115Client):
        if contain_dir:
            raise ValueError("115 Open does not support one-shot multiple-level directories creation")
        makedir: Callable = client.fs_mkdir_open
    elif app in ("", "web", "desktop", "aps"):
        if contain_dir:
            makedir = client.fs_makedirs
        else:
            makedir = client.fs_mkdir
    else:
        request_kwargs["app"] = app
        if contain_dir:
            makedir = client.fs_makedirs_app
        else:
            makedir = client.fs_mkdir_app
    def gen_step():
        resp = yield makedir(
            name, 
            pid=to_id(pid), 
            async_=async_, 
            **request_kwargs, 
        )
        check_response(resp)
        if "cid" in resp:
            return int(resp["cid"])
        data = resp["data"]
        return int(data.get("category_id") or data["file_id"])
    return run_gen_step(gen_step, async_)


@overload
def iter_batch_makedir(
    client: str | PathLike | P115Client | P115OpenClient, 
    pairs: Iterable[str | tuple[int | str, str]], 
    /, 
    pid: int | str = 0, 
    contain_dir: bool = False, 
    mapping: None | MutableMapping[tuple[int, str], dict] = None, 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[tuple[tuple[int, str], dict]]:
    ...
@overload
def iter_batch_makedir(
    client: str | PathLike | P115Client | P115OpenClient, 
    pairs: Iterable[str | tuple[int | str, str]], 
    /, 
    pid: int | str = 0, 
    contain_dir: bool = False, 
    mapping: None | MutableMapping[tuple[int, str], dict] = None, 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[tuple[int, str], dict]]:
    ...
def iter_batch_makedir(
    client: str | PathLike | P115Client | P115OpenClient, 
    pairs: Iterable[str | tuple[int | str, str]], 
    /, 
    pid: int | str = 0, 
    contain_dir: bool = False, 
    mapping: None | MutableMapping[tuple[int, str], dict] = None, 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[tuple[tuple[int, str], dict]] | AsyncIterator[tuple[tuple[int, str], dict]]:
    """批量创建目录

    :param client: 115 客户端或 cookies
    :param pairs: 一系列的 **名字或相对路径** 或者 (**目录的 id 或 pickcode**, **名字或相对路径**) 的 2 元组
    :param pid: 目录的 id 或 pickcode，如果输入的是 **名字或相对路径**，则创建在此目录下
    :param contain_dir: 如果为 True，则要创建的是相对路径（文件存在也能正确返回），否则就是一个文件（即使其中包含 "/"，但文件存在时会报错）
    :param mapping: 结果缓存，如果要创建的对象在此中，则会被跳过
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生 (**每项输入**, **相应的接口响应**) 的 2 元组
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    pid = to_id(pid)
    if app == "open" or not isinstance(client, P115Client):
        if contain_dir:
            raise ValueError("115 Open does not support one-shot multiple-level directories creation")
        makedir: Callable = client.fs_mkdir_open
    elif app in ("", "web", "desktop", "aps"):
        if contain_dir:
            makedir = client.fs_makedirs
        else:
            makedir = client.fs_mkdir
    else:
        request_kwargs["app"] = app
        if contain_dir:
            makedir = client.fs_makedirs_app
        else:
            makedir = client.fs_mkdir_app
    @as_gen_step(async_=async_)
    def call[T: (str, tuple[int | str, str])](pair: T, /):
        if isinstance(pair, tuple):
            cid, name = pair
            cid = to_id(cid)
        else:
            cid = pid
            name = pair
        key = cast(tuple[int, str], (cid, name))
        if mapping and key in mapping:
            return mapping[key]
        resp = yield makedir(name, pid=cid, async_=async_, **request_kwargs)
        if mapping is not None:
            mapping[key] = resp
        return key, resp
    return conmap(
        call, 
        pairs, 
        max_workers=max_workers, 
        async_=async_, 
    )


@overload
def batch_makedir(
    client: str | PathLike | P115Client | P115OpenClient, 
    pairs: str | tuple[int, str] | Iterable[str | tuple[int | str, str]], 
    /, 
    pid: int | str = 0, 
    contain_dir: bool = False, 
    mapping: None | MutableMapping[tuple[int, str], dict] = None, 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> MutableMapping[tuple[int, str], dict]:
    ...
@overload
def batch_makedir(
    client: str | PathLike | P115Client | P115OpenClient, 
    pairs: str | tuple[int, str] | Iterable[str | tuple[int | str, str]], 
    /, 
    pid: int | str = 0, 
    contain_dir: bool = False, 
    mapping: None | MutableMapping[tuple[int, str], dict] = None, 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, MutableMapping[tuple[int, str], dict]]:
    ...
def batch_makedir(
    client: str | PathLike | P115Client | P115OpenClient, 
    pairs: str | tuple[int, str] | Iterable[str | tuple[int | str, str]], 
    /, 
    pid: int | str = 0, 
    contain_dir: bool = False, 
    mapping: None | MutableMapping[tuple[int, str], dict] = None, 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> MutableMapping[tuple[int, str], dict] | Coroutine[Any, Any, MutableMapping[tuple[int, str], dict]]:
    """批量创建目录

    :param client: 115 客户端或 cookies
    :param pairs: 一系列的 **名字或相对路径** 或者 (**目录的 id 或 pickcode**, **名字或相对路径**) 的 2 元组
    :param pid: 目标目录的 id 或 pickcode 或 path，如果输入的是 **名字或相对路径**，则创建在此目录下
    :param contain_dir: 如果为 True，则要创建的是相对路径（文件存在也能正确返回），否则就是一个文件（即使其中包含 "/"，但文件存在时会报错）
    :param mapping: 结果缓存，如果要创建的对象在此中，则会被跳过
    :param max_workers: 并发工作数，如果为 None 或者 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生 (**每项输入**, **相应的接口响应**) 的 2 元组
    """
    if async_:
        async def take(it, /):
            async for _ in it: pass
    else:
        def take(it, /):
            for _ in it: pass
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if (isinstance(pairs, str) or 
        isinstance(pairs, tuple) and 
        len(pairs) == 2 and 
        isinstance(pairs[0], int) and 
        isinstance(pairs[1], str)
    ):
        pairs = pairs, # type: ignore
    def gen_step():
        nonlocal pid, mapping
        if not isinstance(pid, int):
            from .attr import get_id
            try:
                pid = yield get_id(
                    client, 
                    value=pid, 
                    files=False, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )
            except FileNotFoundError:
                pid = yield makedir(
                    client, 
                    cast(str, pid), 
                    contain_dir=True, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )
        if mapping is None:
            mapping = {}
        take(iter_batch_makedir(
            client, 
            pairs, 
            pid=pid, 
            contain_dir=contain_dir, 
            mapping=mapping, 
            max_workers=max_workers, 
            async_=async_, 
            **request_kwargs, 
        ))
        return mapping
    return run_gen_step(gen_step, async_)


@overload
def batch_copy(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: int | str | Iterable[int | str], 
    pid: int | str = 0, 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> None:
    ...
@overload
def batch_copy(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: int | str | Iterable[int | str], 
    pid: int | str = 0, 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, None]:
    ...
def batch_copy(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: int | str | Iterable[int | str], 
    pid: int | str = 0, 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> None | Coroutine[Any, Any, None]:
    """批量复制

    .. note::
        复制操作不支持并发

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param pid: 目标目录的 id 或 pickcode
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app == "open" or not isinstance(client, P115Client):
        fs_copy: Callable = client.fs_copy_open
    elif app in ("", "web", "desktop", "aps"):
        fs_copy = client.fs_copy
    else:
        fs_copy = client.fs_copy_app
        request_kwargs["app"] = app
    if isinstance(ids, (int, str)):
        ids = ids,
    pid = to_id(pid)
    def gen_step():
        if batch_size <= 0:
            resp = yield fs_copy(map(to_id, ids), pid=pid, async_=async_, **request_kwargs)
            check_response(resp)
        else:
            for batch in batched(map(to_id, ids), batch_size):
                while True:
                    with suppress(P115BusyOSError):
                        resp = yield fs_copy(batch, pid=pid, async_=async_, **request_kwargs)
                        check_response(resp)
                        break
    return run_gen_step(gen_step, async_)


# TODO: 还应该支持，当目标存在同名文件时，允许：1) 跳过 2) 替换 3) 共存
@overload
def batch_copy_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    top: int | str, 
    pid: int | str = 0, 
    flatten: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def batch_copy_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    top: int | str, 
    pid: int | str = 0, 
    flatten: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def batch_copy_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    top: int | str, 
    pid: int | str = 0, 
    flatten: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """批量复制某个目录下的所有文件（不包括目录）

    :param client: 115 客户端或 cookies
    :param top: 顶层目录 id
    :param pid: 目标目录的 id 或 pickcode
    :param flatten: 如果为 True，则会把文件直接移动到 ``pid`` 之下，否则会创建次级目录
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 字典，key 是目标目录 id，value 是文件 id 的列表
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    iter_files: Callable
    if app == "open" or not isinstance(client, P115Client):
        from .iterdir import iter_files
    else:
        if app not in ("", "web", "desktop", "aps"):
            request_kwargs["app"] = app
        from .download import iter_download_files as iter_files
    pid = to_id(pid)
    def gen_step():
        cid = to_id(top)
        if cid == pid:
            return {}
        dir_map: defaultdict[int, int] = defaultdict(lambda: pid)
        if not flatten:
            from .attr import get_id_to_name
            from .iterdir import iter_dirs
            dirs = yield collect(iter_dirs(
                client, 
                cid, 
                id_to_dirnode=id_to_dirnode, 
                async_=async_, # type: ignore
                **request_kwargs, 
            ))
            for attr in dirs:
                name = attr["name"]
                try:
                    dir_map[attr["id"]] = yield makedir(
                        client, 
                        attr["name"], 
                        pid=dir_map[attr["parent_id"]], 
                        contain_dir="/" not in name, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                except FileExistsError:
                    dir_map[attr["id"]] = yield get_id_to_name(
                        client, 
                        name, 
                        cid=dir_map[attr["parent_id"]], 
                        ensure_file=False, 
                        recursive=False, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
        d: defaultdict[int, list[int]] = defaultdict(list)
        yield foreach(
            lambda attr: d[attr["parent_id"]].append(attr["id"]), 
            iter_files(
                client, 
                cid, 
                id_to_dirnode=id_to_dirnode, 
                max_workers=None, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            ), 
        )
        result: dict[int, list[int]] = {}
        for cid, ids in d.items():
            to_cid = dir_map[cid]
            if cid == to_cid:
                continue
            yield batch_copy(client, ids, pid=to_cid, app=app, async_=async_, **request_kwargs)
            result[to_cid] = ids
        return result
    return run_gen_step(gen_step, async_)


@overload
def batch_delete(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: int | str | Iterable[int | str], 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> None:
    ...
@overload
def batch_delete(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: int | str | Iterable[int | str], 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, None]:
    ...
def batch_delete(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: int | str | Iterable[int | str], 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> None | Coroutine[Any, Any, None]:
    """批量删除

    .. note::
        删除操作不支持并发

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app == "open" or not isinstance(client, P115Client):
        fs_delete: Callable = client.fs_delete_open
    elif app in ("", "web", "desktop", "aps"):
        fs_delete = client.fs_delete
    else:
        fs_delete = client.fs_delete_app
        request_kwargs["app"] = app
    if isinstance(ids, (int, str)):
        ids = ids,
    def gen_step():
        for batch in batched(map(to_id, ids), batch_size):
            while True:
                with suppress(P115BusyOSError):
                    resp = yield fs_delete(batch, async_=async_, **request_kwargs)
                    check_response(resp)
                    break
    return run_gen_step(gen_step, async_)


@overload
def batch_delete_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    top: int | str = 0, 
    batch_size: int = 1_000, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def batch_delete_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    top: int | str = 0, 
    batch_size: int = 1_000, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def batch_delete_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    top: int | str = 0, 
    batch_size: int = 1_000, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """批量删除某个目录下的所有文件（不包括目录）

    :param client: 115 客户端或 cookies
    :param top: 顶层目录 id
    :param batch_size: 每批次大小
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 删除的文件总数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    from .fs_files import fs_files
    def get_ids_by_fs_files(top=top, /):
        resp = yield fs_files(
            client, 
            {"cid": to_id(top), "show_dir": 0, "cur": 0, "limit": batch_size}, 
            async_=async_, 
            **request_kwargs, 
        )
        return resp["has_next_page"], [a["fid"] for a in resp["data"]]
    if app == "open" or not isinstance(client, P115Client):
        fs_delete: Callable = client.fs_delete_open
        get_ids: Callable = get_ids_by_fs_files
    else:
        if app in ("", "web", "desktop", "aps"):
            fs_delete = client.fs_delete
        else:
            fs_delete = client.fs_delete_app
            request_kwargs["app"] = app
        def get_ids_by_download_files(top=top, /):
            resp = yield client.download_files_app(
                {"pickcode": client.to_pickcode(top), "per_page": batch_size}, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            return resp["data"]["has_next_page"], [to_id(a["pc"]) for a in resp["data"]["list"]]
        if to_id(top):
            get_ids = get_ids_by_download_files
        else:
            dirs: None | list[dict] = None
            def get_ids():
                nonlocal dirs
                if dirs is None:
                    from .iterdir import iterdir
                    dirs = yield collect(iterdir(client, async_=async_, ensure_file=False, **request_kwargs))
                if dirs:
                    has_next_page, ids = yield from get_ids_by_download_files(dirs[-1]["pickcode"])
                    if not has_next_page:
                        dirs.pop()
                    return True, ids
                else:
                    return (yield from get_ids_by_fs_files(0))
    def gen_step():
        has_next_page = True
        total = 0
        while has_next_page:
            has_next_page, ids = yield from get_ids()
            if ids:
                resp = yield fs_delete(
                    ids, 
                    async_=async_, 
                    **request_kwargs, 
                )
                check_response(resp)
                total += len(ids)
        return total
    return run_gen_step(gen_step, async_)


@overload
def batch_move(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: int | str | Iterable[int | str], 
    pid: int | str = 0, 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> None:
    ...
@overload
def batch_move(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: int | str | Iterable[int | str], 
    pid: int | str = 0, 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, None]:
    ...
def batch_move(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: int | str | Iterable[int | str], 
    pid: int | str = 0, 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> None | Coroutine[Any, Any, None]:
    """批量移动

    .. note::
        移动操作不支持并发

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param pid: 目标目录的 id 或 pickcode
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app == "open" or not isinstance(client, P115Client):
        fs_move: Callable = client.fs_move_open
    elif app in ("", "web", "desktop", "aps"):
        fs_move = client.fs_move
    else:
        fs_move = client.fs_move_app
        request_kwargs["app"] = app
    if isinstance(ids, (int, str)):
        ids = ids,
    pid = to_id(pid)
    def gen_step():
        for batch in batched(map(to_id, ids), batch_size):
            while True:
                with suppress(P115BusyOSError):
                    resp = yield fs_move(batch, pid=pid, async_=async_, **request_kwargs)
                    check_response(resp)
                    break
    return run_gen_step(gen_step, async_)


# TODO: 当 flatten=True 时，可以像 batch_delete_files 一样进行一些优化，而不必最先获取文件列表
# TODO: 还应该支持，当目标存在同名文件时，允许：1) 跳过 2) 替换 3) 共存
@overload
def batch_move_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    top: int | str, 
    pid: int | str = 0, 
    flatten: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def batch_move_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    top: int | str, 
    pid: int | str = 0, 
    flatten: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def batch_move_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    top: int | str, 
    pid: int | str = 0, 
    flatten: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """批量移动某个目录下的所有文件（不包括目录）

    :param client: 115 客户端或 cookies
    :param top: 顶层目录 id
    :param pid: 目标目录的 id 或 pickcode
    :param flatten: 如果为 True，则会把文件直接移动到 ``pid`` 之下，否则会创建次级目录
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 字典，key 是目标目录 id，value 是文件 id 的列表
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    iter_files: Callable
    if app == "open" or not isinstance(client, P115Client):
        from .iterdir import iter_files
    else:
        if app not in ("", "web", "desktop", "aps"):
            request_kwargs["app"] = app
        from .download import iter_download_files as iter_files
    pid = to_id(pid)
    def gen_step():
        cid = to_id(top)
        if cid == pid:
            return {}
        dir_map: defaultdict[int, int] = defaultdict(lambda: pid)
        if not flatten:
            from .attr import get_id_to_name
            from .iterdir import iter_dirs
            dirs = yield collect(iter_dirs(
                client, 
                cid, 
                id_to_dirnode=id_to_dirnode, 
                async_=async_, # type: ignore
                **request_kwargs, 
            ))
            for attr in dirs:
                name = attr["name"]
                try:
                    dir_map[attr["id"]] = yield makedir(
                        client, 
                        attr["name"], 
                        pid=dir_map[attr["parent_id"]], 
                        contain_dir="/" not in name, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                except FileExistsError:
                    dir_map[attr["id"]] = yield get_id_to_name(
                        client, 
                        name, 
                        cid=dir_map[attr["parent_id"]], 
                        ensure_file=False, 
                        recursive=False, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
        d: defaultdict[int, list[int]] = defaultdict(list)
        yield foreach(
            lambda attr: d[attr["parent_id"]].append(attr["id"]), 
            iter_files(
                client, 
                cid, 
                id_to_dirnode=id_to_dirnode, 
                max_workers=None, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            ), 
        )
        result: dict[int, list[int]] = {}
        for cid, ids in d.items():
            to_cid = dir_map[cid]
            if cid == to_cid:
                continue
            yield batch_move(client, ids, pid=to_cid, app=app, async_=async_, **request_kwargs)
            result[to_cid] = ids
        return result
    return run_gen_step(gen_step, async_)


@overload
def batch_recyclebin_clean(
    client: str | PathLike | P115Client | P115OpenClient, 
    rids: int | str | Iterable[int | str], 
    /, 
    password: str = "000000", 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> None:
    ...
@overload
def batch_recyclebin_clean(
    client: str | PathLike | P115Client | P115OpenClient, 
    rids: int | str | Iterable[int | str], 
    /, 
    password: str = "000000", 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, None]:
    ...
def batch_recyclebin_clean(
    client: str | PathLike | P115Client | P115OpenClient, 
    rids: int | str | Iterable[int | str], 
    /, 
    password: str = "000000", 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> None | Coroutine[Any, Any, None]:
    """批量永久删除（从回收站）

    .. note::
        可以在设置中的【账号安全/安全密钥】页面下，关闭【文件(隐藏模式/清空删除回收站)】的按钮，就不需要传安全密钥了

    :param client: 115 客户端或 cookies
    :param rids: 文件或目录在回收站中的 id，如果不传，就是清空
    :param password: 安全密钥，是 6 位数字
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app == "open" or not isinstance(client, P115Client):
        recyclebin_clean: Callable = client.recyclebin_clean_open
    elif app in ("", "web", "desktop", "aps"):
        recyclebin_clean = client.recyclebin_clean
    else:
        recyclebin_clean = client.recyclebin_clean_app
        request_kwargs["app"] = app
    if rids and isinstance(rids, (int, str)):
        rids = rids,
    def gen_step():
        if rids:
            for batch in batched(rids, batch_size):
                while True:
                    with suppress(P115BusyOSError):
                        resp = yield recyclebin_clean(batch, password=password, async_=async_, **request_kwargs)
                        check_response(resp)
                        break
        else:
            resp = yield recyclebin_clean(password=password, async_=async_, **request_kwargs)
            check_response(resp)
    return run_gen_step(gen_step, async_)


@overload
def batch_recyclebin_revert(
    client: str | PathLike | P115Client | P115OpenClient, 
    rids: int | str | Iterable[int | str], 
    /, 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> None:
    ...
@overload
def batch_recyclebin_revert(
    client: str | PathLike | P115Client | P115OpenClient, 
    rids: int | str | Iterable[int | str], 
    /, 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, None]:
    ...
def batch_recyclebin_revert(
    client: str | PathLike | P115Client | P115OpenClient, 
    rids: int | str | Iterable[int | str], 
    /, 
    batch_size: int = 1_000, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> None | Coroutine[Any, Any, None]:
    """批量还原（从回收站）

    .. note::
        还原操作不支持并发

    :param client: 115 客户端或 cookies
    :param rids: 文件或目录在回收站中的 id
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param app: 使用此设备的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app == "open" or not isinstance(client, P115Client):
        recyclebin_revert: Callable = client.recyclebin_revert_open
    elif app in ("", "web", "desktop", "aps"):
        recyclebin_revert = client.recyclebin_revert
    else:
        recyclebin_revert = client.recyclebin_revert_app
        request_kwargs["app"] = app
    if isinstance(rids, (int, str)):
        rids = rids,
    def gen_step():
        for batch in batched(rids, batch_size):
            while True:
                with suppress(P115BusyOSError):
                    resp = yield recyclebin_revert(batch, async_=async_, **request_kwargs)
                    check_response(resp)
                    break
    return run_gen_step(gen_step, async_)


@overload
def batch_hide(
    client: str | PathLike | P115Client, 
    ids: int | str | Iterable[int | str], 
    hidden: bool = True, 
    batch_size: int = 10_000, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
):
    ...
@overload
def batch_hide(
    client: str | PathLike | P115Client, 
    ids: int | str | Iterable[int | str], 
    hidden: bool = True, 
    batch_size: int = 10_000, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine:
    ...
def batch_hide(
    client: str | PathLike | P115Client, 
    ids: int | str | Iterable[int | str], 
    hidden: bool = True, 
    batch_size: int = 10_000, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
):
    """批量隐藏（加密/隐藏模式）或展示文件或目录

    :param client: 115 客户端或 cookies
    :param ids: 一组目录的 id 或 pickcode
    :param hidden: 是否隐藏
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app in ("", "web", "desktop", "aps"):
        fs_hide: Callable = client.fs_hide
    else:
        fs_hide = client.fs_hide_app
        request_kwargs["app"] = app
    if isinstance(ids, (int, str)):
        ids = ids,
    def gen_step():
        for batch in batched(ids, batch_size):
            while True:
                with suppress(P115BusyOSError):
                    resp = yield fs_hide(batch, hidden=hidden, async_=async_, **request_kwargs)
                    check_response(resp)
                    break
    return run_gen_step(gen_step, async_)


@overload
def copyfile(
    client: str | PathLike | P115Client | P115OpenClient, 
    id: int | str | Mapping, 
    /, 
    name: str = "", 
    pid: None | int | str = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def copyfile(
    client: str | PathLike | P115Client | P115OpenClient, 
    id: int | str | Mapping, 
    /, 
    name: str = "", 
    pid: None | int | str = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def copyfile(
    client: str | PathLike | P115Client | P115OpenClient, 
    id: int | str | Mapping, 
    /, 
    name: str = "", 
    pid: None | int | str = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """复制文件到目标目录下

    .. note::
        如果复制后的文件名相同，则使用复制接口，否则使用上传接口

    :param client: 115 客户端或 cookies
    :param id: 文件的 id、pickcode 或信息字典
    :param name: 复制后的新名字，如果为空则名字相同
    :param pid: 目录的 id 或 pickcode，如果为 None，则在同一目录下
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app == "open" or not isinstance(client, P115Client):
        get_url: Callable = client.download_url_open
        fs_copy: Callable = client.fs_copy_open
        upload_file_init: Callable = client.upload_file_init_open
    else:
        get_url = client.download_url
        upload_file_init = client.upload_file_init
        if app in ("", "web", "desktop", "aps"):
            fs_copy = client.fs_copy
        else:
            if isinstance(id, Mapping):
                get_url = partial(get_url, app=app)
            fs_copy = partial(client.fs_copy_app, app=app)
    def gen_step():
        nonlocal pid, name
        url: None | P115URL = None
        if isinstance(id, Mapping):
            attr: Mapping = id
        else:
            url = yield get_url(
                client.to_pickcode(id), 
                async_=async_, 
                **request_kwargs, 
            )
            attr = url.__dict__
        if pid is None:
            pid = attr["parent_id"]
        else:
            pid = client.to_id(pid)
        if not name:
            name = attr["name"]
        if attr["name"] == name:
            if pid == attr["parent_id"]:
                return {"state": True}
            return check_response(fs_copy(attr["id"], pid=pid, async_=async_, **request_kwargs))
        else:
            @as_gen_step(async_=async_)
            def read_range_bytes_or_hash(sign_check: str, /):
                nonlocal url
                if url is None:
                    url = yield get_url(
                        attr.get("pickcode") or client.to_pickcode(attr["id"]), 
                        async_=async_, 
                        **request_kwargs, 
                    )
                return client.request(
                    url, 
                    async_=async_, 
                    **{
                        **request_kwargs, 
                        "headers": {**url.headers, "range": "bytes="+sign_check}, 
                        "parse": False, 
                    }
                )
            return check_response(upload_file_init(
                filename=name, 
                filesha1=attr["sha1"], 
                filesize=attr["size"], 
                read_range_bytes_or_hash=read_range_bytes_or_hash, 
                pid=pid, 
                async_=async_, 
                **request_kwargs, 
            ))
    return run_gen_step(gen_step, async_)


@overload
def renamefile(
    client: str | PathLike | P115Client | P115OpenClient, 
    id: int | str | Mapping, 
    /, 
    name: str = "", 
    pid: None | int | str = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def renamefile(
    client: str | PathLike | P115Client | P115OpenClient, 
    id: int | str | Mapping, 
    /, 
    name: str = "", 
    pid: None | int | str = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def renamefile(
    client: str | PathLike | P115Client | P115OpenClient, 
    id: int | str | Mapping, 
    /, 
    name: str = "", 
    pid: None | int | str = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """移动文件到目标目录下

    .. note::
        如果移动后的文件名相同或扩展名相同，则使用移动接口，否则使用上传接口

    :param client: 115 客户端或 cookies
    :param id: 文件的 id、pickcode 或信息字典
    :param name: 移动后的新名字，如果为空则名字相同
    :param pid: 目录的 id 或 pickcode，如果为 None，则不进行移动
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app == "open" or not isinstance(client, P115Client):
        get_url: Callable = client.download_url_open
        fs_move: Callable = client.fs_move_open
        upload_file_init: Callable = client.upload_file_init_open
        fs_delete: Callable = client.fs_delete_open
        fs_rename: Callable = client.fs_rename_open
    else:
        get_url = client.download_url
        upload_file_init = client.upload_file_init
        if app in ("", "web", "desktop", "aps"):
            fs_move = client.fs_move
            fs_delete = client.fs_delete
            fs_rename = client.fs_rename
        else:
            if isinstance(id, Mapping):
                get_url = partial(get_url, app=app)
            fs_move = partial(client.fs_move_app, app=app)
            fs_delete = partial(client.fs_delete_app, app=app)
            fs_rename = partial(client.fs_rename_app, app=app)
    def gen_step():
        nonlocal pid, name
        url: None | P115URL = None
        if isinstance(id, Mapping):
            attr: Mapping = id
        else:
            url = yield get_url(
                client.to_pickcode(id), 
                async_=async_, 
                **request_kwargs, 
            )
            attr = url.__dict__
        if pid is None:
            pid = attr["parent_id"]
        else:
            pid = client.to_id(pid)
        if not name:
            name = attr["name"]
        is_same_name = attr["name"] == name
        is_same_ext = attr["name"].rpartition(".")[-1] == name.rpartition(".")[-1]
        if is_same_name or is_same_ext:
            if pid == attr["parent_id"]:
                if is_same_name:
                    return {"state": True}
            else:
                resp = yield check_response(fs_move(attr["id"], pid=pid, async_=async_, **request_kwargs))
                check_response(resp)
                if is_same_name:
                    return resp
            return check_response(fs_rename((attr["id"], name), async_=async_, **request_kwargs))
        else:
            @as_gen_step(async_=async_)
            def read_range_bytes_or_hash(sign_check: str, /):
                nonlocal url
                if url is None:
                    url = yield get_url(
                        attr.get("pickcode") or client.to_pickcode(attr["id"]), 
                        async_=async_, 
                        **request_kwargs, 
                    )
                return client.request(
                    url, 
                    async_=async_, 
                    **{
                        **request_kwargs, 
                        "headers": {**url.headers, "range": "bytes="+sign_check}, 
                        "parse": False, 
                    }
                )
            resp = yield upload_file_init(
                filename=name, 
                filesha1=attr["sha1"], 
                filesize=attr["size"], 
                read_range_bytes_or_hash=read_range_bytes_or_hash, 
                pid=pid, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            return check_response(fs_delete(attr["id"], async_=async_, **request_kwargs))
    return run_gen_step(gen_step, async_)


@overload
def transferfile(
    client_from: str | PathLike | P115Client | P115OpenClient, 
    client_to: str | PathLike | P115Client | P115OpenClient, 
    id: int | str | Mapping, 
    /, 
    name: str = "", 
    pid: int | str = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def transferfile(
    client_from: str | PathLike | P115Client | P115OpenClient, 
    client_to: str | PathLike | P115Client | P115OpenClient, 
    id: int | str | Mapping, 
    /, 
    name: str = "", 
    pid: int | str = 0, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def transferfile(
    client_from: str | PathLike | P115Client | P115OpenClient, 
    client_to: str | PathLike | P115Client | P115OpenClient, 
    id: int | str | Mapping, 
    /, 
    name: str = "", 
    pid: int | str = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """从一个 115 网盘，转移文件到另一个 115 网盘

    :param client_from: 115 客户端或 cookies，文件来自这个网盘
    :param client_to: 115 客户端或 cookies，文件去往这个网盘
    :param id: 文件的 id、pickcode 或信息字典，关联在 `client_from`
    :param name: 复制后的新名字，如果为空则名字相同，关联在 `client_to`
    :param pid: 目录的 id 或 pickcode，，关联在 `client_to`
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应信息
    """
    if isinstance(client_from, (str, PathLike)):
        client_from = P115Client(client_from)
    if isinstance(client_to, (str, PathLike)):
        client_to = P115Client(client_to)
    if not isinstance(client_from, P115Client) or app == "open":
        get_url: Callable = client_from.download_url_open
    else:
        get_url = client_from.download_url
        if isinstance(id, Mapping):
            get_url = partial(get_url, app=app)
    if not isinstance(client_to, P115Client) or app == "open":
        upload_file_init: Callable = client_to.upload_file_init_open
    else:
        upload_file_init = client_to.upload_file_init
    def gen_step():
        nonlocal pid, name
        url: None | P115URL = None
        if isinstance(id, Mapping):
            attr: Mapping = id
        else:
            url = yield get_url(
                client_from.to_pickcode(id), 
                async_=async_, 
                **request_kwargs, 
            )
            attr = url.__dict__
        pid = client_to.to_id(pid)
        if not name:
            name = attr["name"]
        @as_gen_step(async_=async_)
        def read_range_bytes_or_hash(sign_check: str, /):
            nonlocal url
            if url is None:
                url = yield get_url(
                    attr.get("pickcode") or client_from.to_pickcode(attr["id"]), 
                    async_=async_, 
                    **request_kwargs, 
                )
            return client_to.request(
                url, 
                async_=async_, 
                **{
                    **request_kwargs, 
                    "headers": {**url.headers, "range": "bytes="+sign_check}, 
                    "parse": False, 
                }
            )
        return check_response(upload_file_init(
            filename=name, 
            filesha1=attr["sha1"], 
            filesize=attr["size"], 
            read_range_bytes_or_hash=read_range_bytes_or_hash, 
            pid=pid, 
            async_=async_, 
            **request_kwargs, 
        ))
    return run_gen_step(gen_step, async_)

# TODO: 增加 batch_revert 方法
# TODO: 对于移动、删除、还原，一次之后，再罗列就可以不包括被操作过的，因此可以优化
# TODO: 增加批量修改封面、设置共享等
