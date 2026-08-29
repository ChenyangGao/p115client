#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "get_id_to_dirnode", "ensure_path", "iterdir", "iterdir_skim", "iter_dirs", 
    "iter_files", "iter_files_skim", "traverse_tree", "search_iter", 
    "share_iterdir", "share_iter_files", "share_search_iter", "extract_iterdir", 
    "extract_iter_files", 

    "iter_parents", "iter_keyed_files", "iter_keyed_dupfiles", "iter_keyed_ids", 
    "iter_keyed_dupfile_ids", "iter_unique_keys", 
]
__doc__ = "这个模块提供了一些和目录信息罗列有关的函数"

from asyncio import create_task, sleep as async_sleep, Task
from collections.abc import (
    AsyncIterable, AsyncIterator, Callable, Generator, Iterable, 
    Iterator, Mapping, MutableMapping, MutableSet, Sequence, 
)
from contextlib import contextmanager
from concurrent.futures import Future
from functools import partial
from operator import itemgetter
from os import PathLike
from time import sleep, time
from types import EllipsisType
from typing import cast, overload, Any, Literal
from warnings import warn

from asynctools import async_collect
from concurrenttools import run_as_thread, conmap
from dicttools import get_first
from errno2 import errno
from iterutils import (
    as_gen_step, chunked, chain_from_iterable, collect, 
    run_gen_step, run_gen_step_iter, through, with_iter_next, 
    map as do_map, filter as do_filter, iter_unique, Yield, YieldFrom, 
)
from iter_collect import iter_keyed_dups, SupportsLT

from ..client import check_response, P115Client, P115OpenClient
from ..const import ID_TO_DIRNODE_CACHE
from ..exception import throw, P115Warning, P115FileNotFoundError
from ..type import DirNode
from ..util import posix_escape_name, share_extract_payload
from .attr import normalize_attr, _get_id, update_resp_ancestors, overview_attr
from .iter_nodes import iter_nodes


def get_id_to_dirnode(
    key: int | str | PathLike | P115Client | P115OpenClient, 
    /, 
) -> MutableMapping[int, tuple[str, int] | DirNode]:
    """用指定 key 查询缓存 ``p115client.const.ID_TO_DIRNODE_CACHE``

    :param key: （分享链接的）分享码 或者 用户 id（或者 115 客户端或 cookies，然后间接获取用户 id)

    :return: 迭代器，产生文件或目录的 id 到对应的 ``(name, parent_id)`` 元组
    """
    if not isinstance(key, str) or "UID=" in key:
        if isinstance(key, (str, PathLike)):
            key = P115Client(key)
        if isinstance(key, (P115Client, P115OpenClient)):
            key = key.user_id
    key = cast(int | str, key)
    return ID_TO_DIRNODE_CACHE[key]


def make_path_binder(
    id_to_dirnode: Mapping[int, tuple[str, int]], 
    with_ancestors: bool = False, 
    with_path: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    key_of_ancestors: str = "ancestors", 
    key_of_path: str = "path", 
) -> Callable:
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    if escape is not None:
        from functools import lru_cache
        escape = lru_cache(maxsize=None)(escape)
    id_to_ancestors = {0: [{"id": 0, "parent_id": 0, "name": ""}]}
    def get_ancestors(id: int, attr: None | Mapping | tuple[str, int] = None, /) -> list[dict]:
        if not id:
            return id_to_ancestors[0]
        is_dir = True
        if not attr:
            name, pid = id_to_dirnode[id]
        elif isinstance(attr, Mapping):
            pid = attr["parent_id"]
            name = attr["name"]
            is_dir = attr.get("is_dir", is_dir)
        else:
            name, pid = attr
        try:
            pancestors = id_to_ancestors[pid]
        except KeyError:
            get_ancestors(pid)
            pancestors = id_to_ancestors[pid]
        ancestors = [*pancestors, {"id": id, "parent_id": pid, "name": name}]
        if is_dir:
            id_to_ancestors[id] = ancestors
        return ancestors
    id_to_path: dict[int, str] = {0: "/"}
    def get_path(id: int, attr: None | Mapping | tuple[str, int] = None, /) -> str:
        if not id:
            return id_to_path[0]
        is_dir = True
        if not attr:
            name, pid = id_to_dirnode[id]
        elif isinstance(attr, Mapping):
            pid = attr["parent_id"]
            name = attr["name"]
            is_dir = attr.get("is_dir", is_dir)
        else:
            name, pid = attr
        if escape is not None:
            name = escape(name)
        try:
            dirname = id_to_path[pid]
        except KeyError:
            get_path(pid)
            dirname = id_to_path[pid]
        path = dirname + name
        if is_dir:
            id_to_path[id] = path + "/"
        return path
    if with_ancestors or with_path:
        def bind[D: dict](attr: D, /) -> D:
            if "name" in attr:
                fid = attr["id"]
                if with_ancestors:
                    attr[key_of_ancestors] = get_ancestors(fid, attr)
                if with_path:
                    attr[key_of_path] = get_path(fid, attr)
            else:
                pid = attr["parent_id"]
                if with_ancestors:
                    attr[key_of_ancestors] = get_ancestors(pid)
                if with_path:
                    attr[key_of_path] = get_path(pid)
            return attr
    else:
        bind = lambda attr, /: attr
    setattr(bind, "get_ancestors", get_ancestors)
    setattr(bind, "get_path", get_path)
    return bind


@overload
@contextmanager
def cache_loading[T](
    it: Iterator[T], 
    /, 
) -> Generator[tuple[list[T], Future]]:
    ...
@overload
@contextmanager
def cache_loading[T](
    it: AsyncIterator[T], 
    /, 
) -> Generator[tuple[list[T], Task]]:
    ...
@contextmanager
def cache_loading[T](
    it: Iterator[T] | AsyncIterator[T], 
    /, 
) -> Generator[tuple[list[T], Future | Task]]:
    cache: list[T] = []
    add_to_cache = cache.append
    running = True
    if isinstance(it, AsyncIterator):
        async def arunner():
            async for e in it:
                add_to_cache(e)
                if not running:
                    break
        task: Future | Task = create_task(arunner())
    else:
        def runner():
            for e in it:
                add_to_cache(e)
                if not running:
                    break
        task = run_as_thread(runner)
    try:
        yield (cache, task)
    finally:
        running = False


@overload
def ensure_path[D: dict](
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping, 
    attrs: Iterable[D] | AsyncIterable[D], 
    with_ancestors: bool = False, 
    with_path: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    path_already: bool = False, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[D]:
    ...
@overload
def ensure_path[D: dict](
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping, 
    attrs: Iterable[D] | AsyncIterable[D], 
    with_ancestors: bool = False, 
    with_path: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    path_already: bool = False, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[D]:
    ...
def ensure_path[D: dict](
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping, 
    attrs: Iterable[D] | AsyncIterable[D], 
    with_ancestors: bool = False, 
    with_path: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    path_already: bool = False, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[D] | AsyncIterator[D]:
    """为一组文件信息添加 "path" 字段，可选 "path" 或 "ancestors" 字段

    :param client: 115 客户端或 cookies
    :param cid: 顶层目录 id 或 pickcode
    :param attrs: 一组文件或目录的信息
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param with_path: 文件信息中是否要包含 "path"
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典，如果为 ...，则忽略
    :param path_already: 如果为 True，则说明 id_to_dirnode 中已经具备构建路径所需要的目录节点，所以不会再去拉取目录节点的信息
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
        path_already = False
    bind = make_path_binder(
        id_to_dirnode, 
        with_ancestors=with_ancestors, 
        with_path=with_path, 
        escape=escape, 
    )
    from .attr import get_ancestors
    if path_already:
        def gen_step():
            ok_ids: set[int] = set((0,))
            ok_ids_update = ok_ids.update
            dangling_ids: set[int] = set()
            with with_iter_next(attrs) as get_next:
                while True:
                    attr = yield get_next()
                    pid  = attr["parent_id"]
                    if pid and pid not in ok_ids:
                        ls_pid: list[int] = []
                        while pid and pid in id_to_dirnode:
                            if pid in ok_ids:
                                ok_ids_update(ls_pid)
                                break
                            pid = id_to_dirnode[pid][1]
                            ls_pid.append(pid)
                        else:
                            if pid:
                                if pid not in dangling_ids:
                                    try:
                                        ancestors = yield get_ancestors(
                                            client, 
                                            pid, 
                                            id_to_dirnode=id_to_dirnode, 
                                            ensure_file=False, 
                                            app=app, 
                                            async_=async_, 
                                            **request_kwargs, 
                                        )
                                        ok_ids_update(ls_pid)
                                        ok_ids_update(a["id"] for a in ancestors)
                                    except P115FileNotFoundError:
                                        dangling_ids.add(pid)
                            else:
                                ok_ids_update(ls_pid)
                    yield Yield(bind(attr))
    else:
        from .download import iter_download_nodes
        class BoolRaise:
            def __init__(self, /, exception):
                self.exception = exception
            def __bool__(self, /):
                raise self.exception
        path_not_already: bool | BoolRaise = True
        def set_path_already(fu, /):
            nonlocal path_not_already
            exc = fu.exception()
            if exc is None:
                path_not_already = False
            else:
                path_not_already = BoolRaise(exc)
        @as_gen_step
        def load_dirs(cid, /):
            if cid:
                yield get_ancestors(
                    client, 
                    cid, 
                    ensure_file=False, 
                    id_to_dirnode=id_to_dirnode, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )
            yield through(iter_download_nodes(
                client, 
                cid, 
                files=False, 
                id_to_dirnode=id_to_dirnode, 
                max_workers=None, 
                app="os_windows", 
                async_=async_, 
                **request_kwargs, 
            ))
        def gen_step():
            cache: list[dict] = []
            add_to_cache = cache.append
            if async_:
                task: Any = create_task(load_dirs(cid))
            else:
                task = run_as_thread(load_dirs, cid)
            task.add_done_callback(set_path_already)
            with with_iter_next(attrs) as get_next:
                while path_not_already:
                    add_to_cache((yield get_next()))
                if cache:
                    yield YieldFrom(map(bind, cache))
                    cache.clear()
                while True:
                    yield Yield(bind((yield get_next())))
            if cache:
                if async_:
                    yield task
                else:
                    task.result()
                bool(path_not_already)
                yield YieldFrom(map(bind, cache))
    return run_gen_step_iter(gen_step, async_)


@overload
def iterdir(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    start: int = 0, 
    suffix: str = "", 
    type: int = 99, 
    order: Literal["", "file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "", 
    asc: Literal[0, 1] | bool = 1, 
    min_size: int = 0, 
    max_size: int = 0, 
    show_dir: Literal[0, 1] | bool = 1, 
    cur: Literal[0, 1] | bool = 1, 
    fc_mix: Literal[0, 1] | bool = 1, 
    star: Literal[0, 1] | bool = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    hold_top: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iterdir(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    start: int = 0, 
    suffix: str = "", 
    type: int = 99, 
    order: Literal["", "file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "", 
    asc: Literal[0, 1] | bool = 1, 
    min_size: int = 0, 
    max_size: int = 0, 
    show_dir: Literal[0, 1] | bool = 1, 
    cur: Literal[0, 1] | bool = 1, 
    fc_mix: Literal[0, 1] | bool = 1, 
    star: Literal[0, 1] | bool = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    hold_top: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iterdir(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    start: int = 0, 
    suffix: str = "", 
    type: int = 99, 
    order: Literal["", "file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "", 
    asc: Literal[0, 1] | bool = 1, 
    min_size: int = 0, 
    max_size: int = 0, 
    show_dir: Literal[0, 1] | bool = 1, 
    cur: Literal[0, 1] | bool = 1, 
    fc_mix: Literal[0, 1] | bool = 1, 
    star: Literal[0, 1] | bool = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    hold_top: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代目录，获取文件和目录信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小，如果 <= 0，则和 `page_size` 相同
    :param start: 开始索引，从 0 开始
    :param suffix: 后缀名（优先级高于 type）
    :param type: 文件类型

        - 1: 文档
        - 2: 图片
        - 3: 音频
        - 4: 视频
        - 5: 压缩包
        - 6: 应用
        - 7: 书籍
        - 99: 所有文件

    :param order: 排序

        - "file_name": 文件名
        - "file_size": 文件大小
        - "file_type": 文件种类
        - "user_utime": 修改时间
        - "user_ptime": 创建时间
        - "user_otime": 上一次打开时间

    :param asc: 升序排列。0: 否，1: 是
    :param min_size: 最小的文件大小
    :param max_size: 最大的文件大小（含），0 表示不限
    :param show_dir: 展示文件夹。0: 否，1: 是
    :param cur: 是否当前目录
    :param fc_mix: 文件夹置顶。0: 文件夹在文件之前，1: 文件和文件夹混合并按指定排序
    :param star: 是否星标
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param ensure_file: 是否确保为文件

        - True: 必须是文件
        - False: 必须是目录
        - None: 可以是目录或文件

    :param hold_top: 保留顶层目录信息，返回字段增加 "top_id", "top_ancestors", "top_path"
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1/2）
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    suffix = suffix.strip(".")
    if use_media_api:
        if suffix:
            raise ValueError("media api does not support filtering by suffix")
        if min_size or max_size:
            raise ValueError("media api does not support filtering by size")
    if isinstance(cid, Mapping):
        cid = cast(int | str, get_first(cid, "id", "pickcode"))
    return iter_nodes(
        client, 
        payload={
            "asc": int(asc), "cid": _get_id(cid), "cur": int(cur), "count_folders": 1, 
            "fc_mix": int(fc_mix), "min_size": min_size, "max_size": max_size, 
            "o": order, "offset": start, "show_dir": int(show_dir), "star": int(star), 
            "suffix": suffix, "type": type, 
        }, 
        page_size=page_size, 
        first_page_size=first_page_size, 
        normalize_attr=normalize_attr, 
        id_to_dirnode=id_to_dirnode, 
        use_media_api=use_media_api, 
        raise_for_changed_count=raise_for_changed_count, 
        ensure_file=ensure_file, 
        hold_top=hold_top, 
        escape=escape, 
        app=app, 
        cooldown=cooldown, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def iterdir_skim(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    page_size: int = 10_000, 
    user_id: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iterdir_skim(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    page_size: int = 10_000, 
    user_id: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iterdir_skim(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    page_size: int = 10_000, 
    user_id: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代目录，获取目录信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param page_size: 分页大小
    :param user_id: 用户 id，如果 <= 0，则默认是 ``client`` 所对应的用户 id
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，仅返回此目录内的目录信息
    """
    if isinstance(cid, Mapping):
        cid = cast(int | str, get_first(cid, "id", "pickcode"))
    cid = _get_id(cid)
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if user_id <= 0:
        user_id = client.user_id
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[user_id]
    def gen_step():
        def normalize_attr(info, /):
            cid = int(info["cid"])
            pid = int(info["pid"])
            name = info["name"]
            if id_to_dirnode is not ...:
                id_to_dirnode[cid] = (name, pid)
            return {
                "is_dir": True, 
                "id": cid, 
                "parent_id": pid, 
                "name": name, 
                "is_share": int(info["is_share"]), 
                "pickcode": info["pick_code"], 
                "category_cover": info["category_cover"], 
                "ancestors": [*ancestors, {"id": cid, "parent_id": pid, "name": name}], 
            }
        payload = {"user_id": user_id, "p_id": cid, "limit": page_size, "offset": 0}
        count = -1
        while True:
            resp = yield client.fs_folder_app(payload, async_=async_, **request_kwargs)
            check_response(resp)
            if cid and int(resp["path"][-1]["cid"]) != cid:
                throw(errno.ENOENT, cid)
            if count == -1:
                count = resp["count"]
                update_resp_ancestors(resp, id_to_dirnode)
                ancestors = resp["ancestors"]
            data = resp["data"]
            yield YieldFrom(map(normalize_attr, data))
            size = len(data)
            payload["offset"] += size
            if not data or size < page_size or payload["offset"] >= count:
                break
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_dirs(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_dirs(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_dirs(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取目录信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param with_ancestors: 文件信息中是否要包含 "path" 字段
    :param with_ancestors: 文件信息中是否要包含 "ancestors" 字段
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用指定 app（设备）的接口
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅目录）文件信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ... and (with_path or with_ancestors):
        id_to_dirnode = {}
    cid = _get_id(cid)
    from .download import iter_download_nodes
    attrs = iter_download_nodes(
        client, 
        cid, 
        files=False, 
        id_to_dirnode=id_to_dirnode, 
        app=app, 
        max_workers=max_workers, 
        async_=async_, 
        **request_kwargs, 
    )
    if with_path or with_ancestors:
        def gen_step(attrs, /):
            attrs = yield collect(attrs)
            yield YieldFrom(ensure_path(
                client, 
                cid, 
                attrs, 
                with_ancestors=with_ancestors, 
                with_path=with_path, 
                escape=escape, 
                id_to_dirnode=id_to_dirnode, 
                path_already=True, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            ))
        return run_gen_step_iter(gen_step(attrs), async_)
    return attrs


@overload
def iter_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: int = 99, 
    order: Literal["", "file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    min_size: int = 0, 
    max_size: int = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    path_already: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: int = 99, 
    order: Literal["", "file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    min_size: int = 0, 
    max_size: int = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    path_already: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: int = 99, 
    order: Literal["", "file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    min_size: int = 0, 
    max_size: int = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    path_already: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小，如果 <= 0，则和 `page_size` 相同
    :param suffix: 后缀名（优先级高于 type）
    :param type: 文件类型

        - 1: 文档
        - 2: 图片
        - 3: 音频
        - 4: 视频
        - 5: 压缩包
        - 6: 应用
        - 7: 书籍
        - 99: 所有文件

    :param order: 排序

        - "file_name": 文件名
        - "file_size": 文件大小
        - "file_type": 文件种类
        - "user_utime": 修改时间
        - "user_ptime": 创建时间
        - "user_otime": 上一次打开时间

    :param asc: 升序排列。0: 否，1: 是
    :param min_size: 最小的文件大小
    :param max_size: 最大的文件大小（含），0 表示不限
    :param cur: 仅当前目录。0: 否（将遍历子目录树上所有叶子节点），1: 是
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param with_ancestors: 文件信息中是否要包含 "path" 字段
    :param with_ancestors: 文件信息中是否要包含 "ancestors" 字段
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param path_already: 如果为 True，则说明 id_to_dirnode 中已经具备构建路径所需要的目录节点，所以不会再去拉取目录节点的信息
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1/2）
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（所有文件）文件信息
    """
    suffix = suffix.strip(".")
    if use_media_api:
        if suffix:
            raise ValueError("media api does not support filtering by suffix")
        if min_size or max_size:
            raise ValueError("media api does not support filtering by size")
    if not (type or suffix):
        raise ValueError("please set the non-zero value of suffix or type")
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    cid = _get_id(cid)
    payload: dict = {
        "asc": asc, "cid": cid, "count_folders": 0, "cur": cur, 
        "max_size": max_size, "min_size": min_size, "o": order, 
        "offset": 0, "show_dir": 0, 
    }
    if suffix:
        payload["suffix"] = suffix
    elif type != 99:
        payload["type"] = type
    attrs = iter_nodes(
        client, 
        payload=payload, 
        page_size=page_size, 
        first_page_size=first_page_size, 
        normalize_attr=normalize_attr, 
        id_to_dirnode=id_to_dirnode, 
        use_media_api=use_media_api, 
        raise_for_changed_count=raise_for_changed_count, 
        ensure_file=True, 
        app=app, 
        cooldown=cooldown, 
        max_workers=max_workers, 
        async_=async_, 
        **request_kwargs, 
    )
    if with_path or with_ancestors:
        attrs = ensure_path(
            client, 
            cid, 
            attrs, 
            with_ancestors=with_ancestors, 
            with_path=with_path, 
            escape=escape, 
            id_to_dirnode=id_to_dirnode, 
            path_already=path_already, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )
    return attrs


@overload
def iter_files_skim(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    path_already: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files_skim(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    path_already: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_skim(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    path_already: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息（包含 "path"，可选 "ancestors"）

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param with_ancestors: 文件信息中是否要包含 "path" 字段
    :param with_ancestors: 文件信息中是否要包含 "ancestors" 字段
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param path_already: 如果为 True，则说明 id_to_dirnode 中已经具备构建路径所需要的目录节点，所以不会再去拉取目录节点的信息
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（所有文件）文件信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    cid = _get_id(cid)
    from .download import iter_download_nodes
    attrs = iter_download_nodes(
        client, 
        cid, 
        ensure_name=True, 
        max_workers=max_workers, 
        app=app, 
        async_=async_, 
        **request_kwargs, 
    )
    if with_path or with_ancestors:
        attrs = ensure_path(
            client, 
            cid, 
            attrs, 
            with_ancestors=with_ancestors, 
            with_path=with_path, 
            escape=escape, 
            id_to_dirnode=id_to_dirnode, 
            path_already=path_already, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )
    return attrs


@overload
def traverse_tree(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def traverse_tree(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def traverse_tree(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件或目录节点的信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param with_ancestors: 文件信息中是否要包含 "path" 字段
    :param with_ancestors: 文件信息中是否要包含 "ancestors" 字段
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件或目录节点的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    cid = _get_id(cid)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ... and (with_path or with_ancestors):
        id_to_dirnode = {}
    from .download import iter_download_nodes
    to_pickcode = client.to_pickcode
    def fulfill_dir_node(attr: dict, /) -> dict:
        attr["pickcode"] = to_pickcode(attr["id"], "fa")
        attr["size"] = 0
        attr["sha1"] = ""
        return attr
    def gen_step():
        files = iter_download_nodes(
            client, 
            cid, 
            files=True,
            ensure_name=True, 
            id_to_dirnode=id_to_dirnode, 
            app=app, 
            max_workers=max_workers, 
            async_=async_, 
            **request_kwargs, 
        )
        with cache_loading(files) as (cache, task):
            yield YieldFrom(do_map(fulfill_dir_node, iter_dirs(
                client, 
                cid, 
                with_ancestors=with_ancestors, 
                with_path=with_path, 
                escape=escape, 
                id_to_dirnode=id_to_dirnode, 
                max_workers=max_workers, 
                async_=async_, 
                **request_kwargs, 
            )))
        if async_:
            yield task
        else:
            task.result()
        if with_path or with_ancestors:
            yield YieldFrom(ensure_path(
                client, 
                cid, 
                chain_from_iterable((cache, files), async_=async_), 
                with_ancestors=with_ancestors, 
                with_path=with_path, 
                escape=escape, 
                id_to_dirnode=id_to_dirnode, 
                path_already=True, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            ))
        else:
            yield YieldFrom(cache)
            yield YieldFrom(files)
    return run_gen_step_iter(gen_step, async_)


# TODO: search 接口也做一个通用的封装，用来给各种 search 做复用
@overload
def search_iter(
    client: str | PathLike | P115Client | P115OpenClient, 
    search_value: str = ".", 
    cid: int | str | Mapping = 0, 
    suffix: str = "", 
    type: int = 0, 
    offset: int = 0, 
    page_size: int = 115, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def search_iter(
    client: str | PathLike | P115Client | P115OpenClient, 
    search_value: str = ".", 
    cid: int | str | Mapping = 0, 
    suffix: str = "", 
    type: int = 0, 
    offset: int = 0, 
    page_size: int = 115, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def search_iter(
    client: str | PathLike | P115Client | P115OpenClient, 
    search_value: str = ".", 
    cid: int | str | Mapping = 0, 
    suffix: str = "", 
    type: int = 0, 
    offset: int = 0, 
    page_size: int = 115, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """搜索然后迭代返回结果

    .. attention::
        最多可取回 10,000，但接口有 bug，即使总数 >= 10,000，能取回的往往少于 10,000

    :param client: 115 客户端或 cookies
    :param search_value: 搜索关键词，搜索到的文件名必须包含这个字符串
    :param cid: 目录 id 或 pickcode
    :param suffix: 后缀名（优先级高于 type）
    :param type: 文件类型

        - 1: 文档
        - 2: 图片
        - 3: 音频
        - 4: 视频
        - 5: 压缩包
        - 6: 应用
        - 7: 书籍
        - 99: 所有文件

    :param offset: 开始索引，从 0 开始，要求 <= 10,000
    :param page_size: 分页大小，要求 `offset + page_size <= 10,000`
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 返回文件信息，如果没有，则是 None
    """
    if isinstance(cid, Mapping):
        cid = cast(int | str, get_first(cid, "id", "pickcode"))
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if not isinstance(client, P115Client) or app == "open":
        fs_search: Callable = client.fs_search_open
    elif app in ("", "web", "desktop", "aps"):
        fs_search = client.fs_search
    else:
        fs_search = partial(client.fs_search_app, app=app)
    if offset < 0:
        offset = 0
    elif offset >= 10_000:
        offset = 9_999
    def gen_step():
        nonlocal page_size, offset
        payload = {
            "cid": _get_id(cid), 
            "search_value": search_value, 
            "suffix": suffix, 
            "type": type, 
            "limit": page_size, 
            "offset": offset, 
        }
        while offset < 10_000:
            if offset + page_size > 10_000:
                page_size = 10_000 - offset
            payload["limit"] = page_size
            resp = yield fs_search(
                payload, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            data_list = resp["data"]
            if not data_list:
                return
            if normalize_attr is None:
                yield YieldFrom(data_list)
            else:
                yield YieldFrom(map(normalize_attr, data_list))
            offset += page_size
    return run_gen_step_iter(gen_step, async_)


# TODO: 支持 cooldown, max_workers
@overload
def share_iterdir(
    client: None | str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    cid: int | Mapping = 0, 
    page_size: int = 0, 
    start: int = 0, 
    order: Literal["", "file_name", "file_size", "user_ptime"] = "", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def share_iterdir(
    client: None | str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    cid: int | Mapping = 0, 
    page_size: int = 0, 
    start: int = 0, 
    order: Literal["", "file_name", "file_size", "user_ptime"] = "", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def share_iterdir(
    client: None | str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    cid: int | Mapping = 0, 
    page_size: int = 0, 
    start: int = 0, 
    order: Literal["", "file_name", "file_size", "user_ptime"] = "", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """对分享链接迭代目录，获取文件信息

    .. note::
        当 `app="web"`（默认），则 `client` 可以传 None，即可以不登录获取数据

    :param client: 115 客户端或 cookies
    :param share_code: 分享码或链接
    :param receive_code: 接收码
    :param cid: 目录的 id
    :param page_size: 分页大小
    :param start: 开始索引，从 0 开始
    :param order: 排序

        - "file_name": 文件名
        - "file_size": 文件大小
        - "file_type": 文件种类
        - "user_utime": 修改时间
        - "user_ptime": 创建时间
        - "user_otime": 上一次打开时间

    :param asc: 升序排列。0: 否，1: 是
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1/2）
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    if isinstance(cid, Mapping):
        cid = cast(int, cid["id"])
    if client is None:
        client = P115Client("")
    elif isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app in ("", "web", "desktop", "aps"):
        share_snap: Callable = client.share_snap
    else:
        share_snap = partial(client.share_snap_app, app=app)
    if page_size <= 0:
        page_size = 10_000
    def gen_step():
        nonlocal id_to_dirnode
        payload = cast(dict, share_extract_payload(share_code))
        if receive_code:
            payload["receive_code"] = receive_code
        elif not payload.get("receive_code"):
            resp = yield client.share_info(
                payload["share_code"], 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            payload["receive_code"] = resp["data"]["receive_code"]
        if id_to_dirnode is None:
            id_to_dirnode = ID_TO_DIRNODE_CACHE[payload["share_code"]]
        offset = start
        payload.update({
            "cid": cid, 
            "limit": page_size, 
            "offset": offset, 
            "asc": asc, 
            "o": order, 
        })
        count = 0
        while True:
            resp = yield share_snap(
                payload, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            if count == (count := resp["data"]["count"]):
                break
            for attr in resp["data"]["list"]:
                attr["share_code"] = share_code
                attr["receive_code"] = receive_code
                if id_to_dirnode is not ...:
                    oattr = overview_attr(attr)
                    if oattr.is_dir:
                        id_to_dirnode[oattr.id] = (oattr.name, oattr.parent_id)
                if normalize_attr is not None:
                    attr = normalize_attr(attr)
                yield Yield(attr)
            offset += page_size
            if offset >= count:
                break
            payload["offset"] = offset
    return run_gen_step_iter(gen_step, async_)


@overload
def share_iter_files(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    cid: int | Mapping = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def share_iter_files(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    cid: int | Mapping = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def share_iter_files(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    cid: int | Mapping = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """批量获取分享链接下的文件列表

    :param client: 115 客户端或 cookies
    :param share_code: 分享码或链接
    :param receive_code: 接收码
    :param cid: 顶层目录的 id，从此开始遍历
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典，如果为 ...，则忽略
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此分享链接下的（所有文件）文件信息，由于接口返回信息有限，所以比较简略

        .. code:: python

            {
                "id": int, 
                "sha1": str, 
                "name": str, 
                "size": int, 
                "path": str, 
            }
    """
    if isinstance(cid, Mapping):
        cid = cast(int, cid["id"])
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app in ("", "web", "desktop", "aps"):
        share_downlist: Callable = client.share_downlist
    else:
        share_downlist = client.share_downlist_app
    def gen_step():
        nonlocal id_to_dirnode
        payload = cast(dict, share_extract_payload(share_code))
        if receive_code:
            payload["receive_code"] = receive_code
        elif not payload["receive_code"]:
            resp = yield client.share_info(
                payload["share_code"], 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            payload["receive_code"] = resp["data"]["receive_code"]
        if id_to_dirnode is None:
            id_to_dirnode = ID_TO_DIRNODE_CACHE[payload["share_code"]]
        def load_cid_snap_first(cid, /):
            payload["cid"] = cid
            with with_iter_next(share_iterdir(
                client, 
                **payload, 
                id_to_dirnode=id_to_dirnode, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                while True:
                    attr = yield get_next()
                    if attr.get("is_dir"):
                        yield from load_cid(attr["id"])
                    else:
                        attr["path"] = "/" + attr["name"]
                        yield Yield(attr)
        def load_cid(cid: int, /):
            payload["cid"] = cid
            resp = yield share_downlist(
                payload, 
                async_=async_, 
                **request_kwargs, 
            )
            if resp.get("errno") == 4100030:
                yield from load_cid_snap_first(cid)
            else:
                check_response(resp)
                for info in resp["data"]["list"]:
                    fid, _, hash = info["fid"].partition("_")
                    attr: dict = {"id": int(fid)}
                    if hash:
                        attr["hash"] = hash
                    if "fn" in info:
                        attr["size"] = int(info["si"])
                        attr["name"] = info["fn"]
                        attr["path"] = f"/{info['pt']}/{info['fn']}"
                    else:
                        attr["dir"] = "/" + info["pt"]
                    yield Yield(attr)
        if cid:
            yield from load_cid(cid)
        else:
            yield from load_cid_snap_first(cid)
    return run_gen_step_iter(gen_step, async_)


@overload
def share_search_iter(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    search_value: str = ".", 
    cid: int | Mapping = 0, 
    suffix: str = "", 
    type: int = 99, 
    offset: int = 0, 
    page_size: int = 115, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def share_search_iter(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    search_value: str = ".", 
    cid: int | Mapping = 0, 
    suffix: str = "", 
    type: int = 99, 
    offset: int = 0, 
    page_size: int = 115, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def share_search_iter(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    search_value: str = ".", 
    cid: int | Mapping = 0, 
    suffix: str = "", 
    type: int = 99, 
    offset: int = 0, 
    page_size: int = 115, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """在分享链接下搜索然后迭代返回结果

    :param client: 115 客户端或 cookies
    :param share_code: 分享码或链接
    :param receive_code: 接收码
    :param search_value: 搜索关键词，搜索到的文件名必须包含这个字符串
    :param cid: 目录 id
    :param suffix: 后缀名（优先级高于 type）
    :param type: 文件类型

        - 1: 文档
        - 2: 图片
        - 3: 音频
        - 4: 视频
        - 5: 压缩包
        - 6: 应用
        - 7: 书籍
        - 99: 所有文件

    :param offset: 开始索引，从 0 开始，要求 <= 10,000
    :param page_size: 分页大小，要求 `offset + page_size <= 10,000`
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 返回文件信息，如果没有，则是 None
    """
    if isinstance(cid, Mapping):
        cid = cast(int, cid["id"])
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if offset < 0:
        offset = 0
    elif offset >= 10_000:
        offset = 9_999
    def gen_step():
        nonlocal page_size, offset
        payload = cast(dict, share_extract_payload(share_code))
        if receive_code:
            payload["receive_code"] = receive_code
        elif not payload.get("receive_code"):
            resp = yield client.share_info(
                payload["share_code"], 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            payload["receive_code"] = resp["data"]["receive_code"]
        payload.update(
            cid=cid, 
            search_value=search_value, 
            suffix=suffix, 
            type=type, 
            limit=page_size, 
            offset=offset, 
        )
        while offset < 10_000:
            if offset + page_size > 10_000:
                page_size = 10_000 - offset
            payload["limit"] = page_size
            resp = yield client.share_search(
                payload, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            data_list = resp["data"]["list"]
            if not data_list:
                return
            elif normalize_attr is None:
                yield YieldFrom(data_list)
            else:
                yield YieldFrom(map(normalize_attr, data_list))
            offset += page_size
    return run_gen_step_iter(gen_step, async_)


@overload
def extract_iterdir(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    path: str | Mapping = "/", 
    page_size: int = 999, 
    app: str = "web", 
    cooldown: None | float = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def extract_iterdir(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    path: str | Mapping = "/", 
    page_size: int = 999, 
    app: str = "web", 
    cooldown: None | float = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def extract_iterdir(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    path: str | Mapping = "/", 
    page_size: int = 999, 
    app: str = "web", 
    cooldown: None | float = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """对压缩包迭代目录，获取文件信息

    :param client: 115 客户端或 cookies
    :param pickcode: 压缩文件的 pickcode 或 id
    :param path: 压缩包内（目录）路径，为空则是压缩包的根目录
    :param page_size: 分页大小，最大 999
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1/2）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    if isinstance(pickcode, Mapping):
        pickcode = cast(str | int, get_first(pickcode, "pickcode", "id"))
    if isinstance(path, Mapping):
        path = cast(str, path["path"])
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    pickcode = client.to_pickcode(pickcode)
    def gen_step():
        next_marker = ""
        start_t: float = 0
        extract_list = client.extract_list
        while True:
            if cooldown and cooldown > 0:
                if start_t and (delta := start_t + cooldown - time()) > 0:
                    if async_:
                        yield async_sleep(delta)
                    else:
                        sleep(delta)
                start_t = time()
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
            dirname = path.rstrip("/") + "/"
            for info in resp["data"]["list"]:
                attr: dict = {}
                attr["pickcode"] = pickcode
                attr["is_dir"] = not info["file_category"]
                attr["name"] = info["file_name"]
                attr["path"] = dirname + info["file_name"]
                attr["size"] = info["size"]
                attr["ctime"] = attr["mtime"] = info["time"] or 0
                yield Yield(attr)
            next_marker = resp["data"]["next_marker"]
            if not next_marker:
                break
    return run_gen_step_iter(gen_step, async_)


@overload
def extract_iter_files(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    path: str | Mapping = "/", 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def extract_iter_files(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    path: str | Mapping = "/", 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def extract_iter_files(
    client: str | PathLike | P115Client, 
    pickcode: str | int | Mapping, 
    path: str | Mapping = "/", 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """批量获取压缩包中的文件列表

    :param client: 115 客户端或 cookies
    :param pickcode: 压缩文件的 pickcode 或 id
    :param path: 压缩包内（目录）路径，为空则是压缩包的根目录
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此分享链接下的（所有文件）文件信息，由于接口返回信息有限，所以比较简略

        .. code:: python

            {
                "id": int, 
                "sha1": str, 
                "name": str, 
                "size": int, 
                "path": str, 
            }
    """
    if isinstance(pickcode, Mapping):
        pickcode = cast(str | int, get_first(pickcode, "pickcode", "id"))
    if isinstance(path, Mapping):
        path = cast(str, path["path"])
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    pickcode = client.to_pickcode(pickcode)
    if app in ("", "web", "desktop", "aps"):
        extract_folders: Callable = client.extract_folders
    else:
        extract_folders = partial(client.extract_folders_app, app=app)
    def gen_step():
        def load_path(path: str, /):
            resp = yield extract_folders(
                {"pick_code": pickcode, "full_dir_name": path.strip("/")}, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            for info in resp["data"]:
                yield Yield({
                    "name": info["fn"], 
                    "size": int(info["si"]), 
                    "path": "/" + info["pt"] + "/" + info["fn"], 
                })
        if path.strip("/"):
            yield from load_path(path)
        else:
            with with_iter_next(extract_iterdir(
                client, 
                pickcode, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                while True:
                    attr = yield get_next()
                    if attr.get("is_dir"):
                        yield from load_path(attr["path"])
                    else:
                        attr["path"] = "/" + attr["name"]
                        yield Yield(attr)
    return run_gen_step_iter(gen_step, async_)











# TODO: 创建一个 share_files.py 模块，参照 fs_files.py
# TODO: 需要优化，甚至移除
@overload
def iter_parents(
    client: str | PathLike | P115Client, 
    ids: Iterable[int], 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[tuple[int, tuple[str, str, str]]]:
    ...
@overload
def iter_parents(
    client: str | PathLike | P115Client, 
    ids: Iterable[int] | AsyncIterable[int], 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[int, tuple[str, str, str]]]:
    ...
def iter_parents(
    client: str | PathLike | P115Client, 
    ids: Iterable[int] | AsyncIterable[int], 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[tuple[int, tuple[str, str, str]]] | AsyncIterator[tuple[int, tuple[str, str, str]]]:
    """获取一批 id 的上级目录，最多获取 3 级（不包括被查询的 id 自身这一级）

    :param client: 115 客户端或 cookies
    :param ids: 一批文件或目录的 id
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生 id 和 最近 3 级目录名的元组的 2 元组
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def fix_overflow(t: tuple[str, ...], /) -> tuple[str, ...]:
        try:
            start = t.index("文件") + 1
            return t[start:][::-1] + ("",) * start
        except ValueError:
            return t[::-1]
    set_names = client.fs_rename_set_names
    reset_names = client.fs_rename_reset_names
    def get_parents(ids: Sequence[int], /):
        data: dict = {f"file_list[{i}][file_id]": id for i, id in enumerate(ids)}
        resp = yield set_names(data, async_=async_, **request_kwargs)
        check_response(resp)
        req_id = resp["req_id"]
        data = {
            "func_list[0][name]": "addParent", 
            "func_list[0][config][level]": 1, 
            "func_list[0][config][position]": 1, 
            "func_list[0][config][separator]": 0, 
            "req_id": req_id, 
        }
        while True:
            resp = yield reset_names(data, async_=async_, **request_kwargs)
            if resp["data"][0]["file_name"]:
                l1 = [d["file_name"] for d in resp["data"]]
                break
            if async_:
                yield async_sleep(0.25)
            else:
                sleep(0.25)
        if len(ids) - l1.count("文件") <= 0:
            return ((id, ("" if name == "文件" else name, "", "")) for id, name in zip(ids, l1))
        def call(i):
            return check_response(reset_names(
                {**data, "func_list[0][config][level]": i}, 
                async_=async_, 
                **request_kwargs, 
            ))
        ret = conmap(call, (2, 3), max_workers=2, async_=async_)
        if async_:
            ret = yield async_collect(ret)
        resp2, resp3 = cast(Iterable, ret)
        l2 = [d["file_name"] for d in resp2["data"]]
        l3 = (d["file_name"] for d in resp3["data"])
        return ((id, fix_overflow(t)) for id, t in zip(ids, zip(l3, l2, l1)))
    return chain_from_iterable(conmap(
        lambda ids: run_gen_step(get_parents(ids), async_), # type: ignore
        chunked(do_filter(None, ids), 1150), 
        max_workers=max_workers, 
        async_=async_, # type: ignore
    ))


@overload
def iter_keyed_files[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, dict]]:
    ...
@overload
def iter_keyed_files[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[K, dict]]:
    ...
def iter_keyed_files[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, dict]] | AsyncIterator[tuple[K, dict]]:
    """遍历以迭代获得所有文件信息

    :param client: 115 客户端或 cookies
    :param cid: 待被遍历的目录 id 或 pickcode
    :param key: 函数，用来给文件分组，当多个文件被分配到同一组时，它们相互之间是重复文件关系
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param is_skim: 是否拉取简要信息
    :param with_path: 是否需要 "path" 和 "ancestors" 字段
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回 key 和 文件信息 的元组
    """
    return do_map(
        lambda attr, /: (key(attr), attr), 
        iter_files_shortcut(
            client, 
            cid, 
            id_to_dirnode=id_to_dirnode, 
            max_workers=max_workers, 
            is_skim=is_skim, 
            with_path=with_path, 
            app=app, 
            async_=async_, # type: ignore
            **request_kwargs, 
        ), 
    )


@overload
def iter_keyed_dupfiles[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, dict]]:
    ...
@overload
def iter_keyed_dupfiles[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[K, dict]]:
    ...
def iter_keyed_dupfiles[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, dict]] | AsyncIterator[tuple[K, dict]]:
    """遍历以迭代获得所有重复文件信息

    :param client: 115 客户端或 cookies
    :param cid: 待被遍历的目录 id 或 pickcode
    :param key: 函数，用来给文件分组，当多个文件被分配到同一组时，它们相互之间是重复文件关系
    :param keep_first: 保留某个重复文件不输出，除此以外的重复文件都输出

        - 如果为 None，则输出所有重复文件（不作保留）
        - 如果为 True，则保留最早入组的那个文件
        - 如果为 False，则保留最晚入组的那个文件
        - 如果是 Callable，则会对文件信息进行计算，保留值最小的那个文件

    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param is_skim: 是否拉取简要信息
    :param with_path: 是否需要 "path" 和 "ancestors" 字段
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回 key 和 重复文件信息 的元组
    """
    return iter_keyed_dups(
        iter_files_shortcut(
            client, 
            cid, 
            id_to_dirnode=id_to_dirnode, 
            max_workers=max_workers, 
            is_skim=is_skim, 
            with_path=with_path, 
            app=app, 
            async_=async_, # type: ignore
            **request_kwargs, 
        ), 
        key=key, 
        keep_first=keep_first, 
    )


@overload
def iter_keyed_ids[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, int]]:
    ...
@overload
def iter_keyed_ids[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[K, int]]:
    ...
def iter_keyed_ids[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, int]] | AsyncIterator[tuple[K, int]]:
    """遍历以迭代获得所有文件的 id

    .. note::
        直接用 ("sha1", "size") 作为 key，不支持自己指定，如若不然，请用 ``iter_keyed_dupfiles``

    .. note::
        可以作为一个依据，用来找寻其它目录中，已经在此目录中的重复文件

        .. code:: python

            from p115client import P115Client
            from p115client.tool import *
            client = P115Client.from_path()

            # NOTE: cid1 是作为基准的目录 id，其它目录中是否有重复文件以此为准
            cid1 = ...
            seen = {key for key, _ in iter_keyed_ids(client, cid1)}
            # NOTE: cid2 是目标 id，用来找寻重复文件
            cid2 = ...
            n = 0
            for key, file_id in iter_keyed_ids(client, cid2):
                if key in seen:
                    n += 1
                    print(f"[{n}] 发现重复文件: {key=!r}, {file_id=!r}")

    :param client: 115 客户端或 cookies
    :param cid: 待被遍历的目录 id 或 pickcode
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回 key 和 文件 id 的元组
    """
    from .download import iter_download_nodes
    request_kwargs["app"] = "os_windows"
    return do_map(
        lambda info, /: ((info["sha1"], info["fs"]), _get_id(info["pc"])), 
        iter_download_nodes(
            client, 
            cid, 
            files=True, 
            get_raw=True, 
            max_workers=max_workers, 
            async_=async_, 
            **request_kwargs, 
        ), 
    )


@overload
def iter_keyed_dupfile_ids[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    keep_first: None | bool = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, int]]:
    ...
@overload
def iter_keyed_dupfile_ids[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    keep_first: None | bool = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[K, int]]:
    ...
def iter_keyed_dupfile_ids[K](
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    keep_first: None | bool = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, int]] | AsyncIterator[tuple[K, int]]:
    """遍历以迭代获得所有重复文件的 id

    .. note::
        直接用 ("sha1", "size") 作为 key，不支持自己指定，如若不然，请用 ``iter_keyed_dupfiles``

    :param client: 115 客户端或 cookies
    :param cid: 待被遍历的目录 id 或 pickcode
    :param keep_first: 保留某个重复文件不输出，除此以外的重复文件都输出

        - 如果为 None，则输出所有重复文件（不作保留）
        - 如果为 True，则保留最早入组的那个文件
        - 如果为 False，则保留最晚入组的那个文件

    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回 key 和 重复文件 id 的元组
    """
    from .download import iter_download_nodes
    request_kwargs["app"] = "os_windows"
    return do_map(
        lambda pair, /: (pair[0], _get_id(pair[1]["pc"])), 
        iter_keyed_dups(
            iter_download_nodes(
                client, 
                cid, 
                files=True, 
                get_raw=True, 
                max_workers=max_workers, 
                async_=async_, 
                **request_kwargs, 
            ), 
            key=itemgetter("sha1", "fs"), 
            keep_first=keep_first, 
        )
    )


@overload
def iter_unique_keys(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    max_workers: None | int = None, 
    seen: None | MutableSet[tuple[str, int]] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterable[tuple[str, int]]:
    ...
@overload
def iter_unique_keys(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    max_workers: None | int = None, 
    seen: None | MutableSet[tuple[str, int]] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterable[tuple[str, int]]:
    ...
def iter_unique_keys(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    max_workers: None | int = None, 
    seen: None | MutableSet[tuple[str, int]] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterable[tuple[str, int]] | AsyncIterable[tuple[str, int]]:
    """获取某个目录中，所有不重复的 (sha1, size) 组合

    :param client: 115 客户端或 cookies
    :param cid: 待被遍历的目录 id 或 pickcode
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回 (sha1, size) 的组合
    """
    from .download import iter_download_nodes
    request_kwargs["app"] = "os_windows"
    return iter_unique(
        do_map(
            itemgetter("sha1", "fs"), 
            iter_download_nodes(
                client, 
                cid, 
                files=True, 
                get_raw=True, 
                max_workers=max_workers, 
                async_=async_, 
                **request_kwargs, 
            ), 
        ), 
        seen=seen, 
    )



