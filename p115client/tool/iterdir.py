#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "ensure_attr_path", "ensure_attr_path_using_star_event", "iterdir", 
    "iter_stared_dirs", "iter_dirs", "iter_dirs_with_path", "iter_files", 
    "iter_files_with_path", "iter_files_with_path_skim", "iter_files_shortcut", 
    "iter_files_frament", "traverse_tree", "traverse_tree_with_path", 
    "iter_nodes", "iter_nodes_skim", "iter_nodes_by_pickcode", "iter_nodes_using_update", 
    "iter_nodes_using_info", "iter_nodes_using_event",  "iter_dir_nodes_using_star", 
    "iter_parents", "iter_dupfiles", "iter_media_files", "search_iter", "share_iterdir", 
    "share_iter_files", "share_search_iter", 
]
__doc__ = "这个模块提供了一些和目录信息罗列有关的函数"

from asyncio import create_task, gather as async_gather, sleep as async_sleep, Task
from collections.abc import (
    AsyncIterable, AsyncIterator, Callable, Generator, Iterable, 
    Iterator, Mapping, MutableMapping, Sequence, 
)
from contextlib import contextmanager
from concurrent.futures import Future
from dataclasses import dataclass
from errno import EIO, ENOENT
from functools import partial
from itertools import batched, cycle
from math import inf
from operator import itemgetter
from os import PathLike
from time import sleep, time
from types import EllipsisType
from typing import cast, overload, Any, Literal
from warnings import warn

from asynctools import to_list
from concurrenttools import run_as_thread, conmap
from iterutils import (
    as_gen_step, bfs_gen, chunked, chain, chain_from_iterable, collect, foreach, 
    run_gen_step, run_gen_step_iter, through, with_iter_next, map as do_map, 
    filter as do_filter, Yield, YieldFrom, 
)
from iter_collect import iter_keyed_dups, SupportsLT
from orjson import loads
from p115client import (
    check_response, normalize_attr, 
    P115Client, P115OpenClient, P115OSError, P115Warning, 
)
from p115client.const import ID_TO_DIRNODE_CACHE
from p115client.type import DirNode
from p115pickcode import pickcode_to_id, to_id
from posixpatht import splitext

from .edit import update_desc, update_star, post_event
from .fs_files import iter_fs_files
from .life import iter_life_behavior_once, life_show
from .util import is_timeouterror, posix_escape_name, share_extract_payload, unescape_115_charref


@dataclass(frozen=True, unsafe_hash=True)
class OverviewAttr:
    is_dir: bool
    id: int
    parent_id: int
    name: str
    ctime: int
    mtime: int

    def __getitem__(self, key, /):
        try:
            return getattr(self, key)
        except AttributeError as e:
            raise LookupError(key) from e


def overview_attr(info: Mapping, /) -> OverviewAttr:
    if "n" in info:
        is_dir = "fid" not in info
        name = info["n"]
        if is_dir:
            id = int(info["cid"])
            pid = int(info["pid"])
        else:
            id = int(info["fid"])
            pid = int(info["cid"])
        ctime = int(info.get("tp") or info["t"])
        mtime = int(info.get("te") or info["t"])
    elif "fn" in info:
        is_dir = info["fc"] == "0"
        name = info["fn"]
        id = int(info["fid"])
        pid = int(info["pid"])
        ctime = int(info["uppt"])
        mtime = int(info["upt"])
    elif "file_category" in info:
        is_dir = int(info["file_category"]) == 0
        if is_dir:
            name = info["category_name"]
            id = int(info["category_id"])
            pid = int(info["parent_id"])
            ctime = int(info["pptime"])
            mtime = int(info["ptime"])
        else:
            name = info["file_name"]
            id = int(info["file_id"])
            pid = int(info["category_id"])
            ctime = int(info["user_pptime"])
            mtime = int(info["user_ptime"])
    else:
        raise ValueError(f"can't overview attr data: {info!r}")
    return OverviewAttr(is_dir, id, pid, name, ctime, mtime)


def update_resp_ancestors(
    resp: dict, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    /, 
    error: None | OSError = FileNotFoundError(ENOENT, "not found"), 
) -> dict:
    list_append = list.append
    need_update_id_to_dirnode = id_to_dirnode not in (..., None)
    if "path" in resp:
        ancestors = resp["ancestors"] = []
        start_idx = not resp["path"][0]["cid"]
        if start_idx:
            list_append(ancestors, {"id": 0, "parent_id": 0, "name": ""})
        for info in resp["path"][start_idx:]:
            id, name, pid = int(info["cid"]), info["name"], int(info["pid"])
            list_append(ancestors, {"id": id, "parent_id": pid, "name": name})
            if need_update_id_to_dirnode:
                id_to_dirnode[id] = DirNode(name, pid) # type: ignore
    else:
        if resp and "paths" not in resp:
            check_response(resp)
            resp = resp["data"]
        if not resp:
            if error is None:
                return resp
            raise error
        ancestors = resp["ancestors"] = []
        pid = int(resp["paths"][0]["file_id"])
        for info in resp["paths"][1:]:
            id = int(info["file_id"])
            name = info["file_name"]
            list_append(ancestors, {"id": id, "parent_id": pid, "name": name})
            if need_update_id_to_dirnode:
                id_to_dirnode[id] = DirNode(name, pid) # type: ignore
            pid = id
        if not resp["sha1"]:
            if "file_id" in resp:
                id = int(resp["file_id"])
            else:
                id = to_id(resp["pick_code"])
            name = resp["file_name"]
            list_append(ancestors, {"id": id, "parent_id": pid, "name": name})
            if need_update_id_to_dirnode:
                id_to_dirnode[id] = DirNode(name, pid) # type: ignore
    return resp


def _make_top_adder(
    top_id: int, 
    id_to_dirnode: MutableMapping[int, tuple[str, int] | DirNode], 
    escape: None | bool | Callable[[str], str] = True, 
) -> Callable:
    top_ancestors: list[dict]
    if not top_id:
        top_ancestors = [{"id": 0, "parent_id": 0, "name": ""}]
        top_path = "/"
        top_prefix_len = 1
    def add_top[T: MutableMapping](attr: T, /) -> T:
        nonlocal escape, top_ancestors, top_path, top_prefix_len
        try:
            top_ancestors
        except NameError:
            top_ancestors = []
            add_ancestor = top_ancestors.append
            tid = top_id
            while tid and tid in id_to_dirnode:
                name, pid = id_to_dirnode[tid]
                add_ancestor({"id": tid, "parent_id": pid, "name": name})
                tid = pid
            if not tid:
                add_ancestor({"id": 0, "parent_id": 0, "name": ""})
            top_ancestors.reverse()
            if escape is None:
                top_path = "/".join(a["name"] for a in top_ancestors)
            else:
                if isinstance(escape, bool):
                    if escape:
                        from posixpatht import escape
                    else:
                        escape = posix_escape_name
                top_path = "/".join(escape(a["name"]) for a in top_ancestors)
            top_prefix_len = len(top_path) + 1
        attr["top_id"]        = top_id
        attr["top_ancestors"] = top_ancestors
        attr["top_path"]      = top_path
        if "path" in attr:
            attr["relpath"] = attr["path"][top_prefix_len:]
        return attr
    return add_top


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
def ensure_attr_path[D: dict](
    client: str | PathLike | P115Client | P115OpenClient, 
    attrs: Iterable[D], 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[D]:
    ...
@overload
def ensure_attr_path[D: dict](
    client: str | PathLike | P115Client | P115OpenClient, 
    attrs: Iterable[D] | AsyncIterable[D], 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[D]:
    ...
def ensure_attr_path[D: dict](
    client: str | PathLike | P115Client | P115OpenClient, 
    attrs: Iterable[D] | AsyncIterable[D], 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[D] | AsyncIterator[D]:
    """为一组文件信息添加 "path" 字段，可选 "ancestors" 字段

    .. caution::
        风控非常严重，请谨慎使用

    :param client: 115 客户端或 cookies
    :param attrs: 一组文件或目录的信息
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
    if not isinstance(client, P115Client) or app == "open":
        get_info: Callable = client.fs_info_open
        app = "open"
    elif app in ("", "web", "desktop", "harmony"):
        request_kwargs.setdefault("base_url", cycle(("http://webapi.115.com", "https://webapi.115.com")).__next__)
        get_info = client.fs_category_get
    else:
        request_kwargs.setdefault("base_url", cycle(("http://proapi.115.com", "https://proapi.115.com")).__next__)
        get_info = partial(client.fs_category_get_app, app=app)
    dangling_id_to_name: dict[int, str] = {}
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    id_to_path: dict[int, str] = {}
    def get_path(attr: dict | tuple[str, int] | DirNode, /) -> str:
        if isinstance(attr, (DirNode, tuple)):
            name, pid = attr
        else:
            pid = attr["parent_id"]
            name = attr["name"]
        if escape is not None:
            name = escape(name)
        if pid == 0:
            dirname = "/"
        elif pid in dangling_id_to_name:
            return dangling_id_to_name[pid]
        elif pid in id_to_path:
            dirname = id_to_path[pid]
        else:
            dirname = id_to_path[pid] = get_path(id_to_dirnode[pid]) + "/"
        return dirname + name
    if with_ancestors:
        id_to_node: dict[int, dict] = {0: {"id": 0, "parent_id": 0, "name": ""}}
        def get_ancestors(id: int, attr: dict | tuple[str, int] | DirNode, /) -> list[dict]:
            if not id:
                return [id_to_node[0]]
            if isinstance(attr, (DirNode, tuple)):
                name, pid = attr
            else:
                pid = attr["parent_id"]
                name = attr["name"]
            if id in id_to_node:
                me = id_to_node[id]
            else:
                me = id_to_node[id] = {"id": id, "parent_id": pid, "name": name}
            if pid == 0:
                ancestors = [id_to_node[0]]
            elif pid in dangling_id_to_name:
                if name := dangling_id_to_name[pid]:
                    if pid not in id_to_node:
                        id_to_node[pid] = {"id": pid, "name": name}
                    ancestors = [id_to_node[pid]]
                else:
                    ancestors = []
            else:
                ancestors = get_ancestors(pid, id_to_dirnode[pid])
            ancestors.append(me)
            return ancestors
    def gen_step():
        with with_iter_next(attrs) as get_next:
            while True:
                attr = yield get_next()
                id   = attr["id"]
                pid  = attr["parent_id"]
                while pid and pid in id_to_dirnode:
                    pid = id_to_dirnode[pid][1]
                if pid and pid not in dangling_id_to_name:
                    resp = yield get_info(pid, async_=async_, **request_kwargs)
                    resp = update_resp_ancestors(resp, id_to_dirnode, None)
                    if not resp:
                        dangling_id_to_name[pid] = ""
                        yield Yield(attr)
                        return
                    info = resp["paths"][0]
                    if pid := int(info["file_id"]):
                        dangling_id_to_name[pid] = info["file_name"]
                attr["path"] = path = get_path(attr)
                if "top_path" in attr:
                    top_path = attr["top_path"]
                    attr["relpath"] = path[(1 if top_path == "/" else len(top_path) + 1):]
                if with_ancestors:
                    attr["ancestors"] = get_ancestors(id, attr)
                yield Yield(attr)
    return run_gen_step_iter(gen_step, async_)


@overload
def ensure_attr_path_using_star_event[D: dict](
    client: str | PathLike | P115Client, 
    attrs: Iterable[D], 
    with_ancestors: bool = False, 
    life_event_cooldown: int | float = 0.5, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[D]:
    ...
@overload
def ensure_attr_path_using_star_event[D: dict](
    client: str | PathLike | P115Client, 
    attrs: Iterable[D] | AsyncIterable[D], 
    with_ancestors: bool = False, 
    life_event_cooldown: int | float = 0.5, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[D]:
    ...
def ensure_attr_path_using_star_event[D: dict](
    client: str | PathLike | P115Client, 
    attrs: Iterable[D] | AsyncIterable[D], 
    with_ancestors: bool = False, 
    life_event_cooldown: int | float = 0.5, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[D] | AsyncIterator[D]:
    """为一组文件信息添加 "path" 字段，另外可选 "ancestors" 字段

    :param client: 115 客户端或 cookies
    :param attrs: 一组文件或目录的信息
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param life_event_cooldown: 冷却时间，大于 0 时，两次拉取操作事件的接口调用之间至少间隔这么多秒
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 返回这一组文件信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
    dangling_ids: set[int] = set()
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    id_to_path: dict[int, str] = {}
    def get_path(attr: dict | tuple[str, int] | DirNode, /) -> str:
        if isinstance(attr, (DirNode, tuple)):
            name, pid = attr
        else:
            pid = attr["parent_id"]
            name = attr["name"]
        if escape is not None:
            name = escape(name)
        if pid == 0:
            dirname = "/"
        elif pid in dangling_ids:
            dirname = ""
        elif pid in id_to_path:
            dirname = id_to_path[pid]
        else:
            dirname = id_to_path[pid] = get_path(id_to_dirnode[pid]) + "/"
        return dirname + name
    if with_ancestors:
        id_to_node: dict[int, dict] = {0: {"id": 0, "parent_id": 0, "name": ""}}
        def get_ancestors(id: int, attr: dict | tuple[str, int] | DirNode, /) -> list[dict]:
            if not id:
                return [id_to_node[0]]
            if isinstance(attr, (DirNode, tuple)):
                name, pid = attr
            else:
                pid = attr["parent_id"]
                name = attr["name"]
            if id in id_to_node:
                me = id_to_node[id]
            else:
                me = id_to_node[id] = {"id": id, "parent_id": pid, "name": name}
            if pid == 0:
                ancestors = [id_to_node[0]]
            elif pid in dangling_ids:
                ancestors = []
            else:
                ancestors = get_ancestors(pid, id_to_dirnode[pid])
            ancestors.append(me)
            return ancestors
    def gen_step():
        cache: Sequence[dict]
        if id_to_dirnode:
            cache = []
            add_to_cache = cache.append
            with with_iter_next(attrs) as get_next:
                while True:
                    attr = yield get_next()
                    try:
                        attr["path"] = get_path(attr)
                        if with_ancestors:
                            attr["ancestors"] = get_ancestors(attr["id"], attr)
                    except KeyError:
                        add_to_cache(attr)
                    else:
                        yield Yield(attr)
        elif isinstance(attrs, Sequence):
            cache = attrs
        elif isinstance(attrs, AsyncIterable):
            cache = yield to_list(attrs)
        else:
            cache = list(attrs)
        if cache:
            pids: set[int] = set()
            add_pid = pids.add
            for attr in cache:
                if pid := attr["parent_id"]:
                    add_pid(pid)
                if attr.get("is_dir", False):
                    id_to_dirnode[attr["id"]] = DirNode(attr["name"], pid)
            find_ids: set[int]
            while pids:
                if find_ids := pids - id_to_dirnode.keys() - dangling_ids:
                    yield through(iter_nodes_using_event(
                        client, 
                        find_ids, 
                        normalize_attr=None, 
                        id_to_dirnode=id_to_dirnode, 
                        cooldown=life_event_cooldown, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    ))
                    if dangling_ids_new := find_ids - id_to_dirnode.keys() - dangling_ids:
                        dangling_ids.update(dangling_ids_new)
                pids = {ppid for pid in pids if (ppid := id_to_dirnode[pid][1])}
            del find_ids, pids, add_pid
            for attr in cache:
                attr["path"] = path = get_path(attr)
                if "top_path" in attr:
                    top_path = attr["top_path"]
                    attr["relpath"] = path[(1 if top_path == "/" else len(top_path) + 1):]
                if with_ancestors:
                    attr["ancestors"] = get_ancestors(attr["id"], attr)
                yield Yield(attr)
    return run_gen_step_iter(gen_step, async_)


@overload
def _iter_fs_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    with_dirname: bool = False, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = ..., 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    hold_top: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def _iter_fs_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    with_dirname: bool = False, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = ..., 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    hold_top: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def _iter_fs_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    with_dirname: bool = False, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = ..., 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    hold_top: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代目录，获取文件信息

    :param client: 115 客户端或 cookies
    :param payload: 请求参数（字典）或 id 或 pickcode
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小，如果 <= 0，则和 `page_size` 相同
    :param with_dirname: 是否要包含父目录的名字
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
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
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1）
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if isinstance(payload, (int, str)):
        payload = {"cid": to_id(payload)}
    show_files = payload.get("suffix") or payload.get("type")
    if show_files:
        payload.setdefault("show_dir", 0)
    if not ensure_file:
        payload["count_folders"] = 1
    if ensure_file:
        payload["show_dir"] = 0
        if not show_files:
            payload.setdefault("cur", 1)
    elif ensure_file is False:
        payload["show_dir"] = 1
        payload["nf"] = 1
    if payload.get("type") == 99:
        payload.pop("type", None)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    if not isinstance(client, P115Client):
        with_dirname = False
    if with_dirname:
        pid_to_name = {0: ""}
        def get_pid(info: dict, /) -> int:
            for key in ("parent_id", "pid", "cid"):
                if key in info:
                    return int(info[key])
            raise KeyError("parent_id", "pid", "cid")
        setitem = pid_to_name.__setitem__
        def callback(resp: dict, /):
            return foreach(
                lambda info: setitem(info["file_id"], info["file_name"]), 
                iter_nodes_skim(
                    cast(P115Client, client), 
                    (
                        pid for info in resp["data"] 
                        if (pid := get_pid(info)) and pid not in pid_to_name
                    ), 
                    async_=async_, 
                    **request_kwargs, 
                )
            )
        request_kwargs["callback"] = callback
    def gen_step():
        top_id = int(payload.get("cid") or 0)
        with with_iter_next(iter_fs_files(
            client, 
            payload, 
            page_size=page_size, 
            first_page_size=first_page_size, 
            app=app, 
            raise_for_changed_count=raise_for_changed_count, 
            cooldown=cooldown, 
            max_workers=max_workers, 
            async_=async_, 
            **request_kwargs, 
        )) as get_next:
            while True:
                resp = yield get_next()
                update_resp_ancestors(resp, id_to_dirnode)
                if hold_top:
                    top_ancestors = resp["ancestors"]
                    if escape is None:
                        top_path = "/".join(a["name"] for a in top_ancestors)
                    else:
                        top_path = "/".join(escape(a["name"]) for a in top_ancestors)
                for info in resp["data"]:
                    if normalize_attr is None:
                        attr: dict | OverviewAttr = overview_attr(info)
                    else:
                        attr = info = normalize_attr(info)
                    if attr["is_dir"]:
                        if id_to_dirnode is not ...:
                            id_to_dirnode[attr["id"]] = DirNode(attr["name"], attr["parent_id"])
                        if ensure_file is True:
                            continue
                    elif ensure_file is False:
                        continue
                    if with_dirname:
                        info["dirname"] = pid_to_name[attr["parent_id"]]
                    if hold_top:
                        info["top_id"]        = top_id
                        info["top_ancestors"] = top_ancestors
                        info["top_path"]      = top_path
                    yield Yield(info)
    return run_gen_step_iter(gen_step, async_)


@overload
def iterdir(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    show_dir: Literal[0, 1] = 1, 
    fc_mix: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iterdir(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    show_dir: Literal[0, 1] = 1, 
    fc_mix: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iterdir(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    show_dir: Literal[0, 1] = 1, 
    fc_mix: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代目录，获取文件信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小，如果 <= 0，则和 `page_size` 相同
    :param order: 排序

        - "file_name": 文件名
        - "file_size": 文件大小
        - "file_type": 文件种类
        - "user_utime": 修改时间
        - "user_ptime": 创建时间
        - "user_otime": 上一次打开时间

    :param asc: 升序排列。0: 否，1: 是
    :param show_dir: 展示文件夹。0: 否，1: 是
    :param fc_mix: 文件夹置顶。0: 文件夹在文件之前，1: 文件和文件夹混合并按指定排序
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param ensure_file: 是否确保为文件

        - True: 必须是文件
        - False: 必须是目录
        - None: 可以是目录或文件

    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1）
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    return _iter_fs_files(
        client, 
        payload={
            "asc": asc, "cid": to_id(cid), "cur": 1, "count_folders": 1, 
            "fc_mix": fc_mix, "show_dir": show_dir, "o": order, "offset": 0, 
        }, 
        page_size=page_size, 
        first_page_size=first_page_size, 
        normalize_attr=normalize_attr, 
        id_to_dirnode=id_to_dirnode, 
        raise_for_changed_count=raise_for_changed_count, 
        ensure_file=ensure_file, 
        app=app, 
        cooldown=cooldown, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def iter_stared_dirs(
    client: str | PathLike | P115Client | P115OpenClient, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_stared_dirs(
    client: str | PathLike | P115Client | P115OpenClient, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_stared_dirs(
    client: str | PathLike | P115Client | P115OpenClient, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历以迭代获得所有被打上星标的目录信息

    :param client: 115 客户端或 cookies
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小，如果 <= 0，则和 `page_size` 相同
    :param order: 排序

        - "file_name": 文件名
        - "file_size": 文件大小
        - "file_type": 文件种类
        - "user_utime": 修改时间
        - "user_ptime": 创建时间
        - "user_otime": 上一次打开时间

    :param asc: 升序排列。0: 否，1: 是
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1）
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，被打上星标的目录信息
    """
    return _iter_fs_files(
        client, 
        payload={
            "asc": asc, "cid": 0, "count_folders": 1, "cur": 0, "fc_mix": 0, 
            "o": order, "offset": 0, "show_dir": 1, "star": 1, 
        }, 
        page_size=page_size, 
        first_page_size=first_page_size, 
        normalize_attr=normalize_attr, 
        id_to_dirnode=id_to_dirnode, 
        raise_for_changed_count=raise_for_changed_count, 
        ensure_file=False, 
        app=app, 
        cooldown=cooldown, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def iter_dirs(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_dirs(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_dirs(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取目录信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用指定 app（设备）的接口
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅目录）文件信息
    """
    from .download import iter_download_nodes
    return iter_download_nodes(
        client, 
        cid, 
        files=False, 
        id_to_dirnode=id_to_dirnode, 
        app=app, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def iter_dirs_with_path(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_dirs_with_path(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_dirs_with_path(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取目录信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用指定 app（设备）的接口
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅目录）文件信息
    """
    from .download import iter_download_nodes
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    def gen_step():
        attrs = yield collect(iter_download_nodes(
            client, 
            cid, 
            files=False, 
            id_to_dirnode=id_to_dirnode, 
            app=app, 
            max_workers=max_workers, 
            async_=async_, # type: ignore
            **request_kwargs, 
        ))
        add_top = _make_top_adder(to_id(cid), id_to_dirnode, escape)
        yield YieldFrom(do_map(add_top, ensure_attr_path(
            client, 
            attrs, 
            with_ancestors=with_ancestors, 
            escape=escape, 
            id_to_dirnode=id_to_dirnode, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )))
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
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
    :param cur: 仅当前目录。0: 否（将遍历子目录树上所有叶子节点），1: 是
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1）
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（所有文件）文件信息
    """
    suffix = suffix.strip(".")
    if not (type or suffix):
        raise ValueError("please set the non-zero value of suffix or type")
    payload: dict = {
        "asc": asc, "cid": to_id(cid), "count_folders": 0, "cur": cur, 
        "o": order, "offset": 0, "show_dir": 0, 
    }
    if suffix:
        payload["suffix"] = suffix
    elif type != 99:
        payload["type"] = type
    return _iter_fs_files(
        client, 
        payload=payload, 
        page_size=page_size, 
        first_page_size=first_page_size, 
        normalize_attr=normalize_attr, 
        id_to_dirnode=id_to_dirnode, 
        raise_for_changed_count=raise_for_changed_count, 
        ensure_file=True, 
        app=app, 
        cooldown=cooldown, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )


@overload
def iter_files_with_path(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = 0.5, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files_with_path(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = 0.5, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_with_path(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = 0.5, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息（包含 "path"，可选 "ancestors"）

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param page_size: 分页大小
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
    :param cur: 仅当前目录。0: 否（将遍历子目录树上所有叶子节点），1: 是
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param path_already: 如果为 True，则说明 id_to_dirnode 中已经具备构建路径所需要的目录节点，所以不会再去拉取目录节点的信息
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1）
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（所有文件）文件信息
    """
    suffix = suffix.strip(".")
    if not (type or suffix):
        raise ValueError("please set the non-zero value of suffix or type")
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
        path_already = False
    if with_ancestors:
        id_to_ancestors: dict[int, list[dict]] = {}
        def get_ancestors(id: int, attr: dict | tuple[str, int] | DirNode, /) -> list[dict]:
            if isinstance(attr, (DirNode, tuple)):
                name, pid = attr
            else:
                pid = attr["parent_id"]
                name = attr["name"]
            if pid == 0:
                ancestors = [{"id": 0, "parent_id": 0, "name": ""}]
            else:
                if pid not in id_to_ancestors:
                    id_to_ancestors[pid] = get_ancestors(pid, id_to_dirnode[pid])
                ancestors = [*id_to_ancestors[pid]]
            ancestors.append({"id": id, "parent_id": pid, "name": name})
            return ancestors
    id_to_path: dict[int, str] = {}
    def get_path(attr: dict | tuple[str, int] | DirNode, /) -> str:
        if isinstance(attr, (DirNode, tuple)):
            name, pid = attr
        else:
            pid = attr["parent_id"]
            name = attr["name"]
        if escape is not None:
            name = escape(name)
        if pid == 0:
            dirname = "/"
        elif pid in id_to_path:
            dirname = id_to_path[pid]
        else:
            dirname = id_to_path[pid] = get_path(id_to_dirnode[pid]) + "/"
        return dirname + name
    top_prefix_len = 0
    def update_path(attr: dict, /) -> dict:
        nonlocal top_prefix_len
        try:
            if with_ancestors:
                attr["ancestors"] = get_ancestors(attr["id"], attr)
            attr["path"] = path = get_path(attr)
            if not top_prefix_len:
                top_path = attr["top_path"]
                top_prefix_len = 1 if top_path == "/" else len(top_path) + 1
            attr["relpath"] = path[top_prefix_len:]
        except KeyError:
            pass
        return attr
    cid = to_id(cid)
    if path_already:
        return do_map(update_path, iter_files(
            client, 
            cid, 
            page_size=page_size, 
            suffix=suffix, 
            type=type, 
            order=order, 
            asc=asc, 
            cur=cur, 
            normalize_attr=normalize_attr, 
            id_to_dirnode=id_to_dirnode, 
            raise_for_changed_count=raise_for_changed_count, 
            max_workers=max_workers, 
            app=app, 
            cooldown=cooldown, 
            escape=escape, 
            async_=async_, # type: ignore
            **request_kwargs, 
        ))
    else:
        from .download import iter_download_nodes
        def set_path_already(*_):
            nonlocal path_already
            path_already = True
        def fetch_dirs(id: int | str, /):
            if id:
                return through(iter_download_nodes(
                    client, 
                    client.to_pickcode(id), 
                    files=False, 
                    id_to_dirnode=id_to_dirnode, 
                    max_workers=None, 
                    async_=async_, 
                    **request_kwargs, 
                ))
            else:
                return foreach(
                    lambda a: fetch_dirs(a["pickcode"]), 
                    iterdir(
                        client, 
                        ensure_file=False, 
                        id_to_dirnode=id_to_dirnode, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    ), 
                )
        def gen_step():
            cache: list[dict] = []
            add_to_cache = cache.append
            if not path_already:
                if async_:
                    task: Any = create_task(fetch_dirs(cid))
                else:
                    task = run_as_thread(fetch_dirs, cid)
                task.add_done_callback(set_path_already)
            with with_iter_next(iter_files(
                client, 
                cid, 
                page_size=page_size, 
                suffix=suffix, 
                type=type, 
                order=order, 
                asc=asc, 
                cur=cur, 
                normalize_attr=normalize_attr, 
                id_to_dirnode=id_to_dirnode, 
                raise_for_changed_count=raise_for_changed_count, 
                max_workers=max_workers, 
                app=app, 
                cooldown=cooldown, 
                async_=async_, # type: ignore
                **request_kwargs, 
            )) as get_next:
                while True:
                    attr = yield get_next()
                    if path_already:
                        if cache:
                            yield YieldFrom(map(update_path, cache))
                            cache.clear()
                        yield Yield(update_path(attr))
                    else:
                        add_to_cache(attr)
            if cache:
                if async_:
                    yield task
                else:
                    task.result()
                yield YieldFrom(map(update_path, cache))
        return run_gen_step_iter(gen_step, async_)


@overload
def iter_files_with_path_skim(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files_with_path_skim(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_with_path_skim(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息（包含 "path"，可选 "ancestors"）

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param path_already: 如果为 True，则说明 id_to_dirnode 中已经具备构建路径所需要的目录节点，所以不会再去拉取目录节点的信息
    :param app: 使用指定 app（设备）的接口
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（所有文件）文件信息
    """
    from .download import iter_download_nodes
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
        path_already = False
    if with_ancestors:
        id_to_ancestors: dict[int, list[dict]] = {}
        def get_ancestors(id: int, attr: dict | tuple[str, int] | DirNode, /) -> list[dict]:
            if isinstance(attr, (DirNode, tuple)):
                name, pid = attr
            else:
                pid = attr["parent_id"]
                name = attr["name"]
            if pid == 0:
                ancestors = [{"id": 0, "parent_id": 0, "name": ""}]
            else:
                if pid not in id_to_ancestors:
                    id_to_ancestors[pid] = get_ancestors(pid, id_to_dirnode[pid])
                ancestors = [*id_to_ancestors[pid]]
            ancestors.append({"id": id, "parent_id": pid, "name": name})
            return ancestors
    id_to_path: dict[int, str] = {}
    def get_path(attr: dict | tuple[str, int] | DirNode, /) -> str:
        if isinstance(attr, (DirNode, tuple)):
            name, pid = attr
        else:
            pid = attr["parent_id"]
            name = attr["name"]
        if escape is not None:
            name = escape(name)
        if pid == 0:
            dirname = "/"
        elif pid in id_to_path:
            dirname = id_to_path[pid]
        else:
            dirname = id_to_path[pid] = get_path(id_to_dirnode[pid]) + "/"
        return dirname + name
    top_id: int
    top_ancestors: list[dict]
    top_path: str
    top_prefix_len: int
    def update_path(attr: dict, /) -> dict:
        attr["top_id"]        = top_id
        attr["top_ancestors"] = top_ancestors
        attr["top_path"]      = top_path
        try:
            if with_ancestors:
                attr["ancestors"] = get_ancestors(attr["id"], attr)
            attr["path"] = path = get_path(attr)
            attr["relpath"] = path[top_prefix_len:]
        except KeyError:
            pass
        return attr
    cid = to_id(cid)
    if path_already:
        top_ancestors = []
        add_ancestor = top_ancestors.append
        tid = top_id
        while tid and tid in id_to_dirnode:
            name, pid = id_to_dirnode[tid]
            add_ancestor({"id": tid, "parent_id": pid, "name": name})
            tid = pid
        if not tid:
            add_ancestor({"id": 0, "parent_id": 0, "name": ""})
        top_ancestors.reverse()
        if escape is None:
            top_path = "/".join(a["name"] for a in top_ancestors)
        else:
            top_path = "/".join(escape(a["name"]) for a in top_ancestors)
        top_prefix_len = 1 if top_path == "/" else len(top_path) + 1
        return do_map(update_path, iter_download_nodes(
            client, 
            cid, 
            files=True, 
            ensure_name=True, 
            max_workers=max_workers, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        ))
    else:
        top_id = cid
        @as_gen_step
        def update_top(cid: int | str, /):
            nonlocal top_ancestors, top_path, top_prefix_len
            if cid:
                do_next: Callable = anext if async_ else next
                attr = yield do_next(_iter_fs_files(
                    client, 
                    to_id(cid), 
                    page_size=1, 
                    id_to_dirnode=id_to_dirnode, 
                    normalize_attr=None, 
                    escape=escape, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                ), None)
                if not attr:
                    return
                top_ancestors = attr["top_ancestors"]
                top_path = attr["top_path"]
                top_prefix_len = 1 if top_path == "/" else len(top_path) + 1
            else:
                top_ancestors = [{"id": 0, "parent_id": 0, "name": ""}]
                top_path = "/"
                top_prefix_len = 1
        def fetch_dirs(id: int | str, /):
            if id:
                return through(iter_download_nodes(
                    client, 
                    client.to_pickcode(id), 
                    files=False, 
                    id_to_dirnode=id_to_dirnode, 
                    max_workers=max_workers, 
                    async_=async_, 
                    **request_kwargs, 
                ))
            else:
                return foreach(
                    lambda a: fetch_dirs(a["pickcode"]), 
                    iterdir(
                        client, 
                        ensure_file=False, 
                        id_to_dirnode=id_to_dirnode, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    ), 
                )
        def set_path_already(*_):
            nonlocal path_already
            path_already = True
        def gen_step():
            cache: list[dict] = []
            add_to_cache = cache.append
            if not path_already:
                if async_:
                    task: Any = async_gather(update_top(cid), fetch_dirs(cid))
                    task.add_done_callback(set_path_already)
                else:
                    task0 = run_as_thread(update_top, cid)
                    task = run_as_thread(fetch_dirs, cid)
                    def done_callback(*_):
                        task0.result()
                        set_path_already()
                    task.add_done_callback(done_callback)
            with with_iter_next(iter_download_nodes(
                client, 
                cid, 
                files=True, 
                ensure_name=True, 
                max_workers=max_workers, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                while True:
                    attr = yield get_next()
                    if path_already:
                        if cache:
                            yield YieldFrom(map(update_path, cache))
                            cache.clear()
                        yield Yield(update_path(attr))
                    else:
                        add_to_cache(attr)
            if cache:
                if async_:
                    yield task
                else:
                    task.result()
                yield YieldFrom(map(update_path, cache))
        return run_gen_step_iter(gen_step, async_)


@overload
def iter_files_shortcut(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files_shortcut(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_shortcut(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取（所有文件而非目录）文件信息（整合了多个函数的入口）

    .. node::
        `is_skim` 和 `with_path` 的不同取值组合，会决定采用不同的函数:

        1. `iter_download_nodes`: is_skim=True and with_path=False
        2. `iter_files_with_path_skim`: is_skim=True and with_path=True
        3. `iter_files`: is_skim=False and with_path=False
        4. `iter_files_with_path`: is_skim=False and with_path=True

    :param client: 115 客户端或 cookies
    :param cid: 待被遍历的目录 id 或 pickcode
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param is_skim: 是否拉取简要信息
    :param with_path: 是否需要 "path" 和 "ancestors" 字段
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件信息
    """
    if with_path:
        request_kwargs.setdefault("with_ancestors", True)
        if is_skim:
            method: Callable = iter_files_with_path_skim
        else:
            method = iter_files_with_path
    elif is_skim:
        request_kwargs.update(files=True, ensure_name=True)
        from .download import iter_download_nodes as method
    else:
        request_kwargs.setdefault("cooldown", 0.5)
        method = iter_files
    return method(
        client, 
        cid, 
        id_to_dirnode=id_to_dirnode, 
        max_workers=max_workers, 
        app=app, 
        async_=async_, 
        **request_kwargs, 
    )


# TODO: 属于是 iter_files_shortcut 的姊妹版，支持差不多的参数
# TODO: 可以在拉取的同时，检测其它待拉取目录大小，但需要设定冷却时间（例如一秒最多 10 次查询）
@overload
def iter_files_frament(
    client: str | PathLike | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    auto_splitting_tasks: bool = True, 
    auto_splitting_threshold: int = 300_000, 
    auto_splitting_statistics_timeout: None | int | float = 5, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files_frament(
    client: str | PathLike | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    auto_splitting_tasks: bool = True, 
    auto_splitting_threshold: int = 300_000, 
    auto_splitting_statistics_timeout: None | int | float = 5, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_frament(
    client: str | PathLike | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    auto_splitting_tasks: bool = True, 
    auto_splitting_threshold: int = 300_000, 
    auto_splitting_statistics_timeout: None | int | float = 5, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息（会根据统计信息，分解任务）

    :param client: 115 客户端或 cookies
    :param cid: 目录 id
    :param page_size: 分页大小
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

    :param auto_splitting_tasks: 是否根据统计信息自动拆分任务
    :param auto_splitting_threshold: 如果 `auto_splitting_tasks` 为 True，且目录内的文件数大于 `auto_splitting_threshold`，则分拆此任务到它的各个直接子目录，否则批量拉取
    :param auto_splitting_statistics_timeout: 如果执行统计超过此时间，则立即终止，并认为文件是无限多
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param with_path: 文件信息中是否要包含 "path"
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1）
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（所有文件）文件信息
    """
    suffix = suffix.strip(".")
    if not (type or suffix):
        raise ValueError("please set the non-zero value of suffix or type")
    if suffix:
        suffix = "." + suffix.lower()
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ... and (with_ancestors or with_path):
        id_to_dirnode = {}
    auto_splitting_tasks = auto_splitting_tasks and auto_splitting_threshold > 0
    from .attr import get_file_count, type_of_attr
    def gen_step():
        nonlocal cid
        if auto_splitting_tasks:
            get_count = get_file_count(
                client, 
                id_to_dirnode=id_to_dirnode, 
                **{**request_kwargs, "timeout": auto_splitting_statistics_timeout}
            )
        gen = bfs_gen(cid)
        send = gen.send
        for cid in gen:
            if auto_splitting_tasks:
                try:
                    file_count: float = yield get_count(cid, async_=async_)
                except Exception as e:
                    if not is_timeouterror(e):
                        raise
                    file_count = inf
            else:
                file_count = 0
            if file_count <= auto_splitting_threshold:
                if with_ancestors or with_path:
                    yield YieldFrom(iter_files_with_path(
                        client, 
                        cid, 
                        page_size=page_size, 
                        suffix=suffix, 
                        type=type, 
                        with_ancestors=with_ancestors, 
                        with_path=with_path, 
                        escape=escape, 
                        normalize_attr=normalize_attr, 
                        id_to_dirnode=id_to_dirnode, 
                        raise_for_changed_count=raise_for_changed_count, 
                        app=app, 
                        cooldown=cooldown, 
                        max_workers=max_workers, 
                        async_=async_, # type: ignore
                        **request_kwargs, 
                    ))
                else:
                    yield YieldFrom(iter_files(
                        client, 
                        cid, 
                        page_size=page_size, 
                        suffix=suffix, 
                        type=type, 
                        normalize_attr=normalize_attr, 
                        id_to_dirnode=id_to_dirnode, 
                        raise_for_changed_count=raise_for_changed_count, 
                        app=app, 
                        cooldown=cooldown, 
                        max_workers=max_workers, 
                        async_=async_, # type: ignore
                        **request_kwargs, 
                    ))
            else:
                with with_iter_next(iterdir(
                    client, 
                    cid, 
                    page_size=page_size, 
                    with_ancestors=with_ancestors, 
                    with_path=with_path, 
                    escape=escape, 
                    normalize_attr=normalize_attr, 
                    id_to_dirnode=id_to_dirnode, 
                    app=app, 
                    raise_for_changed_count=raise_for_changed_count, 
                    async_=async_, 
                    **request_kwargs, 
                )) as get_next:
                    attr = yield get_next()
                    if attr.get("is_dir"):
                        send(attr["id"])
                    elif (
                        suffix and 
                        suffix == splitext(attr["name"])[1].lower() or 
                        type > 7 or 
                        type_of_attr(attr) == type
                    ):
                        yield Yield(attr)
    return run_gen_step_iter(gen_step, async_)


@overload
def traverse_tree(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def traverse_tree(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def traverse_tree(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件或目录节点的信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用指定 app（设备）的接口
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件或目录节点的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
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
            yield YieldFrom(do_map(fulfill_dir_node, iter_download_nodes(
                client, 
                cid, 
                files=False, 
                id_to_dirnode=id_to_dirnode, 
                app=app, 
                max_workers=max_workers, 
                async_=async_, 
                **request_kwargs, 
            )))
        if isinstance(task, Task):
            yield task
        else:
            task.result()
        yield YieldFrom(cache)
        yield YieldFrom(files)
    return run_gen_step_iter(gen_step, async_)


@overload
def traverse_tree_with_path(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def traverse_tree_with_path(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def traverse_tree_with_path(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件或目录节点的信息（包含 "path"，可选 "ancestors"）

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用指定 app（设备）的接口
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件或目录节点的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
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
            yield YieldFrom(do_map(fulfill_dir_node, iter_dirs_with_path(
                client, 
                cid, 
                with_ancestors=with_ancestors, 
                escape=escape, 
                id_to_dirnode=id_to_dirnode, 
                app=app, 
                max_workers=max_workers, 
                async_=async_, 
                **request_kwargs, 
            )))
        if isinstance(task, Task):
            yield task
        else:
            task.result()
        add_top = _make_top_adder(to_id(cid), id_to_dirnode, escape)
        yield YieldFrom(do_map(add_top, ensure_attr_path(
            client, 
            chain(cache, files), # type: ignore
            with_ancestors=with_ancestors, 
            escape=escape, 
            id_to_dirnode=id_to_dirnode, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )))
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_nodes(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    ignore_deleted: bool = False, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    ignore_deleted: bool = False, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    ignore_deleted: bool = False, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    .. caution::
        风控比较严重，请谨慎使用

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param ignore_deleted: 忽略已经被删除的
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    request_kwargs.setdefault(
        "base_url", 
        cycle(("http://webapi.115.com", "https://webapi.115.com")).__next__, 
    )
    def project(resp: dict, /) -> None | dict:
        if resp.get("code") == 20018:
            return None
        check_response(resp)
        info = resp["data"][0]
        was_deleted = int(info.get("aid") or info.get("area_id") or 1) != 1
        if ignore_deleted and was_deleted:
            return None
        if id_to_dirnode is not ... and not was_deleted:
            attr = overview_attr(info)
            if attr.is_dir:
                id_to_dirnode[attr.id] = DirNode(attr.name, attr.parent_id)
        if normalize_attr is None:
            return info
        return normalize_attr(info)
    return do_filter(None, do_map(
        project, 
        conmap(
            client.fs_file, 
            map(to_id, ids), 
            max_workers=max_workers, 
            kwargs=request_kwargs, 
            async_=async_, 
        ), 
    ))


@overload
def iter_nodes_skim(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    batch_size: int = 50_000, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_skim(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    batch_size: int = 50_000, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_skim(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    batch_size: int = 50_000, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组节点的简略信息

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，获取节点的简略信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    def get_nodes(resp: dict, /) -> Sequence[dict]:
        if resp.get("error") == "文件不存在":
            return ()
        check_response(resp)
        nodes = resp["data"]
        for node in nodes:
            node["file_id"] = int(node["file_id"])
            node["file_name"] = unescape_115_charref(node["file_name"])
            node["file_size"] = int(node["file_size"])
        return nodes
    return chain_from_iterable(do_map(
        get_nodes, 
        conmap(
            partial(client.fs_file_skim, method="POST", async_=async_, **request_kwargs), 
            batched(map(to_id, ids), batch_size), 
            max_workers=max_workers, 
            async_=async_, # type: ignore 
        ), 
    ))


@overload
def iter_nodes_by_pickcode(
    client: str | PathLike | P115Client, 
    pickcodes: Iterable[str | int], 
    ignore_deleted: None | bool = False, 
    normalize_attr: None | Callable[[dict], dict] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_by_pickcode(
    client: str | PathLike | P115Client, 
    pickcodes: Iterable[str | int], 
    ignore_deleted: None | bool = False, 
    normalize_attr: None | Callable[[dict], dict] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_by_pickcode(
    client: str | PathLike | P115Client, 
    pickcodes: Iterable[str | int], 
    ignore_deleted: None | bool = False, 
    normalize_attr: None | Callable[[dict], dict] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    .. caution::
        并发数较多时，容易发生 HTTP 链接中断现象

    :param client: 115 客户端或 cookies
    :param pickcodes: 一组文件或目录的 pickcode 或 id
    :param ignore_deleted: 是否忽略已经被删除的
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    methods: list[Callable] = []
    if ignore_deleted or ignore_deleted is None:
        methods += (
            partial(client.fs_document, base_url="http://webapi.115.com"), 
            partial(client.fs_document_app, base_url="http://proapi.115.com"), 
            partial(client.fs_document_app, base_url="https://proapi.115.com"), 
        )
    if not ignore_deleted:
       methods += (
            partial(client.fs_supervision, base_url="http://webapi.115.com"), 
            partial(client.fs_supervision_app, base_url="http://proapi.115.com"), 
            partial(client.fs_supervision_app, base_url="https://proapi.115.com"), 
        )
    def get_response(pickcode: str, /, get_method=cycle(methods).__next__):
        return get_method()(
            pickcode, 
            async_=async_, 
            **request_kwargs, 
        )
    def project(resp: dict, /) -> None | dict:
        was_deleted = resp.get("code") == 31001 or resp.get("msg_code") == 70005
        info = resp.get("data")
        if not info or not info.get("file_id") or ignore_deleted and was_deleted:
            return None
        if not info and not resp["state"] and not was_deleted:
            check_response(resp)
        if id_to_dirnode is not ... and not info["file_sha1"] and not was_deleted:
            id_to_dirnode[int(info["file_id"])] = DirNode(info["file_name"], int(info["parent_id"]))
        if normalize_attr is None:
            return info
        return normalize_attr(info)
    return do_filter(None, do_map(
        project, 
        conmap(
            get_response, 
            map(client.to_pickcode, pickcodes), 
            max_workers=max_workers, 
            kwargs=request_kwargs, 
            async_=async_, 
        )))


@overload
def iter_nodes_using_update(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    ignore_deleted: None | bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_using_update(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    ignore_deleted: None | bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_using_update(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    ignore_deleted: None | bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    .. caution::
        风控比较严重，且速度较慢，请斟酌使用

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param ignore_deleted: 是否忽略已经被删除的
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    request_kwargs.setdefault(
        "base_url", 
        cycle(("http://proapi.115.com", "https://proapi.115.com")).__next__, 
    )
    def project(resp: dict, /) -> None | dict:
        if error := resp.get("error"):
            if error == "文件不存在/数据库错误了" or ignore_deleted and "不存在或已删除" in error:
                return None
            check_response(resp)
        info = resp["data"]
        info["id"] = info["file_id"] = int(info["file_id"])
        info["size"] = info["file_size"] = int(info["file_size"])
        info["parent_id"] = int(info["parent_id"])
        info["name"] = info["file_name"]
        info["is_dir"] = not info["sha1"]
        if id_to_dirnode is not ... and info["is_dir"]:
            id_to_dirnode[info["id"]] = DirNode(info["name"], info["parent_id"])
        return info
    return do_filter(None, do_map(
        project, 
        conmap(
            client.fs_files_update_app, 
            ({"file_id": to_id(fid), "show_play_long": 1} for fid in ids), 
            max_workers=max_workers, 
            kwargs=request_kwargs, 
            async_=async_, 
        )
    ))


@overload
def iter_nodes_using_info(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: Iterable[int | str], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    app: str = "", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_using_info(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: Iterable[int | str], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    app: str = "", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_using_info(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: Iterable[int | str], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 1, 
    app: str = "", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    .. caution::
        风控比较严重，且速度较慢，请斟酌使用

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    get_method: Callable[[], Callable]
    if not isinstance(client, P115Client) or app == "open":
        app = "open"
        fs_info = client.fs_info_open
        get_method = lambda: fs_info
    elif app == "":
        get_method = cycle((
            partial(client.fs_category_get, base_url="http://webapi.115.com"), 
            partial(client.fs_category_get_app, base_url="http://proapi.115.com"), 
            partial(client.fs_category_get, base_url="https://webapi.115.com"), 
            partial(client.fs_category_get_app, base_url="https://proapi.115.com"), 
        )).__next__
    elif app in ("web", "desktop", "harmony"):
        get_method = cycle((
            partial(client.fs_category_get, base_url="http://webapi.115.com"), 
            partial(client.fs_category_get, base_url="https://webapi.115.com"), 
        )).__next__
    else:
        get_method = cycle((
            partial(client.fs_category_get_app, base_url="http://proapi.115.com", app=app), 
            partial(client.fs_category_get_app, base_url="https://proapi.115.com", app=app), 
        )).__next__
    def parse(_, content: bytes):
        resp = loads(content)
        if app == "open":
            check_response(resp)
            resp = resp["data"]
        if resp:
            if "file_id" in resp:
                resp["id"] = int(resp["file_id"])
            else:
                resp["id"] = pickcode_to_id(resp["pick_code"])
            resp["parent_id"] = int(resp["paths"][-1]["file_id"])
            resp["name"] = resp["file_name"]
            resp["is_dir"] = not resp["sha1"]
        return resp
    def call(id: int, /):
        return get_method()(id, parse=parse, async_=async_, **request_kwargs)
    def project(resp: dict, /) -> None | dict:
        if not resp:
            return None
        check_response(resp)
        if id_to_dirnode is not ...:
            update_resp_ancestors(resp, id_to_dirnode)
        return resp
    return do_filter(None, do_map(
        project, 
        conmap(
            call, 
            map(to_id, ids), 
            max_workers=max_workers, 
            async_=async_, 
        )
    ))


# TODO: 是否能批量推送 "browse_audio" 或 "browse_video" 事件？
@overload
def iter_nodes_using_event(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    type: Literal["doc", "img"] = "img", 
    normalize_attr: None | bool | Callable[[dict], dict] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    cooldown: float = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_using_event(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    type: Literal["doc", "img"] = "img", 
    normalize_attr: None | bool | Callable[[dict], dict] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    cooldown: float = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_using_event(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    type: Literal["doc", "img"] = "img", 
    normalize_attr: None | bool | Callable[[dict], dict] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    cooldown: float = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """通过先发送事件，然后收集这个事件，来获取一组 id 的信息

    .. note::
        如果未收集到事件，则说明文件 id 不存在或者已删除，你也可以因此找出所有的无效 id

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param type: 事件类型

        - "doc": 推送 "browse_document" 事件
        - "img": 推送 "browse_image" 事件

    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，大于 0 时，两次拉取操作事件的接口调用之间至少间隔这么多秒
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生简略的信息

        .. code:: python

            {
                "id": int, 
                "parent_id": int, 
                "name": str, 
                "is_dir": 0 | 1, 
                "pickcode": str, 
                "sha1": str, 
                "size": int, 
                "star": 0 | 1, 
                "labels": list[dict], 
                "ftype": int, 
                "type": int, 
            }
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    if type == "doc":
        event_name = "browse_document"
    else:
        event_name = "browse_image"
    from .attr import type_of_attr
    def gen_step():
        nonlocal ids
        ts = int(time())
        ids = set(map(to_id, ids))
        yield life_show(client, async_=async_, **request_kwargs)
        yield post_event(
            client, 
            ids, 
            type=type, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )
        if app in ("", "web", "desktop", "harmony"):
            get_base_url = cycle(("http://webapi.115.com", "https://webapi.115.com")).__next__
        else:
            get_base_url = cycle(("http://proapi.115.com", "https://proapi.115.com")).__next__
        request_kwargs.setdefault("base_url", get_base_url)
        discard = ids.discard
        with with_iter_next(iter_life_behavior_once(
            client, 
            from_time=ts, 
            type=event_name, 
            app=app, 
            cooldown=cooldown, 
            async_=async_, 
            **request_kwargs, 
        )) as get_next:
            while True:
                event: dict = yield get_next()
                fid = int(event["file_id"])
                pid = int(event["parent_id"])
                name = event["file_name"]
                is_dir = not event["file_category"]
                if is_dir and id_to_dirnode is not ...:
                    id_to_dirnode[fid] = DirNode(name, pid)
                if fid in ids:
                    if not normalize_attr:
                        yield Yield(event)
                    elif normalize_attr is True:
                        attr = {
                            "id": fid, 
                            "parent_id": pid, 
                            "name": name, 
                            "is_dir": is_dir, 
                            "pickcode": event["pick_code"], 
                            "sha1": event["sha1"], 
                            "size": event["file_size"], 
                            "star": event["is_mark"], 
                            "labels": event["fl"], 
                            "ftype": event["file_type"], 
                        }
                        if attr["is_dir"]:
                            attr["type"] = 0
                        elif event.get("isv"):
                            attr["type"] = 4
                        elif event.get("play_long"):
                            attr["type"] = 3
                        else:
                            attr["type"] = type_of_attr(attr)
                        yield Yield(attr)
                    else:
                        yield Yield(normalize_attr(event))
                    discard(fid)
                    if not ids:
                        break
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_dir_nodes_using_star(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    already_stared: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_dir_nodes_using_star(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    already_stared: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_dir_nodes_using_star(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 1, 
    already_stared: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """通过先打星标来，然后用文件列表接口获取一组 id 的信息（仅支持目录）

    .. caution::
        在打星标后，随即还会把备注清空（以改变目录的更新时间），若要保留备注，则请不要使用此方法

    .. caution::
        如果有任一 id 已经被删除，则打星标时会报错

    :param client: 115 客户端或 cookies
    :param ids: 一组目录的 id 或 pickcode（如果包括文件，则会被忽略）
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param already_stared: 说明所有 id 都已经打过星标，不用再次打星标
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    def gen_step():
        nonlocal ids
        ts = int(time())
        ids = set(map(to_id, ids))
        if not already_stared:
            yield update_star(client, ids, app=app, async_=async_, **request_kwargs)
        yield update_desc(client, ids, async_=async_, **request_kwargs)
        discard = ids.discard
        with with_iter_next(iter_stared_dirs(
            client, 
            order="user_utime", 
            asc=0, 
            first_page_size=len(ids), 
            id_to_dirnode=id_to_dirnode, 
            normalize_attr=normalize_attr, 
            raise_for_changed_count=raise_for_changed_count, 
            app=app, 
            cooldown=cooldown, 
            max_workers=max_workers, 
            async_=async_, # type: ignore
            **request_kwargs, 
        )) as get_next:
            while True:
                info: dict = yield get_next()
                if normalize_attr is None:
                    attr: Any = overview_attr(info)
                else:
                    attr = info
                if not (attr["mtime"] >= ts and attr["is_dir"]):
                    break
                cid = attr["id"]
                if cid in ids:
                    yield Yield(info)
                    discard(cid)
                    if not ids:
                        break
    return run_gen_step_iter(gen_step, async_)


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
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生 id 和 最近 3 级目录名的元组的 2 元组
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
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
            ret = yield to_list(ret)
        resp2, resp3 = cast(Iterable, ret)
        l2 = [d["file_name"] for d in resp2["data"]]
        l3 = (d["file_name"] for d in resp3["data"])
        return ((id, fix_overflow(t)) for id, t in zip(ids, zip(l3, l2, l1)))
    return chain_from_iterable(conmap(
        lambda ids: run_gen_step(get_parents(ids), async_), 
        chunked(do_filter(None, ids), 1150), 
        max_workers=max_workers, 
        async_=async_, # type: ignore
    ))


@overload
def iter_dupfiles[K](
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
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
def iter_dupfiles[K](
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[K, dict]]:
    ...
def iter_dupfiles[K](
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
    is_skim: bool = True, 
    with_path: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, dict]] | AsyncIterator[tuple[K, dict]]:
    """遍历以迭代获得所有重复文件

    :param client: 115 客户端或 cookies
    :param cid: 待被遍历的目录 id 或 pickcode
    :param key: 函数，用来给文件分组，当多个文件被分配到同一组时，它们相互之间是重复文件关系
    :param keep_first: 保留某个重复文件不输出，除此以外的重复文件都输出

        - 如果为 None，则输出所有重复文件（不作保留）
        - 如果是 Callable，则保留值最小的那个文件
        - 如果为 True，则保留最早入组的那个文件
        - 如果为 False，则保留最晚入组的那个文件

    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
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
def iter_media_files(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    page_size: int = 8192, 
    type: Literal[0, 1, 2, 3, 4, 5, 6, 7, 99] = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_media_files(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    page_size: int = 8192, 
    type: Literal[0, 1, 2, 3, 4, 5, 6, 7, 99] = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_media_files(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    page_size: int = 8192, 
    type: Literal[0, 1, 2, 3, 4, 5, 6, 7, 99] = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息（如果是图片，则包含图片的 CDN 链接）

    .. tip::
        这个函数的效果相当于 ``iter_files(client, cid, type=type, ...)`` 所获取的文件列表，只是返回信息有些不同，速度似乎还是 ``iter_files`` 更快

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param page_size: 分页大小
    :param type: 文件类型

        - 0: 相当于 2，即获取图片，但用一个单独的接口
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
    :param cur: 仅当前目录。0: 否（将遍历子目录树上所有叶子节点），1: 是
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的图片文件信息
    """
    def normalize(attr: dict, /):
        for key, val in attr.items():
            if key.endswith(("_id", "_type", "_size", "time")) or key.startswith("is_") or val in "01":
                attr[key] = int(val)
        attr["id"] = attr["file_id"]
        attr["name"] = attr["file_name"]
        return attr
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if page_size <= 0:
        page_size = 8192
    elif page_size < 16:
        page_size = 16
    cid = to_id(cid)
    payload = {"asc": asc, "cid": cid, "cur": cur, "limit": page_size, "o": order, "offset": 0}
    if type:
        fs_files = client.fs_files_media_app
        if type == 99:
            payload["type"] = -1
        else:
            payload["type"] = type
    else:
        fs_files = client.fs_files_image_app
    def gen_step():
        offset = 0
        count = 0
        while True:
            resp = yield fs_files(payload, async_=async_, **request_kwargs)
            check_response(resp)
            if int(resp["cid"]) != cid:
                raise FileNotFoundError(ENOENT, cid)
            if count == 0:
                count = int(resp.get("count") or 0)
            elif count != int(resp.get("count") or 0):
                message = f"cid={cid} detected count changes during traversing: {count} => {resp['count']}"
                if raise_for_changed_count:
                    raise P115OSError(EIO, message)
                else:
                    warn(message, category=P115Warning)
                count = int(resp.get("count") or 0)
            if offset != resp["offset"]:
                break
            yield YieldFrom(map(normalize, resp["data"]))
            offset += len(resp["data"])
            if offset >= count:
                break
            payload["offset"] = offset
    return run_gen_step_iter(gen_step, async_)


@overload
def search_iter(
    client: str | PathLike | P115Client | P115OpenClient, 
    search_value: str = ".", 
    cid: int | str = 0, 
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
    cid: int | str = 0, 
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
    cid: int | str = 0, 
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
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if not isinstance(client, P115Client) or app == "open":
        fs_search: Callable = client.fs_search_open
    elif app in ("", "web", "desktop", "harmony"):
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
            "cid": to_id(cid), 
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


@overload
def share_iterdir(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    cid: int = 0, 
    page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def share_iterdir(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    cid: int = 0, 
    page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def share_iterdir(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    cid: int = 0, 
    page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """对分享链接迭代目录，获取文件信息

    :param client: 115 客户端或 cookies
    :param share_code: 分享码或链接
    :param receive_code: 接收码
    :param cid: 目录的 id
    :param page_size: 分页大小
    :param order: 排序

        - "file_name": 文件名
        - "file_size": 文件大小
        - "file_type": 文件种类
        - "user_utime": 修改时间
        - "user_ptime": 创建时间
        - "user_otime": 上一次打开时间

    :param asc: 升序排列。0: 否，1: 是
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，被打上星标的目录信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if page_size <= 0:
        page_size = 10_000
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
            id_to_dirnode = ID_TO_DIRNODE_CACHE[(client.user_id, payload["share_code"])]
        offset = 0
        payload.update({
            "cid": cid, 
            "limit": page_size, 
            "offset": offset, 
            "asc": asc, 
            "o": order, 
        })
        count = 0
        while True:
            resp = yield client.share_snap(
                payload, 
                base_url=True, 
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
                        id_to_dirnode[oattr.id] = DirNode(oattr.name, oattr.parent_id)
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
    cid: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
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
    cid: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def share_iter_files(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    cid: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None,  
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """批量获取分享链接下的文件列表

    :param client: 115 客户端或 cookies
    :param share_code: 分享码或链接
    :param receive_code: 接收码
    :param cid: 顶层目录的 id，从此开始遍历
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
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
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
            id_to_dirnode = ID_TO_DIRNODE_CACHE[(client.user_id, payload["share_code"])]
        payload["cid"] = cid
        with with_iter_next(share_iterdir(
            client, 
            **payload, 
            id_to_dirnode=id_to_dirnode, 
            async_=async_, 
            **request_kwargs, 
        )) as get_next:
            while True:
                attr = yield get_next()
                if attr.get("is_dir"):
                    payload["cid"] = attr["id"]
                    resp = yield client.share_downlist(
                        payload, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    check_response(resp)
                    for info in resp["data"]["list"]:
                        fid, sha1 = info["fid"].split("_", 1)
                        yield Yield({
                            "id": int(fid), 
                            "sha1": sha1, 
                            "name": info["fn"], 
                            "size": int(info["si"]), 
                            "path": f"/{info['pt']}/{info['fn']}", 
                        })
                else:
                    yield Yield({k: attr[k] for k in ("id", "sha1", "name", "size", "path")})
    return run_gen_step(gen_step, async_)


@overload
def share_search_iter(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    search_value: str = ".", 
    cid: int = 0, 
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
    cid: int = 0, 
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
    cid: int = 0, 
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
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if offset < 0:
        offset = 0
    elif offset >= 10_000:
        offset = 9_999
    def gen_step():
        nonlocal page_size, offset
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

# TODO: share_* 方法支持参数 app
# TODO: 去除掉一些并不便利的办法，然后加上 traverse 和 walk 方法，通过递归拉取（支持深度和广度优先遍历）
