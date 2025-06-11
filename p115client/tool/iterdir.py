#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "ID_TO_DIRNODE_CACHE", "DirNode", "get_path_to_cid", "get_file_count", "get_ancestors", 
    "get_ancestors_to_cid", "get_id_to_path", "get_id_to_sha1", "get_id_to_pickcode", 
    "iter_nodes_skim", "iter_stared_dirs_raw", "iter_stared_dirs", "ensure_attr_path", 
    "ensure_attr_path_by_category_get", "iterdir_raw", "iterdir", "iterdir_limited", 
    "iter_files_raw", "iter_files", "traverse_files", "iter_dirs", "iter_dupfiles", 
    "iter_image_files", "share_iterdir", "share_iter_files", "share_get_id_to_path", 
    "iter_selected_nodes", "iter_selected_nodes_by_pickcode", "iter_selected_nodes_using_category_get", 
    "iter_selected_nodes_using_edit", "iter_selected_nodes_using_star_event", 
    "iter_selected_dirs_using_star", "iter_files_with_dirname", "iter_files_with_path", 
    "iter_files_with_path_by_export_dir", "iter_parents_3_level", "iter_dir_nodes", 
    "search_for_any_file", 
]
__doc__ = "这个模块提供了一些和目录信息罗列有关的函数"

from asyncio import create_task, sleep as async_sleep, Lock as AsyncLock
from collections import defaultdict
from collections.abc import (
    AsyncIterable, AsyncIterator, Callable, Collection, Coroutine, Iterable, Iterator, 
    Mapping, MutableMapping, Sequence, 
)
from dataclasses import dataclass
from errno import EIO, ENOENT, ENOTDIR
from functools import partial
from itertools import chain, cycle, islice
from math import inf
from operator import itemgetter
from string import digits, hexdigits
from threading import Lock
from time import sleep, time
from types import EllipsisType
from typing import cast, overload, Any, Final, Literal, NamedTuple
from warnings import warn
from weakref import WeakValueDictionary

from asynctools import async_chain, async_filter, async_map, to_list
from concurrenttools import run_as_thread, taskgroup_map, threadpool_map
from iterutils import (
    as_gen_step, bfs_gen, chunked, ensure_aiter, foreach, 
    flatten, iter_unique, run_gen_step, run_gen_step_iter, through, 
    async_through, with_iter_next, Yield, YieldFrom, 
)
from iter_collect import iter_keyed_dups, SupportsLT
from orjson import loads
from p115client import (
    check_response, normalize_attr, normalize_attr_simple, 
    P115Client, P115OSError, P115Warning, 
)
from p115client.type import P115ID
from posixpatht import joins, path_is_dir_form, splitext, splits

from .attr import type_of_attr
from .edit import update_desc, update_star
from .fs_files import is_timeouterror, iter_fs_files, iter_fs_files_threaded, iter_fs_files_asynchronized
from .life import iter_life_behavior_once, life_show
from .util import posix_escape_name, share_extract_payload, unescape_115_charref


class DirNode(NamedTuple):
    name: str
    parent_id: int


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


#: 用于缓存每个用户（根据用户 id 区别）的每个目录 id 到所对应的 (名称, 父id) 的元组的字典的字典
ID_TO_DIRNODE_CACHE: Final[defaultdict[int | tuple[int, str], dict[int, tuple[str, int] | DirNode]]] = defaultdict(dict)


def _overview_attr(info: Mapping, /) -> OverviewAttr:
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


@overload
def get_path_to_cid(
    client: str | P115Client, 
    cid: int = 0, 
    root_id: None | int = None, 
    escape: None | bool | Callable[[str], str] = True, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> str:
    ...
@overload
def get_path_to_cid(
    client: str | P115Client, 
    cid: int = 0, 
    root_id: None | int = None, 
    escape: None | bool | Callable[[str], str] = True, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, str]:
    ...
def get_path_to_cid(
    client: str | P115Client, 
    cid: int = 0, 
    root_id: None | int = None, 
    escape: None | bool | Callable[[str], str] = True, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> str | Coroutine[Any, Any, str]:
    """获取目录对应的路径（绝对路径或相对路径）

    :param client: 115 客户端或 cookies
    :param cid: 目录的 id
    :param root_id: 根目录 id，如果指定此参数且不为 None，则返回相对路径，否则返回绝对路径
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param refresh: 是否刷新。如果为 True，则会执行网络请求以查询；如果为 False，则直接从 `id_to_dirnode` 中获取
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用某个 app （设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 目录对应的绝对路径或相对路径
    """
    if isinstance(client, str):
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
    def gen_step():
        nonlocal cid
        parts: list[str] = []
        if cid and (refresh or cid not in id_to_dirnode):
            if not isinstance(client, P115Client) or app == "open":
                resp = yield client.fs_files_open(
                    {"cid": cid, "cur": 1, "nf": 1, "hide_data": 1}, 
                    async_=async_, 
                    **request_kwargs, 
                )
            elif app in ("", "web", "desktop", "harmony"):
                resp = yield client.fs_files_aps(
                    {"cid": cid, "limit": 1, "nf": 1, "star": 1}, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                resp = yield client.fs_files_app(
                    {"cid": cid, "cur": 1, "nf": 1, "hide_data": 1}, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )
            check_response(resp)
            if cid and int(resp["path"][-1]["cid"]) != cid:
                raise FileNotFoundError(ENOENT, cid)
            parts.extend(info["name"] for info in resp["path"][1:])
            for info in resp["path"][1:]:
                id_to_dirnode[int(info["cid"])] = DirNode(info["name"], int(info["pid"]))
        else:
            while cid and (not root_id or cid != root_id):
                name, cid = id_to_dirnode[cid]
                parts.append(name)
            parts.reverse()
        if root_id is not None and cid != root_id:
            return ""
        if escape is None:
            path = "/".join(parts)
        else:
            path = "/".join(map(escape, parts))
        if root_id is None or root_id:
            return "/" + path
        else:
            return path
    return run_gen_step(gen_step, may_call=False, async_=async_)


@overload
def get_file_count(
    client: str | P115Client, 
    cid: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    use_fs_files: bool = True, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def get_file_count(
    client: str | P115Client, 
    cid: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    use_fs_files: bool = True, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def get_file_count(
    client: str | P115Client, 
    cid: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    use_fs_files: bool = True, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """获取文件总数

    :param client: 115 客户端或 cookies
    :param cid: 目录 id
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用某个 app （设备）的接口
    :param use_fs_files: 使用 `client.fs_files`，否则使用 `client.fs_category_get`
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 目录内的文件总数（不包括目录）
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    def get_resp_of_fs_files(id: int, /):
        if not isinstance(client, P115Client) or app == "open":
            return client.fs_files_open(
                {"cid": id, "hide_data": 1, "show_dir": 0}, 
                async_=async_, 
                **request_kwargs, 
            )
        elif app in ("", "web", "desktop", "harmony"):
            return client.fs_files(
                {"cid": id, "limit": 1, "show_dir": 0}, 
                async_=async_, 
                **request_kwargs, 
            )
        elif app == "aps":
            return client.fs_files_aps(
                {"cid": id, "limit": 1, "show_dir": 0}, 
                async_=async_, 
                **request_kwargs, 
            )
        else:
            return client.fs_files_app(
                {"cid": id, "hide_data": 1, "show_dir": 0}, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
    def get_resp_of_category_get(id: int, /):
        if not isinstance(client, P115Client) or app == "open":
            return client.fs_info_open(
                id, 
                async_=async_, 
                **request_kwargs, 
            )
        elif app in ("", "web", "desktop", "harmony", "aps"):
            return client.fs_category_get(
                id, 
                async_=async_, 
                **request_kwargs, 
            )
        else:
            return client.fs_category_get_app(
                id, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
    def gen_step():
        if not cid:
            resp = yield client.fs_space_summury(async_=async_, **request_kwargs)
            check_response(resp)
            return sum(v["count"] for k, v in resp["type_summury"].items() if k.isupper())
        if use_fs_files:
            resp = yield get_resp_of_fs_files(cid)
            check_response(resp)
            if cid != int(resp["path"][-1]["cid"]):
                resp["cid"] = cid
                raise NotADirectoryError(ENOTDIR, resp)
            if id_to_dirnode is not ...:
                for info in resp["path"][1:]:
                    id_to_dirnode[int(info["cid"])] = DirNode(info["name"], int(info["pid"]))
            return int(resp["count"])
        else:
            resp = yield get_resp_of_category_get(cid)
            if not resp:
                raise FileNotFoundError(ENOENT, cid)
            if "paths" not in resp:
                check_response(resp)
                resp = resp["data"]
                if not resp:
                    raise FileNotFoundError(ENOENT, cid)
            if int(resp["file_category"]):
                resp["cid"] = cid
                raise NotADirectoryError(ENOTDIR, resp)
            if id_to_dirnode is not ...:
                pid = 0
                for info in resp["paths"][1:]:
                    node = DirNode(info["file_name"], pid)
                    id_to_dirnode[(pid := int(info["file_id"]))] = node
            return int(resp["count"]) - int(resp.get("folder_count") or 0)
    return run_gen_step(gen_step, may_call=False, async_=async_)


@overload
def get_ancestors(
    client: str | P115Client, 
    attr: int | dict, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> list[dict]:
    ...
@overload
def get_ancestors(
    client: str | P115Client, 
    attr: int | dict, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, list[dict]]:
    ...
def get_ancestors(
    client: str | P115Client, 
    attr: int | dict, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> list[dict] | Coroutine[Any, Any, list[dict]]:
    """获取某个节点对应的祖先节点列表（只有 id、parent_id 和 name 的信息）

    :param client: 115 客户端或 cookies
    :param attr: 待查询节点 `id` 或信息（必须有 `id`，可选有 `parent_id`）
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用某个 app （设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 目录所对应的祖先信息列表，每一条的结构如下

        .. code:: python

            {
                "id": int, # 目录的 id
                "parent_id": int, # 上级目录的 id
                "name": str, # 名字
            }
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    def get_resp_of_fs_files(id: int, /):
        if not isinstance(client, P115Client) or app == "open":
            return client.fs_files_open(
                {"cid": id, "cur": 1, "nf": 1, "hide_data": 1}, 
                async_=async_, 
                **request_kwargs, 
            )
        elif app in ("", "web", "desktop", "harmony"):
            return client.fs_files(
                {"cid": id, "limit": 1, "nf": 1, "star": 1}, 
                async_=async_, 
                **request_kwargs, 
            )
        elif app == "aps":
            return client.fs_files_aps(
                {"cid": id, "limit": 1, "nf": 1, "star": 1}, 
                async_=async_, 
                **request_kwargs, 
            )
        else:
            return client.fs_files_app(
                {"cid": id, "cur": 1, "nf": 1, "hide_data": 1}, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
    def get_resp_of_category_get(id: int, /):
        if not isinstance(client, P115Client) or app == "open":
            return client.fs_info_open(
                id, 
                async_=async_, 
                **request_kwargs, 
            )
        elif app in ("", "web", "desktop", "harmony", "aps"):
            return client.fs_category_get(
                id, 
                async_=async_, 
                **request_kwargs, 
            )
        else:
            return client.fs_category_get_app(
                id, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
    def gen_step():
        ancestors: list[dict] = [{"id": 0, "parent_id": 0, "name": ""}]
        add_ancestor = ancestors.append
        pid = 0
        is_completed = False
        if isinstance(attr, dict):
            fid = cast(int, attr["id"])
            if not fid:
                return ancestors
            is_dir: None | bool = attr.get("is_dir") or attr.get("is_directory")
            if is_dir is None:
                if "parent_id" in attr:
                    cid = cast(int, attr["parent_id"])
                    resp = yield get_resp_of_fs_files(cid)
                    if cid != int(resp["path"][-1]["cid"]):
                        resp["attr"] = attr
                        raise FileNotFoundError(ENOENT, resp)
                    for info in resp["path"][1:]:
                        add_ancestor({
                            "parent_id": pid, 
                            "id": (pid := int(info["cid"])), 
                            "name": info["name"], 
                        })
                    if id_to_dirnode is not ...:
                        for ans in ancestors[1:]:
                            id_to_dirnode[ans["id"]] = DirNode(ans["name"], ans["parent_id"])
                    if "name" in attr:
                        name = attr["name"]
                        is_dir = bool(attr.get("is_dir"))
                    else:
                        resp = yield client.fs_file_skim(attr["id"], async_=async_, **request_kwargs)
                        check_response(resp)
                        name = unescape_115_charref(resp["data"]["file_name"])
                        is_dir = not resp["data"]["sha1"]
                    ans = {"id": fid, "parent_id": pid, "name": name}
                    add_ancestor(ans)
                    if is_dir and id_to_dirnode is not ...:
                        id_to_dirnode[ans["id"]] = DirNode(ans["name"], ans["parent_id"])
                    is_completed = True
            elif is_dir:
                resp = yield get_resp_of_fs_files(fid)
                if fid != int(resp["path"][-1]["cid"]):
                    resp["attr"] = attr
                    raise FileNotFoundError(ENOENT, resp)
                for info in resp["path"][1:]:
                    add_ancestor({
                        "parent_id": pid, 
                        "id": (pid := int(info["cid"])), 
                        "name": info["name"], 
                    })
                if id_to_dirnode is not ...:
                    for ans in ancestors[1:]:
                        id_to_dirnode[ans["id"]] = DirNode(ans["name"], ans["parent_id"])
                is_completed = True
            else:
                resp = yield get_resp_of_category_get(fid)
                if not resp:
                    raise FileNotFoundError(ENOENT, attr)
                if "paths" not in resp:
                    check_response(resp)
                    resp = resp["data"]
                    if not resp:
                        raise FileNotFoundError(ENOENT, attr)
                for info in resp["paths"]:
                    add_ancestor({
                        "parent_id": pid, 
                        "id": (pid := int(info["file_id"])), 
                        "name": info["file_name"], 
                    })
                if id_to_dirnode is not ...:
                    for ans in ancestors[1:]:
                        id_to_dirnode[ans["id"]] = DirNode(ans["name"], ans["parent_id"])
                ans = {"id": fid, "parent_id": pid, "name": resp["file_name"]}
                add_ancestor(ans)
                if not resp.get("sha1") and id_to_dirnode is not ...:
                    id_to_dirnode[ans["id"]] = DirNode(ans["name"], ans["parent_id"])
                is_completed = True
        else:
            fid = attr
        if not is_completed:
            if not fid:
                return ancestors
            resp = yield get_resp_of_fs_files(fid)
            check_response(resp)
            if fid == int(resp["path"][-1]["cid"]):
                for info in resp["path"][1:]:
                    add_ancestor({
                        "parent_id": pid, 
                        "id": (pid := int(info["cid"])), 
                        "name": info["name"], 
                    })
                if id_to_dirnode is not ...:
                    for ans in ancestors[1:]:
                        id_to_dirnode[ans["id"]] = DirNode(ans["name"], ans["parent_id"])
            else:
                resp = yield get_resp_of_category_get(fid)
                if not resp:
                    raise FileNotFoundError(ENOENT, fid)
                if "paths" not in resp:
                    check_response(resp)
                    resp = resp["data"]
                    if not resp:
                        raise FileNotFoundError(ENOENT, fid)
                for info in resp["paths"]:
                    add_ancestor({
                        "parent_id": pid, 
                        "id": (pid := int(info["file_id"])), 
                        "name": info["file_name"], 
                    })
                if id_to_dirnode is not ...:
                    for ans in ancestors[1:]:
                        id_to_dirnode[ans["id"]] = DirNode(ans["name"], ans["parent_id"])
                ans = {"id": fid, "parent_id": pid, "name": resp["file_name"]}
                add_ancestor(ans)
                if not resp.get("sha1") and id_to_dirnode is not ...:
                    id_to_dirnode[ans["id"]] = DirNode(ans["name"], ans["parent_id"])
        return ancestors
    return run_gen_step(gen_step, may_call=False, async_=async_)


@overload
def get_ancestors_to_cid(
    client: str | P115Client, 
    cid: int = 0, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> list[dict]:
    ...
@overload
def get_ancestors_to_cid(
    client: str | P115Client, 
    cid: int = 0, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, list[dict]]:
    ...
def get_ancestors_to_cid(
    client: str | P115Client, 
    cid: int = 0, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> list[dict] | Coroutine[Any, Any, list[dict]]:
    """获取目录对应的祖先节点列表（只有 id、parent_id 和 name 的信息）

    :param client: 115 客户端或 cookies
    :param cid: 目录的 id
    :param refresh: 是否刷新。如果为 True，则会执行网络请求以查询；如果为 False，则直接从 `id_to_dirnode` 中获取
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用某个 app （设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 目录所对应的祖先信息列表，每一条的结构如下

        .. code:: python

            {
                "id": int, # 目录的 id
                "parent_id": int, # 上级目录的 id
                "name": str, # 名字
            }
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
    def gen_step():
        nonlocal cid
        parts: list[dict] = []
        if cid and (refresh or cid not in id_to_dirnode):
            if not isinstance(client, P115Client) or app == "open":
                resp = yield client.fs_files_open(
                    {"cid": cid, "cur": 1, "nf": 1, "hide_data": 1}, 
                    async_=async_, 
                    **request_kwargs, 
                )
            elif app in ("", "web", "desktop", "harmony"):
                resp = yield client.fs_files_aps(
                    {"cid": cid, "limit": 1, "nf": 1, "star": 1}, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                resp = yield client.fs_files_app(
                    {"cid": cid, "cur": 1, "nf": 1, "hide_data": 1}, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )
            check_response(resp)
            if cid and int(resp["path"][-1]["cid"]) != cid:
                raise FileNotFoundError(ENOENT, cid)
            parts.append({"id": 0, "name": "", "parent_id": 0})
            for info in resp["path"][1:]:
                id, pid, name = int(info["cid"]), int(info["pid"]), info["name"]
                id_to_dirnode[id] = DirNode(name, pid)
                parts.append({"id": id, "name": name, "parent_id": pid})
        else:
            while cid:
                id = cid
                name, cid = id_to_dirnode[cid]
                parts.append({"id": id, "name": name, "parent_id": cid})
            parts.append({"id": 0, "name": "", "parent_id": 0})
            parts.reverse()
        return parts
    return run_gen_step(gen_step, may_call=False, async_=async_)


# TODO: 使用 search 接口以在特定目录之下搜索某个名字，以便减少风控
@overload
def get_id_to_path(
    client: str | P115Client, 
    path: str | Sequence[str], 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    dont_use_getid: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def get_id_to_path(
    client: str | P115Client, 
    path: str | Sequence[str], 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    dont_use_getid: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def get_id_to_path(
    client: str | P115Client, 
    path: str | Sequence[str], 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    dont_use_getid: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """获取路径对应的 id

    :param client: 115 客户端或 cookies
    :param path: 路径
    :param parent_id: 上级目录的 id
    :param ensure_file: 是否确保为文件

        - True: 必须是文件
        - False: 必须是目录
        - None: 可以是目录或文件

    :param is_posixpath: 使用 posixpath，会把 "/" 转换为 "|"，因此解析的时候，会对 "|" 进行特别处理
    :param refresh: 是否刷新。如果为 True，则会执行网络请求以查询；如果为 False，则直接从 `id_to_dirnode` 中获取
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用某个 app （设备）的接口
    :param dont_use_getid: 不要使用 `client.fs_dir_getid` 或 `client.fs_dir_getid_app`，以便 `id_to_dirnode` 有缓存
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 文件或目录的 id
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    error = FileNotFoundError(ENOENT, f"no such path: {path!r}")
    def gen_step():
        nonlocal ensure_file, parent_id
        if isinstance(path, str):
            if path.startswith("/"):
                parent_id = 0
            if path in (".", "..", "/"):
                if ensure_file:
                    raise error
                return parent_id
            elif path.startswith("根目录 > "):
                parent_id = 0
                patht = path.split(" > ")[1:]
            elif is_posixpath:
                if ensure_file is None and path.endswith("/"):
                    ensure_file = False
                patht = [p for p in path.split("/") if p]
            else:
                if ensure_file is None and path_is_dir_form(path):
                    ensure_file = False
                patht, _ = splits(path.lstrip("/"))
        else:
            if path and not path[0]:
                parent_id = 0
                patht = list(path[1:])
            else:
                patht = [p for p in path if p]
            if not patht:
                return parent_id
        if not patht:
            if ensure_file:
                raise error
            return parent_id
        i = 0
        start_parent_id = parent_id
        if not refresh and id_to_dirnode and id_to_dirnode is not ...:
            if i := len(patht) - bool(ensure_file):
                obj = "|" if is_posixpath else "/"
                for i in range(i):
                    if obj in patht[i]:
                        break
                else:
                    i += 1
            if i:
                for i in range(i):
                    needle = (patht[i], parent_id)
                    for fid, key in id_to_dirnode.items():
                        if needle == key:
                            parent_id = fid
                            break
                    else:
                        break
                else:
                    i += 1
        if i == len(patht):
            return parent_id
        if not start_parent_id:
            stop = 0
            if j := len(patht) - bool(ensure_file):
                for stop, part in enumerate(patht[:j]):
                    if "/" in part:
                        break
                else:
                    stop += 1
            if not dont_use_getid:
                while stop > i:
                    if app in ("", "web", "desktop", "harmony"):
                        fs_dir_getid: Callable = client.fs_dir_getid
                    else:
                        fs_dir_getid = partial(client.fs_dir_getid_app, app=app)
                    dirname = "/".join(patht[:stop])
                    resp = yield fs_dir_getid(dirname, async_=async_, **request_kwargs)
                    check_response(resp)
                    cid = int(resp["id"])
                    if not cid:
                        if stop == len(patht) and ensure_file is None:
                            stop -= 1
                            continue
                        raise error
                    parent_id = cid
                    i = stop
                    break
        if i == len(patht):
            return parent_id
        for name in patht[i:-1]:
            if is_posixpath:
                name = name.replace("/", "|")
            with with_iter_next(iterdir(
                client, 
                parent_id, 
                ensure_file=False, 
                app=app, 
                id_to_dirnode=id_to_dirnode, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                found = False
                while not found:
                    attr = yield get_next()
                    found = (attr["name"].replace("/", "|") if is_posixpath else attr["name"]) == name
                    parent_id = attr["id"]
                if not found:
                    raise error
        name = patht[-1]
        if is_posixpath:
            name = name.replace("/", "|")
        with with_iter_next(iterdir(
            client, 
            parent_id, 
            app=app, 
            id_to_dirnode=id_to_dirnode, 
            async_=async_, 
            **request_kwargs, 
        )) as get_next:
            while True:
                attr = yield get_next()
                if (attr["name"].replace("/", "|") if is_posixpath else attr["name"]) == name:
                    if ensure_file is None or ensure_file ^ attr["is_dir"]:
                        return P115ID(attr["id"], attr, about="path")
        raise error
    return run_gen_step(gen_step, may_call=False, async_=async_)


@overload
def get_id_to_pickcode(
    client: str | P115Client, 
    pickcode: str, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> P115ID:
    ...
@overload
def get_id_to_pickcode(
    client: str | P115Client, 
    pickcode: str, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, P115ID]:
    ...
def get_id_to_pickcode(
    client: str | P115Client, 
    pickcode: str, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> P115ID | Coroutine[Any, Any, P115ID]:
    """获取 pickcode 对应的 id

    :param client: 115 客户端或 cookies
    :param pickcode: 提取码
    :param app: 使用某个 app （设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 文件或目录的 id
    """
    if not 17 <= len(pickcode) <= 18 or not pickcode.isalnum():
        raise ValueError(f"bad pickcode: {pickcode!r}")
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    def gen_step():
        if app in ("", "web", "desktop", "harmony"):
            fs_supervision: Callable = client.fs_supervision
        else:
            fs_supervision = partial(client.fs_supervision_app, app=app)
        resp = yield fs_supervision(pickcode, async_=async_, **request_kwargs)
        check_response(resp)
        data = resp["data"]
        return P115ID(data["file_id"], data, about="pickcode")
    return run_gen_step(gen_step, may_call=False, async_=async_)


@overload
def get_id_to_sha1(
    client: str | P115Client, 
    sha1: str, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> P115ID:
    ...
@overload
def get_id_to_sha1(
    client: str | P115Client, 
    sha1: str, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, P115ID]:
    ...
def get_id_to_sha1(
    client: str | P115Client, 
    sha1: str, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> P115ID | Coroutine[Any, Any, P115ID]:
    """获取 sha1 对应的文件的 id

    :param client: 115 客户端或 cookies
    :param sha1: sha1 摘要值
    :param app: 使用某个 app （设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 文件或目录的 id
    """
    if len(sha1) != 40 or sha1.strip(hexdigits):
        raise ValueError(f"bad sha1: {sha1!r}")
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    def gen_step():
        file_sha1 = sha1.upper()
        if app in ("", "web", "desktop", "harmony"):
            resp = yield client.fs_shasearch(sha1, async_=async_, **request_kwargs)
            check_response(resp)
            data = resp["data"]
        else:
            resp = yield client.fs_search_app(sha1, async_=async_, **request_kwargs)
            check_response(resp)
            for data in resp["data"]:
                if data["sha1"] == file_sha1:
                    break
            else:
                raise FileNotFoundError(ENOENT, file_sha1)
        return P115ID(data["file_id"], data, about="sha1", file_sha1=file_sha1)
    return run_gen_step(gen_step, may_call=False, async_=async_)


@overload
def iter_nodes_skim(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    batch_size: int = 50_000, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_skim(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    batch_size: int = 50_000, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_skim(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    batch_size: int = 50_000, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组节点的简略信息

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，获取节点的简略信息
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    def gen_step():
        file_skim = client.fs_file_skim
        for batch in chunked(ids, batch_size):
            resp = yield file_skim(batch, method="POST", async_=async_, **request_kwargs)
            if resp.get("error") == "文件不存在":
                continue
            check_response(resp)
            for a in resp["data"]:
                a["file_name"] = unescape_115_charref(a["file_name"])
            yield YieldFrom(resp["data"])
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def _iter_fs_files(
    client: str | P115Client, 
    payload: int | str | dict = 0, 
    first_page_size: int = 0, 
    page_size: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def _iter_fs_files(
    client: str | P115Client, 
    payload: int | str | dict = 0, 
    first_page_size: int = 0, 
    page_size: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def _iter_fs_files(
    client: str | P115Client, 
    payload: int | str | dict = 0, 
    first_page_size: int = 0, 
    page_size: int = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代目录，获取文件信息

    :param client: 115 客户端或 cookies
    :param payload: 请求参数，如果是 int 或 str，则视为 cid
    :param first_page_size: 首次拉取的分页大小
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param ensure_file: 是否确保为文件

        - True: 必须是文件
        - False: 必须是目录
        - None: 可以是目录或文件

    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    if isinstance(payload, (int, str)):
        payload = {"cid": payload}
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
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    def gen_step():
        request_kwargs.update(
            app=app, 
            page_size=page_size, 
            raise_for_changed_count=raise_for_changed_count, 
        )
        if cooldown <= 0 or max_workers == 1:
            it = iter_fs_files(
                client, 
                payload, 
                first_page_size=first_page_size, 
                async_=async_, 
                **request_kwargs, 
            )
        elif async_:
            it = iter_fs_files_asynchronized(
                client, 
                payload, 
                cooldown=cooldown, 
                max_workers=max_workers, 
                **request_kwargs, 
            )
        else:
            it = iter_fs_files_threaded(
                client, 
                payload, 
                cooldown=cooldown, 
                max_workers=max_workers, 
                **request_kwargs, 
            )
        do_next = anext if async_ else next
        try:
            while True:
                resp = yield do_next(it) # type: ignore
                if id_to_dirnode is not ...:
                    for info in resp["path"][1:]:
                        pid, name = int(info["cid"]), info["name"]
                        id_to_dirnode[pid] = DirNode(name, int(info["pid"]))
                if ensure_file is None:
                    if id_to_dirnode is not ...:
                        for info in resp["data"]:
                            attr = _overview_attr(info)
                            if attr.is_dir:
                                id_to_dirnode[attr.id] = DirNode(attr.name, attr.parent_id)
                    yield YieldFrom(resp["data"])
                else:
                    for info in resp["data"]:
                        attr = _overview_attr(info)
                        if attr.is_dir:
                            if id_to_dirnode is not ...:
                                id_to_dirnode[attr.id] = DirNode(attr.name, attr.parent_id)
                        elif ensure_file is False:
                            return
                        yield Yield(info)
        except (StopAsyncIteration, StopIteration):
            pass
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def iter_stared_dirs_raw(
    client: str | P115Client, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_stared_dirs_raw(
    client: str | P115Client, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_stared_dirs_raw(
    client: str | P115Client, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历以迭代获得所有被打上星标的目录信息

    :param client: 115 客户端或 cookies
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小
    :param order: 排序

        - "file_name": 文件名
        - "file_size": 文件大小
        - "file_type": 文件种类
        - "user_utime": 修改时间
        - "user_ptime": 创建时间
        - "user_otime": 上一次打开时间

    :param asc: 升序排列。0: 否，1: 是
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数
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
def iter_stared_dirs(
    client: str | P115Client, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_stared_dirs(
    client: str | P115Client, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_stared_dirs(
    client: str | P115Client, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历以迭代获得所有被打上星标的目录信息

    :param client: 115 客户端或 cookies
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小
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
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，被打上星标的目录信息
    """
    do_map = lambda f, it: it if not callable(f) else (async_map if async_ else map)(f, it)
    return do_map(normalize_attr, iter_stared_dirs_raw( # type: ignore
        client, 
        page_size=page_size, 
        first_page_size=first_page_size, 
        order=order, 
        asc=asc, 
        id_to_dirnode=id_to_dirnode, 
        raise_for_changed_count=raise_for_changed_count, 
        app=app, 
        cooldown=cooldown, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    ))


@overload
def ensure_attr_path[D: dict](
    client: str | P115Client, 
    attrs: Iterable[D], 
    page_size: int = 0, 
    with_ancestors: bool = False, 
    with_path: bool = True, 
    use_star: bool = False, 
    life_event_cooldown: int | float = 0.5, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    make_up_missing: bool = True, 
    app: str = "web", 
    errors: Literal["ignore", "raise", "warn"] = "raise", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[D]:
    ...
@overload
def ensure_attr_path[D: dict](
    client: str | P115Client, 
    attrs: Iterable[D], 
    page_size: int = 0, 
    with_ancestors: bool = False, 
    with_path: bool = True, 
    use_star: bool = False, 
    life_event_cooldown: int | float = 0.5, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    make_up_missing: bool = True, 
    app: str = "web", 
    errors: Literal["ignore", "raise", "warn"] = "raise", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[D]:
    ...
def ensure_attr_path[D: dict](
    client: str | P115Client, 
    attrs: Iterable[D], 
    page_size: int = 0, 
    with_ancestors: bool = False, 
    with_path: bool = True, 
    use_star: bool = False, 
    life_event_cooldown: int | float = 0.5, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    make_up_missing: bool = True, 
    app: str = "web", 
    errors: Literal["ignore", "raise", "warn"] = "raise", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[D] | AsyncIterator[D]:
    """为一组文件信息添加 "path" 或 "ancestors" 字段

    :param client: 115 客户端或 cookies
    :param attrs: 一组文件或目录的信息
    :param page_size: 分页大小
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param with_path: 文件信息中是否要包含 "path"
    :param use_star: 获取目录信息时，是否允许使用星标
    :param life_event_cooldown: 冷却时间，大于 0 时，两次拉取操作事件的接口调用之间至少间隔这么多秒
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param make_up_missing: 是否补全缺失的节点信息
    :param app: 使用某个 app （设备）的接口
    :param errors: 如何处理错误

        - "ignore": 忽略异常后继续
        - "raise": 抛出异常
        - "warn": 输出警告信息后继续

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 返回这一组文件信息
    """
    if not (with_ancestors or with_path):
        if async_:
            return ensure_aiter(attrs)
        else:
            return iter(attrs)
    if make_up_missing and not isinstance(attrs, Collection):
        attrs = tuple(attrs)
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if page_size <= 0:
        page_size = 10_000
    elif page_size < 16:
        page_size = 16
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
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
    if with_path:
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
            elif pid in id_to_path:
                dirname = id_to_path[pid]
            else:
                dirname = id_to_path[pid] = get_path(id_to_dirnode[pid]) + "/"
            return dirname + name
    def gen_step():
        if make_up_missing:
            pids: set[int] = set()
            add_pid = pids.add
            for attr in attrs:
                if pid := attr["parent_id"]:
                    add_pid(pid)
                if attr.get("is_dir", False) or attr.get("is_directory", False):
                    id_to_dirnode[attr["id"]] = DirNode(attr["name"], pid)
            find_ids: set[int]
            do_through: Callable = async_through if async_ else through
            while pids:
                if find_ids := pids - id_to_dirnode.keys():
                    try:
                        if use_star:
                            yield do_through(iter_selected_nodes_using_star_event(
                                client, 
                                find_ids, 
                                normalize_attr=None, 
                                id_to_dirnode=id_to_dirnode, 
                                cooldown=life_event_cooldown, 
                                app=app, 
                                async_=async_, # type: ignore
                                **request_kwargs, 
                            ))
                        else:
                            yield do_through(iter_selected_nodes_by_pickcode(
                                client, 
                                find_ids, 
                                normalize_attr=None, 
                                id_to_dirnode=id_to_dirnode, 
                                ignore_deleted=None, 
                                async_=async_, # type: ignore
                                **request_kwargs, 
                            ))
                    except Exception as e:
                        match errors:
                            case "raise":
                                raise
                            case "warn":
                                warn(f"{type(e).__module__}.{type(e).__qualname__}: {e}", category=P115Warning)
                pids = {ppid for pid in pids if (ppid := id_to_dirnode[pid][1])}
            del pids, find_ids, add_pid
        for attr in attrs:
            try:
                if with_ancestors:
                    attr["ancestors"] = get_ancestors(attr["id"], attr)
                if with_path:
                    attr["path"] = get_path(attr)
            except Exception as e:
                match errors:
                    case "raise":
                        raise
                    case "warn":
                        warn(f"{type(e).__module__}.{type(e).__qualname__}: {e} of {attr}", category=P115Warning)
                attr.setdefault("ancestors", None)
                attr.setdefault("path", "")
            yield Yield(attr)
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def ensure_attr_path_by_category_get[D: dict](
    client: str | P115Client, 
    attrs: Iterable[D], 
    with_ancestors: bool = False, 
    with_path: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[D]:
    ...
@overload
def ensure_attr_path_by_category_get[D: dict](
    client: str | P115Client, 
    attrs: Iterable[D], 
    with_ancestors: bool = False, 
    with_path: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[D]:
    ...
def ensure_attr_path_by_category_get[D: dict](
    client: str | P115Client, 
    attrs: Iterable[D], 
    with_ancestors: bool = False, 
    with_path: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[D] | AsyncIterator[D]:
    """为一组文件信息添加 "path" 或 "ancestors" 字段

    .. caution::
        风控非常严重，建议不要使用

    :param client: 115 客户端或 cookies
    :param attrs: 一组文件或目录的信息
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param with_path: 文件信息中是否要包含 "path"
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param app: 使用某个 app （设备）的接口
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器
    """
    if not (with_ancestors or with_path):
        if async_:
            return ensure_aiter(attrs)
        return attrs # type: ignore
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
    if app in ("", "web", "desktop", "harmony"):
        request_kwargs.setdefault("base_url", cycle(("http://webapi.115.com", "https://webapi.115.com")).__next__)
        func: Callable = partial(client.fs_category_get, **request_kwargs)
    else:
        request_kwargs.setdefault("base_url", cycle(("http://proapi.115.com", "https://proapi.115.com")).__next__)
        func = partial(client.fs_category_get_app, app=app, **request_kwargs)
    if with_ancestors:
        id_to_node: dict[int, dict] = {0: {"id": 0, "parent_id": 0, "name": ""}}
        def get_ancestors(id: int, attr: dict | tuple[str, int] | DirNode, /) -> list[dict]:
            if isinstance(attr, (DirNode, tuple)):
                name, pid = attr
                if pid in id_to_node:
                    me = id_to_node[pid] = {"id": id, "parent_id": pid, "name": name}
                else:
                    me = id_to_node[pid]
            else:
                pid = attr["parent_id"]
                name = attr["name"]
                me = {"id": id, "parent_id": pid, "name": name}
            if pid == 0:
                ancestors = [id_to_node[0]]
            else:
                ancestors = get_ancestors(pid, id_to_dirnode[pid])
            ancestors.append(me)
            return ancestors
    if with_path:
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
            elif pid in id_to_path:
                dirname = id_to_path[pid]
            else:
                dirname = id_to_path[pid] = get_path(id_to_dirnode[pid]) + "/"
            return dirname + name
    waiting: WeakValueDictionary[int, Any] = WeakValueDictionary()
    none: set[int] = set()
    if async_:
        async def async_project(attr: D, /) -> D:
            id = attr["id"]
            pid = attr["parent_id"]
            if pid and pid not in id_to_dirnode:
                async with waiting.setdefault(pid, AsyncLock()):
                    if pid in none:
                        return attr
                    if pid not in id_to_dirnode:
                        resp = await func(id, async_=True)
                        if not resp:
                            none.add(pid)
                            return attr
                        check_response(resp)
                        pid = 0
                        for info in resp["paths"][1:]:
                            fid = int(info["file_id"])
                            id_to_dirnode[fid] = DirNode(info["file_name"], pid)
                            pid = fid
                        if not resp["sha1"]:
                            id_to_dirnode[id] = DirNode(resp["file_name"], pid)
            if with_ancestors:
                attr["ancestors"] = get_ancestors(id, attr)
            if with_path:
                attr["path"] = get_path(attr)
            return attr
        return taskgroup_map(async_project, attrs, max_workers=max_workers)
    else:
        def project(attr: D, /) -> D:
            id = attr["id"]
            pid = attr["parent_id"]
            if pid and pid not in id_to_dirnode:
                with waiting.setdefault(pid, Lock()):
                    if pid in none:
                        return attr
                    if pid not in id_to_dirnode:
                        resp = func(id)
                        if not resp:
                            none.add(pid)
                            return attr
                        check_response(resp)
                        pid = 0
                        for info in resp["paths"][1:]:
                            fid = int(info["file_id"])
                            id_to_dirnode[fid] = DirNode(info["file_name"], pid)
                            pid = fid
                        if not resp["sha1"]:
                            id_to_dirnode[id] = DirNode(resp["file_name"], pid)
            if with_ancestors:
                attr["ancestors"] = get_ancestors(id, attr)
            if with_path:
                attr["path"] = get_path(attr)
            return attr
        return threadpool_map(project, attrs, max_workers=max_workers)


@overload
def iterdir_raw(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    show_dir: Literal[0, 1] = 1, 
    fc_mix: Literal[0, 1] = 1, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iterdir_raw(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    show_dir: Literal[0, 1] = 1, 
    fc_mix: Literal[0, 1] = 1, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iterdir_raw(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    show_dir: Literal[0, 1] = 1, 
    fc_mix: Literal[0, 1] = 1, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代目录，获取文件信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小
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
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param ensure_file: 是否确保为文件

        - True: 必须是文件
        - False: 必须是目录
        - None: 可以是目录或文件

    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    return _iter_fs_files(
        client, 
        payload={
            "asc": asc, "cid": cid, "cur": 1, "count_folders": 1, "fc_mix": fc_mix, 
            "show_dir": show_dir, "o": order, "offset": 0, 
        }, 
        page_size=page_size, 
        first_page_size=first_page_size, 
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
def iterdir(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    show_dir: Literal[0, 1] = 1, 
    fc_mix: Literal[0, 1] = 1, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iterdir(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    show_dir: Literal[0, 1] = 1, 
    fc_mix: Literal[0, 1] = 1, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iterdir(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    show_dir: Literal[0, 1] = 1, 
    fc_mix: Literal[0, 1] = 1, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代目录，获取文件信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小
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
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param with_path: 文件信息中是否要包含 "path"
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param ensure_file: 是否确保为文件

        - True: 必须是文件
        - False: 必须是目录
        - None: 可以是目录或文件

    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ... and (with_ancestors or with_path):
        id_to_dirnode = {}
    def gen_step():
        nonlocal cid
        it = iterdir_raw(
            client, 
            cid=cid, 
            page_size=page_size, 
            first_page_size=first_page_size, 
            order=order, 
            asc=asc, 
            show_dir=show_dir, 
            fc_mix=fc_mix, 
            id_to_dirnode=id_to_dirnode, 
            raise_for_changed_count=raise_for_changed_count, 
            ensure_file=ensure_file, 
            app=app, 
            cooldown=cooldown, 
            max_workers=max_workers, 
            async_=async_, # type: ignore
            **request_kwargs, 
        )
        do_map = lambda f, it: it if not callable(f) else (async_map if async_ else map)(f, it)
        dirname = ""
        pancestors: list[dict] = []
        if with_ancestors or with_path:
            def process(info: dict, /) -> dict:
                nonlocal dirname, pancestors, id_to_dirnode
                id_to_dirnode = cast(dict, id_to_dirnode)
                attr = normalize_attr(info)
                if not pancestors:
                    cid = attr["parent_id"]
                    while cid:
                        name, pid = id_to_dirnode[cid]
                        pancestors.append({"id": cid, "parent_id": pid, "name": name})
                        cid = pid
                    pancestors.append({"id": 0, "parent_id": 0, "name": ""})
                    pancestors.reverse()
                if with_ancestors:
                    attr["ancestors"] = [
                        *pancestors, 
                        {"id": attr["id"], "parent_id": attr["parent_id"], "name": attr["name"]}, 
                    ]
                if with_path:
                    if not dirname:
                        if escape is None:
                            dirname = "/".join(info["name"] for info in pancestors) + "/"
                        else:
                            dirname = "/".join(escape(info["name"]) for info in pancestors) + "/"
                    name = attr["name"]
                    if escape is not None:
                        name = escape(name)
                    attr["path"] = dirname + name
                return attr
            yield YieldFrom(do_map(process, it)) # type: ignore
        else:
            yield YieldFrom(do_map(normalize_attr, it)) # type: ignore
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


def iterdir_limited(
    client: str | P115Client, 
    cid: int = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    ensure_file: None | bool = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代目录，获取文件信息，但受限，文件或目录最多分别获取 max(1201, 2402 - 此类型被置顶的个数) 个

    :param client: 115 客户端或 cookies
    :param cid: 目录 id
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param with_path: 文件信息中是否要包含 "path"
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param ensure_file: 是否确保为文件

        - True: 必须是文件
        - False: 必须是目录
        - None: 可以是目录或文件

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    seen_dirs: set[int] = set()
    add_dir = seen_dirs.add
    seen_files: set[int] = set()
    add_file = seen_files.add
    ancestors: list[dict] = [{"id": 0, "name": "", "parent_id": 0}]
    payload = {
        "asc": 1, "cid": cid, "count_folders": 1, "cur": 1, "fc_mix": 0, "limit": 10_000, 
        "offset": 0, "show_dir": 1,  
    }
    if ensure_file is not None:
        if ensure_file:
            payload["show_dir"] = 0
        else:
            payload["nf"] = 1
    def request(params={}, /):
        resp = yield client.fs_files_aps(
            {**payload, **params}, 
            base_url=True, 
            async_=async_, 
            **request_kwargs, 
        )
        check_response(resp)
        if cid and int(resp["path"][-1]["cid"]) != cid:
            raise FileNotFoundError(ENOENT, cid)
        ancestors[1:] = [
            {"id": int(info["cid"]), "name": info["name"], "parent_id": int(info["pid"])} 
            for info in resp["path"][1:]
        ]
        return resp
    def iter_attrs(resp, /):
        if with_path:
            names: Iterator[str] = (info["name"] for info in ancestors)
            if escape is not None:
                names = map(escape, names)
            dirname = "/".join(names) + "/"
        for attr in map(normalize_attr, resp["data"]):
            is_dir = ensure_file is False or attr.get("is_dir") or attr.get("is_directory")
            fid = attr["id"]
            if is_dir:
                if fid in seen_dirs:
                    continue
                add_dir(fid)
            else:
                if fid in seen_files:
                    continue
                add_file(fid)
            name = attr["name"]
            if id_to_dirnode is not ...:
                id_to_dirnode[fid] = DirNode(name, cid)
            if with_ancestors:
                attr["ancestors"] = [*ancestors, {"id": fid, "name": name, "parent_id": cid}]
            if with_path:
                if escape is not None:
                    name = escape(name)
                attr["path"] = dirname + name
            yield attr
    def gen_step():
        resp: dict = yield run_gen_step(request, may_call=False, async_=async_)
        yield YieldFrom(iter_attrs(resp))
        count = int(resp["count"])
        count_fetched = len(resp["data"])
        if count > count_fetched:
            count_dirs = int(resp.get("folder_count") or 0)
            count_files = count - count_dirs
            count_top_dirs = 0
            count_top_files = 0
            for attr in map(normalize_attr, resp["data"]):
                is_dir = ensure_file is False or attr.get("is_dir") or attr.get("is_directory")
                if attr["is_top"]:
                    if is_dir:
                        count_top_dirs += 1
                    else:
                        count_top_files += 1
                elif not cid and is_dir and attr["name"] in ("我的接收", "手机相册", "云下载", "我的时光记录"):
                    count_top_dirs += 1
                else:
                    break
            else:
                if diff := count_dirs - len(seen_dirs):
                    warn(f"lost {diff} directories: cid={cid}", category=P115Warning)
                if diff := count_files - len(seen_files):
                    warn(f"lost {diff} files: cid={cid}", category=P115Warning)
                return
            count_top = count_top_dirs + count_top_files
            if count <= count_fetched * 2 - count_top:
                resp = request({"asc": 0, "offset": count_top, "limit": count - count_fetched})
                yield YieldFrom(iter_attrs(resp))
                return
            if diff := count_dirs - len(seen_dirs):
                if diff > count_fetched - count_top_dirs:
                    resp = request({"nf": 1, "offset": len(seen_dirs)})
                    yield YieldFrom(iter_attrs(resp))
                    diff = count_dirs - len(seen_dirs)
                if diff > 0:
                    resp = request({"asc": 0, "nf": 1, "offset": count_top_dirs, "limit": diff})
                    yield YieldFrom(iter_attrs(resp))
                    
                    if diff := count_dirs - len(seen_dirs):
                        warn(f"lost {diff} directories: cid={cid}", category=P115Warning)
            if diff := count_files - len(seen_files):
                if diff > count_fetched - count_top_files:
                    resp = request({"show_dir": 0, "offset": len(seen_files)})
                    yield YieldFrom(iter_attrs(resp))
                    diff = count_files - len(seen_files)
                if diff > 0:
                    resp = request({"asc": 0, "show_dir": 0, "offset": count_top_files, "limit": diff})
                    yield YieldFrom(iter_attrs(resp))
                    if diff := count_files - len(seen_files):
                        warn(f"lost {diff} files: cid={cid}", category=P115Warning)
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def iter_files_raw(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files_raw(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_raw(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小
    :param suffix: 后缀名（优先级高于 type）
    :param type: 文件类型

        - 1: 文档
        - 2: 图片
        - 3: 音频
        - 4: 视频
        - 5: 压缩包
        - 6: 应用
        - 7: 书籍
        - 99: 仅文件

    :param order: 排序

        - "file_name": 文件名
        - "file_size": 文件大小
        - "file_type": 文件种类
        - "user_utime": 修改时间
        - "user_ptime": 创建时间
        - "user_otime": 上一次打开时间

    :param asc: 升序排列。0: 否，1: 是
    :param cur: 仅当前目录。0: 否（将遍历子目录树上所有叶子节点），1: 是
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅文件）文件信息
    """
    suffix = suffix.strip(".")
    if not (type or suffix):
        raise ValueError("please set the non-zero value of suffix or type")
    payload: dict = {
        "asc": asc, "cid": cid, "count_folders": 0, "cur": cur, "o": order, 
        "offset": 0, "show_dir": 0, 
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
def iter_files(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小
    :param suffix: 后缀名（优先级高于 type）
    :param type: 文件类型

        - 1: 文档
        - 2: 图片
        - 3: 音频
        - 4: 视频
        - 5: 压缩包
        - 6: 应用
        - 7: 书籍
        - 99: 仅文件

    :param order: 排序

        - "file_name": 文件名
        - "file_size": 文件大小
        - "file_type": 文件种类
        - "user_utime": 修改时间
        - "user_ptime": 创建时间
        - "user_otime": 上一次打开时间

    :param asc: 升序排列。0: 否，1: 是
    :param cur: 仅当前目录。0: 否（将遍历子目录树上所有叶子节点），1: 是
    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param with_path: 文件信息中是否要包含 "path"
    :param use_star: 获取目录信息时，是否允许使用星标 （如果为 None，则采用流处理，否则采用批处理）
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅文件）文件信息
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ... and (with_ancestors or with_path):
        id_to_dirnode = {}
    if with_ancestors or with_path:
        cache: list[dict] = []
        add_to_cache = cache.append
    if with_ancestors:
        id_to_ancestors: dict[int, list[dict]] = {}
        def get_ancestors(id: int, attr: dict | tuple[str, int] | DirNode, /) -> list[dict]:
            nonlocal id_to_dirnode
            id_to_dirnode = cast(dict, id_to_dirnode)
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
    if with_path:
        id_to_path: dict[int, str] = {}
        def get_path(attr: dict | tuple[str, int] | DirNode, /) -> str:
            nonlocal id_to_dirnode
            id_to_dirnode = cast(dict, id_to_dirnode)
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
    def gen_step():
        it = iter_files_raw(
            client, 
            cid=cid, 
            page_size=page_size, 
            first_page_size=first_page_size, 
            suffix=suffix, 
            type=type, 
            order=order, 
            asc=asc, 
            cur=cur, 
            id_to_dirnode=id_to_dirnode, 
            raise_for_changed_count=raise_for_changed_count, 
            app=app, 
            cooldown=cooldown, 
            max_workers=max_workers, 
            async_=async_, # type: ignore
            **request_kwargs, 
        )
        do_map = lambda f, it: it if not callable(f) else (async_map if async_ else map)(f, it)
        if with_path or with_ancestors:
            if use_star is None:
                return YieldFrom(ensure_attr_path_by_category_get(
                    client, 
                    do_map(normalize_attr, it), # type: ignore
                    with_ancestors=with_ancestors, 
                    with_path=with_path, 
                    escape=escape, 
                    id_to_dirnode=id_to_dirnode, 
                    app=app, 
                    async_=async_, # type: ignore
                    **request_kwargs, 
                ))
            do_filter = async_filter if async_ else filter
            def process(info):
                attr = normalize_attr(info)
                try:
                    if with_ancestors:
                        attr["ancestors"] = get_ancestors(attr["id"], attr)
                    if with_path:
                        attr["path"] = get_path(attr)
                except KeyError:
                    add_to_cache(attr)
                else:
                    return attr
            yield YieldFrom(do_filter(bool, do_map(process, it))) # type: ignore
        else:
            yield YieldFrom(do_map(normalize_attr, it)) # type: ignore
        if (with_ancestors or with_path) and cache:
            yield YieldFrom(ensure_attr_path(
                client, 
                cache, 
                page_size=page_size, 
                with_ancestors=with_ancestors, 
                with_path=with_path, 
                use_star=use_star, # type: ignore
                escape=escape, 
                id_to_dirnode=id_to_dirnode, 
                app=app, 
                async_=async_, # type: ignore
                **request_kwargs, 
            ))
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def traverse_files(
    client: str | P115Client, 
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
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def traverse_files(
    client: str | P115Client, 
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
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def traverse_files(
    client: str | P115Client, 
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
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
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
        - 99: 仅文件

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
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅文件）文件信息
    """
    suffix = suffix.strip(".")
    if not (type or suffix):
        raise ValueError("please set the non-zero value of suffix or type")
    if suffix:
        suffix = "." + suffix.lower()
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ... and (with_ancestors or with_path):
        id_to_dirnode = {}
    auto_splitting_tasks = auto_splitting_tasks and auto_splitting_threshold > 0
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
                    if attr.get("is_dir") or attr.get("is_directory"):
                        send(attr["id"])
                    elif (
                        suffix and 
                        suffix == splitext(attr["name"])[1].lower() or 
                        type > 7 or 
                        type_of_attr(attr) == type
                    ):
                        yield Yield(attr)
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def iter_dirs(
    client: str | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    with_pickcode: bool = False, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_dirs(
    client: str | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    with_pickcode: bool = False, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_dirs(
    client: str | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    with_pickcode: bool = False, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取目录信息

    :param client: 115 客户端或 cookies
    :param cid: 目录 id（如果是 int） 或者 pickcode（如果是 str）
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param with_pickcode: 是否需要包含提取码
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅目录）文件信息
    """
    from .download import iter_download_nodes
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    it = iter_download_nodes(
        client, 
        cid, 
        files=False, 
        max_workers=max_workers, 
        async_=async_, # type: ignore
        **request_kwargs, 
    )
    do_map: Callable = async_map if async_ else map
    def project(info: dict, /) -> dict:
        attr = {"id": int(info["fid"]), "parent_id": int(info["pid"]), "name": info["fn"]}
        if id_to_dirnode is not ...:
            id_to_dirnode[attr["id"]] = DirNode(attr["name"], attr["parent_id"])
        return attr
    it = do_map(project, it)
    if with_pickcode:
        file_skim = client.fs_file_skim
        @as_gen_step(async_=async_)
        def batch_load_pickcode(batch: Sequence[dict], /):
            resp = yield file_skim(
                (a["id"] for a in batch), 
                method="POST", 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            maps = {int(a["file_id"]): a["pick_code"] for a in resp["data"]}
            for attr in batch:
                attr["pickcode"] = maps[attr["id"]]
            return batch
        def gen_step(iterable):
            batch_map = taskgroup_map if async_ else threadpool_map
            with with_iter_next(batch_map(
                batch_load_pickcode, 
                chunked(iterable, 3000), 
                max_workers=max_workers, 
            )) as get_next:
                while True:
                    batch = yield get_next()
                    yield YieldFrom(batch)
        it = run_gen_step_iter(gen_step(it), may_call=False, async_=async_)
    return it


@overload
def iter_dupfiles[K](
    client: str | P115Client, 
    cid: int = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    auto_splitting_tasks: bool = False, 
    auto_splitting_threshold: int = 300_000, 
    auto_splitting_statistics_timeout: None | int | float = 5, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, dict]]:
    ...
@overload
def iter_dupfiles[K](
    client: str | P115Client, 
    cid: int = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    auto_splitting_tasks: bool = False, 
    auto_splitting_threshold: int = 300_000, 
    auto_splitting_statistics_timeout: None | int | float = 5, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[K, dict]]:
    ...
def iter_dupfiles[K](
    client: str | P115Client, 
    cid: int = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    auto_splitting_tasks: bool = False, 
    auto_splitting_threshold: int = 300_000, 
    auto_splitting_statistics_timeout: None | int | float = 5, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, dict]] | AsyncIterator[tuple[K, dict]]:
    """遍历以迭代获得所有重复文件

    :param client: 115 客户端或 cookies
    :param cid: 待被遍历的目录 id，默认为根目录
    :param key: 函数，用来给文件分组，当多个文件被分配到同一组时，它们相互之间是重复文件关系
    :param keep_first: 保留某个重复文件不输出，除此以外的重复文件都输出

        - 如果为 None，则输出所有重复文件（不作保留）
        - 如果是 Callable，则保留值最小的那个文件
        - 如果为 True，则保留最早入组的那个文件
        - 如果为 False，则保留最晚入组的那个文件

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
        - 99: 仅文件

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
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回 key 和 重复文件信息 的元组
    """
    return iter_keyed_dups(
        traverse_files(
            client, 
            cid, 
            page_size=page_size, 
            suffix=suffix, 
            type=type, 
            auto_splitting_tasks=auto_splitting_tasks, 
            auto_splitting_threshold=auto_splitting_threshold, 
            auto_splitting_statistics_timeout=auto_splitting_statistics_timeout, 
            with_ancestors=with_ancestors, 
            with_path=with_path, 
            escape=escape, 
            normalize_attr=normalize_attr, 
            id_to_dirnode=id_to_dirnode, 
            raise_for_changed_count=raise_for_changed_count, 
            app=app, 
            cooldown=cooldown, 
            async_=async_, # type: ignore
            **request_kwargs, 
        ), 
        key=key, 
        keep_first=keep_first, 
    )


@overload
def iter_image_files(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 8192, 
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
def iter_image_files(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 8192, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_image_files(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 8192, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取图片文件信息（包含图片的 CDN 链接）

    .. tip::
        这个函数的效果相当于 ``iter_files(client, cid, type=2, ...)`` 所获取的文件列表，只是返回信息有些不同，速度似乎还是 ``iter_files`` 更快

    :param client: 115 客户端或 cookies
    :param cid: 目录 id
    :param page_size: 分页大小
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
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if page_size <= 0:
        page_size = 8192
    elif page_size < 16:
        page_size = 16
    payload = {"asc": asc, "cid": cid, "cur": cur, "limit": page_size, "o": order, "offset": 0}
    def gen_step():
        offset = 0
        count = 0
        while True:
            resp = check_response((yield client.fs_imglist_app(payload, async_=async_, **request_kwargs)))
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
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def share_iterdir(
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    :param share_code: 分享码
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
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[(client.user_id, share_code)]
    if page_size <= 0:
        page_size = 10_000
    def gen_step():
        nonlocal receive_code
        if not receive_code:
            resp = yield client.share_info(share_code, async_=async_, **request_kwargs)
            check_response(resp)
            receive_code = resp["data"]["receive_code"]
        payload = {
            "share_code": share_code, 
            "receive_code": receive_code, 
            "cid": cid, 
            "limit": page_size, 
            "offset": 0, 
            "asc": asc, 
            "o": order, 
        }
        count = 0
        while True:
            resp = yield client.share_snap(payload, base_url=True, async_=async_, **request_kwargs)
            check_response(resp)
            if count == (count := resp["data"]["count"]):
                break
            for attr in resp["data"]["list"]:
                attr["share_code"] = share_code
                attr["receive_code"] = receive_code
                if id_to_dirnode is not ...:
                    oattr = _overview_attr(attr)
                    if oattr.is_dir:
                        id_to_dirnode[oattr.id] = DirNode(oattr.name, oattr.parent_id)
                if normalize_attr is not None:
                    attr = normalize_attr(attr)
                yield Yield(attr)
            payload["offset"] += page_size # type: ignore
            if payload["offset"] >= count: # type: ignore
                break
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def share_iter_files(
    client: str | P115Client, 
    share_link: str, 
    receive_code: str = "", 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def share_iter_files(
    client: str | P115Client, 
    share_link: str, 
    receive_code: str = "", 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def share_iter_files(
    client: str | P115Client, 
    share_link: str, 
    receive_code: str = "", 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None,  
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """批量获取分享链接中的文件列表

    .. hint::
        `share_link` 支持 3 种形式（圆括号中的字符表示可有可无）：

        1. http(s)://115.com/s/{share_code}?password={receive_code}(#) 或 http(s)://share.115.com/{share_code}?password={receive_code}(#)
        2. (/){share_code}-{receive_code}(/)
        3. {share_code}

        如果使用第 3 种形式，而且又不提供 `receive_code`，则认为这是你自己所做的分享，会尝试自动去获取这个密码

        如果 `share_link` 中有 `receive_code`，而你又单独提供了 `receive_code`，则后者的优先级更高

    :param client: 115 客户端或 cookies
    :param share_link: 分享码或分享链接
    :param receive_code: 密码
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此分享链接下的（仅文件）文件信息，由于接口返回信息有限，所以比较简略

        .. code:: python

            {
                "id": int, 
                "sha1": str, 
                "name": str, 
                "size": int, 
                "path": str, 
            }

    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    def gen_step():
        nonlocal id_to_dirnode
        payload: dict = cast(dict, share_extract_payload(share_link))
        if receive_code:
            payload["receive_code"] = receive_code
        elif not payload["receive_code"]:
            resp = yield client.share_info(payload["share_code"], async_=async_, **request_kwargs)
            check_response(resp)
            payload["receive_code"] = resp["data"]["receive_code"]
        if id_to_dirnode is None:
            id_to_dirnode = ID_TO_DIRNODE_CACHE[(client.user_id, payload["share_code"])]
        payload["cid"] = 0
        payload["id_to_dirnode"] = id_to_dirnode
        it = share_iterdir(client, **payload, async_=async_, **request_kwargs)
        do_next: Callable = anext if async_ else next
        try:
            while True:
                attr = yield do_next(it)
                if attr.get("is_dir") or attr.get("is_directory"):
                    payload["cid"] = attr["id"]
                    resp = yield client.share_downlist(payload, async_=async_, **request_kwargs)
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
        except (StopIteration, StopAsyncIteration):
            pass
    return run_gen_step(gen_step, may_call=False, async_=async_)


@overload
def share_get_id_to_path(
    client: str | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    path: str | Sequence[str] = "", 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def share_get_id_to_path(
    client: str | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    path: str | Sequence[str] = "", 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def share_get_id_to_path(
    client: str | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    path: str | Sequence[str] = "", 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """对分享链接，获取路径对应的 id

    :param client: 115 客户端或 cookies
    :param share_code: 分享码
    :param receive_code: 密码
    :param path: 路径
    :param parent_id: 上级目录的 id
    :param ensure_file: 是否确保为文件

        - True: 必须是文件
        - False: 必须是目录
        - None: 可以是目录或文件

    :param is_posixpath: 使用 posixpath，会把 "/" 转换为 "|"，因此解析的时候，会对 "|" 进行特别处理
    :param refresh: 是否刷新。如果为 True，则会执行网络请求以查询；如果为 False，则直接从 `id_to_dirnode` 中获取
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 文件或目录的 id
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[(client.user_id, share_code)]
    error = FileNotFoundError(ENOENT, f"no such path: {path!r}")
    def gen_step():
        nonlocal ensure_file, parent_id, receive_code
        if isinstance(path, str):
            if path.startswith("/"):
                parent_id = 0
            if path in (".", "..", "/"):
                if ensure_file:
                    raise error
                return parent_id
            elif path.startswith("根目录 > "):
                parent_id = 0
                patht = path.split(" > ")[1:]
            elif is_posixpath:
                if ensure_file is None and path.endswith("/"):
                    ensure_file = False
                patht = [p for p in path.split("/") if p]
            else:
                if ensure_file is None and path_is_dir_form(path):
                    ensure_file = False
                patht, _ = splits(path.lstrip("/"))
        else:
            if path and not path[0]:
                parent_id = 0
                patht = list(path[1:])
            else:
                patht = [p for p in path if p]
            if not patht:
                return parent_id
        if not patht:
            if ensure_file:
                raise error
            return parent_id
        if not receive_code:
            resp = yield client.share_info(share_code, async_=async_, **request_kwargs)
            check_response(resp)
            receive_code = resp["data"]["receive_code"]
        i = 0
        if not refresh and id_to_dirnode and id_to_dirnode is not ...:
            if i := len(patht) - bool(ensure_file):
                obj = "|" if is_posixpath else "/"
                for i in range(i):
                    if obj in patht[i]:
                        break
                else:
                    i += 1
            if i:
                for i in range(i):
                    needle = (patht[i], parent_id)
                    for fid, key in id_to_dirnode.items():
                        if needle == key:
                            parent_id = fid
                            break
                    else:
                        break
                else:
                    i += 1
        if i == len(patht):
            return parent_id
        for name in patht[i:-1]:
            if is_posixpath:
                name = name.replace("/", "|")
            with with_iter_next(share_iterdir(
                client, 
                share_code, 
                receive_code=receive_code, 
                cid=parent_id, 
                id_to_dirnode=id_to_dirnode, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                found = False
                while not found:
                    attr = yield get_next()
                    found = attr["is_dir"] and (attr["name"].replace("/", "|") if is_posixpath else attr["name"]) == name
                    parent_id = attr["id"]
            if not found:
                raise error
        name = patht[-1]
        if is_posixpath:
            name = name.replace("/", "|")
        with with_iter_next(share_iterdir(
            client, 
            share_code, 
            receive_code=receive_code, 
            cid=parent_id, 
            id_to_dirnode=id_to_dirnode, 
            async_=async_, 
            **request_kwargs, 
        )) as get_next:
            while True:
                attr = yield get_next()
                if (attr["name"].replace("/", "|") if is_posixpath else attr["name"]) == name:
                    if ensure_file is None or ensure_file ^ attr["is_dir"]:
                        return P115ID(attr["id"], attr, about="path")
        raise error
    return run_gen_step(gen_step, may_call=False, async_=async_)


@overload
def iter_selected_nodes(
    client: str | P115Client, 
    ids: Iterable[int], 
    ignore_deleted: bool = True, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_selected_nodes(
    client: str | P115Client, 
    ids: Iterable[int], 
    ignore_deleted: bool = True, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_selected_nodes(
    client: str | P115Client, 
    ids: Iterable[int], 
    ignore_deleted: bool = True, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    .. caution::
        风控非常严重，建议不要使用

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param ignore_deleted: 忽略已经被删除的
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    get_base_url = cycle(("http://webapi.115.com", "https://webapi.115.com")).__next__
    request_kwargs.setdefault("base_url", get_base_url)
    def project(resp: dict, /) -> None | dict:
        if resp.get("code") == 20018:
            return None
        check_response(resp)
        info = resp["data"][0]
        was_deleted = int(info.get("aid") or info.get("area_id") or 1) != 1
        if ignore_deleted and was_deleted:
            return None
        if id_to_dirnode is not ... and not was_deleted:
            attr = _overview_attr(info)
            if attr.is_dir:
                id_to_dirnode[attr.id] = DirNode(attr.name, attr.parent_id)
        if normalize_attr is None:
            return info
        return normalize_attr(info)
    if async_:
        request_kwargs["async_"] = True
        return async_filter(None, async_map(
            project, # type: ignore
            taskgroup_map(
                client.fs_file, # type: ignore
                ids, 
                max_workers=max_workers, 
                kwargs=request_kwargs, 
            ), 
        ))
    else:
        return filter(None, map(
            project, 
            threadpool_map(
                client.fs_file, 
                ids, 
                max_workers=max_workers, 
                kwargs=request_kwargs, 
            ), 
        ))


@overload
def iter_selected_nodes_by_pickcode(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    ignore_deleted: None | bool = True, 
    normalize_attr: None | Callable[[dict], dict] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_selected_nodes_by_pickcode(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    ignore_deleted: None | bool = True, 
    normalize_attr: None | Callable[[dict], dict] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20,  
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_selected_nodes_by_pickcode(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    ignore_deleted: None | bool = True, 
    normalize_attr: None | Callable[[dict], dict] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    .. caution::
        并发数较多时，容易发生 HTTP 链接中断现象

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param ignore_deleted: 是否忽略已经被删除的
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, str):
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
    def get_response(pickcode: str | dict, /, get_method=cycle(methods).__next__):
        if isinstance(pickcode, dict):
            pickcode = pickcode["pick_code"]
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
    ls_pickcode: list[str] = []
    ls_id: list[int] = []
    append = list.append
    for val in ids:
        if val:
            if isinstance(val, int):
                append(ls_id, val)
            else:
                append(ls_pickcode, val)
    if ls_id:
        it: Any = iter_nodes_skim(client, ls_id, async_=async_, **request_kwargs)
        if async_:
            it = async_chain(ls_pickcode, it)
        else:
            it = chain(ls_pickcode, it)
    else:
        it = ls_pickcode
    if async_:
        return async_filter(None, async_map(project, taskgroup_map( # type: ignore
            get_response, it, max_workers=max_workers, kwargs=request_kwargs)))
    else:
        return filter(None, map(project, threadpool_map(
            get_response, it, max_workers=max_workers, kwargs=request_kwargs)))


@overload
def iter_selected_nodes_using_edit(
    client: str | P115Client, 
    ids: Iterable[int], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_selected_nodes_using_edit(
    client: str | P115Client, 
    ids: Iterable[int], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_selected_nodes_using_edit(
    client: str | P115Client, 
    ids: Iterable[int], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    .. caution::
        速度较慢，风控较严重，建议不要使用

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    get_base_url = cycle(("http://proapi.115.com", "https://proapi.115.com")).__next__
    request_kwargs.setdefault("base_url", get_base_url)
    def project(resp: dict, /) -> None | dict:
        if resp.get("error") == "文件不存在/数据库错误了":
            return None
        check_response(resp)
        info = resp["data"]
        info["id"] = int(info["file_id"])
        info["parent_id"] = int(info["parent_id"])
        info["name"] = info["file_name"]
        info["is_dir"] = not info["sha1"]
        if id_to_dirnode is not ... and info["is_dir"]:
            id_to_dirnode[info["id"]] = DirNode(info["name"], info["parent_id"])
        return info
    args_it = ({"file_id": fid, "show_play_long": 1} for fid in ids)
    if async_:
        request_kwargs["async_"] = True
        return async_filter(None, async_map(
            project, # type: ignore
            taskgroup_map(
                client.fs_edit_app, # type: ignore
                args_it, 
                max_workers=max_workers, 
                kwargs=request_kwargs, 
            ), 
        ))
    else:
        return filter(None, map(
            project, 
            threadpool_map(
                client.fs_edit_app, 
                args_it, 
                max_workers=max_workers, 
                kwargs=request_kwargs, 
            ), 
        ))


@overload
def iter_selected_nodes_using_category_get(
    client: str | P115Client, 
    ids: Iterable[int], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_selected_nodes_using_category_get(
    client: str | P115Client, 
    ids: Iterable[int], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_selected_nodes_using_category_get(
    client: str | P115Client, 
    ids: Iterable[int], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = 20, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    .. caution::
        风控非常严重，建议不要使用

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    get_method = cycle((
        partial(client.fs_category_get, base_url="http://webapi.115.com"), 
        partial(client.fs_category_get_app, base_url="http://proapi.115.com"), 
        partial(client.fs_category_get, base_url="https://webapi.115.com"), 
        partial(client.fs_category_get_app, base_url="https://proapi.115.com"), 
    )).__next__
    def call(id, /):
        def parse(_, content: bytes):
            resp = loads(content)
            if resp:
                resp["id"] = id
                resp["parent_id"] = int(resp["paths"][-1]["file_id"])
                resp["name"] = resp["file_name"]
                resp["is_dir"] = not resp["sha1"]
            return resp
        return get_method()(id, parse=parse, async_=async_, **request_kwargs)
    def project(resp: dict, /) -> None | dict:
        if not resp:
            return None
        check_response(resp)
        if id_to_dirnode is not ...:
            pid = 0
            for info in resp["paths"][1:]:
                fid = int(info["file_id"])
                id_to_dirnode[fid] = DirNode(info["file_name"], pid)
                pid = fid
            if resp["is_dir"]:
                id_to_dirnode[resp["id"]] = DirNode(resp["name"], pid)
        return resp
    if async_:
        return async_filter(None, async_map(project, taskgroup_map( # type: ignore
            call, ids, max_workers=max_workers)))
    else:
        return filter(None, map(project, threadpool_map(
            call, ids, max_workers=max_workers)))


@overload
def iter_selected_nodes_using_star_event(
    client: str | P115Client, 
    ids: Iterable[int], 
    with_pics: bool = False, 
    normalize_attr: None | bool | Callable[[dict], dict] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_selected_nodes_using_star_event(
    client: str | P115Client, 
    ids: Iterable[int], 
    with_pics: bool = False, 
    normalize_attr: None | bool | Callable[[dict], dict] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_selected_nodes_using_star_event(
    client: str | P115Client, 
    ids: Iterable[int], 
    with_pics: bool = False, 
    normalize_attr: None | bool | Callable[[dict], dict] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """通过打星标来获取一组 id 的信息

    .. caution::
        如果 id 已经被删除，则打星标时会报错

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param with_pics: 包含图片的 id
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典，如果为 ...，则忽略
    :param app: 使用某个 app （设备）的接口
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
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    def gen_step():
        nonlocal ids
        ts = int(time())
        ids = set(ids)
        yield life_show(client, async_=async_, **request_kwargs)
        yield update_star(client, ids, async_=async_, **request_kwargs)
        if app in ("", "web", "desktop", "harmony"):
            get_base_url = cycle(("http://webapi.115.com", "https://webapi.115.com")).__next__
        else:
            get_base_url = cycle(("http://proapi.115.com", "https://proapi.115.com")).__next__
        request_kwargs.setdefault("base_url", get_base_url)
        discard = ids.discard
        it = iter_life_behavior_once(
            client, 
            from_time=ts, 
            type="star_file", 
            app=app, 
            cooldown=cooldown, 
            async_=async_, 
            **request_kwargs, 
        )
        if with_pics:
            it2 = iter_life_behavior_once(
                client, 
                from_time=ts, 
                type="star_image_file", 
                app=app, 
                cooldown=cooldown, 
                async_=async_, 
                **request_kwargs, 
            )
            if async_:
                it = async_chain(it, it2)
            else:
                it = chain(it, it2) # type: ignore
        do_next = anext if async_ else next
        try:
            while True:
                event: dict = yield do_next(it) # type: ignore
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
        except (StopIteration, StopAsyncIteration):
            pass
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def iter_selected_dirs_using_star(
    client: str | P115Client, 
    ids: Iterable[int], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    already_stared: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_selected_dirs_using_star(
    client: str | P115Client, 
    ids: Iterable[int], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    already_stared: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_selected_dirs_using_star(
    client: str | P115Client, 
    ids: Iterable[int], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "web", 
    cooldown: int | float = 0, 
    already_stared: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """通过打星标来获取一组 id 的信息（仅支持目录）

    .. caution::
        如果 id 已经被删除，则打星标时会报错

    :param client: 115 客户端或 cookies
    :param ids: 一组目录的 id（如果包括文件，则会被忽略）
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param already_stared: 说明所有 id 都已经打过星标，不用再次打星标
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    def gen_step():
        nonlocal ids
        ts = int(time())
        ids = set(ids)
        if not already_stared:
            yield update_star(client, ids, async_=async_, **request_kwargs)
        yield update_desc(client, ids, async_=async_, **request_kwargs)
        discard = ids.discard
        it = iter_stared_dirs(
            client, 
            order="user_utime", 
            asc=0, 
            first_page_size=len(ids), 
            id_to_dirnode=id_to_dirnode, 
            normalize_attr=normalize_attr, 
            app=app, 
            cooldown=cooldown, 
            async_=async_, # type: ignore
            **request_kwargs, 
        )
        do_next = anext if async_ else next
        try:
            while True:
                info: dict = yield do_next(it) # type: ignore
                if normalize_attr is None:
                    attr: Any = _overview_attr(info)
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
        except (StopIteration, StopAsyncIteration):
            pass
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def iter_files_with_dirname(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    with_parents_4_level: bool = False, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0.5, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files_with_dirname(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    with_parents_4_level: bool = False, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0.5, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_with_dirname(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    with_parents_4_level: bool = False, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0.5, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息（包含 "dir_name" 和 "dir_pickcode"，即目录的名字和提取码，根目录名字和提取码都是 ""）

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
        - 99: 仅文件

    :param order: 排序

        - "file_name": 文件名
        - "file_size": 文件大小
        - "file_type": 文件种类
        - "user_utime": 修改时间
        - "user_ptime": 创建时间
        - "user_otime": 上一次打开时间

    :param asc: 升序排列。0: 否，1: 是
    :param with_parents_4_level: 添加一个字段 "parents"，包含最近的 4 级父目录名字
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅文件）文件信息
    """
    suffix = suffix.strip(".")
    if not (type or suffix):
        raise ValueError("please set the non-zero value of suffix or type")
    payload: dict = {
        "asc": asc, "cid": cid, "count_folders": 0, "cur": 0, "o": order, 
        "offset": 0, "show_dir": 0, 
    }
    if suffix:
        payload["suffix"] = suffix
    elif type != 99:
        payload["type"] = type
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    request_kwargs.update(
        page_size=page_size, 
        app=app, 
        raise_for_changed_count=raise_for_changed_count, 
    )
    if cooldown <= 0:
        request_kwargs["async_"] = async_
        func: Callable = iter_fs_files
    else:
        request_kwargs["cooldown"] = cooldown
        request_kwargs["max_workers"] = max_workers
        func = iter_fs_files_asynchronized if async_ else iter_fs_files_threaded
    pid_to_info = {0: {"dir_name": "", "dir_pickcode": ""}}
    def callback(resp: dict, /):
        files = resp["data"] = list(map(normalize_attr, resp["data"]))
        pids = (pid for a in files if (pid := a["parent_id"]) not in pid_to_info)
        if async_:
            async def request():
                async for info in iter_nodes_skim(
                    client, 
                    pids, 
                    async_=True, 
                    **request_kwargs, 
                ):
                    pid_to_info[int(info["file_id"])] = {
                        "dir_name": info["file_name"], 
                        "dir_pickcode": info["pick_code"], 
                    }
            return request()
        else:
            pid_to_info.update(
                (int(info["file_id"]), {
                    "dir_name": info["file_name"], 
                    "dir_pickcode": info["pick_code"], 
                })
                for info in iter_nodes_skim(
                    client, 
                    pids, 
                    **request_kwargs, 
                )
            )
    def gen_step():
        it = func(client, payload, callback=callback, **request_kwargs)
        get_next = it.__anext__ if async_ else it.__next__
        try:
            while True:
                resp = yield get_next()
                for attr in resp["data"]:
                    attr.update(pid_to_info[attr["parent_id"]])
                    yield Yield(attr)
        except (StopIteration, StopAsyncIteration):
            pass
    if with_parents_4_level:
        def gen_step2():
            files: list[dict] = []
            add_file = files.append
            def get_pid(attr):
                add_file(attr)
                return attr["parent_id"]
            it = iter_parents_3_level(
                client, 
                iter_unique((async_map if async_ else map)( 
                    get_pid, run_gen_step_iter(gen_step, may_call=False, async_=async_))), # type: ignore
                async_=async_, # type: ignore
                **request_kwargs, 
            )
            if async_:
                async def collect():
                    return {k: v async for k, v in cast(AsyncIterator, it)}
                id_to_parents: dict[int, tuple[str, str, str]] = yield collect()
            else:
                id_to_parents = dict(it) # type: ignore
            id_to_parents[0] = ("", "", "")
            for attr in files:
                attr["parents"] = (attr["dir_name"], *id_to_parents[attr["parent_id"]])
                yield Yield(attr)
        return run_gen_step_iter(gen_step2, may_call=False, async_=async_)
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def iter_files_with_path(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0.5, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files_with_path(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0.5, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_with_path(
    client: str | P115Client, 
    cid: int = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0.5, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息（包含 "path"，可选 "ancestors"）

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
        - 99: 仅文件

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
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅文件）文件信息
    """
    suffix = suffix.strip(".")
    if not (type or suffix):
        raise ValueError("please set the non-zero value of suffix or type")
    if isinstance(client, str):
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
    _path_already: None | bool = None if path_already else False
    if not path_already:
        from .download import iter_download_nodes
        def set_path_already(*_):
            nonlocal _path_already
            _path_already = True
        def fetch_dirs(id: int | str, /):
            if id:
                if isinstance(id, int):
                    resp = yield client.fs_file_skim(id, async_=async_, **request_kwargs)
                    check_response(resp)
                    pickcode = resp["data"][0]["pick_code"]
                else:
                    pickcode = id
                with with_iter_next(iter_download_nodes(
                    client, 
                    pickcode, 
                    files=False, 
                    max_workers=None, 
                    async_=async_, 
                    **request_kwargs, 
                )) as get_next:
                    while True:
                        info = yield get_next()
                        id_to_dirnode[int(info["fid"])] = DirNode(info["fn"], int(info["pid"]))
            else:
                with with_iter_next(iterdir(
                    client, 
                    ensure_file=False, 
                    id_to_dirnode=id_to_dirnode, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )) as get_next:
                    while True:
                        attr = yield get_next()
                        yield run_gen_step(fetch_dirs(attr["pickcode"]), may_call=False, async_=async_)
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
    def update_path(attr: dict, /) -> dict:
        try:
            if with_ancestors:
                attr["ancestors"] = get_ancestors(attr["id"], attr)
            attr["path"] = get_path(attr)
        except KeyError:
            pass
        return attr
    def gen_step():
        nonlocal _path_already
        cache: list[dict] = []
        add_to_cache = cache.append
        if not path_already:
            if async_:
                task: Any = create_task(run_gen_step(fetch_dirs(cid), may_call=False, async_=True))
            else:
                task = run_as_thread(run_gen_step, fetch_dirs(cid))
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
                if _path_already is None:
                    yield Yield(update_path(attr))
                elif _path_already:
                    if async_:
                        yield task
                    else:
                        task.result()
                    if cache:
                        yield YieldFrom(map(update_path, cache))
                        cache.clear()
                    yield Yield(update_path(attr))
                    _path_already = None
                else:
                    add_to_cache(attr)
        if cache:
            if async_:
                yield task
            else:
                task.result()
            yield YieldFrom(map(update_path, cache))
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def iter_files_with_path_by_export_dir(
    client: str | P115Client, 
    cid: int, 
    escape: None | bool | Callable[[str], str] = True, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files_with_path_by_export_dir(
    client: str | P115Client, 
    cid: int, 
    escape: None | bool | Callable[[str], str] = True, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_with_path_by_export_dir(
    client: str | P115Client, 
    cid: int, 
    escape: None | bool | Callable[[str], str] = True, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取文件信息（包含 "path"）

    .. important::
        相比较于 `iter_files`，这个函数专门针对获取路径的风控问题做了优化，会用到 导出目录树，尝试进行匹配，不能唯一确定的，会再用其它办法获取路径

    .. note::
        通过几个步骤一点点减少要检查的数据量：

        1. unique name: 导出目录树中，唯一出现的名字，就可以直接确定同一个目录下所有节点的路径
        2. unique listdir: 导出目录树中，一个目录下所有名字（可以理解为 listdir）的组合，只要它是唯一的，就能唯一确定同一个目录下所有节点的路径
        3. repeat 1-2 for higher dir: 引入目录的名字后，再考虑 `1` 和 `2`，又可排除掉一部分
        4. repeat 3: 通过反复引入更高层级的目录名字，反复执行 `3`，最后总能确定完整路径，最坏的情况就是直到 `cid` 为止才把所有未定项确定

    :param client: 115 客户端或 cookies
    :param cid: 目录 id，不能为 0 （受限于 export_dir 接口）
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅文件）文件信息
    """
    from .export_dir import export_dir, export_dir_parse_iter, parse_export_dir_as_patht_iter
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    def gen_step():
        append = list.append
        # 首先启动导出目录的后台任务
        export_id = yield export_dir(client, cid, async_=async_, **request_kwargs)
        # 名字 到 parent_id 的映射，如果名字不唯一，则 parent_id 设为 0
        name_to_pid: dict[str, int] = {}
        # 获取指定目录树下的所有文件节点信息，再根据 parent_id 分组
        pid_to_files: defaultdict[int, list[dict]] = defaultdict(list)
        def update_name_to_pid(attr: dict, /):
            pid = attr["parent_id"]
            name = attr["name"]
            append(pid_to_files[pid], attr)
            if name in name_to_pid:
                name_to_pid[name] = 0
            else:
                name_to_pid[name] = pid
        yield foreach(
            update_name_to_pid, 
            iter_files(
                client, 
                cid, 
                app="android", 
                cooldown=0.5, 
                async_=async_, # type: ignore
                **request_kwargs, 
            ), 
        )
        # 从导出的目录树文件中获取完整路径，再根据所归属目录的路径对名字进行分组
        dirpatht_to_names: dict[tuple[str, ...], list[str]] = defaultdict(list)
        def update_dirpatht_to_names(patht: list[str], /):
            append(dirpatht_to_names[tuple(patht[:-1])], patht[-1])
        yield foreach(
            update_dirpatht_to_names, 
            export_dir_parse_iter(
                client, 
                export_id=export_id, 
                parse_iter=parse_export_dir_as_patht_iter, 
                async_=async_, # type: ignore
                **request_kwargs, 
            ), 
        )
        if not name_to_pid or not dirpatht_to_names:
            return
        # 尽量从所收集到名字中移除目录
        for dir_patht in islice(dirpatht_to_names, 1, None):
            dirpatht_to_names[dir_patht[:-1]].remove(dir_patht[-1])
        # 收集所有名字到所归属目录的路径
        name_to_dirpatht: dict[str, tuple[str, ...]] = {}
        for dir_patht, names in dirpatht_to_names.items():
            for name in names:
                if name in name_to_dirpatht:
                    name_to_dirpatht[name] = ()
                else:
                    name_to_dirpatht[name] = dir_patht
        # 用唯一出现过的名字，尽量确定所有 parent_id 所对应的路径
        pid_to_dirpatht: dict[int, tuple[str, ...]] = {}
        undetermined: dict[tuple[str, ...], tuple[str, ...]] = {}
        for dir_patht, names in dirpatht_to_names.items():
            if not names:
                continue
            for name in names:
                if (pid := name_to_pid.get(name)) and name_to_dirpatht[name]:
                    pid_to_dirpatht[pid] = dir_patht
                    break
            else:
                names.sort()
                group_key = tuple(names)
                if group_key in undetermined:
                    undetermined[group_key] = ()
                else:
                    undetermined[group_key] = dir_patht
                def detect_file(name: str, /) -> bool:
                    if ext := splitext(name)[-1][1:]:
                        return bool(ext.strip(digits)) and ext.isalnum()
                    return False
                group_key2 = tuple(filter(detect_file, names))
                if group_key != group_key2:
                    if group_key2 in undetermined:
                        undetermined[group_key2] = ()
                    else:
                        undetermined[group_key2] = dir_patht
        # 假设文件名列表相同，就关联 parent_id 到它的路径（注意：这有可能出错，例如有空目录和某个文件同名时）
        if pids := pid_to_files.keys() - pid_to_dirpatht.keys():
            for pid in pids:
                group_key = tuple(sorted(attr["name"] for attr in pid_to_files[pid]))
                if dir_patht := undetermined.get(group_key, ()):
                    pid_to_dirpatht[pid] = dir_patht
            pids = pid_to_files.keys() - pid_to_dirpatht.keys()
            if pids:
                for dir_patht in pid_to_dirpatht.values():
                    del dirpatht_to_names[dir_patht]
        del name_to_pid, name_to_dirpatht, undetermined
        def update_pid_dict(info: dict, /):
            fid = int(info["file_id"])
            if name in name_to_pid:
                name_to_pid[name] = 0
            else:
                name_to_pid[name] = fid
            id_to_pickcode[fid] = info["pick_code"]
        id_to_dirnode: dict[int, tuple[str, int] | DirNode] = {}
        go_back_depth = 1
        while pids:
            id_to_pickcode: dict[int, str] = {}
            name_to_pid = {}
            yield foreach(
                update_pid_dict, 
                iter_nodes_skim(client, pids, async_=async_, **request_kwargs), 
            )
            name_idx = -go_back_depth
            name_to_dirpatht = {}
            name_to_list_dirpatht: dict[str, list[tuple[str, ...]]] = defaultdict(list)
            for dir_patht in dirpatht_to_names:
                if len(dir_patht) > go_back_depth:
                    name = dir_patht[name_idx]
                    append(name_to_list_dirpatht[name], dir_patht)
                    dir_patht = dir_patht[:name_idx]
                    if name in name_to_dirpatht:
                        if name_to_dirpatht[name] != dir_patht:
                            name_to_dirpatht[name] = ()
                    else:
                        name_to_dirpatht[name] = dir_patht
            for name, pid in name_to_pid.items():
                if dir_patht := name_to_dirpatht.get(name, ()):
                    pid_to_dirpatht[pid] = dir_patht
                    for dir_patht in name_to_list_dirpatht[name]:
                        del dirpatht_to_names[dir_patht]
                    del id_to_pickcode[pid]
            # TODO: 再用掉名字组合后也是唯一的部分路径
            # TODO: 再用掉名字组合后唯一的部分路径组合
            if len(id_to_pickcode) >= 1000:
                yield through(iter_selected_nodes_using_star_event(
                    client, 
                    id_to_pickcode, 
                    normalize_attr=None, 
                    id_to_dirnode=id_to_dirnode, 
                    app="android", 
                    cooldown=0.5, 
                    async_=async_, # type: ignore
                    **request_kwargs, 
                ))
            else:
                yield through(iter_selected_nodes_by_pickcode(
                    client, 
                    id_to_pickcode.values(), 
                    normalize_attr=None, 
                    id_to_dirnode=id_to_dirnode, 
                    ignore_deleted=None, 
                    async_=async_, # type: ignore
                    **request_kwargs, 
                ))
            pids = {
                pid for id in id_to_pickcode
                if (pid := id_to_dirnode[id][1]) and pid not in id_to_dirnode and pid not in pid_to_dirpatht
            }
            go_back_depth += 1
        for pid in pid_to_files.keys() - pid_to_dirpatht.keys():
            if pid not in id_to_dirnode:
                continue
            ls_pid = [pid]
            name, pid = id_to_dirnode[pid]
            names = [name]
            dir_patht = ()
            while pid:
                if pid in pid_to_dirpatht:
                    dir_patht = pid_to_dirpatht[pid]
                    break
                append(ls_pid, pid)
                name, pid = id_to_dirnode[pid]
                append(names, name)
            else:
                if not pid:
                    dir_patht = ("",)
            if dir_patht:
                ls_pid.reverse()
                names.reverse()
                for pid, name in zip(ls_pid, names):
                    dir_patht = pid_to_dirpatht[pid] = (*dir_patht, name)
        del id_to_dirnode, dirpatht_to_names
        # 迭代地返回所有文件节点信息
        for pid, files in pid_to_files.items():
            if pid not in pid_to_dirpatht:
                continue
            dir_patht = pid_to_dirpatht[pid]
            dir_path = joins(dir_patht) + "/"
            for attr in files:
                name = attr["name"]
                if escape is not None:
                    name = escape(name)
                attr["path"] = dir_path + name
                yield Yield(attr)
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def iter_parents_3_level(
    client: str | P115Client, 
    ids: Iterable[int], 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[tuple[int, tuple[str, str, str]]]:
    ...
@overload
def iter_parents_3_level(
    client: str | P115Client, 
    ids: Iterable[int] | AsyncIterable[int], 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[int, tuple[str, str, str]]]:
    ...
def iter_parents_3_level(
    client: str | P115Client, 
    ids: Iterable[int] | AsyncIterable[int], 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[tuple[int, tuple[str, str, str]]] | AsyncIterator[tuple[int, tuple[str, str, str]]]:
    """获取一批 id 的上级目录，最多获取 3 级

    :param client: 115 客户端或 cookies
    :param ids: 一批文件或目录的 id
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生 id 和 最近 3 级目录名的元组的 2 元组
    """
    if isinstance(client, str):
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
        ret = batch_map(call, (2, 3), max_workers=2)
        if async_:
            ret = yield to_list(ret)
        resp2, resp3 = cast(Iterable, ret)
        l2 = [d["file_name"] for d in resp2["data"]]
        l3 = (d["file_name"] for d in resp3["data"])
        return ((id, fix_overflow(t)) for id, t in zip(ids, zip(l3, l2, l1)))
    batch_map = taskgroup_map if async_ else threadpool_map
    ids = (async_filter if async_ else filter)(None, ids) # type: ignore
    return flatten(
        batch_map(
            lambda ids, /: run_gen_step(get_parents(ids), may_call=False, async_=async_), 
            chunked(ids, 1150), 
            max_workers=max_workers, 
        ), 
        exclude_types=tuple, 
    )


@overload
def iter_dir_nodes(
    client: str | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_dir_nodes(
    client: str | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_dir_nodes(
    client: str | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """遍历目录树，获取目录节点信息（简略）

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param max_workers: 最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅目录）文件信息
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    from .download import iter_download_nodes
    def gen_step(id: int | str, /):
        if id:
            if isinstance(id, int):
                resp = yield client.fs_file_skim(id, async_=async_, **request_kwargs)
                check_response(resp)
                pickcode = resp["data"][0]["pick_code"]
            else:
                pickcode = id
            with with_iter_next(iter_download_nodes(
                client, 
                pickcode, 
                files=False, 
                max_workers=max_workers, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next_info:
                while True:
                    info = yield get_next_info()
                    id = int(info["fid"])
                    parent_id = int(info["pid"])
                    name = info["fn"]
                    if id_to_dirnode is not ...:
                        id_to_dirnode[id] = DirNode(name, parent_id)
                    yield Yield(
                        {"id": id, "parent_id": parent_id, "name": name}
                    )
        else:
            with with_iter_next(iterdir(
                client, 
                ensure_file=False, 
                normalize_attr=normalize_attr_simple, 
                id_to_dirnode=id_to_dirnode, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                while True:
                    attr = yield get_next()
                    yield Yield(
                        {
                            "id": attr["id"], 
                            "parent_id": attr["parent_id"], 
                            "name": attr["name"], 
                        }
                    )
                    yield YieldFrom(run_gen_step_iter(
                        gen_step(attr["pickcode"]), 
                        may_call=False, 
                        async_=async_, 
                    ))
    return run_gen_step_iter(gen_step(cid or 0), may_call=False, async_=async_)


@overload
def search_for_any_file(
    client: str | P115Client, 
    cid: int = 0, 
    search_value: str = ".", 
    suffix: str = "", 
    type: int = 99, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> bool:
    ...
@overload
def search_for_any_file(
    client: str | P115Client, 
    cid: int = 0, 
    search_value: str = ".", 
    suffix: str = "", 
    type: int = 99, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, bool]:
    ...
def search_for_any_file(
    client: str | P115Client, 
    cid: int = 0, 
    search_value: str = ".", 
    suffix: str = "", 
    type: int = 99, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> bool | Coroutine[Any, Any, bool]:
    """搜索以判断是否存在某种文件

    :param client: 115 客户端或 cookies
    :param cid: 目录 id
    :param search_value: 搜索关键词，搜索到的文件名必须包含这个字符串
    :param suffix: 后缀名（优先级高于 type）
    :param type: 文件类型

        - 1: 文档
        - 2: 图片
        - 3: 音频
        - 4: 视频
        - 5: 压缩包
        - 6: 应用
        - 7: 书籍
        - 99: 仅文件

    :param app: 使用某个 app （设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 是否存在某种文件
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if not isinstance(client, P115Client) or app == "open":
        fs_search: Callable = client.fs_search_open
    elif app in ("", "web", "desktop", "harmony"):
        fs_search = partial(client.fs_search, app=app)
    else:
        fs_search = client.fs_search_app
    def gen_step():
        resp = yield fs_search(
            {"cid": cid, "limit": 1, "search_value": search_value, "suffix": suffix, "type": type}, 
            async_=async_, 
            **request_kwargs, 
        )
        check_response(resp)
        return bool(resp["data"])
    return run_gen_step(gen_step, may_call=False, async_=async_)

