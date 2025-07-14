#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "get_path_to_cid", "get_file_count", "get_ancestors", 
    "get_ancestors_to_cid", "get_id_to_path", "get_id_to_sha1", 
    "share_get_id_to_path", 
    # TODO: 上面这些方法还需要调整
    "ID_TO_DIRNODE_CACHE", "DirNode", 
    "ensure_attr_path", "ensure_attr_path_using_star_event", 
    "iterdir", "iter_stared_dirs", "iter_dirs", "iter_dirs_with_path", 
    "iter_files", "iter_files_with_path", "iter_files_with_path_skim", 
    "iter_nodes", "iter_nodes_skim", "iter_nodes_by_pickcode", 
    "iter_nodes_using_update", "iter_nodes_using_info", 
    "iter_nodes_using_star_event",  "iter_dir_nodes_using_star", 
    "iter_parents", "iter_dupfiles", "iter_image_files", "search_iter", 
    "share_iterdir", "share_iter_files", "share_search_iter", 
]
__doc__ = "这个模块提供了一些和目录信息罗列有关的函数"

# TODO: 对于路径，增加 top_id 和 relpath 字段，表示搜素目录的 id 和相对于搜索路径的相对路径
# TODO: get_id* 这类方法，应该放在 attr.py，用来获取某个 id 对应的值（根本还是 get_attr）
# TODO: 创造函数 get_id, get_parent_id, get_ancestors, get_sha1, get_pickcode, get_path 等，支持多种类型的参数，目前已有的名字太长，需要改造，甚至转为私有，另外这些函数或许可以放到另一个包中，attr.py
# TODO: 去除掉一些并不便利的办法，然后加上 traverse 和 walk 方法，通过递归拉取（支持深度和广度优先遍历）
# TODO: 要获取某个 id 对应的路径，可以先用 fs_file_skim 或 fs_info 看一下是不是存在，以及是不是文件，然后再选择响应最快的办法获取

from asyncio import create_task, sleep as async_sleep
from collections import defaultdict
from collections.abc import (
    AsyncIterable, AsyncIterator, Callable, Coroutine, Iterable, 
    Iterator, Mapping, MutableMapping, Sequence, 
)
from dataclasses import dataclass
from errno import EIO, ENOENT, ENOTDIR
from functools import partial
from itertools import batched, cycle
from math import inf
from operator import itemgetter
from string import hexdigits
from time import sleep, time
from types import EllipsisType
from typing import cast, overload, Any, Final, Literal, NamedTuple
from warnings import warn

from asynctools import to_list
from concurrenttools import run_as_thread, taskgroup_map, threadpool_map, conmap
from iterutils import (
    as_gen_step, bfs_gen, chunked, chain, chain_from_iterable, collect, run_gen_step, 
    run_gen_step_iter, through, with_iter_next, map as do_map, filter as do_filter, 
    Yield, YieldFrom, 
)
from iter_collect import iter_keyed_dups, SupportsLT
from orjson import loads
from p115client import (
    check_response, normalize_attr, 
    P115Client, P115OpenClient, P115OSError, P115Warning, 
)
from p115client.type import P115ID
from p115pickcode import pickcode_to_id, to_id, to_pickcode
from posixpatht import path_is_dir_form, splitext, splits

from .attr import type_of_attr
from .edit import update_desc, update_star
from .fs_files import (
    is_timeouterror, iter_fs_files, iter_fs_files_threaded, 
    iter_fs_files_asynchronized, 
)
from .life import iter_life_behavior_once, life_show
from .util import (
    posix_escape_name, share_extract_payload, unescape_115_charref, 
)


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
    cid: int | str = 0, 
    root_id: None | int | str = None, 
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
    cid: int | str = 0, 
    root_id: None | int | str = None, 
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
    cid: int | str = 0, 
    root_id: None | int | str = None, 
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
    :param cid: 目录的 id 或 pickcode
    :param root_id: 根目录 id 或 pickcode，如果指定此参数且不为 None，则返回相对路径，否则返回绝对路径
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param refresh: 是否刷新。如果为 True，则会执行网络请求以查询；如果为 False，则直接从 `id_to_dirnode` 中获取
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用指定 app（设备）的接口
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
    if root_id is not None:
        root_id = to_id(root_id)
    def gen_step(cid: int = to_id(cid), /):
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
    return run_gen_step(gen_step, async_)


@overload
def get_file_count(
    client: str | P115Client, 
    cid: int | str = 0, 
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
    cid: int | str = 0, 
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
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    use_fs_files: bool = True, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """获取文件总数

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用指定 app（设备）的接口
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
    def gen_step(cid: int = to_id(cid), /):
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
                pid = int(resp["paths"][0]["file_id"])
                for info in resp["paths"][1:]:
                    node = DirNode(info["file_name"], pid)
                    id_to_dirnode[(pid := int(info["file_id"]))] = node
            return int(resp["count"]) - int(resp.get("folder_count") or 0)
    return run_gen_step(gen_step, async_)


@overload
def get_ancestors(
    client: str | P115Client, 
    attr: int | str | dict, 
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
    attr: int | str | dict, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, list[dict]]:
    ...
def get_ancestors(
    client: str | P115Client, 
    attr: int | str | dict, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> list[dict] | Coroutine[Any, Any, list[dict]]:
    """获取某个节点对应的祖先节点列表（只有 id、parent_id 和 name 的信息）

    :param client: 115 客户端或 cookies
    :param attr: 待查询节点 id 或 pickcode 或信息字典（必须有 id，可选有 parent_id）
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用指定 app（设备）的接口
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
        if isinstance(attr, dict):
            fid = cast(int, attr["id"])
            if not fid:
                return ancestors
            is_dir: None | bool = attr.get("is_dir")
            if is_dir is None and "pickcode" in attr:
                is_dir = not attr["pickcode"] or attr["pickcode"].startswith("f")
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
                    return ancestors
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
                return ancestors
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
                return ancestors
        else:
            fid = to_id(attr)
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
    return run_gen_step(gen_step, async_)


@overload
def get_ancestors_to_cid(
    client: str | P115Client, 
    cid: int | str, 
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
    cid: int | str, 
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
    cid: int | str, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> list[dict] | Coroutine[Any, Any, list[dict]]:
    """获取目录对应的祖先节点列表（只有 id、parent_id 和 name 的信息）

    :param client: 115 客户端或 cookies
    :param cid: 目录的 id 或 pickcode
    :param refresh: 是否刷新。如果为 True，则会执行网络请求以查询；如果为 False，则直接从 `id_to_dirnode` 中获取
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param app: 使用指定 app（设备）的接口
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
    def gen_step(cid: int = to_id(cid), /):
        parts: list[dict] = []
        add_part = parts.append
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
            add_part({"id": 0, "name": "", "parent_id": 0})
            for info in resp["path"][1:]:
                id, pid, name = int(info["cid"]), int(info["pid"]), info["name"]
                id_to_dirnode[id] = DirNode(name, pid)
                add_part({"id": id, "name": name, "parent_id": pid})
        else:
            while cid:
                id = cid
                name, cid = id_to_dirnode[cid]
                add_part({"id": id, "name": name, "parent_id": cid})
            add_part({"id": 0, "name": "", "parent_id": 0})
            parts.reverse()
        return parts
    return run_gen_step(gen_step, async_)


# TODO: 使用 search 接口以在特定目录之下搜索某个名字，以便减少风控
# TODO: open 接口可以立即获得结果（如果名字里面包含/，就用>做分隔符）
# TODO: 立即支持几种形式，分隔符可以是 / 和 > 或 " > "
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
    :param app: 使用指定 app（设备）的接口
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
    return run_gen_step(gen_step, async_)


# TODO: 支持 open 接口
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
    :param app: 使用指定 app（设备）的接口
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
    return run_gen_step(gen_step, async_)



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
    :param share_code: 分享码或链接
    :param receive_code: 接收码
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
    def gen_step():
        nonlocal ensure_file, parent_id, id_to_dirnode
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
        request_kwargs.update(payload)
        error = FileNotFoundError(ENOENT, f"no such path: {path!r}")
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
    return run_gen_step(gen_step, async_)











@overload
def ensure_attr_path[D: dict](
    client: str | P115Client | P115OpenClient, 
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
    client: str | P115Client | P115OpenClient, 
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
    client: str | P115Client | P115OpenClient, 
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
    if isinstance(client, str):
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
    @as_gen_step
    def ensure_path(attr: dict, /):
        id  = attr["id"]
        pid = attr["parent_id"]
        while pid and pid in id_to_dirnode:
            pid = id_to_dirnode[pid][1]
        if pid and pid not in dangling_id_to_name:
            cur_id = pid
            resp = yield get_info(pid, async_=async_, **request_kwargs)
            if app == "open":
                check_response(resp)
                resp = resp["data"] 
            if not resp:
                dangling_id_to_name[pid] = ""
                return attr
            paths = resp["paths"]
            info: dict = paths[0]
            if pid := int(info["file_id"]):
                dangling_id_to_name[pid] = info["file_name"]
            for info in paths[1:]:
                fid = int(info["file_id"])
                id_to_dirnode[fid] = DirNode(info["file_name"], pid)
                pid = fid
            id_to_dirnode[pid] = DirNode(resp["file_name"], pid)
            if not resp["sha1"]:
                id_to_dirnode[cur_id] = DirNode(resp["file_name"], pid)
        attr["path"] = get_path(attr)
        if with_ancestors:
            attr["ancestors"] = get_ancestors(id, attr)
        return attr
    return do_map(ensure_path, attrs)


@overload
def ensure_attr_path_using_star_event[D: dict](
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    if isinstance(client, str):
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
                    yield through(iter_nodes_using_star_event(
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
                attr["path"] = get_path(attr)
                if with_ancestors:
                    attr["ancestors"] = get_ancestors(attr["id"], attr)
                yield Yield(attr)
    return run_gen_step_iter(gen_step, async_)


@overload
def _iter_fs_files(
    client: str | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    with_dirname: bool = False, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = ..., 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "android", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def _iter_fs_files(
    client: str | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    with_dirname: bool = False, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = ..., 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "android", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def _iter_fs_files(
    client: str | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    with_dirname: bool = False, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = ..., 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    app: str = "android", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代目录，获取文件信息

    :param client: 115 客户端或 cookies
    :param payload: 请求参数（字典）或 id 或 pickcode
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小，如果 <= 0，则和 `page_size` 相同
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param ensure_file: 是否确保为文件

        - True: 必须是文件
        - False: 必须是目录
        - None: 可以是目录或文件

    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的文件信息（文件和目录）
    """
    if isinstance(client, str):
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
    request_kwargs.update(
        app=app, 
        page_size=page_size, 
        raise_for_changed_count=raise_for_changed_count, 
    )
    if not isinstance(client, P115Client):
        with_dirname = False
    if with_dirname:
        pid_to_name = {0: ""}
        def get_pid(info: dict, /):
            for key in ("parent_id", "pid", "cid"):
                if key in info:
                    return int(info[key])
            raise KeyError("parent_id", "pid", "cid")
        @as_gen_step
        def callback(resp: dict, /):
            pids = (
                pid for info in resp["data"] 
                if (pid := get_pid(info)) and pid not in pid_to_name
            )
            with with_iter_next(iter_nodes_skim(
                cast(P115Client, client), 
                pids, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                while True:
                    info = yield get_next()
                    pid_to_name[info["file_id"]] = info["file_name"]
        request_kwargs["callback"] = callback
    def gen_step():
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
        with with_iter_next(it) as get_next:
            while True:
                resp = yield get_next()
                if id_to_dirnode is not ...:
                    for info in resp["path"][1:]:
                        id_to_dirnode[int(info["cid"])] = DirNode(info["name"], int(info["pid"]))
                for info in resp["data"]:
                    if normalize_attr is None:
                        attr: dict | OverviewAttr = _overview_attr(info)
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
                    yield Yield(info)
    return run_gen_step_iter(gen_step, async_)


@overload
def iterdir(
    client: str | P115Client | P115OpenClient, 
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
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iterdir(
    client: str | P115Client | P115OpenClient, 
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
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iterdir(
    client: str | P115Client | P115OpenClient, 
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
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
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
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
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
    client: str | P115Client | P115OpenClient, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_stared_dirs(
    client: str | P115Client | P115OpenClient, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_stared_dirs(
    client: str | P115Client | P115OpenClient, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
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
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    client: str | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = True, 
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
    client: str | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = True, 
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
    client: str | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = True, 
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
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
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
        return YieldFrom(ensure_attr_path(
            client, 
            attrs, 
            with_ancestors=with_ancestors, 
            escape=escape, 
            id_to_dirnode=id_to_dirnode, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        ))
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_files(
    client: str | P115Client | P115OpenClient, 
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
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files(
    client: str | P115Client | P115OpenClient, 
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
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files(
    client: str | P115Client | P115OpenClient, 
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
    cooldown: int | float = 0, 
    max_workers: None | int = None, 
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
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回此目录内的（仅文件）文件信息
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
    client: str | P115Client, 
    cid: int | str = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
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
    cid: int | str = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
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
    cid: int | str = 0, 
    page_size: int = 0, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    order: Literal["file_name", "file_size", "file_type", "user_utime", "user_ptime", "user_otime"] = "user_ptime", 
    asc: Literal[0, 1] = 1, 
    cur: Literal[0, 1] = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
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
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
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
                yield through(iter_download_nodes(
                    client, 
                    to_pickcode(id), 
                    files=False, 
                    id_to_dirnode=id_to_dirnode, 
                    max_workers=None, 
                    async_=async_, 
                    **request_kwargs, 
                ))
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
                        yield run_gen_step(fetch_dirs(attr["pickcode"]), async_)
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
    cid = to_id(cid)
    def gen_step():
        nonlocal _path_already
        cache: list[dict] = []
        add_to_cache = cache.append
        if not path_already:
            if async_:
                task: Any = create_task(run_gen_step(fetch_dirs(cid), True))
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
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_files_with_path_skim(
    client: str | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = True, 
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
    client: str | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = True, 
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
    client: str | P115Client, 
    cid: int | str = 0, 
    with_ancestors: bool = True, 
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

    :return: 迭代器，返回此目录内的（仅文件）文件信息
    """
    from .download import iter_download_nodes
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
        def set_path_already(*_):
            nonlocal _path_already
            _path_already = True
        @as_gen_step
        def fetch_dirs(id: int | str, /):
            if id:
                if cid:
                    do_next: Callable = anext if async_ else next
                    yield do_next(_iter_fs_files(
                        client, 
                        to_id(id), 
                        page_size=1, 
                        id_to_dirnode=id_to_dirnode, 
                        async_=async_, 
                        **request_kwargs, 
                    ))
                yield through(iter_download_nodes(
                    client, 
                    to_pickcode(id), 
                    files=False, 
                    id_to_dirnode=id_to_dirnode, 
                    max_workers=max_workers, 
                    async_=async_, 
                    **request_kwargs, 
                ))
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
                        yield fetch_dirs(attr["pickcode"])
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
    cid = to_id(cid)
    def gen_step():
        nonlocal _path_already
        cache: list[dict] = []
        add_to_cache = cache.append
        if not path_already:
            if async_:
                task: Any = create_task(fetch_dirs(cid))
            else:
                task = run_as_thread(fetch_dirs, cid)
            task.add_done_callback(set_path_already)
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
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_nodes(
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    if isinstance(client, str):
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
            attr = _overview_attr(info)
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
    client: str | P115Client, 
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
    client: str | P115Client, 
    ids: Iterable[int | str], 
    batch_size: int = 50_000, 
    max_workers: None | int = 1, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_skim(
    client: str | P115Client, 
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
    if isinstance(client, str):
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
            map(to_pickcode, pickcodes), 
            max_workers=max_workers, 
            kwargs=request_kwargs, 
            async_=async_, 
        )))


@overload
def iter_nodes_using_update(
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    if isinstance(client, str):
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
    client: str | P115Client | P115OpenClient, 
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
    client: str | P115Client | P115OpenClient, 
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
    client: str | P115Client | P115OpenClient, 
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
    if isinstance(client, str):
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
            pid = int(resp["paths"][0]["file_id"])
            for info in resp["paths"][1:]:
                fid = int(info["file_id"])
                id_to_dirnode[fid] = DirNode(info["file_name"], pid)
                pid = fid
            if resp["is_dir"]:
                id_to_dirnode[resp["id"]] = DirNode(resp["name"], pid)
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


@overload
def iter_nodes_using_star_event(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    with_pics: bool = False, 
    normalize_attr: None | bool | Callable[[dict], dict] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_using_star_event(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    with_pics: bool = False, 
    normalize_attr: None | bool | Callable[[dict], dict] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_using_star_event(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    with_pics: bool = False, 
    normalize_attr: None | bool | Callable[[dict], dict] = True, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "android", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """通过先打星标，然后收集这个操作事件，来获取一组 id 的信息

    .. caution::
        如果有任一 id 已经被删除，则打星标时会报错

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param with_pics: 包含图片的 id
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
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    def gen_step():
        nonlocal ids
        ts = int(time())
        ids = set(map(to_id, ids))
        yield life_show(client, async_=async_, **request_kwargs)
        yield update_star(client, ids, app=app, async_=async_, **request_kwargs)
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
            it = chain(
                it, 
                iter_life_behavior_once(
                    client, 
                    from_time=ts, 
                    type="star_image_file", 
                    app=app, 
                    cooldown=cooldown, 
                    async_=async_, 
                    **request_kwargs, 
                ), 
                async_=async_, # type: ignore
            )
        with with_iter_next(it) as get_next:
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
    client: str | P115Client, 
    ids: Iterable[int | str], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0, 
    max_workers: None | int = 1, 
    already_stared: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_dir_nodes_using_star(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0, 
    max_workers: None | int = 1, 
    already_stared: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_dir_nodes_using_star(
    client: str | P115Client, 
    ids: Iterable[int | str], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    raise_for_changed_count: bool = False, 
    app: str = "android", 
    cooldown: int | float = 0, 
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
    if isinstance(client, str):
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
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_parents(
    client: str | P115Client, 
    ids: Iterable[int], 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[tuple[int, tuple[str, str, str]]]:
    ...
@overload
def iter_parents(
    client: str | P115Client, 
    ids: Iterable[int] | AsyncIterable[int], 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[int, tuple[str, str, str]]]:
    ...
def iter_parents(
    client: str | P115Client, 
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
    @as_gen_step
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
        get_parents, 
        chunked(do_filter(None, ids), 1150), 
        max_workers=max_workers, 
        async_=async_, # type: ignore
    ))


@overload
def iter_dupfiles[K](
    client: str | P115Client, 
    cid: int | str = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[tuple[K, dict]]:
    ...
@overload
def iter_dupfiles[K](
    client: str | P115Client, 
    cid: int | str = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[tuple[K, dict]]:
    ...
def iter_dupfiles[K](
    client: str | P115Client, 
    cid: int | str = 0, 
    key: Callable[[dict], K] = itemgetter("sha1", "size"), 
    keep_first: None | bool | Callable[[dict], SupportsLT] = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    max_workers: None | int = None, 
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
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，大于 0，则使用此时间间隔执行并发
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，返回 key 和 重复文件信息 的元组
    """
    from .download import iter_download_nodes
    return iter_keyed_dups(
        iter_download_nodes(
            client, 
            cid, 
            files=True, 
            ensure_name=True, 
            id_to_dirnode=id_to_dirnode, 
            max_workers=max_workers, 
            app=app, 
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
            resp = yield client.fs_imglist_app(payload, async_=async_, **request_kwargs)
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
    client: str | P115Client | P115OpenClient, 
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
    client: str | P115Client | P115OpenClient, 
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
    client: str | P115Client | P115OpenClient, 
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
        - 99: 仅文件

    :param offset: 开始索引，从 0 开始，要求 <= 10,000
    :param page_size: 分页大小，要求 `offset + page_size <= 10,000`
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 返回文件信息，如果没有，则是 None
    """
    if isinstance(client, str):
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
    if isinstance(client, str):
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
                    oattr = _overview_attr(attr)
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
        it = share_iterdir(
            client, 
            **payload, 
            id_to_dirnode=id_to_dirnode, 
            async_=async_, 
            **request_kwargs, 
        )
        do_next: Callable = anext if async_ else next
        try:
            while True:
                attr = yield do_next(it)
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
        except (StopIteration, StopAsyncIteration):
            pass
    return run_gen_step(gen_step, async_)


@overload
def share_search_iter(
    client: str | P115Client, 
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
    client: str | P115Client, 
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
    client: str | P115Client, 
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
        - 99: 仅文件

    :param offset: 开始索引，从 0 开始，要求 <= 10,000
    :param page_size: 分页大小，要求 `offset + page_size <= 10,000`
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 返回文件信息，如果没有，则是 None
    """
    if isinstance(client, str):
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


'''
# TODO: 需要优化，大优化，优化不好，就删了
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
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
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
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
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
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
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
    :param app: 使用指定 app（设备）的接口
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
'''
