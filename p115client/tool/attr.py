#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "get_attr", "type_of_attr", 
    "get_path_to_cid", "get_file_count", "get_ancestors", 
    "get_ancestors_to_cid", "get_id_to_path", "get_id_to_sha1", 
    "share_get_id_to_path", 
]
__doc__ = "这个模块提供了一些和文件或目录信息有关的函数"

# TODO: 至少要达到让 p115tinydb 直接可用的程度
# TODO: 要获取某个 id 对应的路径，可以先用 fs_file_skim 或 fs_info 看一下是不是存在，以及是不是文件，然后再选择响应最快的办法获取
# TODO: 创造函数 get_id, get_parent_id, get_ancestors, get_sha1, get_pickcode, get_path 等，支持多种类型的参数，目前已有的名字太长，需要改造，甚至转为私有
# TODO: 路径表示法，应该支持 / 和 > 开头，而不仅仅是 / 开头

from collections.abc import Callable, Coroutine, Mapping, MutableMapping, Sequence
from functools import partial
from errno import ENOENT, ENOTDIR
from os import PathLike
from string import hexdigits
from types import EllipsisType
from typing import cast, overload, Any, Literal

from iterutils import run_gen_step, with_iter_next
from p115client import check_response, normalize_attr_web, P115Client, P115OpenClient
from p115client.const import CLASS_TO_TYPE, SUFFIX_TO_TYPE, ID_TO_DIRNODE_CACHE
from p115client.type import P115ID
from p115pickcode import to_id
from posixpatht import path_is_dir_form, splitext, splits

from .iterdir import iterdir, share_iterdir, update_resp_ancestors
from .util import posix_escape_name, share_extract_payload, unescape_115_charref


@overload
def get_attr(
    client: str | PathLike | P115Client, 
    id: int | str, 
    skim: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def get_attr(
    client: str | PathLike | P115Client, 
    id: int | str, 
    skim: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def get_attr(
    client: str | PathLike | P115Client, 
    id: int | str, 
    skim: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取文件或目录的信息

    .. note::
        不要传入根目录，即不能是 0 或 ""

    :param client: 115 客户端或 cookies
    :param id: 文件或目录的 id 或 pickcode
    :param skim: 是否获取简要信息（可避免风控）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 文件或目录的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    id = to_id(id)
    def gen_step():
        from dictattr import AttrDict
        if skim:
            resp = yield client.fs_file_skim(id, async_=async_, **request_kwargs)
            check_response(resp)
            info = resp["data"][0]
            return AttrDict(
                id=int(info["file_id"]), 
                name=info["file_name"], 
                pickcode=info["pick_code"], 
                sha1=info["sha1"], 
                size=int(info["file_size"]), 
                is_dir=not info["sha1"], 
            )
        else:
            resp = yield client.fs_file(id, async_=async_, **request_kwargs)
            check_response(resp)
            return normalize_attr_web(resp["data"][0], dict_cls=AttrDict)
    return run_gen_step(gen_step, async_)


def type_of_attr(attr: Mapping, /) -> int:
    """推断文件信息所属类型（试验版，未必准确）

    :param attr: 文件信息

    :return: 返回类型代码

        - 0: 目录
        - 1: 文档
        - 2: 图片
        - 3: 音频
        - 4: 视频
        - 5: 压缩包
        - 6: 应用
        - 7: 书籍
        - 99: 其它文件
"""
    if attr.get("is_dir"):
        return 0
    type: None | int
    if type := CLASS_TO_TYPE.get(attr.get("class", "")):
        return type
    if type := SUFFIX_TO_TYPE.get(splitext(attr["name"])[1].lower()):
        return type
    if attr.get("is_video") or "defination" in attr:
        return 4
    return 99




# TODO: 支持 open
@overload
def get_path_to_cid(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    root_id: None | int | str = None, 
    escape: None | bool | Callable[[str], str] = True, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> str:
    ...
@overload
def get_path_to_cid(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    root_id: None | int | str = None, 
    escape: None | bool | Callable[[str], str] = True, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, str]:
    ...
def get_path_to_cid(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    root_id: None | int | str = None, 
    escape: None | bool | Callable[[str], str] = True, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
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
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 目录对应的绝对路径或相对路径
    """
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
                id_to_dirnode[int(info["cid"])] = (info["name"], int(info["pid"]))
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
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    use_fs_files: bool = True, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def get_file_count(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    use_fs_files: bool = True, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def get_file_count(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    use_fs_files: bool = True, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """获取文件总数

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用指定 app（设备）的接口
    :param use_fs_files: 使用 `client.fs_files`，否则使用 `client.fs_category_get`
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 目录内的文件总数（不包括目录）
    """
    if isinstance(client, (str, PathLike)):
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
            update_resp_ancestors(resp, id_to_dirnode)
            return int(resp["count"])
        else:
            resp = yield get_resp_of_category_get(cid)
            resp = update_resp_ancestors(resp, id_to_dirnode, FileNotFoundError(ENOENT, cid))
            if resp["sha1"]:
                resp["cid"] = cid
                raise NotADirectoryError(ENOTDIR, resp)
            return int(resp["count"]) - int(resp.get("folder_count") or 0)
    return run_gen_step(gen_step, async_)


# TODO: 支持 open
# TODO: app 默认用 ""，会自动切换多个接口
@overload
def get_ancestors(
    client: str | PathLike | P115Client, 
    attr: int | str | dict, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> list[dict]:
    ...
@overload
def get_ancestors(
    client: str | PathLike | P115Client, 
    attr: int | str | dict, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, list[dict]]:
    ...
def get_ancestors(
    client: str | PathLike | P115Client, 
    attr: int | str | dict, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> list[dict] | Coroutine[Any, Any, list[dict]]:
    """获取某个节点对应的祖先节点列表（只有 id、parent_id 和 name 的信息）

    :param client: 115 客户端或 cookies
    :param attr: 待查询节点 id 或 pickcode 或信息字典（必须有 id，可选有 parent_id）
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
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
    if isinstance(client, (str, PathLike)):
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
                            id_to_dirnode[ans["id"]] = (ans["name"], ans["parent_id"])
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
                        id_to_dirnode[ans["id"]] = (ans["name"], ans["parent_id"])
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
                        id_to_dirnode[ans["id"]] = (ans["name"], ans["parent_id"])
                return ancestors
            else:
                resp = yield get_resp_of_category_get(fid)
                resp = update_resp_ancestors(resp, id_to_dirnode)
                for info in resp["paths"]:
                    add_ancestor({
                        "parent_id": pid, 
                        "id": (pid := int(info["file_id"])), 
                        "name": info["file_name"], 
                    })
                ans = {"id": fid, "parent_id": pid, "name": resp["file_name"]}
                add_ancestor(ans)
                if not resp.get("sha1") and id_to_dirnode is not ...:
                    id_to_dirnode[ans["id"]] = (ans["name"], ans["parent_id"])
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
                    id_to_dirnode[ans["id"]] = (ans["name"], ans["parent_id"])
        else:
            resp = yield get_resp_of_category_get(fid)
            resp = update_resp_ancestors(resp, id_to_dirnode)
            for info in resp["paths"]:
                add_ancestor({
                    "parent_id": pid, 
                    "id": (pid := int(info["file_id"])), 
                    "name": info["file_name"], 
                })
            ans = {"id": fid, "parent_id": pid, "name": resp["file_name"]}
            add_ancestor(ans)
            if not resp.get("sha1") and id_to_dirnode is not ...:
                id_to_dirnode[ans["id"]] = (ans["name"], ans["parent_id"])
        return ancestors
    return run_gen_step(gen_step, async_)


# TODO: 支持 open
# TODO: 合并到 get_ancestors
@overload
def get_ancestors_to_cid(
    client: str | PathLike | P115Client, 
    cid: int | str, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> list[dict]:
    ...
@overload
def get_ancestors_to_cid(
    client: str | PathLike | P115Client, 
    cid: int | str, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, list[dict]]:
    ...
def get_ancestors_to_cid(
    client: str | PathLike | P115Client, 
    cid: int | str, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> list[dict] | Coroutine[Any, Any, list[dict]]:
    """获取目录对应的祖先节点列表（只有 id、parent_id 和 name 的信息）

    :param client: 115 客户端或 cookies
    :param cid: 目录的 id 或 pickcode
    :param refresh: 是否刷新。如果为 True，则会执行网络请求以查询；如果为 False，则直接从 `id_to_dirnode` 中获取
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
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
    if isinstance(client, (str, PathLike)):
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
            elif app == "aps":
                return client.fs_files_aps(
                    {"cid": id, "limit": 1, "nf": 1, "star": 1}, 
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
                id_to_dirnode[id] = (name, pid)
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
    client: str | PathLike | P115Client | P115OpenClient, 
    path: str | Sequence[str], 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    dont_use_getid: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def get_id_to_path(
    client: str | PathLike | P115Client | P115OpenClient, 
    path: str | Sequence[str], 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    dont_use_getid: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def get_id_to_path(
    client: str | PathLike | P115Client | P115OpenClient, 
    path: str | Sequence[str], 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
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
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用指定 app（设备）的接口
    :param dont_use_getid: 不要使用 `client.fs_dir_getid` 或 `client.fs_dir_getid_app`，以便 `id_to_dirnode` 有缓存
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 文件或目录的 id
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    error = FileNotFoundError(ENOENT, f"no such path: {path!r}")
    def gen_step():
        nonlocal ensure_file, parent_id, path
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
        if not isinstance(client, P115Client) or app == "open":
            path = ">" + ">".join(patht)
            resp = yield client.fs_info_open(path, async_=async_, **request_kwargs)
            data = update_resp_ancestors(resp, id_to_dirnode)
            return P115ID(data["file_id"], data, about="path", path=path)
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


@overload
def get_id_to_sha1(
    client: str | PathLike | P115Client | P115OpenClient, 
    sha1: str, 
    app: str = "", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> P115ID:
    ...
@overload
def get_id_to_sha1(
    client: str | PathLike | P115Client | P115OpenClient, 
    sha1: str, 
    app: str = "", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, P115ID]:
    ...
def get_id_to_sha1(
    client: str | PathLike | P115Client | P115OpenClient, 
    sha1: str, 
    app: str = "", 
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
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    def gen_step():
        file_sha1 = sha1.upper()
        if app == "" and isinstance(client, P115Client):
            resp = yield client.fs_shasearch(sha1, async_=async_, **request_kwargs)
            check_response(resp)
            data = resp["data"]
        else:
            if not isinstance(client, P115Client) or app == "open":
                search: Callable = client.fs_search_open
            elif app in ("", "web", "desktop", "harmony"):
                search = client.fs_search
            else:
                search = partial(client.fs_search_app, app=app)
            resp = yield search(sha1, async_=async_, **request_kwargs)
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
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    path: str | Sequence[str] = "", 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def share_get_id_to_path(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    path: str | Sequence[str] = "", 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def share_get_id_to_path(
    client: str | PathLike | P115Client, 
    share_code: str, 
    receive_code: str = "", 
    path: str | Sequence[str] = "", 
    parent_id: int = 0, 
    ensure_file: None | bool = None, 
    is_posixpath: bool = False, 
    refresh: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
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
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 文件或目录的 id
    """
    if isinstance(client, (str, PathLike)):
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

