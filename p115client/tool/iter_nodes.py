#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "iter_nodes", "iter_nodes_by_file", "iter_nodes_by_file_skim", "iter_nodes_by_info", 
    "iter_nodes_by_supervision", "iter_nodes_by_update", "iter_nodes_by_event",  
    "iter_nodes_by_label", "iter_nodes_by_star", 
]
__doc__ = "这个模块提供了一些和罗列节点信息有关的函数"

from asyncio import sleep as async_sleep
from collections.abc import (
    AsyncIterator, Callable, Iterable, Iterator, Mapping, MutableMapping
)
from functools import partial
from itertools import batched
from os import PathLike
from time import sleep, time
from types import EllipsisType
from typing import cast, overload, Any, Literal
from uuid import uuid4
from warnings import warn

from concurrenttools import conmap
from iterutils import (
    as_gen_step, chain_from_iterable, run_gen_step_iter, with_iter_next, 
    map as do_map, filter as do_filter, Yield,  
)

from ..client import check_response, P115Client, P115OpenClient
from ..const import ID_TO_DIRNODE_CACHE
from ..exception import P115Warning
from ..util import posix_escape_name, unescape_115_charref
from .attr import (
    normalize_attr, normalize_attr_simple, _get_id, _get_pickcode, 
    update_resp_ancestors, overview_attr, OverviewAttr, 
)
from .edit import update_desc, update_star, post_event, update_label
from .fs_files import fs_files_iter
from .life import iter_life_behavior_once, life_show


@overload
def iter_nodes(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    hold_top: bool = True, 
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
def iter_nodes(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    hold_top: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    ensure_file: None | bool = None, 
    hold_top: bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    app: str = "web", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """迭代目录，获取文件信息

    .. tip::
        当 ``app="web"`` 时，还可以获取其它 ``aid`` 的文件列表，例如，你可以用下面的代码获取所有已经被永久删除且不超过 200 MB 的文件信息

        .. code:: python

            from p115client import P115Client
            from p115client.tool import iter_nodes

            client = P115Client.from_path()

            # NOTE: 你还可以指定 suffix 或 type，做进一步筛选
            files = list(iter_nodes(
                client, 
                {"aid": 120, "show_dir": 0, "max_size": 1024*1024*200}, 
                max_workers=None， 
            ))

        更进一步的，你还可以获取已经被删除的所有文件和一级目录，这些文件可以随时用于恢复（如果你知道怎么做的话）

        .. code:: python

            from p115client import P115Client
            from p115client.tool import iter_nodes
            client = P115Client.from_path()

            folders = list(iter_nodes(client, {"aid": 120, "nf": 1}, max_workers=None))
            files = list(iter_nodes(client, {"aid": 120, "show_dir": 0}, max_workers=None, cooldown=0.1))

    :param client: 115 客户端或 cookies
    :param payload: 请求参数（字典）或 id 或 pickcode
    :param page_size: 分页大小
    :param first_page_size: 首次拉取的分页大小，如果 <= 0，则和 `page_size` 相同
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param use_media_api: 是否使用 ``P115Client.fs_files_media`` 接口
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
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if isinstance(payload, (int, str)):
        payload = {"cid": _get_id(payload)}
    suffix = payload.get("suffix")
    if suffix:
        use_media_api = False
    show_files = bool(suffix or payload.get("type"))
    if show_files:
        payload.setdefault("show_dir", 0)
    if not ensure_file:
        payload["count_folders"] = 1
    if ensure_file:
        payload["show_dir"] = 0
        payload.setdefault("cur", 0 if show_files else 1)
    elif ensure_file is False:
        payload["show_dir"] = 1
        payload.setdefault("cur", 1)
        payload["nf"] = 1
    if payload.get("type") == 99:
        payload.pop("type", None)
    if payload.get("show_dir"):
        use_media_api = False
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    def gen_step():
        top_id = int(payload.get("cid") or 0)
        with with_iter_next(fs_files_iter(
            client, 
            payload, 
            page_size=page_size, 
            first_page_size=first_page_size, 
            app=app, 
            use_media_api=use_media_api, 
            raise_for_changed_count=raise_for_changed_count, 
            cooldown=cooldown, 
            max_workers=max_workers, 
            async_=async_, 
            **request_kwargs, 
        )) as get_next:
            while True:
                resp = yield get_next()
                if hold_top:
                    update_resp_ancestors(resp, id_to_dirnode)
                    if top_ancestors := resp.get("ancestors"):
                        if escape is None:
                            top_path = "/".join(a["name"] for a in top_ancestors)
                        else:
                            top_path = "/".join(escape(a["name"]) for a in top_ancestors)
                        if top_path:
                            topdir = top_path + "/"
                        else:
                            topdir = top_path = "/"
                for info in resp["data"]:
                    if normalize_attr is None:
                        attr: Mapping | OverviewAttr = overview_attr(info)
                    else:
                        attr = info = normalize_attr(info)
                    if attr["is_dir"]:
                        if id_to_dirnode is not ...:
                            id_to_dirnode[attr["id"]] = (attr["name"], attr["parent_id"])
                        if ensure_file is True:
                            continue
                    elif ensure_file is False:
                        continue
                    if hold_top:
                        info["top_id"]            = top_id
                        if top_ancestors:
                            info["top_ancestors"] = top_ancestors
                            info["top_path"]      = top_path
                    if attr["parent_id"] == top_id:
                        name = attr["name"]
                        if escape is not None:
                            name = escape(name)
                        if hold_top and top_ancestors:
                            info["ancestors"] = [
                                *top_ancestors, 
                                {"name": attr["name"], "id": attr["id"], "parent_id": top_id}, 
                            ]
                            info["path"] = topdir + name
                    yield Yield(info)
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_nodes_by_file(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_by_file(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_by_file(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    .. caution::
        风控比较严重，请谨慎使用

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def project(resp: dict, /) -> None | dict:
        if resp.get("code") == 20018:
            return None
        check_response(resp)
        info = resp["data"][0]
        if normalize_attr is None:
            return info
        return normalize_attr(info)
    return do_filter(None, do_map(
        project, 
        conmap(
            partial(client.fs_file, async_=async_, **request_kwargs), 
            map(_get_id, ids), 
            max_workers=max_workers, 
            async_=async_, # type: ignore
        ), 
    ))


@overload
def iter_nodes_by_file_skim(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    batch_size: int = 50_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_by_file_skim(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    batch_size: int = 50_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_by_file_skim(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    batch_size: int = 50_000, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组节点的简略信息

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，获取节点的简略信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def get_nodes(resp: dict, /) -> list[dict]:
        if resp.get("error") == "文件不存在":
            return []
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
            batched(map(_get_id, ids), batch_size), 
            max_workers=max_workers, 
            async_=async_, # type: ignore 
        ), 
    ))


@overload
def iter_nodes_by_info(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: Iterable[int | str | Mapping], 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_by_info(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: Iterable[int | str | Mapping], 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_by_info(
    client: str | PathLike | P115Client | P115OpenClient, 
    ids: Iterable[int | str | Mapping], 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    .. caution::
        风控比较严重，且速度较慢，请斟酌使用

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if not isinstance(client, P115Client) or app == "open":
        fs_info = client.fs_info_open
    elif app in ("", "web", "desktop", "aps"):
        fs_info = client.fs_category_get
    else:
        fs_info = client.fs_category_get_app
        request_kwargs["app"] = app
    def project(resp: dict, /) -> None | dict:
        if not resp or resp.get("errno") == 70005 or resp.get("data") == []:
            return None
        check_response(resp)
        return resp
    return do_filter(None, do_map(
        project, 
        conmap(
            partial(fs_info, async_=async_, **request_kwargs), 
            map(_get_id, ids), 
            max_workers=max_workers, 
            async_=async_, 
        )
    ))


# TODO: client.fs_document 也可以用来获取文件信息，单独做一个接口
@overload
def iter_nodes_by_supervision(
    client: str | PathLike | P115Client, 
    pickcodes: Iterable[str | int | Mapping], 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_by_supervision(
    client: str | PathLike | P115Client, 
    pickcodes: Iterable[str | int | Mapping], 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_by_supervision(
    client: str | PathLike | P115Client, 
    pickcodes: Iterable[str | int | Mapping], 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    :param client: 115 客户端或 cookies
    :param pickcodes: 一组文件或目录的 pickcode 或 id
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app in ("", "web", "desktop", "chrome", "aps"):
        fs_supervision = client.fs_supervision
    else:
        fs_supervision = client.fs_supervision_app
        request_kwargs["app"] = app
    def project(resp: dict, /) -> None | dict:
        if not resp["data"]["file_name"] if resp["state"] else resp.get("msg") == "必传参数少了":
            return None
        check_response(resp)
        return resp["data"]
    return do_filter(None, do_map(
        project, 
        conmap(
            partial(fs_supervision, async_=async_, **request_kwargs), 
            map(_get_pickcode, pickcodes), 
            max_workers=max_workers, 
            async_=async_, 
        )))


@overload
def iter_nodes_by_update(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_by_update(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_by_update(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    max_workers: None | int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一组 id 的信息

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def project(resp: dict, /) -> None | dict:
        if error := resp.get("error"):
            if "不存在" in error:
                return None
        check_response(resp)
        return resp["data"]
    return do_filter(None, do_map(
        project, 
        conmap(
            partial(client.fs_files_update_app, app=app, async_=async_, **request_kwargs), 
            map(_get_id, ids), 
            max_workers=max_workers, 
            async_=async_, 
        )
    ))


# TODO: 再增加一些其它事件，例如打星标、添加备注、浏览视频、浏览音频、重命名等，并且还要支持一种分块推送、拉取的模式，而不是一次性推送完，然后拉取
@overload
def iter_nodes_by_event(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    type: Literal["doc", "img"] = "img", 
    app: str = "web", 
    cooldown: float = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_by_event(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    type: Literal["doc", "img"] = "img", 
    app: str = "web", 
    cooldown: float = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_by_event(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    type: Literal["doc", "img"] = "img", 
    app: str = "web", 
    cooldown: float = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """通过先发送事件，然后收集这个事件，来获取一组 id 的信息

    .. note::
        如果未收集到事件，则说明文件 id 不存在或者已删除，你也可以因此找出所有的无效 id

    .. note::
        如果 ``app="web"``，则最多一次获取前 1 万条数据，此时必须克制 ``ids`` 的规模在 1 万以下

    :param client: 115 客户端或 cookies
    :param ids: 一组文件或目录的 id 或 pickcode
    :param type: 事件类型

        - "doc": 推送 "browse_document" 事件
        - "img": 推送 "browse_image" 事件

    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，大于 0 时，两次拉取操作事件的接口调用之间至少间隔这么多秒
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if type == "doc":
        event_name = "browse_document"
    else:
        event_name = "browse_image"
    def gen_step():
        nonlocal ids
        ts = int(time())
        ids = set(map(_get_id, ids))
        yield life_show(client, async_=async_, **request_kwargs)
        yield post_event(
            client, 
            ids, 
            type=type, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )
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
            while ids:
                event: dict = yield get_next()
                fid = int(event["file_id"])
                if fid in ids:
                    yield Yield(event)
                    discard(fid)
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_nodes_by_label(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    batch_size: int = 5_000, 
    max_workers: None | int = 0, 
    sleep_interval: float = 1, 
    no_deletion: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_by_label(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    batch_size: int = 5_000, 
    max_workers: None | int = 0, 
    sleep_interval: float = 1, 
    no_deletion: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_by_label(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    batch_size: int = 5_000, 
    max_workers: None | int = 0, 
    sleep_interval: float = 1, 
    no_deletion: bool = False, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """通过先加标签，然后用文件列表接口获取一组 id 的信息

    .. attention::
        为了速度和稳妥起见，使用 app 版的替换标签接口，也即如果原有标签，会被直接替换掉，由于不用此接口会导致遗漏，斟酌后定死

    :param client: 115 客户端或 cookies
    :param ids: 一组目录的 id 或 pickcode（如果包括文件，则会被忽略）
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param batch_size: 批次大小，分批次，每次提交的 id 数
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param sleep_interval: 拉取文件列表时，发现文件数不对时，睡眠一定时间后重试
    :param no_deletion: 确定所有 id 都是有效的，不会有已被删除的
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if batch_size <= 0:
        batch_size = 5_000
    elif batch_size > 10_000:
        batch_size = 10_000
    if max_workers is None or max_workers < 0:
        if async_:
            max_workers = 32
        else:
            from os import process_cpu_count
            max_workers = min(32, (process_cpu_count() or 1) + 4)
    is_webapi = app in ("", "web", "desktop", "aps")
    @as_gen_step
    def get_response(batch, /):
        label_name = uuid4().bytes.decode("latin-1")
        if is_webapi:
            resp = yield client.fs_label_add(
                label_name, 
                async_=async_, 
                **request_kwargs, 
            )
        else:
            resp = yield client.fs_label_add_app(
                label_name, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
        check_response(resp)
        label_id = int(resp["data"][0]["id"])
        try:
            yield update_label(
                client, 
                batch, 
                label_id, 
                async_=async_, 
                **request_kwargs, 
            )
            count = -1
            size = len(batch)
            while True:
                if is_webapi:
                    resp = yield client.fs_search(
                        {"file_label": label_id, "limit": 1}, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                else:
                    resp = yield client.fs_search_app(
                        {"file_label": label_id, "limit": 1}, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                check_response(resp)
                count_ = resp["count"]
                if count_ == size or not no_deletion and count_ == count:
                    if is_webapi:
                        resp = yield client.fs_label_files(
                            {"label_id": label_id, "limit": size}, 
                            async_=async_, 
                            **request_kwargs, 
                        )
                    elif size <= 1150:
                        resp = yield client.fs_search_app(
                            {"file_label": label_id, "limit": size}, 
                            app=app, 
                            async_=async_, 
                            **request_kwargs, 
                        )
                    else:
                        # NOTE: 使用 search 接口，但还用 web 端接口，因为 app 端接口一次最多获取 1150 条
                        resp = yield client.fs_search(
                            {"file_label": label_id, "limit": size}, 
                            async_=async_, 
                            **request_kwargs, 
                        )
                    check_response(resp)
                    if count_ == (count_ := resp["count"]):
                        if count_ != size:
                            warn(f"{label_id=!r} may be missing data or deleted items, expected {size!r}, got {count_!r}", category=P115Warning)
                        break
                count = count_
                if sleep_interval > 0:
                    if async_:
                        yield async_sleep(sleep_interval)
                    else:
                        sleep(sleep_interval)
            if normalize_attr is None:
                return resp["data"]
            return map(normalize_attr, resp["data"])
        finally:
            if is_webapi:
                yield client.fs_label_del(
                    label_id, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                yield client.fs_label_del_app(
                    label_id, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )
    return chain_from_iterable(conmap(
        get_response, 
        batched(map(_get_id, ids), batch_size), 
        max_workers=max_workers, 
        async_=async_, 
    ))


# TODO: 可以分批处理，首先去除所有的星标，然后按批进行打星标和获取文件信息，获取完成后清空星标，如此可以控制规模，加快拉取速度
@overload
def iter_nodes_by_star(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_nodes_by_star(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_nodes_by_star(
    client: str | PathLike | P115Client, 
    ids: Iterable[int | str | Mapping], 
    normalize_attr: None | Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    cooldown: None | float = None, 
    max_workers: None | int = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """通过先打星标，然后用文件列表接口获取一组 id 的信息

    .. caution::
        在打星标后，随即还会把备注清空（借助于设置备注，以改变更新时间）

    .. caution::
        如果有任一 id 已经被删除，则打星标时会报错

    .. note::
        为稳妥起见，尽量只传入目录的 id，而不要有任何文件的 id，除非你确定用 web 端接口。
        目前只有 web 端的文件列表拉取接口，支持按打星标时间排序，其它能用上的，也就按照更新时间排序，也就是需要有个步骤来批量更新它们的更新时间，目前是利用更新备注来引发改变更新时间，但这只对目录有效，对文件无效。

    :param client: 115 客户端或 cookies
    :param ids: 一组目录的 id 或 pickcode（如果包括文件，则会被忽略）
    :param normalize_attr: 把数据进行转换处理，使之便于阅读
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用指定 app（设备）的接口
    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生详细的信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if app in ("", "web", "desktop", "chrome") and isinstance(client, P115Client):
        order = ""
        key_mtime = "star_time"
    else:
        order = "user_utime"
        key_mtime = "mtime"
    def gen_step():
        nonlocal ids
        ts = int(time())
        ids = set(map(_get_id, ids))
        discard = ids.discard
        yield update_star(
            client, 
            ids, 
            max_workers=max_workers, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )
        if order:
            # NOTE: 非 web 端文件列表接口并不能按照星标时间排序，只能利用更新时间排序，但是只有在更新目录的备注后，才会改变更新时间，文件是不会改变的
            yield update_desc(
                client, 
                ids, 
                max_workers=max_workers, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
        from .iterdir import iterdir
        with with_iter_next(iterdir(
            client, 
            asc=0, 
            cur=0, 
            order=order, 
            star=1, 
            first_page_size=min(len(ids), 1150), 
            id_to_dirnode=id_to_dirnode, 
            normalize_attr=normalize_attr, 
            app=app, 
            cooldown=cooldown, 
            max_workers=max_workers, 
            async_=async_, # type: ignore
            **request_kwargs, 
        )) as get_next:
            while ids:
                info: dict = yield get_next()
                if normalize_attr is None:
                    attr: Any = normalize_attr_simple(info)
                else:
                    attr = info
                if attr[key_mtime] < ts:
                    break
                cid = attr["id"]
                if cid in ids:
                    yield Yield(info)
                    discard(cid)
    return run_gen_step_iter(gen_step, async_)

# TODO: 还可以把某些一个目录设为共享，就能用罗列恭喜目录等接口来获取文件信息
# TODO: 还可以分享一些文件，然后直接罗列分享链接里面的文件列表，获取信息，但因此得不到父目录 id
# TODO: 把文件列表添加到我听、我看、听单、相册等，然后从中拉取文件信息列表，可能因此也得不到父目录 id
# TODO: 基于合集的拉取：更一般的来讲，把一堆 id 添加到某个合集，从此合集中获取信息，最后删除此合集

