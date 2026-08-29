#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "get_pic_url", "iter_urls", "iter_subtitles", "iter_download_nodes", 
    "get_remaining_open_count", "download_file", 
]
__doc__ = "这个模块提供了一些和下载有关的函数"

from asyncio import to_thread
from base64 import b32decode
from collections.abc import (
    AsyncIterable, AsyncIterator, Buffer, Callable, Coroutine, 
    Iterable, Iterator, Mapping, MutableMapping, Sequence, 
)
from functools import partial
from inspect import isawaitable
from operator import methodcaller
from itertools import cycle
from os import cpu_count, makedirs, PathLike
from os.path import dirname, getsize
from re import compile as re_compile
from string import hexdigits, ascii_uppercase
from types import EllipsisType
from typing import cast, overload, Any, Final, Literal
from urllib.request import urlopen, Request
from uuid import uuid4

from argtools import argcount
from concurrenttools import conmap, iter_page, iter_page_multi
from errno2 import errno
from filewrap import (
    bio_chunk_iter, bio_chunk_async_iter, 
    bytes_to_chunk_iter, bytes_to_chunk_async_iter, 
)
from http_response import get_status_code, is_timeouterror
from iterutils import (
    chunked, map as do_map, chain_from_iterable, run_gen_step, 
    run_gen_step_iter, wrap_iter, wrap_aiter, with_iter_next, 
    Yield, YieldFrom, 
)
from p115pickcode import to_id

from ..client import check_response, json_maybe_decrypt_parse, P115Client, P115OpenClient, P115URL
from ..const import ID_TO_DIRNODE_CACHE
from ..exception import P115AccessError
from ..type import TaskResultTuple
from ..util import unescape_115_charref
from .attr import normalize_attr_simple, get_attr, get_info, _get_id, _get_pickcode
from .iterdir import iterdir, iter_files


_get_pic_url_next_select: Final = cycle(("life_v1", "life_v2", "note_v1", "note_v2")).__next__


@overload
def get_pic_url(
    client: str | PathLike | P115Client, 
    sha1: str, 
    select: None | Literal["life_v1", "life_v2", "note_v1", "note_v2"] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> str:
    ...
@overload
def get_pic_url(
    client: str | PathLike | P115Client, 
    sha1: Iterable[str], 
    select: None | Literal["life_v1", "life_v2", "note_v1", "note_v2"] = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> list[str]:
    ...
@overload
def get_pic_url(
    client: str | PathLike | P115Client, 
    sha1: str, 
    select: None | Literal["life_v1", "life_v2", "note_v1", "note_v2"] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, str]:
    ...
@overload
def get_pic_url(
    client: str | PathLike | P115Client, 
    sha1: Iterable[str], 
    select: None | Literal["life_v1", "life_v2", "note_v1", "note_v2"] = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, list[str]]:
    ...
def get_pic_url(
    client: str | PathLike | P115Client, 
    sha1: str | Iterable[str], 
    select: None | Literal["life_v1", "life_v2", "note_v1", "note_v2"] = None, 
    *, 
    _match_fhn_prefix=re_compile("^fhn[a-z]+_").match, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> str | list[str] | Coroutine[Any, Any, str] | Coroutine[Any, Any, list[str]]:
    """单个或批量获取图片链接

    .. note::
        不仅限于图片，每个文件必须限制在 50 MB 以内（含）

    :param client: 115 客户端或 cookies
    :param sha1: 图片的 sha1 或 f"{bucket}_{object}"（`bucket` 是所在存储桶， `object`是对象 id）
    :param select: 选择使用某个接口

        - "life_v1": 调用 ``P115Client.life_get_pic_url``
        - "life_v2": 调用 ``P115Client.life_get_pic_url2``
        - "note_v1": 调用 ``P115Client.note_get_pic_url``
        - "note_v2": 调用 ``P115Client.note_get_pic_url2``
        - None: 轮流使用以上接口，以分散压力，缓解风控

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 图片链接的单个或列表
    """
    if select is None:
        select = cast(Literal["life_v1", "life_v2", "note_v1", "note_v2"], _get_pic_url_next_select())
    def formalize_sha1(sha1):
        if len(sha1) and not sha1.upper().lstrip(ascii_uppercase):
            return b32decode(sha1).hex().upper()
        elif len(sha1) == 40 and not sha1.lstrip(hexdigits):
            return sha1.upper()
        elif not _match_fhn_prefix(sha1):
            return "fhnfile_" + sha1
        return sha1
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def gen_step():
        match select:
            case "life_v1":
                call: Callable = client.life_get_pic_url
                def get_urls(resp: dict, /) -> list[str]:
                    return [u["json"].replace("&i=0", "&i=1") for u in resp["data"]]
            case "life_v2":
                call = client.life_get_pic_url2
                def get_urls(resp: dict, /) -> list[str]:
                    return [u + "&i=1" for u in resp["data"]["json"]]
            case "note_v1" | "note_v2":
                if select == "note_v1":
                    call = client.note_get_pic_url
                else:
                    call = client.note_get_pic_url2
                def get_urls(resp: dict, /) -> list[str]:
                    return ["https://q.115.com/imgload?" + u[u.find("&")+1:] + "&i=1" for u in resp["data"]]
        if isinstance(sha1, str):
            resp = yield call(
                formalize_sha1(sha1), 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            return get_urls(resp)[0]
        else:
            resp = yield call(
                tuple(map(formalize_sha1, sha1)), 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            return get_urls(resp)
    return run_gen_step(gen_step, async_)


@overload
def iter_urls(
    client: str | PathLike | P115Client | P115OpenClient, 
    pickcodes: int | str | Mapping | Iterator[int | str | Mapping] = 0, 
    user_agent: str = "", 
    batch_size: int = 10, 
    max_workers: None | int = 0, 
    app: str = "os_windows", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[P115URL]:
    ...
@overload
def iter_urls(
    client: str | PathLike | P115Client | P115OpenClient, 
    pickcodes: int | str | Mapping | Iterator[int | str | Mapping] | AsyncIterable[int | str | Mapping] = 0, 
    user_agent: str = "", 
    batch_size: int = 10, 
    max_workers: None | int = 0, 
    app: str = "os_windows", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[P115URL]:
    ...
def iter_urls(
    client: str | PathLike | P115Client | P115OpenClient, 
    pickcodes: int | str | Mapping | Iterator[int | str | Mapping] | AsyncIterable[int | str | Mapping] = 0, 
    user_agent: str = "", 
    batch_size: int = 10, 
    max_workers: None | int = 0, 
    app: str = "os_windows", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[P115URL] | AsyncIterator[P115URL]:
    """批量获取下载链接

    .. attention::
        请确保所有的 pickcode 都是有效的，要么是现在存在的，要么是以前存在过被删除的。

        如果有目录的 pickcode 混在其中，则会自动排除。

    .. note::
        一次获取多个下载链接时，每多一个提取码，大约多耗时 50ms，因此 ``batch_size`` 指定得很大反而会拖慢响应速度。

    :param client: 115 客户端或 cookies
    :param pickcodes: 一组文件的 pickcode 或 id，或者一个顶层目录的 id 或 pickcode
    :param user_agent: "user-agent" 请求头的值
    :param batch_size: 每一个批次处理的个量
    :param max_workers: 并发工作数，如果为 None 或者 < 0，则自动确定
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 字典，key 是文件 id，value 是下载链接，自动忽略所有无效项目
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if isinstance(pickcodes, (int, str, Mapping)):
        if app == "open" or not isinstance(client, P115Client):
            pickcodes = iter_files(
                client, 
                pickcodes, 
                normalize_attr=normalize_attr_simple, 
                id_to_dirnode=..., 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )
        else:
            pickcodes = iter_download_nodes(
                client, 
                pickcodes, 
                async_=async_, 
                **request_kwargs, 
            )
    if headers := request_kwargs.get("headers"):
        request_kwargs["headers"] = dict(headers, **{"user-agent": user_agent})
    else:
        request_kwargs["headers"] = {"user-agent": user_agent}
    stable_point = client.pickcode_stable_point
    if batch_size <= 1:
        get_url = client.download_url
        return conmap(
            lambda pickcode, /: get_url(
                _get_pickcode(stable_point, pickcode), 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            ), 
            pickcodes, 
            max_workers=max_workers, 
            async_=async_, 
        )
    else:
        get_urls = client.download_urls
        return chain_from_iterable(do_map(methodcaller("values"), conmap(
            lambda pickcodes, /: get_urls(
                ",".join(_get_pickcode(stable_point, p) for p in pickcodes), 
                chunked(pickcodes, batch_size), 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            ), 
        )))


@overload
def iter_subtitles(
    client: str | PathLike | P115Client | P115OpenClient, 
    file_ids: int | str | Mapping | Iterable[int | str | Mapping] = 0, 
    batch_size: int = 1_000, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_subtitles(
    client: str | PathLike | P115Client | P115OpenClient, 
    file_ids: int | str | Mapping | Iterable[int | str | Mapping] | AsyncIterable[int | str | Mapping] = 0, 
    batch_size: int = 1_000, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_subtitles(
    client: str | PathLike | P115Client | P115OpenClient, 
    file_ids: int | str | Mapping | Iterable[int | str | Mapping] | AsyncIterable[int | str | Mapping] = 0, 
    batch_size: int = 1_000, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """批量获取字幕文件的信息和下载链接

    .. caution::
        这个函数运行时，会把相关文件以 1,000 为一批，同一批次复制到同一个新建的目录，在批量获取链接后，自动把目录删除到回收站。

    .. attention::
        目前看来 115 只支持：".srt"、".ass"、".ssa"，如果不能被 115 识别为字幕，将会被自动略过

    :param client: 115 客户端或 cookies
    :param file_ids: 一组文件的 id 或 pickcode，或者一个顶层目录的 id 或 pickcode
    :param batch_size: 每一个批次处理的个量
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if batch_size <= 0:
        batch_size = 1_000
    from .edit import makedir, batch_copy, batch_delete
    if not isinstance(client, P115Client) or app == "open":
        fs_video_subtitle: Callable = client.fs_video_subtitle_open
    elif app in ("", "web", "desktop", "aps"):
        fs_video_subtitle = client.fs_video_subtitle
    else:
        fs_video_subtitle = partial(client.fs_video_subtitle_app, app=app)
    from .fs_files import fs_files
    def gen_step():
        nonlocal file_ids
        if isinstance(file_ids, (int, str, Mapping)):
            cid = _get_id(file_ids)
            if app in ("", "web", "desktop", "chrome", "aps") and isinstance(client, P115Client):
                file_ids = iter_files(
                    client, 
                    cid, 
                    page_size=1000, 
                    type=16, 
                    id_to_dirnode=..., 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                file_ids = chain_from_iterable(
                    iter_files(
                        client, 
                        cid, 
                        page_size=1000, 
                        suffix=suffix, 
                        id_to_dirnode=..., 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    for suffix in (".srt", ".ass", ".ssa")
                )
        with with_iter_next(chunked(file_ids, batch_size)) as get_next:
            while True:
                ids = map(_get_id, (yield get_next()))
                try:
                    scid = yield makedir(
                        client, 
                        f"subtitle-{uuid4()}", 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    resp = yield batch_copy(
                        ids, 
                        pid=scid, 
                        batch_size=0, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    check_response(resp)
                    resp = yield fs_files(
                        client, 
                        scid, 
                        page_size=1, 
                        normalize_attr=normalize_attr_simple, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    attr = normalize_attr_simple(resp["data"][0])
                    resp = yield fs_video_subtitle(
                        attr["pickcode"], 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    check_response(resp)
                    yield YieldFrom(filter(lambda info: "file_id" in info, resp["data"]["list"]))
                except (StopIteration, StopAsyncIteration):
                    pass
                finally:
                    yield batch_delete(
                        client, 
                        scid, 
                        batch_size=0, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_download_nodes(
    client: str | PathLike | P115Client, 
    pickcodes: str | int | Mapping | Iterable[str | int | Mapping] = "", 
    page_size: int = 5000, 
    files: bool = True, 
    ensure_name: bool = False, 
    get_raw: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    cooldown: float = 0, 
    max_page: int = 0, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_download_nodes(
    client: str | PathLike | P115Client, 
    pickcodes: str | int | Mapping | Iterable[str | int | Mapping] = "", 
    page_size: int = 5000, 
    files: bool = True, 
    ensure_name: bool = False, 
    get_raw: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    cooldown: float = 0, 
    max_page: int = 0, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_download_nodes(
    client: str | PathLike | P115Client, 
    pickcodes: str | int | Mapping | Iterable[str | int | Mapping] = "", 
    page_size: int = 5000, 
    files: bool = True, 
    ensure_name: bool = False, 
    get_raw: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    cooldown: float = 0, 
    max_page: int = 0, 
    max_workers: None | int = 0, 
    app: str = "web", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一个目录内所有的文件或者目录的信息（简略）

    :param client: 115 客户端或 cookies
    :param pickcodes: 若干个目录的 pickcode 或 id，如果为空，则是根目录
    :param page_size: 分页大小，取值范围 1~5000
    :param files: 如果为 True，则只获取文件，否则只获取目录
    :param ensure_name: 确保返回数据中有 "name" 字段
    :param get_raw: 返回原始数据
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param cooldown: 接口调用冷却时间，单位：秒
    :param max_page: 最大页数，如果 <= 0，则不作限定。如果可调用，不接受参数时，直接调用它以获取最大页数，否则，接受 call 的返回数据来获取最大页数
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件或者目录的简略信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if max_workers is None or max_workers < 0:
        max_workers = 20 if async_ else min(32, (cpu_count() or 1) + 4)
    if not 0 < page_size <= 5000:
        page_size = 5000
    if files:
        if app in ("", "web", "desktop", "aps"):
            get_nodes = client.download_files
        else:
            get_nodes = partial(client.download_files_app, app=app)
    else:
        ensure_name = False
        if app in ("", "web", "desktop", "aps"):
            get_nodes = client.download_folders
        else:
            get_nodes = partial(client.download_folders_app, app=app)
        if id_to_dirnode is None:
            id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    def parse(_, content: bytes, /) -> dict:
        resp = json_maybe_decrypt_parse(_, content)
        check_response(resp)
        data = resp["data"]
        if not get_raw and (attrs := data.get("list")):
            if files:
                for i, info in enumerate(attrs):
                    attrs[i] = {
                        "is_dir": False, 
                        "id": to_id(info["pc"]), 
                        "pickcode": info["pc"], 
                        "parent_id": int(info["pid"]), 
                        "size": info["fs"], 
                    }
                    if "sha1" in info:
                        attrs[i]["sha1"] = info["sha1"]
            else:
                for i, info in enumerate(attrs):
                    attrs[i] = {
                        "is_dir": True, 
                        "id": int(info["fid"]), 
                        "name": info["fn"], 
                        "parent_id": int(info["pid"]), 
                    }
                if id_to_dirnode is not ... and id_to_dirnode is not None:
                    for attr in attrs:
                        id_to_dirnode[attr["id"]] = (attr["name"], attr["parent_id"])
        return data
    call = partial(get_nodes, **dict(request_kwargs, parse=parse, async_=async_))
    is_multi = True
    if isinstance(pickcodes, (int, str, Mapping)):
        pickcode = _get_pickcode(client, pickcodes)
        if pickcode:
            is_multi = False
        else:
            pickcodes = ()
    else:
        pickcodes = tuple(dict.fromkeys(_get_pickcode(client, pc) for pc in pickcodes))
        if not pickcodes or "" in pickcodes:
            pickcodes = ()
        elif len(pickcodes) == 1:
            pickcode = pickcodes[0]
            is_multi = False
    if is_multi:
        def gen_step():
            nonlocal pickcodes
            pickcodes = cast(Sequence[str], pickcodes)
            if not pickcodes:
                pickcodes = []
                add_pickcode = pickcodes.append
                attrs: list[dict] = []
                add_attr = attrs.append
                with with_iter_next(iterdir(
                    client, 
                    ensure_file=None if files else False, 
                    normalize_attr=normalize_attr_simple, 
                    id_to_dirnode=id_to_dirnode, 
                    raise_for_changed_count=True, 
                    app="web", 
                    async_=async_, 
                    **request_kwargs, 
                )) as get_next:
                    while True:
                        attr = yield get_next()
                        if get_raw:
                            if attr["is_dir"]:
                                if not files:
                                    add_attr({
                                        "fid": attr["id"], 
                                        "fn": attr["name"], 
                                        "pid": attr["parent_id"], 
                                    })
                                add_pickcode(attr["pickcode"])
                            elif files:
                                add_attr({
                                    "pid": attr["parent_id"], 
                                    "pc": attr["pickcode"], 
                                    "fn": attr["name"], 
                                    "fs": attr["size"], 
                                    "sha1": attr["sha1"], 
                                })
                        else:
                            if attr["is_dir"]:
                                if not files:
                                    add_attr(attr)
                                add_pickcode(attr["pickcode"])
                            elif files:
                                add_attr(attr)
                if attrs:
                    yield Yield(attrs)
                del add_pickcode, attrs, add_attr
            with with_iter_next(iter_page_multi(
                call, 
                ({"pickcode": pc} for pc in pickcodes), 
                check_for_stop=lambda _, _2, resp: not resp["has_next_page"], 
                retry_for_exception=lambda e, /: is_timeouterror(e) or isinstance(e, Exception) and get_status_code(e) < 400, 
                page_size=page_size, 
                key_page_size="per_page", 
                cooldown=cooldown, 
                max_workers=max_workers, 
                async_=async_, # type: ignore
            )) as get_next:
                while True:
                    resp = yield get_next()
                    check_response(resp)
                    if ls := resp.get("list"):
                        yield Yield(ls)
    else:
        def gen_step():
            with with_iter_next(iter_page(
                call, 
                {"pickcode": pickcode}, 
                check_for_stop=lambda _, _2, resp: not resp["has_next_page"], 
                retry_for_exception=lambda e, /: is_timeouterror(e) or isinstance(e, Exception) and get_status_code(e) < 400, 
                page_size=page_size, 
                max_page=max_page, 
                key_page_size="per_page", 
                cooldown=cooldown, 
                max_workers=max_workers, 
                async_=async_, # type: ignore
            )) as get_next:
                while True:
                    resp = yield get_next()
                    check_response(resp)
                    if ls := resp.get("list"):
                        yield Yield(ls)
    it = run_gen_step_iter(gen_step, async_)
    if ensure_name:
        file_skim = client.fs_file_skim
        def update_attrs_by_data(attrs, data, /):
            if get_raw:
                f_pickcode, f_name = "pc", "fn"
            else:
                f_pickcode, f_name = "pickcode", "name"
            if "sha1" in attrs[0]:
                nodes: dict = {
                    node["pick_code"]: unescape_115_charref(node["file_name"]) 
                    for node in data
                }
                for attr in attrs:
                    if name := nodes.get(attr[f_pickcode]):
                        attr[f_name] = name
            else:
                nodes = {
                    node["pick_code"]: (
                        unescape_115_charref(node["file_name"]), 
                        node["sha1"], 
                    ) for node in data
                }
                for attr in attrs:
                    if name_sha1 := nodes.get(attr[f_pickcode]):
                        attr[f_name] = name_sha1[0]
                        attr["sha1"] = name_sha1[1]
        def ensure_names(attrs: Sequence[dict], /):
            if not attrs:
                return attrs
            elif async_:
                async def request(attrs=attrs, /):
                    while True:
                        resp = await file_skim(
                            (a["id"] for a in attrs), 
                            method="POST", 
                            async_=True, 
                            **request_kwargs, 
                        )
                        if resp["state"] or resp.get("error") != "参数错误。":
                            break
                    if resp.get("error") != "文件不存在":
                        check_response(resp)
                        update_attrs_by_data(attrs, resp["data"])
                    return attrs
                return request()
            else:
                while True:
                    resp = file_skim(
                        (a["id"] for a in attrs), 
                        method="POST", 
                        **request_kwargs, 
                    )
                    if resp["state"] or resp.get("error") != "参数错误。":
                        break
                if resp.get("error") != "文件不存在":
                    check_response(resp)
                    update_attrs_by_data(attrs, resp["data"])
            return attrs
        it = conmap(ensure_names, it, max_workers=max_workers, async_=async_)
    return chain_from_iterable(it, async_=async_)


@overload
def get_remaining_open_count(
    client: str | PathLike | P115Client | P115OpenClient, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def get_remaining_open_count(
    client: str | PathLike | P115Client | P115OpenClient, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def get_remaining_open_count(
    client: str | PathLike | P115Client | P115OpenClient, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """获取剩余的可打开下载链接数

    .. note::
        假设总数是 n，通常总数是 10，偶尔会调整，如果已经有 m 个被打开的链接，则返回的数字是 n-m

    :param client: 115 客户端或 cookies
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 个数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    get_url = client.download_url
    def gen_step():
        cache: list = []
        add_to_cache = cache.append
        try:
            if isinstance(client, P115OpenClient):
                it: Iterator[dict] | AsyncIterator[dict] = iter_files(
                    client, 
                    normalize_attr=normalize_attr_simple, 
                    id_to_dirnode=..., 
                    app=app, 
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
            else:
                it = iter_download_nodes(
                    client, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )
            with with_iter_next(it) as get_next:
                while True:
                    attr = yield get_next()
                    try:
                        url = yield get_url(attr["pickcode"], app=app, async_=async_)
                    except FileNotFoundError:
                        continue
                    request = Request(url, headers={"user-agent": ""})
                    if async_:
                        file = yield to_thread(urlopen, request)
                    else:
                        file = urlopen(request)
                    add_to_cache(file)
        finally:
            for f in cache:
                f.close()
            return len(cache)
    return run_gen_step(gen_step, async_)


@overload
def download_file(
    client: str | PathLike | P115Client | P115OpenClient, 
    fid: int | str | Mapping, 
    path: str = "", 
    resume: bool = True, 
    reporthook: None | Callable[[int], Any] = None, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> TaskResultTuple:
    ...
@overload
def download_file(
    client: str | PathLike | P115Client | P115OpenClient, 
    fid: int | str | Mapping, 
    path: str = "", 
    resume: bool = True, 
    reporthook: None | Callable[[int], Any] = None, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, TaskResultTuple]:
    ...
def download_file(
    client: str | PathLike | P115Client | P115OpenClient, 
    fid: int | str | Mapping, 
    path: str = "", 
    resume: bool = True, 
    reporthook: None | Callable[[int], Any] = None, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> TaskResultTuple | Coroutine[Any, Any, TaskResultTuple]:
    """从 115 网盘下载一个文件到本地

    :param client: 115 客户端或 cookies
    :param fid: 待下载文件的 id、pickcode 或者信息字典
    :param path: 下载到本地路径，如果不提供或者以 "/" 结尾，则用网盘上的名字
    :param resume: 是否断点续传
    :param reporthook: 用于更新进度条
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 下载结果信息
    """
    def iter_wrap(resp, /):
        if hasattr(resp, "read") and argcount(resp.read) > 1 or hasattr(resp, "readinto"):
            if async_:
                resp = bio_chunk_async_iter(resp, can_buffer=True)
            else:
                resp = bio_chunk_iter(resp, can_buffer=True)
        elif isinstance(resp, Buffer):
            if async_:
                resp = bytes_to_chunk_async_iter(resp)
            else:
                resp = bytes_to_chunk_iter(resp)
        elif not isinstance(resp, (AsyncIterable, Iterable)):
            attrs: tuple[str, ...] = (
                "iter_content", "iter_chunks", "iter_chunked", "iter_bytes", 
                "iter_stream", "iter_raw", "content", "body", 
            )
            if async_:
                attrs = (
                    "aiter_content", "aiter_chunks", "aiter_chunked", "aiter_bytes", 
                    "aiter_stream", "aiter_raw", 
                ) + attrs
            for attr in attrs:
                if hasattr(resp, attr):
                    resp = getattr(resp, attr)
                    if callable(resp):
                        resp = resp()
                    break
            else:
                raise TypeError("can't read response body")
        if reporthook is not None:
            if async_:
                resp = wrap_aiter(resp, callnext=lambda b, /: reporthook(len(b)))
            else:
                resp = wrap_iter(resp, callnext=lambda b, /: reporthook(len(b)))
        return resp
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if isinstance(fid, Mapping):
        attr = fid
        if "pickcode" in attr:
            pickcode = attr["pickcode"]
            fid = cast(int, attr.get("id") or client.to_id(pickcode))
        else:
            fid = cast(int, attr["id"])
            pickcode = client.to_pickcode(fid)
    else:
        attr = None
        pickcode = client.to_pickcode(fid)
        fid = client.to_id(fid)
    get_url = client.download_url
    def gen_step():
        nonlocal attr, path, resume
        if not path or path.endswith("/"):
            if not attr or "name" not in attr:
                if isinstance(client, P115Client):
                    attr = yield get_attr(
                        client, 
                        fid, 
                        skim=True, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                else:
                    attr = yield get_info(
                        client, 
                        fid, 
                        async_=async_, 
                        **request_kwargs, 
                    )
            path += attr["name"].replace("/", ":")
        start = 0
        try:
            if resume:
                try:
                    start = getsize(path)
                except FileNotFoundError:
                    pass
            if start:
                if not attr or "size" not in attr:
                    if isinstance(client, P115Client):
                        attr = yield get_attr(
                            client, 
                            fid, 
                            skim=True, 
                            async_=async_, 
                            **request_kwargs, 
                        )
                    else:
                        attr = yield get_info(
                            client, 
                            fid, 
                            async_=async_, 
                            **request_kwargs, 
                        )
                if start == attr["size"]:
                    return TaskResultTuple(False, None)
                elif start > attr["size"]:
                    resume = False
                    start = 0
            if attr and attr.get("is_dir", ):
                return TaskResultTuple(False, NotADirectoryError(errno.EISDIR, attr))
            if app != "web2" and isinstance(client, P115Client):
                try:
                    url = yield get_url(
                        pickcode, 
                        strict=True, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                except P115AccessError as e:
                    if not attr or "size" not in attr:
                        attr = yield get_attr(
                            client, 
                            fid, 
                            skim=True, 
                            async_=async_, 
                            **request_kwargs, 
                        )
                        if attr["is_dir"]:
                            return TaskResultTuple(False, NotADirectoryError(errno.EISDIR, attr))
                        if attr["size"] > 1024 * 1024 * 200:
                            return TaskResultTuple(False, e)
                    url = yield get_url(
                        pickcode, 
                        strict=True, 
                        app="web2", 
                        async_=async_, 
                        **request_kwargs, 
                    )
            else:
                url = get_url(
                    pickcode, 
                    strict=True, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )
            resp = yield client.request(
                url, 
                async_=async_, 
                **({"parse": None} | request_kwargs | {
                    "headers": (getattr(url, "headers", None) or {}) | {"range": f"bytes={start}-"}, 
                }), 
            )
            try:
                try:
                    file = open(path, "ab" if resume else "wb")
                except FileNotFoundError:
                    makedirs(dirname(path), exist_ok=True)
                    file = open(path, "ab" if resume else "wb")
                fwrite = file.write
                if start and reporthook:
                    if async_:
                        ret = reporthook(start)
                        if isawaitable(ret):
                            yield ret
                    else:
                        yield reporthook(start)
                with with_iter_next(iter_wrap(resp)) as get_next:
                    while True:
                        chunk = yield get_next()
                        if async_:
                            yield to_thread(fwrite, chunk)
                        else:
                            fwrite(chunk)
            finally:
                if async_ and hasattr(resp, "aclose"):
                    yield resp.aclose()
                elif hasattr(resp, "close"):
                    yield resp.close()
        except Exception as e:
            return TaskResultTuple(False, e)
        else:
            return TaskResultTuple(True)
    return run_gen_step(gen_step, async_)

