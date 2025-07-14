#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "batch_get_url", "iter_url_batches", "iter_files_with_url", 
    "iter_images_with_url", "iter_subtitles_with_url", "iter_subtitle_batches", "make_strm", 
    "iter_download_nodes", "iter_download_files", "get_remaining_open_count", 
]
__doc__ = "这个模块提供了一些和下载有关的函数"

from asyncio import create_task, to_thread, Queue as AsyncQueue, TaskGroup
from collections.abc import (
    AsyncIterator, Callable, Coroutine, Iterable, Iterator, MutableMapping, 
)
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from glob import iglob
from itertools import batched, chain, count, cycle
from os import fsdecode, makedirs, remove, PathLike
from os.path import abspath, dirname, join as joinpath, normpath, splitext
from queue import SimpleQueue
from shutil import rmtree
from threading import Lock
from time import time
from typing import cast, overload, Any, Literal
from types import EllipsisType
from urllib.request import urlopen, Request
from uuid import uuid4
from warnings import warn

from asynctools import async_chain
from concurrenttools import run_as_thread, thread_batch, async_batch
from encode_uri import encode_uri_component_loose
from iterutils import (
    as_gen_step, chunked, run_gen_step, run_gen_step_iter, through, 
    with_iter_next, Yield, YieldFrom, 
)
from p115client import (
    check_response, normalize_attr, normalize_attr_simple, P115Client, 
    P115OpenClient, P115URL, 
)
from p115client.exception import P115Warning
from p115pickcode import to_id, to_pickcode

from .iterdir import (
    get_path_to_cid, iterdir, iter_files, iter_files_with_path, 
    unescape_115_charref, posix_escape_name, DirNode, ID_TO_DIRNODE_CACHE, 
)
from .util import reduce_image_url_layers


@overload
def batch_get_url(
    client: str | P115Client | P115OpenClient, 
    pickcode: int | str | Iterable[int | str], 
    user_agent: str = "", 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict[int, P115URL]:
    ...
@overload
def batch_get_url(
    client: str | P115Client | P115OpenClient, 
    pickcode: int | str | Iterable[int | str], 
    user_agent: str = "", 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict[int, P115URL]]:
    ...
def batch_get_url(
    client: str | P115Client | P115OpenClient, 
    pickcode: int | str | Iterable[int | str], 
    user_agent: str = "", 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict[int, P115URL] | Coroutine[Any, Any, dict[int, P115URL]]:
    """批量获取下载链接

    :param client: 115 客户端或 cookies
    :param pickcode: pickcode 或 id
    :param user_agent: "user-agent" 请求头的值
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 字典，key 是文件 id，value 是下载链接，自动忽略所有无效项目
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if headers := request_kwargs.get("headers"):
        request_kwargs["headers"] = dict(headers, **{"user-agent": user_agent})
    else:
        request_kwargs["headers"] = {"user-agent": user_agent}
    if isinstance(pickcode, (int, str)):
        pickcode = to_pickcode(pickcode)
    elif not isinstance(pickcode, str):
        pickcode = ",".join(map(to_pickcode, pickcode))
    if not isinstance(client, P115Client) or app == "open":
        get_download_url: Callable = client.download_url_info_open
    else:
        get_download_url = partial(client.download_url_app, app=app)
    def gen_step():
        resp = yield get_download_url(pickcode, async_=async_, **request_kwargs)
        if not resp["state"]:
            if resp.get("errno") != 50003:
                check_response(resp)
            return {}
        headers = resp["headers"]
        return {
            int(id): P115URL(
                info["url"]["url"], 
                id=int(id), 
                pickcode=info["pick_code"], 
                name=info["file_name"], 
                size=int(info["file_size"]), 
                sha1=info["sha1"], 
                is_dir=False,
                headers=headers, 
            )
            for id, info in resp["data"].items()
            if info["url"]
        }
    return run_gen_step(gen_step, async_)


@overload
def iter_url_batches(
    client: str | P115Client | P115OpenClient, 
    pickcodes: Iterator[int | str], 
    user_agent: str = "", 
    batch_size: int = 10, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[P115URL]:
    ...
@overload
def iter_url_batches(
    client: str | P115Client | P115OpenClient, 
    pickcodes: Iterator[int | str], 
    user_agent: str = "", 
    batch_size: int = 10, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[P115URL]:
    ...
def iter_url_batches(
    client: str | P115Client | P115OpenClient, 
    pickcodes: Iterator[int | str], 
    user_agent: str = "", 
    batch_size: int = 10, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[P115URL] | AsyncIterator[P115URL]:
    """批量获取下载链接

    .. attention::
        请确保所有的 pickcode 都是有效的，要么是现在存在的，要么是以前存在过被删除的。

        如果有目录的 pickcode 混在其中，则会自动排除。

    :param client: 115 客户端或 cookies
    :param pickcodes: 一个迭代器，产生 pickcode 或 id
    :param user_agent: "user-agent" 请求头的值
    :param batch_size: 每一个批次处理的个量
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 字典，key 是文件 id，value 是下载链接，自动忽略所有无效项目
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if headers := request_kwargs.get("headers"):
        request_kwargs["headers"] = dict(headers, **{"user-agent": user_agent})
    else:
        request_kwargs["headers"] = {"user-agent": user_agent}
    if not isinstance(client, P115Client) or app == "open":
        get_download_url: Callable = client.download_url_info_open
    else:
        get_download_url = partial(client.download_url_app, app=app)
    if batch_size <= 0:
        batch_size = 1
    def gen_step():
        for pcs in batched(map(to_pickcode, pickcodes), batch_size):
            resp = yield get_download_url(
                ",".join(pcs), 
                async_=async_, 
                **request_kwargs, 
            )
            if not resp["state"]:
                if resp.get("errno") != 50003:
                    check_response(resp)
                continue
            headers = resp["headers"]
            for id, info in resp["data"].items():
                if url_info := info["url"]:
                    yield Yield(P115URL(
                        url_info["url"], 
                        id=int(id), 
                        pickcode=info["pick_code"], 
                        name=info["file_name"], 
                        size=int(info["file_size"]), 
                        sha1=info["sha1"], 
                        is_dir=False,
                        headers=headers, 
                    ))
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_files_with_url(
    client: str | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    user_agent: str = "", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_files_with_url(
    client: str | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    user_agent: str = "", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_with_url(
    client: str | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    user_agent: str = "", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取文件信息和下载链接

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param suffixes: 扩展名，可以有多个，最前面的 "." 可以省略
    :param type: 文件类型

        - 1: 文档
        - 2: 图片
        - 3: 音频
        - 4: 视频
        - 5: 压缩包
        - 6: 应用
        - 7: 书籍
        - 99: 仅文件

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
    :param app: 使用指定 app（设备）的接口
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param user_agent: "user-agent" 请求头的值
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件信息，并增加一个 "url" 作为下载链接
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    params = dict(
        cur=cur, 
        with_ancestors=with_ancestors, 
        with_path=with_path, 
        use_star=use_star, 
        escape=escape, 
        normalize_attr=normalize_attr, 
        id_to_dirnode=id_to_dirnode, 
        raise_for_changed_count=raise_for_changed_count, 
        async_=async_, 
        **request_kwargs, 
    )
    if not isinstance(client, P115Client) or app == "open":
        get_url: Callable[..., P115URL] = client.download_url_open
    elif app in ("", "web", "desktop", "harmony"):
        get_url = client.download_url
    else:
        get_url = partial(client.download_url, app=app)
    cid = to_id(cid)
    def gen_step():
        if suffixes is None:
            it = iter_files(
                client, 
                cid, 
                type=type, 
                app=app, 
                **params, # type: ignore
            )
        elif isinstance(suffixes, str):
            it = iter_files(
                client, 
                cid, 
                suffix=suffixes, 
                app=app, 
                **params, # type: ignore
            )
        else:
            for suffix in suffixes:
                yield YieldFrom(
                    iter_files_with_url(
                        client, 
                        cid, 
                        suffixes=suffix, 
                        app=app, 
                        user_agent=user_agent, 
                        **params, # type: ignore
                    )
                )
            return
        if headers := request_kwargs.get("headers"):
            request_kwargs["headers"] = dict(headers, **{"user-agent": user_agent})
        else:
            request_kwargs["headers"] = {"user-agent": user_agent}
        with with_iter_next(it) as get_next:
            while True:
                attr = yield get_next()
                if attr.get("is_collect", False):
                    if attr["size"] < 1024 * 1024 * 115:
                        attr["url"] = yield get_url(
                            attr["pickcode"], 
                            use_web_api=True, 
                            async_=async_, 
                            **request_kwargs, 
                        )
                    else:
                        warn(f"unable to get url for {attr!r}", category=P115Warning)
                else:
                    attr["url"] = yield get_url(
                        attr["pickcode"], 
                        async_=async_, 
                        **request_kwargs, 
                    )
                yield Yield(attr)
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_images_with_url(
    client: str | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_images_with_url(
    client: str | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_images_with_url(
    client: str | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取图片文件信息和下载链接

    .. attention::
        请不要把不能被 115 识别为图片的文件扩展名放在 `suffixes` 参数中传入，这只是浪费时间，最后也只能获得普通的下载链接

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param suffixes: 扩展名，可以有多个，最前面的 "." 可以省略（请确保扩展名确实能被 115 认为是图片，否则会因为不能批量获取到链接而浪费一些时间再去单独生成下载链接）；如果不传（默认），则会获取所有图片
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
    :param app: 使用指定 app（设备）的接口
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件信息，并增加一个 "url" 作为下载链接
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    params = dict(
        cur=cur, 
        with_ancestors=with_ancestors, 
        with_path=with_path, 
        use_star=use_star, 
        escape=escape, 
        normalize_attr=normalize_attr, 
        id_to_dirnode=id_to_dirnode, 
        raise_for_changed_count=raise_for_changed_count, 
        async_=async_, 
        **request_kwargs
    )
    if not isinstance(client, P115Client) or app == "open":
        get_url: Callable[..., P115URL] = client.download_url_open
    elif app in ("", "web", "desktop", "harmony"):
        get_url = client.download_url
    else:
        get_url = partial(client.download_url, app=app)
    cid = to_id(cid)
    def gen_step():
        if suffixes is None:
            it = iter_files(
                client, 
                cid, 
                type=2, 
                app=app, 
                **params, # type: ignore
            )
        elif isinstance(suffixes, str):
            it = iter_files(
                client, 
                cid, 
                suffix=suffixes, 
                app=app, 
                **params, # type: ignore
            )
        else:
            for suffix in suffixes:
                yield YieldFrom(
                    iter_images_with_url(
                        client, 
                        cid, 
                        suffixes=suffix, 
                        app=app, 
                        **params, # type: ignore
                    )
                )
            return
        with with_iter_next(it) as get_next:
            while True:
                attr = yield get_next()
                try:
                    attr["url"] = reduce_image_url_layers(attr["thumb"])
                except KeyError:
                    if attr.get("is_collect", False):
                        if attr["size"] < 1024 * 1024 * 115:
                            attr["url"] = yield get_url(
                                attr["pickcode"], 
                                use_web_api=True, 
                                async_=async_, 
                                **request_kwargs, 
                            )
                        else:
                            warn(f"unable to get url for {attr!r}", category=P115Warning)
                    else:
                        attr["url"] = yield get_url(
                            attr["pickcode"], 
                            async_=async_, 
                            **request_kwargs, 
                        )
                yield Yield(attr)
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_subtitles_with_url(
    client: str | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: str | Iterable[str] = (".srt", ".ass", ".ssa"), 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_subtitles_with_url(
    client: str | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: str | Iterable[str] = (".srt", ".ass", ".ssa"), 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_subtitles_with_url(
    client: str | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: str | Iterable[str] = (".srt", ".ass", ".ssa"), 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取字幕文件信息和下载链接

    .. caution::
        这个函数运行时，会把相关文件以 1,000 为一批，同一批次复制到同一个新建的目录，在批量获取链接后，自动把目录删除到回收站。

    .. attention::
        目前看来 115 只支持：".srt", ".ass", ".ssa"

        请不要把不能被 115 识别为字幕的文件扩展名放在 `suffixes` 参数中传入，这只是浪费时间，最后也只能获得普通的下载链接

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param suffixes: 扩展名，可以有多个，最前面的 "." 可以省略（请确保扩展名确实能被 115 认为是字幕，否则会因为不能批量获取到链接而浪费一些时间再去单独生成下载链接）
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
    :param app: 使用指定 app（设备）的接口
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件信息，并增加一个 "url" 作为下载链接
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if not isinstance(client, P115Client) or app == "open":
        get_url: Callable[..., P115URL] = client.download_url_open
        fs_mkdir: Callable = client.fs_mkdir_open
        fs_copy: Callable = client.fs_copy_open
        fs_delete: Callable = client.fs_delete_open
        fs_video_subtitle: Callable = client.fs_video_subtitle_open
    elif app in ("", "web", "desktop", "harmony"):
        get_url = client.download_url
        fs_mkdir = client.fs_mkdir
        fs_copy = client.fs_copy
        fs_delete = client.fs_delete
        fs_video_subtitle = client.fs_video_subtitle
    else:
        get_url = partial(client.download_url, app=app)
        fs_mkdir = partial(client.fs_mkdir_app, app=app)
        fs_copy = partial(client.fs_copy_app, app=app)
        fs_delete = partial(client.fs_delete_app, app=app)
        fs_video_subtitle = partial(client.fs_video_subtitle_app, app=app)
    cid = to_id(cid)
    def gen_step():
        nonlocal suffixes
        if isinstance(suffixes, str):
            suffixes = suffixes,
        do_chain: Callable = async_chain.from_iterable if async_ else chain.from_iterable
        do_next = anext if async_ else next
        with with_iter_next(chunked(do_chain(
            iter_files(
                client, 
                cid, 
                suffix=suffix, 
                cur=cur, 
                with_ancestors=with_ancestors, 
                with_path=with_path, 
                use_star=use_star, 
                escape=escape, 
                normalize_attr=normalize_attr, 
                id_to_dirnode=id_to_dirnode, 
                app=app, 
                raise_for_changed_count=raise_for_changed_count, 
                async_=async_, # type: ignore
                **request_kwargs, 
            )
            for suffix in suffixes
        ), 1000)) as get_next:
            while True:
                items: tuple[dict] = yield get_next()
                resp = yield fs_mkdir(
                    f"subtitle-{uuid4()}", 
                    async_=async_, 
                    **request_kwargs, 
                )
                check_response(resp)
                try:
                    if "cid" in resp:
                        scid = resp["cid"]
                    else:
                        data = resp["data"]
                        if "category_id" in data:
                            scid = data["category_id"]
                        else:
                            scid = data["file_id"]
                    resp = yield fs_copy(
                        (attr["id"] for attr in items), 
                        pid=scid, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    check_response(resp)
                    attr = yield do_next(iter_files(
                        client, 
                        scid, 
                        first_page_size=1, 
                        normalize_attr=None, 
                        base_url=True, 
                        app=app, 
                        async_=async_, # type: ignore
                        **request_kwargs, 
                    ))
                    resp = yield fs_video_subtitle(
                        attr["pc"], 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    subtitles = {
                        info["sha1"]: info["url"]
                        for info in resp["data"]["list"] 
                        if info.get("file_id")
                    }
                finally:
                    yield fs_delete(scid, async_=async_, **request_kwargs)
                if subtitles:
                    for attr in items:
                        attr["url"] = subtitles[attr["sha1"]]
                        yield Yield(attr)
                else:
                    for attr in items:
                        if attr.get("is_collect", False):
                            if attr["size"] < 1024 * 1024 * 115:
                                attr["url"] = yield get_url(
                                    attr["pickcode"], 
                                    use_web_api=True, 
                                    async_=async_, 
                                    **request_kwargs, 
                                )
                            else:
                                warn(f"unable to get url for {attr!r}", category=P115Warning)
                        else:
                            attr["url"] = yield get_url(
                                attr["pickcode"], 
                                async_=async_, 
                                **request_kwargs, 
                            )
                        yield Yield(attr)
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_subtitle_batches(
    client: str | P115Client | P115OpenClient, 
    file_ids: Iterable[int | str], 
    batch_size: int = 1_000, 
    app: str = "web", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_subtitle_batches(
    client: str | P115Client | P115OpenClient, 
    file_ids: Iterable[int | str], 
    batch_size: int = 1_000, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_subtitle_batches(
    client: str | P115Client | P115OpenClient, 
    file_ids: Iterable[int | str], 
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
    :param file_ids: 一组文件的 id 或 pickcode
    :param batch_size: 每一个批次处理的个量
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件信息，并增加一个 "url" 作为下载链接，文件信息中的 file_id 是复制所得的文件信息，不是原来文件的 id
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if batch_size <= 0:
        batch_size = 1_000
    if not isinstance(client, P115Client) or app == "open":
        fs_mkdir: Callable = client.fs_mkdir_open
        fs_copy: Callable = client.fs_copy_open
        fs_delete: Callable = client.fs_delete_open
        fs_video_subtitle: Callable = client.fs_video_subtitle_open
    elif app in ("", "web", "desktop", "harmony"):
        fs_mkdir = client.fs_mkdir
        fs_copy = client.fs_copy
        fs_delete = client.fs_delete
        fs_video_subtitle = client.fs_video_subtitle
    else:
        fs_mkdir = partial(client.fs_mkdir_app, app=app)
        fs_copy = partial(client.fs_copy_app, app=app)
        fs_delete = partial(client.fs_delete_app, app=app)
        fs_video_subtitle = partial(client.fs_video_subtitle_app, app=app)
    def gen_step():
        do_next: Callable = anext if async_ else next
        for ids in batched(map(to_id, file_ids), batch_size):
            try:
                resp = yield fs_mkdir(
                    f"subtitle-{uuid4()}", 
                    async_=async_, 
                    **request_kwargs, 
                )
                check_response(resp)
                scid = resp["cid"]
                resp = yield fs_copy(
                    ids, 
                    pid=scid, 
                    async_=async_, 
                    **request_kwargs, 
                )
                check_response(resp)
                attr = yield do_next(iter_files(
                    client, 
                    scid, 
                    first_page_size=1, 
                    normalize_attr=None, 
                    base_url=True, 
                    app=app, 
                    async_=async_, # type: ignore
                    **request_kwargs, 
                ))
                resp = yield fs_video_subtitle(
                    attr["pc"], 
                    async_=async_, 
                    **request_kwargs, 
                )
                check_response(resp)
                yield YieldFrom(
                    filter(lambda info: "file_id" in info, resp["data"]["list"])
                )
            except (StopIteration, StopAsyncIteration):
                pass
            finally:
                yield fs_delete(scid, async_=async_, **request_kwargs)
    return run_gen_step_iter(gen_step, async_)


# TODO: 要支持 open 接口
@overload
def make_strm(
    client: str | P115Client, 
    cid: int | str = 0, 
    save_dir: bytes | str | PathLike = ".", 
    origin: str = "http://localhost:8000", 
    update: bool = False, 
    discard: bool = True, 
    use_abspath: bool = True, 
    with_root: bool = False, 
    with_tree: bool = True, 
    without_suffix: bool = True, 
    complete_url: bool = True, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 4, 
    max_workers: None | int = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    app: str = "android", 
    fs_files_cooldown: int | float = 0.5, 
    fs_files_max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def make_strm(
    client: str | P115Client, 
    cid: int | str = 0, 
    save_dir: bytes | str | PathLike = ".", 
    origin: str = "http://localhost:8000", 
    update: bool = False, 
    discard: bool = True, 
    use_abspath: bool = True, 
    with_root: bool = False, 
    with_tree: bool = True, 
    without_suffix: bool = True, 
    complete_url: bool = True, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 4, 
    max_workers: None | int = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    app: str = "android", 
    fs_files_cooldown: int | float = 0.5, 
    fs_files_max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def make_strm(
    client: str | P115Client, 
    cid: int | str = 0, 
    save_dir: bytes | str | PathLike = ".", 
    origin: str = "http://localhost:8000", 
    update: bool = False, 
    discard: bool = True, 
    use_abspath: bool = True, 
    with_root: bool = False, 
    with_tree: bool = True, 
    without_suffix: bool = True, 
    complete_url: bool = True, 
    suffix: str = "", 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 4, 
    max_workers: None | int = None, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    path_already: bool = False, 
    app: str = "android", 
    fs_files_cooldown: int | float = 0.5, 
    fs_files_max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """生成 strm 保存到本地

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param save_dir: 本地的保存目录，默认是当前工作目录
    :param origin: strm 文件的 `HTTP 源 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin>`_
    :param update: 是否更新 strm 文件，如果为 False，则跳过已存在的路径
    :param discard: 是否清理 strm 文件，如果为 True，则删除未取得的路径（不在本次的路径集合内）
    :param use_abspath: 是否使用相对路径

        - 如果为 True，则使用 115 的完整路径
        - 如果为 False，则使用从 `cid` 的目录开始的相对路径

    :param with_root: 仅在 use_abspath 为 False 时生效。如果为 True，则在 `save_dir` 下创建一个和 `cid` 目录名字相同的目录，作为实际的 `save_dir`
    :param with_tree: 如果为 False，则所有文件直接保存到 `save_dir` 下，不构建多级的目录结构
    :param without_suffix: 是否去除原来的扩展名。如果为 False，则直接用 ".strm" 拼接到原来的路径后面；如果为 True，则去掉原来的扩展名后再拼接
    :param complete_url: 是否需要完整的 url

        - 如果为 False, 格式为 ff"{origin}?pickcode={attr['pickcode']}"
        - 如果为 True,  格式为 f"{origin}/{attr['name']}?pickcode={attr['pickcode']}&id={attr['id']}&sha1={attr['sha1']}&size={attr['size']}"

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
 
    :param max_workers: 最大并发数，主要用于限制同时打开的文件数
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param path_already: 如果为 True，则说明 id_to_dirnode 中已经具备构建路径所需要的目录节点，所以不会再去拉取目录节点的信息
    :param app: 使用指定 app（设备）的接口
    :param fs_files_cooldown: `fs_files` 接口调用的冷却时间，大于 0，则使用此时间间隔执行并发
    :param fs_files_max_workers: `fs_files` 接口调用的最大并发数
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    user_id = client.user_id
    origin = origin.rstrip("/")
    savedir = abspath(fsdecode(save_dir))
    makedirs(savedir, exist_ok=True)
    mode = "wb" if update else "xb"
    abspath_prefix_length = 1
    upserted: list[str] = []
    ignored: list[str] = []
    removed: list[str] = []
    append = list.append
    add    = set.add
    if discard:
        seen: set[str] = set()
        seen_add = seen.add
        existing: set[str] = set()
        def do_discard():
            if not seen:
                rmtree(savedir)
                makedirs(savedir, exist_ok=True)
                return
            dirs: set[str] = {""}
            for path in seen:
                while path := dirname(path):
                    add(dirs, path)
            removed_dirs: set[str] = set()
            for path in existing - seen:
                d = dirname(path)
                if d in dirs:
                    path = joinpath(savedir, path)
                    remove(path)
                elif d not in removed_dirs:
                    while True:
                        add(removed_dirs, d)
                        pdir = dirname(d)
                        if not pdir or pdir in dirs:
                            rmtree(joinpath(savedir, d))
                            break
                        elif pdir in removed_dirs:
                            break
                        d = pdir
                append(removed, path)
    def normalize_path(attr: dict, /) -> str:
        if with_tree:
            path = attr["path"][abspath_prefix_length:]
        else:
            path = attr["name"]
        if without_suffix:
            path = splitext(path)[0]
        relpath = normpath(path) + ".strm"
        if discard:
            seen_add(relpath)
        return joinpath(savedir, relpath)
    write_url: Callable
    if async_:
        from aiofile import async_open
        async def write_url(path: str, url: bytes, /):
            async with async_open(path, mode) as f:
                await f.write(url)
    else:
        def write_url(path: str, url: bytes, /):
            with open(path, mode) as f:
                f.write(url)
    def save(attr: dict, /):
        path = normalize_path(attr)
        if complete_url:
            name = encode_uri_component_loose(attr["name"])
            url = f"{origin}/{name}?user_id={user_id}&pickcode={attr['pickcode']}&id={attr['id']}&sha1={attr['sha1']}&size={attr['size']}"
            urlb = bytes(url, "utf-8")
        else:
            url = f"{origin}?user_id={user_id}&pickcode={attr['pickcode']}"
            urlb = bytes(url, "ascii")
        try:
            yield write_url(path, urlb)
        except FileNotFoundError:
            makedirs(dirname(path), exist_ok=True)
            yield write_url(path, urlb)
        except OSError:
            append(ignored, path)
            return
        append(upserted, path)
    cid = to_id(cid)
    def gen_step():
        nonlocal abspath_prefix_length, savedir
        start_t = time()
        if cid:
            if use_abspath or with_tree:
                root = yield get_path_to_cid(
                    client, 
                    cid, 
                    escape=posix_escape_name, 
                    refresh=True, 
                    async_=async_, # type: ignore
                    **request_kwargs, 
                )
                abspath_prefix_length = len(root) + 1
                if use_abspath:
                    savedir += normpath(root)
                elif with_root:
                    name = root.rpartition("/")[-1]
                    savedir = joinpath(savedir, name)
            elif with_root:
                resp = yield client.fs_file_skim(
                    cid, 
                    async_=async_, # type: ignore
                    **request_kwargs
                )
                check_response(resp)
                name = posix_escape_name(unescape_115_charref(resp["data"][0]["file_name"]))
                savedir = joinpath(savedir, name)
        if discard:
            strm_files = iglob("**/*.strm", root_dir=savedir, recursive=True)
            if async_:
                task: Any = create_task(to_thread(existing.update, strm_files))
            else:
                task = run_as_thread(existing.update, strm_files)
        params: dict[str, Any] = {}
        if use_abspath is not None:
            params["path_already"] = path_already
        yield (async_batch if async_ else thread_batch)(
            lambda attr: run_gen_step(save(attr), async_), 
            (iter_files if use_abspath is None else iter_files_with_path)(
                client, 
                cid, 
                order="file_name", 
                suffix=suffix, 
                type=type, 
                normalize_attr=normalize_attr_simple, 
                escape=posix_escape_name, 
                with_ancestors=False, 
                id_to_dirnode=id_to_dirnode, 
                cooldown=fs_files_cooldown, 
                max_workers=fs_files_max_workers, 
                app=app, 
                async_=async_, # type: ignore
                **params, # type: ignore
                **request_kwargs, 
            ), 
            max_workers=max_workers, 
        )
        if discard:
            if async_:
                yield task
                yield to_thread(do_discard)
            else:
                task.result()
                do_discard()
        return {
            "cost": time() - start_t, 
            "total": len(upserted) + len(ignored) + len(removed), 
            "count_upsert": len(upserted), 
            "count_ignore": len(ignored), 
            "count_remove": len(removed), 
            "upsert": upserted, 
            "ignore": ignored, 
            "remove": removed, 
        }
    return run_gen_step(gen_step, async_)


@overload
def iter_download_nodes(
    client: str | P115Client, 
    pickcode: str | int = "", 
    files: bool = True, 
    ensure_name: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = ..., 
    max_workers: None | int = 1, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_download_nodes(
    client: str | P115Client, 
    pickcode: str | int = "", 
    files: bool = True, 
    ensure_name: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = ..., 
    max_workers: None | int = 1, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_download_nodes(
    client: str | P115Client, 
    pickcode: str | int = "", 
    files: bool = True, 
    ensure_name: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = ..., 
    max_workers: None | int = 1, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一个目录内所有的文件或者目录的信息（简略）

    :param client: 115 客户端或 cookies
    :param pickcode: 目录的 pickcode 或 id
    :param files: 如果为 True，则只获取文件，否则只获取目录
    :param ensure_name: 确保返回数据中有 "name" 字段
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件或者目录的简略信息
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    get_base_url = cycle(("http://proapi.115.com", "https://proapi.115.com")).__next__
    if async_:
        if max_workers is None or max_workers <= 0:
            max_workers = 20
    elif max_workers is not None and max_workers <= 0:
        max_workers = None
    if files:
        method = client.download_files
    else:
        method = client.download_folders
        if id_to_dirnode is None:
            id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    file_skim = client.fs_file_skim
    @as_gen_step
    def normalize_attrs(attrs: list[dict], /):
        if files:
            for i, info in enumerate(attrs):
                attrs[i] = {
                    "is_dir": False, 
                    "id": to_id(info["pc"]), 
                    "pickcode": info["pc"], 
                    "parent_id": int(info["pid"]), 
                    "size": info["fs"], 
                }
            if ensure_name:
                resp = yield file_skim(
                    (a["id"] for a in attrs), 
                    method="POST", 
                    async_=async_, 
                    **request_kwargs, 
                )
                if resp.get("error") != "文件不存在":
                    check_response(resp)
                    nodes = {int(a["file_id"]): a for a in resp["data"]}
                    for attr in attrs:
                        if node := nodes.get(attr["id"]):
                            attr["sha1"] = node["sha1"]
                            attr["name"] = unescape_115_charref(node["file_name"])
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
                    id_to_dirnode[attr["id"]] = DirNode(attr["name"], attr["parent_id"])
        return attrs
    get_nodes = partial(
        method, 
        async_=async_, 
        **{"base_url": get_base_url, **request_kwargs}, 
    )
    if max_workers == 1:
        def gen_step(pickcode: int | str, /):
            pickcode = to_pickcode(pickcode)
            for i in count(1):
                payload = {"pickcode": pickcode, "page": i}
                resp = yield get_nodes(payload)
                check_response(resp)
                data = resp["data"]
                yield YieldFrom(normalize_attrs(data["list"]))
                if not data["has_next_page"]:
                    break
    else:
        max_page = 0
        get_next_page = count(1).__next__
        if async_:
            q: Any = AsyncQueue()
        else:
            q = SimpleQueue()
        get, put = q.get, q.put_nowait
        @as_gen_step
        def request(pickcode: str, /):
            nonlocal max_page
            while True:
                page = get_next_page()
                if max_page and page > max_page:
                    return
                resp: dict = yield get_nodes({"pickcode": pickcode, "page": page})
                try:
                    check_response(resp)
                except BaseException as e:
                    put(e)
                    return
                data = resp["data"]
                put((yield normalize_attrs(data["list"])))
                if not data["has_next_page"]:
                    max_page = page
        def gen_step(pickcode: int | str, /):
            if async_:
                n = cast(int, max_workers)
                task_group = TaskGroup()
                yield task_group.__aenter__()
                create_task = task_group.create_task
                submit: Callable = lambda f, /, *a, **k: create_task(f(*a, **k))
                shutdown: Callable = lambda: task_group.__aexit__(None, None, None)
            else:
                executor = ThreadPoolExecutor(max_workers)
                n = executor._max_workers
                submit = executor.submit
                shutdown = lambda: executor.shutdown(False, cancel_futures=True)
            pickcode = to_pickcode(pickcode)
            try:
                sentinel = object()
                countdown: Callable
                if async_:
                    def countdown(_, /):
                        nonlocal n
                        n -= 1
                        if not n:
                            put(sentinel)
                else:
                    def countdown(_, /, lock=Lock()):
                        nonlocal n
                        with lock:
                            n -= 1
                            if not n:
                                put(sentinel)
                for _ in range(n):
                    submit(request, pickcode, async_=async_).add_done_callback(countdown)
                while True:
                    ls = yield get()
                    if ls is sentinel:
                        break
                    elif isinstance(ls, BaseException):
                        raise ls
                    yield YieldFrom(ls)
            finally:
                yield shutdown()
    if pickcode:
        return run_gen_step_iter(gen_step(pickcode), async_)
    else:
        def chain():
            nonlocal max_page, get_next_page
            pickcodes: list[str] = []
            add_pickcode = pickcodes.append
            with with_iter_next(iterdir(
                client, 
                ensure_file=None if files else False, 
                app=app, 
                normalize_attr=normalize_attr_simple, 
                id_to_dirnode=id_to_dirnode, 
                raise_for_changed_count=True, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                while True:
                    attr = yield get_next()
                    if attr["is_dir"]:
                        if not files:
                            yield Yield(attr)
                        add_pickcode(attr["pickcode"])
                    elif files:
                        yield Yield(attr)
            for pickcode in pickcodes:
                yield YieldFrom(run_gen_step_iter(gen_step(pickcode), async_))             
                max_page = 0
                get_next_page = count(1).__next__
        return run_gen_step_iter(chain, async_)


@overload
def iter_download_files(
    client: str | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = True, 
    max_workers: None | int = None, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_download_files(
    client: str | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = True, 
    max_workers: None | int = None, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_download_files(
    client: str | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int] | DirNode] = None, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = True, 
    max_workers: None | int = None, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一个目录内所有的文件信息（简略），且包括 "dir_ancestors"、"dirname"

    .. note::
        并不提供文件的 name，如果需要获得 name，你可以在之后获取下载链接，然后从下载链接中获取实际的名字

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param id_to_dirnode: 字典，保存 id 到对应文件的 `DirNode(name, parent_id)` 命名元组的字典
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件的简略信息
    """
    if isinstance(client, str):
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
    def norm_attr(attr: dict, /) -> dict:
        pid = attr["parent_id"]
        pnode = id_to_dirnode[pid]
        if with_ancestors:
            attr["dir_ancestors"] = get_ancestors(pid, pnode)
        attr["dirname"] = get_path(pnode)
        return attr
    ancestors_loaded: None | bool = False
    @as_gen_step
    def load_ancestors(pickcode: str, /):
        nonlocal ancestors_loaded
        try:
            yield through(iter_download_nodes(
                client, 
                pickcode, 
                files=False, 
                id_to_dirnode=id_to_dirnode, 
                max_workers=max_workers, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            ))
        finally:
            ancestors_loaded = True
    def gen_step(pickcode: str = to_pickcode(cid), /):
        nonlocal ancestors_loaded
        if pickcode:
            if cid:
                from .iterdir import _iter_fs_files
                do_next: Callable = anext if async_ else next
                yield do_next(_iter_fs_files(
                    client, 
                    to_id(cid), 
                    page_size=1, 
                    id_to_dirnode=id_to_dirnode, 
                    async_=async_, 
                    **request_kwargs, 
                ))
            if async_:
                task: Any = create_task(load_ancestors(pickcode))
            else:
                task = run_as_thread(load_ancestors, pickcode)
            cache: list[dict] = []
            add_to_cache = cache.append
            with with_iter_next(iter_download_nodes(
                client, 
                pickcode, 
                files=True, 
                max_workers=max_workers, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                while True:
                    attr = yield get_next()
                    if ancestors_loaded is None:
                        yield Yield(norm_attr(attr))
                    elif ancestors_loaded:
                        yield YieldFrom(map(norm_attr, cache))
                        cache.clear()
                        if async_:
                            yield task
                        else:
                            task.result()
                        ancestors_loaded = None
                    else:
                        add_to_cache(attr)
            if cache:
                if async_:
                    yield task
                else:
                    task.result()
                yield YieldFrom(map(norm_attr, cache))
        else:
            defaults = {
                "dir_ancestors": [{"id": 0, "parent_id": 0, "name": ""}],
                "dirname": "/",
            }
            pickcodes: list[str] = []
            add_pickcode = pickcodes.append
            with with_iter_next(iterdir(
                client, 
                id_to_dirnode=id_to_dirnode, 
                app=app, 
                raise_for_changed_count=True, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                while True:
                    attr = yield get_next()
                    if attr["is_dir"]:
                        add_pickcode(attr["pickcode"])
                    else:
                        yield Yield({
                            "parent_id": attr["parent_id"], 
                            "pickcode": attr["pickcode"], 
                            "size": attr["size"], 
                            **defaults, 
                        })
            for pickcode in pickcodes:
                yield YieldFrom(run_gen_step_iter(gen_step(pickcode), async_))
                ancestors_loaded = False
    return run_gen_step_iter(gen_step, async_)


@overload
def get_remaining_open_count(
    client: str | P115Client | P115OpenClient, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def get_remaining_open_count(
    client: str | P115Client | P115OpenClient, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def get_remaining_open_count(
    client: str | P115Client | P115OpenClient, 
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
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if not isinstance(client, P115Client) or app == "open":
        get_url: Callable[..., P115URL] = client.download_url_open
    elif app in ("", "web", "desktop", "harmony"):
        get_url = client.download_url
    else:
        get_url = partial(client.download_url, app=app)
    def gen_step():
        cache: list = []
        add_to_cache = cache.append
        try:
            if isinstance(client, P115OpenClient):
                it: Iterator[dict] | AsyncIterator[dict] = iter_files(
                    client, 
                    type=4, 
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
                    if attr["size"] <= 1024 * 1024 * 200:
                        continue
                    try:
                        url = yield get_url(attr["pickcode"], async_=async_)
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

