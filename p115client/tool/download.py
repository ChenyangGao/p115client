#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "batch_get_url", "iter_url_batches", "iter_files_with_url", "iter_images_with_url", 
    "iter_subtitles_with_url", "iter_subtitle_batches", "make_db", "make_strm", 
    "iter_download_nodes", "iter_download_files", "get_remaining_open_count", 
]
__doc__ = "这个模块提供了一些和下载有关的函数"

from asyncio import (
    create_task, to_thread, CancelledError as AsyncCancelledError, 
    Queue as AsyncQueue, TaskGroup, 
)
from collections import defaultdict
from collections.abc import (
    AsyncIterator, Callable, Coroutine, Iterable, Iterator, MutableMapping, 
)
from concurrent.futures import CancelledError, ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime
from functools import partial
from itertools import batched, chain, count, cycle
from math import inf
from os import fsdecode, makedirs, remove, rmdir, scandir, DirEntry, PathLike
from os.path import abspath, dirname, join as joinpath, normpath, splitext
from queue import SimpleQueue
from sqlite3 import connect, Connection, Cursor
from sys import exc_info
from threading import Lock
from time import time
from typing import cast, overload, Any, Literal
from types import EllipsisType
from urllib.parse import urlsplit
from urllib.request import urlopen, Request
from uuid import uuid4
from warnings import warn

from asynctools import async_chain
from concurrenttools import run_as_thread
from encode_uri import encode_uri_component_loose
from iterutils import (
    chunked, map as do_map, run_gen_step, run_gen_step_iter, 
    through, with_iter_next, Yield, YieldFrom, GenStep, 
)
from p115client import (
    check_response, normalize_attr, normalize_attr_simple, P115Client, 
    P115OpenClient, P115URL, 
)
from p115client.const import ID_TO_DIRNODE_CACHE
from p115client.exception import AccessError, P115Warning
from p115pickcode import to_id

from .iterdir import (
    iterdir, iter_files, iter_files_shortcut, unescape_115_charref, 
    posix_escape_name, 
)
from .util import reduce_image_url_layers


# TODO: 之后加上并发拉取，以加快速度
# TODO: 为了避免拉了太多赶不上用，用队列来收集结果，队列长度有限，这样可以在队列满的时候阻塞工作者
@overload
def batch_get_url(
    client: str | PathLike | P115Client | P115OpenClient, 
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
    client: str | PathLike | P115Client | P115OpenClient, 
    pickcode: int | str | Iterable[int | str], 
    user_agent: str = "", 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict[int, P115URL]]:
    ...
def batch_get_url(
    client: str | PathLike | P115Client | P115OpenClient, 
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
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if headers := request_kwargs.get("headers"):
        request_kwargs["headers"] = dict(headers, **{"user-agent": user_agent})
    else:
        request_kwargs["headers"] = {"user-agent": user_agent}
    if isinstance(pickcode, (int, str)):
        pickcode = client.to_pickcode(pickcode)
    elif not isinstance(pickcode, str):
        pickcode = ",".join(map(client.to_pickcode, pickcode))
    if not isinstance(client, P115Client) or app == "open":
        get_download_urls: Callable = client.download_urls_open
    else:
        get_download_urls = client.download_urls
    return get_download_urls(pickcode, async_=async_, **request_kwargs)


@overload
def iter_url_batches(
    client: str | PathLike | P115Client | P115OpenClient, 
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
    client: str | PathLike | P115Client | P115OpenClient, 
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
    client: str | PathLike | P115Client | P115OpenClient, 
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
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    if headers := request_kwargs.get("headers"):
        request_kwargs["headers"] = dict(headers, **{"user-agent": user_agent})
    else:
        request_kwargs["headers"] = {"user-agent": user_agent}
    if batch_size <= 0:
        batch_size = 1
    def gen_step():
        if batch_size == 1:
            if not isinstance(client, P115Client) or app == "open":
                get_download_url: Callable = client.download_url_open
            else:
                get_download_url = partial(client.download_url, app=app)
            for pickcode in map(client.to_pickcode, pickcodes):
                yield Yield(get_download_url(
                    pickcode, 
                    async_=async_, 
                    **request_kwargs, 
                ))
        else:
            if not isinstance(client, P115Client) or app == "open":
                get_download_urls: Callable = client.download_urls_open
            else:
                get_download_urls = client.download_urls
            for pcs in batched(map(client.to_pickcode, pickcodes), batch_size):
                if urls := (yield get_download_urls(
                    ",".join(pcs), 
                    async_=async_, 
                    **request_kwargs, 
                )):
                    yield YieldFrom(urls.values())
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_files_with_url(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
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
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    user_agent: str = "", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_files_with_url(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    type: Literal[1, 2, 3, 4, 5, 6, 7, 99] = 99, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
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
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用指定 app（设备）的接口
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param user_agent: "user-agent" 请求头的值
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件信息，并增加一个 "url" 作为下载链接
    """
    if isinstance(client, (str, PathLike)):
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
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_images_with_url(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_images_with_url(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: None | str | Iterable[str] = None, 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
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
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用指定 app（设备）的接口
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件信息，并增加一个 "url" 作为下载链接
    """
    if isinstance(client, (str, PathLike)):
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
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: str | Iterable[str] = (".srt", ".ass", ".ssa"), 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_subtitles_with_url(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: str | Iterable[str] = (".srt", ".ass", ".ssa"), 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "web", 
    raise_for_changed_count: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_subtitles_with_url(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str = 0, 
    suffixes: str | Iterable[str] = (".srt", ".ass", ".ssa"), 
    cur: Literal[0, 1] = 0, 
    with_ancestors: bool = False, 
    with_path: bool = False, 
    use_star: None | bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    normalize_attr: Callable[[dict], dict] = normalize_attr, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
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
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用指定 app（设备）的接口
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件信息，并增加一个 "url" 作为下载链接
    """
    if isinstance(client, (str, PathLike)):
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
    from .iterdir import _iter_fs_files
    cid = to_id(cid)
    def gen_step():
        nonlocal suffixes
        if isinstance(suffixes, str):
            suffixes = suffixes,
        do_chain: Callable = async_chain.from_iterable if async_ else chain.from_iterable
        do_next: Callable = anext if async_ else next
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
                    attr = yield do_next(_iter_fs_files(
                        client, 
                        scid, 
                        page_size=1, 
                        normalize_attr=normalize_attr_simple, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    ))
                    resp = yield fs_video_subtitle(
                        attr["pickcode"], 
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
    client: str | PathLike | P115Client | P115OpenClient, 
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
    client: str | PathLike | P115Client | P115OpenClient, 
    file_ids: Iterable[int | str], 
    batch_size: int = 1_000, 
    app: str = "web", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_subtitle_batches(
    client: str | PathLike | P115Client | P115OpenClient, 
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
    if isinstance(client, (str, PathLike)):
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
    from .iterdir import _iter_fs_files
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
                attr = yield do_next(_iter_fs_files(
                    client, 
                    scid, 
                    page_size=1, 
                    normalize_attr=normalize_attr_simple, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                ))
                resp = yield fs_video_subtitle(
                    attr["pickcode"], 
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


@overload
def make_db(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    dbfile: str | PathLike | Connection | Cursor = "115-file-tree.db", 
    clean: bool = True, 
    replace: bool = True, 
    with_path: bool = True, 
    with_event: bool = False, 
    batch_size: int = 3_000, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def make_db(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    dbfile: str | PathLike | Connection | Cursor = "115-file-tree.db", 
    clean: bool = True, 
    replace: bool = True, 
    with_path: bool = True, 
    with_event: bool = False, 
    batch_size: int = 3_000, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def make_db(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    dbfile: str | PathLike | Connection | Cursor = "115-file-tree.db", 
    clean: bool = True, 
    replace: bool = True, 
    with_path: bool = True, 
    with_event: bool = False, 
    batch_size: int = 3_000, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """拉取目录树，保存到数据库

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param dbfile: 数据库路径或连接
    :param clean: 是否清理旧数据
    :param replace: 遇到相同 id 时是否替换数据
    :param with_path: 拉取数据时是否需要 "path" 字段
    :param with_event: 是否收集和文件系统变更（文件的增删改）有关的事件，数据保存在 ``event`` 表中
    :param batch_size: 每批写入数据库的最多条数
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param app: 使用指定 app（设备）的接口
    :param max_workers: 最大并发数，用户拉取目录树，但写入数据库仍然是单线程的（经过测试如此效率更高）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 一些统计信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    init_sql = """\
-- 修改日志模式为 WAL (write-ahead-log)
PRAGMA journal_mode = WAL;

-- 创建表
CREATE TABLE IF NOT EXISTS data (
    id INTEGER NOT NULL PRIMARY KEY,   -- id
    parent_id INTEGER NOT NULL ,       -- 所在的目录 id
    user_id INTEGER NOT NULL,          -- 用户 id
    name TEXT NOT NULL,                -- 名字
    sha1 TEXT NOT NULL DEFAULT '',     -- 文件的 sha1 散列值
    size INTEGER NOT NULL DEFAULT 0,   -- 文件大小
    pickcode TEXT NOT NULL DEFAULT '', -- 提取码
    is_dir INTEGER NOT NULL DEFAULT 0, -- 是否目录
    path TEXT NOT NULL DEFAULT '',     -- 路径
    top_id INTEGER NOT NULL DEFAULT 0, -- 最近一次拉取时顶层目录的 id
    extra BLOB DEFAULT NULL,           -- 其它信息
    created_at TIMESTAMP DEFAULT (STRFTIME('%s', 'now')), -- 创建时间
    updated_at TIMESTAMP DEFAULT (STRFTIME('%s', 'now')) -- 更新时间
);

-- 创建索引（一些索引需要时候自己加）
CREATE INDEX IF NOT EXISTS idx_data_pid ON data(parent_id);
CREATE INDEX IF NOT EXISTS idx_data_tid ON data(top_id);
CREATE INDEX IF NOT EXISTS idx_data_utime ON data(updated_at);
-- CREATE INDEX IF NOT EXISTS idx_data_sha1_size ON data(sha1, size);
-- CREATE INDEX IF NOT EXISTS idx_data_uid ON data(user_id);
-- CREATE INDEX IF NOT EXISTS idx_data_name ON data(name);
-- CREATE INDEX IF NOT EXISTS idx_data_path ON data(path);
"""
    if with_event:
        init_sql += """
-- event 表，只用于记录 data 表中与文件系统有关的增删改事件
CREATE TABLE IF NOT EXISTS event (
    _id INTEGER PRIMARY KEY AUTOINCREMENT, -- 主键
    id INTEGER NOT NULL,               -- id
    is_dir INTEGER NOT NULL DEFAULT 0, -- 是否目录
    pid0 INTEGER NOT NULL DEFAULT -1,  -- 更新前的父目录 id
    pid1 INTEGER NOT NULL DEFAULT -1,  -- 更新后的父目录 id
    name0 TEXT NOT NULL DEFAULT "",    -- 更新前的名字
    name1 TEXT NOT NULL DEFAULT "",    -- 更新后的名字
    path0 TEXT NOT NULL DEFAULT "",    -- 更新前的路径
    path1 TEXT NOT NULL DEFAULT "",    -- 更新后的路径
    event TEXT NOT NULL DEFAULT "",    -- 事件名
    created_at DATETIME DEFAULT (STRFTIME('%s', 'now')) -- 创建时间
);

-- data 表发生新增
DROP TRIGGER IF EXISTS trg_data_insert;
CREATE TRIGGER trg_data_insert
AFTER INSERT ON data
FOR EACH ROW
BEGIN
    INSERT INTO event(id, is_dir, pid1, name1, path1, event) 
    VALUES (NEW.id, NEW.is_dir, NEW.parent_id, NEW.name, NEW.path, 'add');
END;

-- data 表发生删除
DROP TRIGGER IF EXISTS trg_data_delete;
CREATE TRIGGER trg_data_delete
AFTER DELETE ON data
FOR EACH ROW
BEGIN
    INSERT INTO event(id, is_dir, pid0, name0, path0, event) 
    VALUES (OLD.id, OLD.is_dir, OLD.parent_id, OLD.name, OLD.path, 'remove');
END;

-- data 表发生更新
DROP TRIGGER IF EXISTS trg_data_update;
CREATE TRIGGER trg_data_update
AFTER UPDATE ON data
FOR EACH ROW
BEGIN
    UPDATE data SET updated_at = STRFTIME('%s', 'now') WHERE id = NEW.id;
    INSERT INTO event(id, is_dir, pid0, pid1, name0, name1, path0, path1, event)
    SELECT
        OLD.id, OLD.is_dir, OLD.parent_id, NEW.parent_id, OLD.name, NEW.name, OLD.path, NEW.path, 
        CASE WHEN OLD.parent_id != NEW.parent_id THEN 
            CASE WHEN OLD.name != NEW.name THEN 'move,rename' ELSE 'move' END
        ELSE 'rename' END
    WHERE
        OLD.parent_id != NEW.parent_id OR OLD.name != NEW.name;
END;"""
    else:
        init_sql += """
DROP TRIGGER IF EXISTS trg_data_insert;
DROP TRIGGER IF EXISTS trg_data_delete;

-- data 表发生更新
DROP TRIGGER IF EXISTS trg_data_update;
CREATE TRIGGER trg_data_update
AFTER UPDATE ON data
FOR EACH ROW
BEGIN
    UPDATE data SET updated_at = STRFTIME('%s', 'now') WHERE id = NEW.id;
END;"""
    clean_sql = """\
DELETE FROM data WHERE id in (
    WITH ids(id) AS (
        SELECT id FROM data WHERE parent_id = :top_id AND updated_at < :start_t
        UNION ALL
        SELECT data.id FROM ids JOIN data ON (ids.id = data.parent_id) WHERE updated_at < :start_t
    )
    SELECT id FROM ids
    UNION ALL
    SELECT id FROM data WHERE top_id = :top_id AND updated_at < :start_t
);"""
    cid = to_id(cid)
    user_id = client.user_id
    def write_records(cur: Cursor, records: tuple[dict], /):
        if replace:
            if with_path:
                sql = """\
INSERT OR REPLACE INTO data (id, parent_id, user_id, name, sha1, size, pickcode, is_dir, top_id, path)
VALUES (:id, :parent_id, :user_id, :name, :sha1, :size, :pickcode, :is_dir, :top_id, :path);"""
            else:
                sql = """\
INSERT OR REPLACE INTO data (id, parent_id, user_id, name, sha1, size, pickcode, is_dir, top_id)
VALUES (:id, :parent_id, :user_id, :name, :sha1, :size, :pickcode, :is_dir, :top_id);"""
        elif with_path:
            sql = """\
INSERT INTO data (id, parent_id, user_id, name, sha1, size, pickcode, is_dir, top_id, path)
VALUES (:id, :parent_id, :user_id, :name, :sha1, :size, :pickcode, :is_dir, :top_id, :path)
ON CONFLICT(id) DO UPDATE SET id = excluded.id;"""
        else:
            sql = """\
INSERT INTO data (id, parent_id, user_id, name, sha1, size, pickcode, is_dir, top_id)
VALUES (:id, :parent_id, :user_id, :name, :sha1, :size, :pickcode, :is_dir, :top_id)
ON CONFLICT (id) DO UPDATE SET id = excluded.id;"""
        for record in records:
            record["user_id"] = user_id
            record["top_id"] = cid
        cur.executemany(sql, records)
    traverse_tree: Callable
    if with_path:
        from .iterdir import traverse_tree_with_path as traverse_tree
    else:
        from .iterdir import traverse_tree
    def gen_step():
        if isinstance(dbfile, (Connection, Cursor)):
            will_close = False
            con = dbfile
            if isinstance(con, Cursor):
                cur = con
                con = con.connection
        else:
            will_close = True
            con = connect(
                dbfile, 
                uri=isinstance(dbfile, str) and dbfile.startswith("file:"), 
                check_same_thread=False, 
                timeout=inf, 
            )
            cur = con.cursor()
        nupsert = 0
        nremove = 0
        try:
            cur.executescript(init_sql)
            start_t = time()
            with with_iter_next(chunked(traverse_tree(
                client, 
                cid, 
                id_to_dirnode=id_to_dirnode, 
                app=app, 
                max_workers=max_workers, 
                async_=async_, 
                **request_kwargs, 
            ), batch_size)) as get_next:
                while True:
                    records = yield get_next()
                    if async_:
                        yield to_thread(write_records, cur, records)
                    else:
                        write_records(cur, records)
                    nupsert += len(records)
            if clean:
                clean_start_t = time()
                cur.execute(clean_sql, {"top_id": cid, "start_t": int(start_t)})
                nremove = cur.rowcount
            if async_:
                yield to_thread(con.commit)
            else:
                con.commit()
        except:
            con.rollback()
            raise
        finally:
            if will_close:
                con.close()
        stop_t = time()
        result = {
            "total": nupsert + nremove, 
            "count_upsert": nupsert, 
            "count_remove": nremove, 
            "start_time": start_t, 
            "start_time_str": str(datetime.fromtimestamp(start_t)), 
            "stop_time": stop_t, 
            "stop_time_str": str(datetime.fromtimestamp(stop_t)), 
            "elapsed_seconds": stop_t - start_t, 
        }
        if clean:
            result["elapsed_seconds_of_cleaning"] = stop_t - clean_start_t
        return result
    return run_gen_step(gen_step, async_)


@overload
def make_strm(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    save_dir: bytes | str | PathLike = ".", 
    base_url: str = "", 
    with_root: None | bool = None, 
    without_suffix: bool = True, 
    clean: bool = True, 
    replace: bool = True, 
    predicate: None | Literal[1, 2, 3, 4, 5, 6, 7] | str | tuple[str, ...] | Callable[[dict], bool] = 4, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    path_already: bool = False, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def make_strm(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    save_dir: bytes | str | PathLike = ".", 
    base_url: str = "", 
    with_root: None | bool = None, 
    without_suffix: bool = True, 
    clean: bool = True, 
    replace: bool = True, 
    predicate: None | Literal[1, 2, 3, 4, 5, 6, 7] | str | tuple[str, ...] | Callable[[dict], bool] = 4, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    path_already: bool = False, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def make_strm(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    save_dir: bytes | str | PathLike = ".", 
    base_url: str = "", 
    with_root: None | bool = None, 
    without_suffix: bool = True, 
    clean: bool = True, 
    replace: bool = True, 
    predicate: None | Literal[1, 2, 3, 4, 5, 6, 7] | str | tuple[str, ...] | Callable[[dict], bool] = 4, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    path_already: bool = False, 
    app: str = "android", 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """拉取目录树，保存到 .strm 文件

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param save_dir: 本地的保存目录，默认是当前工作目录
    :param base_url: STRM 链接（或者说 302 服务）的基地址
    :param with_root: 是否保留根

        - 如果为 True，则在 ``save_dir`` 保留从根目录 / 开始的目录结构
        - 如果为 False，则在 ``save_dir`` 保留从拉取目录开始的目录结构
        - 如果为 None，则在 ``save_dir`` 下创建一个和 ``cid`` 目录名字相同的目录作为 ``save_dir``，然后保留从拉取目录开始的目录结构

    :param without_suffix: 是否去除原来的扩展名

        - 如果为 True，则去掉原来的扩展名后再拼接
        - 如果为 False，则直接用 ".strm" 拼接到原来的路径后面

    :param clean: 是否清理 ``save_dir``，如果为 True，则删除所有不包含本次更新所涉及到的 .strm 文件和相应目录
    :param replace: 遇到路径下有 .strm 文件时是否替换
    :param predicate: 断言，断言为真的文件才会生成 .strm 文件

        - 如果为 None，则不进行筛选
        - 如果为整数，则筛选某一类型的文件

            - 1: 文档
            - 2: 图片
            - 3: 音频
            - 4: 视频
            - 5: 压缩包
            - 6: 应用
            - 7: 书籍

        - 如果是 str 或元组，则是后缀或一组后缀，筛选这些后缀的文件
        - 如果是 Callable，则逐个对获取到的文件信息调用它，返回值为 True 才保留
 
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param path_already: 如果为 True，则说明 ``id_to_dirnode`` 中已经具备构建路径所需要的目录节点，所以不会再去拉取目录节点的信息
    :param app: 使用指定 app（设备）的接口
    :param max_workers: 最大并发数，用户拉取目录树，但写入本地文件仍然是单线程的（经过测试如此效率更高）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 一些统计信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    user_id = client.user_id
    base_url = base_url.rstrip("/")
    if base_url.startswith("//"):
        base_url = "http:" + base_url
        is_url = True
    else:
        is_url = bool(urlsplit(base_url).scheme)
    save_dir = abspath(fsdecode(save_dir))
    mode = "w" if replace else "x"
    prefix_length = -1
    upserts: list[str] = []
    ignores: list[str] = []
    removes: list[str] = []
    errors: list[OSError] = []
    count_errors: dict[str, int] = defaultdict(int)
    push = list.append
    oserror_flag = False
    @contextmanager
    def collect_oserror():
        nonlocal oserror_flag
        oserror_flag = False
        try:
            yield 
        except OSError as e:
            oserror_flag = True
            push(errors, e)
            count_errors[type(e).__qualname__] += 1
    if clean:
        seen: set[str] = set()
        add_to_seen = seen.add
        def do_clean():
            nonlocal save_dir
            save_dir = cast(str, save_dir)
            with collect_oserror():
                stack = [scandir(save_dir)]
            if oserror_flag:
                return
            if not stack: return
            ancestors: list[str | PathLike] = [save_dir]
            caches: list[list[DirEntry]] = [[]]
            is_dir = DirEntry.is_dir
            t = i = 0
            b = 1
            while i >= 0:
                cache = caches[i]
                for entry in stack[i]:
                    if is_dir(entry, follow_symlinks=False):
                        i += 1
                        with collect_oserror():
                            try:
                                scanit = scandir(entry)
                                stack[i] = scanit
                                ancestors[i] = entry
                                caches[i] = []
                            except IndexError:
                                push(stack, scanit)
                                push(ancestors, entry)
                                push(caches, [])
                        if oserror_flag:
                            t |= b
                            continue
                        b <<= 1
                        break
                    path = entry.path
                    if path in seen:
                        t |= b
                    elif path.endswith(".strm"):
                        with collect_oserror():
                            remove(entry)
                            push(removes, path)
                    else:
                        push(cache, entry)
                else:
                    pred = t & b
                    if not pred:
                        for entry in cache:
                            with collect_oserror():
                                remove(entry)
                                push(removes, entry.path)
                        with collect_oserror():
                            rmdir(ancestors[i])
                    t &= ~b
                    i -= 1
                    b >>= 1
                    if pred:
                        t |= b
    def normalize_path(attr: dict, /) -> str:
        nonlocal prefix_length, save_dir, clean
        if prefix_length < 0:
            if cid:
                prefix_length = sum(len(a["name"]) + 1 for a in attr["top_ancestors"]) - 1
                if with_root:
                    save_dir = joinpath(save_dir, *(a["name"] for a in attr["top_ancestors"][1:]))
                elif with_root is None:
                    save_dir = joinpath(save_dir, attr["top_ancestors"][-1]["name"])
            else:
                prefix_length = 0
            try:
                rmdir(save_dir)
                clean = False
            except FileNotFoundError:
                clean = False
            except OSError:
                pass
        path: str = attr["path"]
        if prefix_length:
            path = path[prefix_length:]
        if without_suffix:
            path = splitext(path)[0]
        path = joinpath(cast(str, save_dir), normpath("." + path + ".strm"))
        if clean:
            add_to_seen(path)
        return path
    params: dict = {
        "cid": cid, 
        "max_workers": max_workers, 
        "with_path": True, 
        "id_to_dirnode": id_to_dirnode, 
        "path_already": path_already, 
    }
    if isinstance(predicate, (int, str)):
        params["is_skim"] = False
        if isinstance(predicate, int):
            params["type"] = predicate
        else:
            params["suffix"] = predicate
        predicate = None
    elif isinstance(predicate, tuple):
        suffixes = predicate
        predicate = lambda attr: attr["name"].endswith(suffixes)
    cid = to_id(cid)
    def gen_step():
        files: Iterator[dict] | AsyncIterator[dict] = iter_files_shortcut(
            client, 
            **params, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )
        if predicate is not None:
            from iterutils import filter
            files = filter(predicate, files)
        start_t = time()
        with with_iter_next(files) as get_next:
            while True:
                attr = yield get_next()
                path = attr["path"]
                if is_url:
                    url = f"{base_url}/{encode_uri_component_loose(path, quote_slash=False)}?user_id={user_id}&id={attr['id']}&pickcode={attr['pickcode']}&&sha1={attr['sha1']}&size={attr['size']}"
                else:
                    url = base_url + path
                path = normalize_path(attr)
                with collect_oserror():
                    try:
                        file = open(path, mode, encoding="utf-8")
                    except FileNotFoundError:
                        makedirs(dirname(path), exist_ok=True)
                        file = open(path, mode, encoding="utf-8")
                    except FileExistsError:
                        push(ignores, path)
                        continue
                if oserror_flag:
                    push(ignores, path)
                    continue
                with file:
                    file.write(url)
                    push(upserts, path)
        if clean:
            clean_start_t = time()
            if async_:
                yield to_thread(do_clean)
            else:
                do_clean()
        stop_t = time()
        result = {
            "upserts": upserts, 
            "ignores": ignores, 
            "removes": removes, 
            "errors": errors, 
            "total": len(upserts) + len(ignores) + len(removes), 
            "count_upserts": len(upserts), 
            "count_ignores": len(ignores), 
            "count_removes": len(removes), 
            "count_errors": count_errors, 
            "start_time": start_t, 
            "start_time_str": str(datetime.fromtimestamp(start_t)), 
            "stop_time": stop_t, 
            "stop_time_str": str(datetime.fromtimestamp(stop_t)), 
            "elapsed_seconds": stop_t - start_t, 
        }
        if clean:
            result["elapsed_seconds_of_cleaning"] = stop_t - clean_start_t
        return result
    return run_gen_step(gen_step, async_)


@overload
def iter_download_nodes(
    client: str | PathLike | P115Client, 
    pickcode: str | int = "", 
    files: bool = True, 
    ensure_name: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    max_workers: None | int = 1, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_download_nodes(
    client: str | PathLike | P115Client, 
    pickcode: str | int = "", 
    files: bool = True, 
    ensure_name: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    max_workers: None | int = 1, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_download_nodes(
    client: str | PathLike | P115Client, 
    pickcode: str | int = "", 
    files: bool = True, 
    ensure_name: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
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
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件或者目录的简略信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client, check_for_relogin=True)
    get_base_url = cycle(("http://pro.api.115.com", "https://proapi.115.com")).__next__
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
    need_yield = files and ensure_name
    def normalize_attrs(attrs: list[dict], /):
        if attrs:
            if files:
                for i, info in enumerate(attrs):
                    attrs[i] = {
                        "is_dir": False, 
                        "id": to_id(info["pc"]), 
                        "pickcode": info["pc"], 
                        "parent_id": int(info["pid"]), 
                        "size": info["fs"], 
                    }
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
        return attrs
    if need_yield:
        prepare = normalize_attrs
        def normalize_attrs(attrs: list[dict], /):
            prepare(attrs)
            if attrs:
                def load_names(attrs, /):
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
                    return attrs
                return GenStep(load_names(attrs))
            return attrs
    get_nodes = partial(
        method, 
        async_=async_, 
        **{"base_url": get_base_url, **request_kwargs}, 
    )
    to_pickcode = client.to_pickcode
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
        def gen_step(pickcode: int | str, /):
            max_page = 0
            def request(task_idx, pickcode: str, /):
                nonlocal max_page
                while True:
                    page = get_next_page()
                    if max_page and page > max_page:
                        return
                    task_page[task_idx] = page
                    try:
                        resp: dict = yield get_nodes({"pickcode": pickcode, "page": page})
                        check_response(resp)
                        data = resp["data"]
                        attrs = normalize_attrs(data["list"])
                        if need_yield:
                            attrs = yield attrs
                    except BaseException as e:
                        put(e)
                        return
                    put(attrs)
                    if not data["has_next_page"]:
                        max_page = page
                        for i, p in enumerate(task_page):
                            if p > page:
                                task_list[i].cancel()
            get_next_page = count(1).__next__
            if async_:
                q: Any = AsyncQueue()
            else:
                q = SimpleQueue()
            get, put = q.get, q.put_nowait
            if async_:
                n = cast(int, max_workers)
                task_group = TaskGroup()
                yield task_group.__aenter__()
                create_task = task_group.create_task
                submit: Callable = lambda f, /, *a, **k: create_task(f(*a, **k))
                shutdown: Callable = lambda: task_group.__aexit__(*exc_info())
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
                task_list: list = [None] * n
                task_page: list[int] = [0] * n
                for i in range(n):
                    task = task_list[i] = submit(run_gen_step, request(i, pickcode), async_)
                    task.add_done_callback(countdown)
                while True:
                    ls = yield get()
                    if ls is sentinel:
                        break
                    elif isinstance(ls, (CancelledError, AsyncCancelledError)):
                        continue
                    elif isinstance(ls, BaseException):
                        raise ls
                    yield YieldFrom(ls)
            finally:
                yield shutdown()
    if pickcode:
        return run_gen_step_iter(gen_step(pickcode), async_)
    else:
        def chain():
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
        return run_gen_step_iter(chain, async_)


@overload
def iter_download_files(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = False, 
    with_url: bool = False, 
    path_already: bool = False, 
    user_agent: None | str = None, 
    max_workers: None | int = None, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_download_files(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = False, 
    with_url: bool = False, 
    path_already: bool = False, 
    user_agent: None | str = None, 
    max_workers: None | int = None, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_download_files(
    client: str | PathLike | P115Client, 
    cid: int | str = 0, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = False, 
    with_url: bool = False, 
    path_already: bool = False, 
    user_agent: None | str = None, 
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
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param with_url: 文件信息中是否要包含 "url" 字段。

        .. caution::
            要求但如果实际上不包含 "url" 字段，则说明获取失败，文件可能违规了

    :param path_already: 如果为 True，则说明 id_to_dirnode 中已经具备构建路径所需要的目录节点，所以不会再去拉取目录节点的信息
    :param user_agent: 如果不为 None，则作为获取下载链接时，请求头 "user-agent" 的值
    :param max_workers: 最大并发数，如果为 None 或 <= 0，则自动确定
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件的简略信息
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
    if with_ancestors:
        id_to_node = {0: {"id": 0, "parent_id": 0, "name": ""}}
        push = list.append
        def get_ancestors(id: int, attr: None | dict | tuple[str, int] = None, /) -> list[dict]:
            if not id:
                return [id_to_node[0]]
            elif attr is None:
                name, pid = id_to_dirnode[id]
            elif isinstance(attr, tuple):
                name, pid = attr
            else:
                pid = attr["parent_id"]
                name = attr["name"]
            ancestors: list[dict] = []
            while True:
                if id in id_to_node:
                    ancestor = id_to_node[id]
                else:
                    ancestor = id_to_node[id] = {"id": id, "parent_id": pid, "name": name}
                push(ancestors, ancestor)
                if not pid:
                    push(ancestors, id_to_node[0])
                    break
                id = pid
                try:
                    name, pid = id_to_dirnode[id]
                except KeyError:
                    break
            ancestors.reverse()
            return ancestors
    id_to_path: dict[int, str] = {0: "/"}
    def get_path(attr: dict | tuple[str, int], /) -> str:
        if isinstance(attr, tuple):
            name, pid = attr
        else:
            pid = attr["parent_id"]
            name = attr["name"]
        if escape is not None:
            name = escape(name)
        dirname = id_to_path.get(pid, "")
        if not dirname and (node := id_to_dirnode.get(pid)):
            dirname = id_to_path[pid] = get_path(node) + "/"
        return dirname + name
    root_ancestors = [{"id": 0, "parent_id": 0, "name": ""}]
    top_path: str = ""
    top_ancestors: list[dict]
    top_id = to_id(cid)
    if not top_id:
        top_path = "/"
        top_ancestors = root_ancestors
    def update_attr_from_url(attr: dict, url: P115URL, /):
        name = attr["name"] = url["name"]
        if escape is not None:
            name = escape(name)
        dirname = attr["dirname"]
        if dirname != "/":
            dirname += "/"
        attr["path"] = dirname + name
    def norm_attr(attr: dict, /):
        nonlocal top_path, top_ancestors
        pid = attr["parent_id"]
        if pid:
            pnode = id_to_dirnode[pid]
            if with_ancestors:
                attr["dir_ancestors"] = get_ancestors(pid, pnode)
            attr["dirname"] = get_path(pnode)
        else:
            if with_ancestors:
                attr["dir_ancestors"] = root_ancestors
            attr["dirname"] = "/"
        if not top_path:
            top_path = get_path(id_to_dirnode[top_id])
            if with_ancestors:
                top_ancestors = get_ancestors(top_id, id_to_dirnode[top_id])
        attr["top_id"] = top_id
        attr["top_path"] = top_path
        if with_ancestors:
            attr["top_ancestors"] = top_ancestors
        if with_url:
            if async_:
                async def set_url():
                    try:
                        url = attr["url"] = await client.download_url(
                            attr["pickcode"], 
                            user_agent=user_agent, 
                            app="android", 
                            async_=True, 
                            **request_kwargs, 
                        )
                        update_attr_from_url(attr, url)
                    except AccessError as e:
                        warn(f"file is inaccessible: {e!r}")
                    return attr
                return set_url()
            else:
                try:
                    url = attr["url"] = client.download_url(
                        attr["pickcode"], 
                        user_agent=user_agent, 
                        app="android", 
                        **request_kwargs, 
                    )
                    update_attr_from_url(attr, url)
                except AccessError as e:
                    warn(f"file is inaccessible: {e!r}")
        return attr
    if path_already:
        if cid:
            return do_map(norm_attr, iter_download_nodes(
                client, 
                client.to_pickcode(cid), 
                files=True, 
                max_workers=max_workers, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            ))
        else:
            def gen_step(pickcode: str, /):
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
                            attr = {
                                "parent_id": attr["parent_id"], 
                                "pickcode": attr["pickcode"], 
                                "size": attr["size"], 
                            }
                            yield Yield(norm_attr(attr))
                for pickcode in pickcodes:
                    yield YieldFrom(run_gen_step_iter(gen_step(pickcode), async_))
            return run_gen_step_iter(gen_step(client.to_pickcode(cid)), async_)
    else:
        ancestors_loaded: bool = False
        def load_ancestors(pickcode: str, /):
            return through(iter_download_nodes(
                client, 
                pickcode, 
                files=False, 
                id_to_dirnode=id_to_dirnode, 
                max_workers=max_workers, 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            ))
        def set_ancestors_loaded(fu, /):
            nonlocal ancestors_loaded
            exc = fu.exception()
            if exc is not None:
                raise exc
            ancestors_loaded = True
        def gen_step(pickcode: str, /):
            nonlocal ancestors_loaded
            if pickcode:
                if cid:
                    from .iterdir import _iter_fs_files
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
                if async_:
                    task: Any = create_task(load_ancestors(pickcode))
                else:
                    task = run_as_thread(load_ancestors, pickcode)
                task.add_done_callback(set_ancestors_loaded)
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
                        if ancestors_loaded:
                            if cache:
                                yield YieldFrom(do_map(norm_attr, cache))
                                cache.clear()
                            yield Yield(norm_attr(attr))
                        else:
                            add_to_cache(attr)
                if cache:
                    if async_:
                        yield task
                    else:
                        task.result()
                    yield YieldFrom(do_map(norm_attr, cache))
            else:
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
                            attr = {
                                "parent_id": attr["parent_id"], 
                                "pickcode": attr["pickcode"], 
                                "size": attr["size"], 
                            }
                            yield Yield(norm_attr(attr))
                for pickcode in pickcodes:
                    yield YieldFrom(run_gen_step_iter(gen_step(pickcode), async_))
                    ancestors_loaded = False
    return run_gen_step_iter(gen_step(client.to_pickcode(cid)), async_)


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

