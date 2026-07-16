#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "get_pic_url", "batch_get_url", "iter_url_batches", "iter_files_with_url", 
    "iter_images_with_url", "iter_subtitles_with_url", "iter_subtitle_batches", 
    "iter_download_nodes", "iter_download_files", "get_remaining_open_count", 
    "download_file", 
]
__doc__ = "这个模块提供了一些和下载有关的函数"

from asyncio import (
    create_task, gather as async_gather, to_thread, 
    CancelledError as AsyncCancelledError, 
    Queue as AsyncQueue, TaskGroup, 
)
from base64 import b32decode
from collections.abc import (
    AsyncIterable, AsyncIterator, Buffer, Callable, Coroutine, 
    Iterable, Iterator, Mapping, MutableMapping, Sequence, 
)
from concurrent.futures import CancelledError, ThreadPoolExecutor
from functools import partial
from inspect import isawaitable
from itertools import batched, chain, count, repeat
from os import cpu_count, makedirs, PathLike
from os.path import dirname, getsize
from queue import Queue
from re import compile as re_compile
from string import hexdigits, ascii_uppercase
from sys import exc_info
from threading import Lock
from types import EllipsisType
from typing import cast, overload, Any, Literal
from urllib.request import urlopen, Request
from uuid import uuid4
from warnings import warn

from argtools import argcount
from asynctools import async_chain_from_iterable
from concurrenttools import conmap, run_as_thread
from dicttools import get_first
from errno2 import errno
from filewrap import (
    bio_chunk_iter, bio_chunk_async_iter, 
    bytes_to_chunk_iter, bytes_to_chunk_async_iter, 
)
from iterutils import (
    chunked, map as do_map, chain_from_iterable, run_gen_step, 
    run_gen_step_iter, through, wrap_iter, wrap_aiter, with_iter_next, 
    Yield, YieldFrom, 
)
from p115pickcode import to_id

from ..client import check_response, json_maybe_decrypt_parse, P115Client, P115OpenClient, P115URL
from ..const import ID_TO_DIRNODE_CACHE
from ..exception import P115Warning, P115AccessError
from ..type import TaskResultTuple
from ..util import reduce_image_url_layers
from .attr import normalize_attr, normalize_attr_simple, get_attr, get_info
from .iterdir import iterdir, iter_files, unescape_115_charref


def _get_id(id: int | str | Mapping, /) -> int:
    if isinstance(id, Mapping):
        id = cast(int | str, get_first(id, "id", "pickcode"))
    return to_id(id)


def _get_pickcode(client: P115OpenClient, pickcode: int | str | Mapping, /) -> str:
    if isinstance(pickcode, Mapping):
        pickcode = cast(str | int, get_first(pickcode, "pickcode", "id"))
    return client.to_pickcode(pickcode)


# TODO: 目前至少有 4 个接口可用于获取图片链接，以后允许选择用哪一种
@overload
def get_pic_url(
    client: str | PathLike | P115Client, 
    sha1: str, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> str:
    ...
@overload
def get_pic_url(
    client: str | PathLike | P115Client, 
    sha1: Iterable[str], 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> list[str]:
    ...
@overload
def get_pic_url(
    client: str | PathLike | P115Client, 
    sha1: str, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, str]:
    ...
@overload
def get_pic_url(
    client: str | PathLike | P115Client, 
    sha1: Iterable[str], 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, list[str]]:
    ...
def get_pic_url(
    client: str | PathLike | P115Client, 
    sha1: str | Iterable[str], 
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
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 图片链接的单个或列表
    """
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
        if isinstance(sha1, str):
            resp = yield client.life_get_pic_url(
                formalize_sha1(sha1), 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            return resp["data"][0]["json"].replace("&i=0", "&i=1")
        else:
            resp = yield client.life_get_pic_url(
                tuple(map(formalize_sha1, sha1)), 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            return [u["json"].replace("&i=0", "&i=1") for u in resp["data"]]
    return run_gen_step(gen_step, async_)


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
        client = P115Client(client)
    if headers := request_kwargs.get("headers"):
        request_kwargs["headers"] = dict(headers, **{"user-agent": user_agent})
    else:
        request_kwargs["headers"] = {"user-agent": user_agent}
    if isinstance(pickcode, (int, str)):
        pickcode = client.to_pickcode(pickcode)
    elif not isinstance(pickcode, str):
        pickcode = ",".join(map(client.to_pickcode, pickcode))
    return client.download_urls(pickcode, app=app, async_=async_, **request_kwargs)


@overload
def iter_url_batches(
    client: str | PathLike | P115Client | P115OpenClient, 
    pickcodes: Iterator[int | str], 
    user_agent: str = "", 
    batch_size: int = 10, 
    app: str = "os_windows", 
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
    app: str = "os_windows", 
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
    app: str = "os_windows", 
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
        client = P115Client(client)
    if headers := request_kwargs.get("headers"):
        request_kwargs["headers"] = dict(headers, **{"user-agent": user_agent})
    else:
        request_kwargs["headers"] = {"user-agent": user_agent}
    if batch_size <= 0:
        batch_size = 1
    def gen_step():
        if batch_size == 1:
            get_url = client.download_url
            for pickcode in map(client.to_pickcode, pickcodes):
                yield Yield(get_url(
                    pickcode, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                ))
        else:
            get_urls = client.download_urls
            for pcs in batched(map(client.to_pickcode, pickcodes), batch_size):
                if urls := (yield get_urls(
                    ",".join(pcs), 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                )):
                    yield YieldFrom(urls.values())
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_files_with_url(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping = 0, 
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
    cid: int | str | Mapping = 0, 
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
    cid: int | str | Mapping = 0, 
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
    cid = _get_id(cid)
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
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
    get_url = client.download_url
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
                    if attr["size"] <= 1024 * 1024 * 200:
                        attr["url"] = yield get_url(
                            attr["pickcode"], 
                            app="web2", 
                            async_=async_, 
                            **request_kwargs, 
                        )
                    else:
                        warn(f"unable to get url for {attr!r}", category=P115Warning)
                else:
                    attr["url"] = yield get_url(
                        attr["pickcode"], 
                        app="os_windows", 
                        async_=async_, 
                        **request_kwargs, 
                    )
                yield Yield(attr)
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_images_with_url(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping = 0, 
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
    cid: int | str | Mapping = 0, 
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
    cid: int | str | Mapping = 0, 
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
        请不要把不能被 115 识别为图片的文件扩展名放在 ``suffixes`` 参数中传入，这只是浪费时间，最后也只能获得普通的下载链接

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
    cid = _get_id(cid)
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
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
    get_url = client.download_url
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
                        if attr["size"] <= 1024 * 1024 * 200:
                            attr["url"] = yield get_url(
                                attr["pickcode"], 
                                app="web2", 
                                async_=async_, 
                                **request_kwargs, 
                            )
                        else:
                            warn(f"unable to get url for {attr!r}", category=P115Warning)
                    else:
                        attr["url"] = yield get_url(
                            attr["pickcode"], 
                            app="os_windows", 
                            async_=async_, 
                            **request_kwargs, 
                        )
                yield Yield(attr)
    return run_gen_step_iter(gen_step, async_)


@overload
def iter_subtitles_with_url(
    client: str | PathLike | P115Client | P115OpenClient, 
    cid: int | str | Mapping = 0, 
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
    cid: int | str | Mapping = 0, 
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
    cid: int | str | Mapping = 0, 
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
    cid = _get_id(cid)
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    get_url = client.download_url
    if not isinstance(client, P115Client) or app == "open":
        fs_mkdir: Callable = client.fs_mkdir_open
        fs_copy: Callable = client.fs_copy_open
        fs_delete: Callable = client.fs_delete_open
        fs_video_subtitle: Callable = client.fs_video_subtitle_open
    elif app in ("", "web", "desktop", "aps"):
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
    cid = to_id(cid)
    def gen_step():
        nonlocal suffixes
        if isinstance(suffixes, str):
            suffixes = suffixes,
        do_chain: Callable = async_chain_from_iterable if async_ else chain.from_iterable
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
                            if attr["size"] <= 1024 * 1024 * 200:
                                attr["url"] = yield get_url(
                                    attr["pickcode"], 
                                    app="web2", 
                                    async_=async_, 
                                    **request_kwargs, 
                                )
                            else:
                                warn(f"unable to get url for {attr!r}", category=P115Warning)
                        else:
                            attr["url"] = yield get_url(
                                attr["pickcode"], 
                                app="os_windows", 
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
        client = P115Client(client)
    if batch_size <= 0:
        batch_size = 1_000
    if not isinstance(client, P115Client) or app == "open":
        fs_mkdir: Callable = client.fs_mkdir_open
        fs_copy: Callable = client.fs_copy_open
        fs_delete: Callable = client.fs_delete_open
        fs_video_subtitle: Callable = client.fs_video_subtitle_open
    elif app in ("", "web", "desktop", "aps"):
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
def iter_download_nodes(
    client: str | PathLike | P115Client, 
    pickcodes: str | int | Mapping | Iterable[str | int | Mapping] = "", 
    files: bool = True, 
    ensure_name: bool = False, 
    get_raw: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    max_workers: None | int = 0, 
    per_page: int = 5000, 
    max_page: int = 0, 
    app: str = "chrome", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_download_nodes(
    client: str | PathLike | P115Client, 
    pickcodes: str | int | Mapping | Iterable[str | int | Mapping] = "", 
    files: bool = True, 
    ensure_name: bool = False, 
    get_raw: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    max_workers: None | int = 0, 
    per_page: int = 5000, 
    max_page: int = 0, 
    app: str = "chrome", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_download_nodes(
    client: str | PathLike | P115Client, 
    pickcodes: str | int | Mapping | Iterable[str | int | Mapping] = "", 
    files: bool = True, 
    ensure_name: bool = False, 
    get_raw: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    max_workers: None | int = 0, 
    per_page: int = 5000, 
    max_page: int = 0, 
    app: str = "chrome", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一个目录内所有的文件或者目录的信息（简略）

    .. caution::
        不要在不确定的情况下，给 ``max_page`` 设置一个特别大的值，这会大致大量无用的请求，导致服务器繁忙，响应效率低下    

        对于 ``x`` 个文件或目录，相应的 ``d, r = divmod(x, per_page); max_page += (r > 0)``，或者 ``max_page = -(-x // per_page)``

    :param client: 115 客户端或 cookies
    :param pickcodes: 若干个目录的 pickcode 或 id，如果为空，则是根目录
    :param files: 如果为 True，则只获取文件，否则只获取目录
    :param ensure_name: 确保返回数据中有 "name" 字段
    :param get_raw: 返回原始数据
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param per_page: 每一页最多拉取条数，取值范围 1~5000
    :param max_page: 要拉取的最大页码（从 1 开始计数）

        - 如果 > 0，则拉到 ``max_page`` 为止
        - 如果 = 0，则拉完为止
        - 如果 < 0，则拉完为止，且会同时去尝试去查询总数

    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件或者目录的简略信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if max_workers is None or max_workers < 0:
        max_workers = 20 if async_ else min(32, (cpu_count() or 1) + 4)
    if not 0 < per_page <= 5000:
        per_page = 5000
    is_multi_tops = True
    if isinstance(pickcodes, (int, str, Mapping)):
        pickcode = _get_pickcode(client, pickcodes)
        pickcodes = ()
        if pickcode:
            is_multi_tops = False
    else:
        pickcodes = tuple(dict.fromkeys(_get_pickcode(client, pc) for pc in pickcodes))
        if not pickcodes or "" in pickcodes:
            pickcodes = ()
        elif len(pickcodes) == 1:
            pickcode = pickcodes[0]
            is_multi_tops = False
    if is_multi_tops:
        return _iter_download_nodes_multi(
            client, 
            pickcodes=pickcodes, 
            files=files, 
            ensure_name=ensure_name, 
            get_raw=get_raw, 
            id_to_dirnode=id_to_dirnode, 
            max_workers=max_workers, 
            per_page=per_page, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )
    if files:
        get_nodes = client.download_files_app
    else:
        ensure_name = False
        get_nodes = client.download_folders_app
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
    kwargs = dict(request_kwargs, parse=parse, app=app, async_=async_)
    if max_workers == 0:
        def gen_step():
            if max_page > 0:
                counter: Iterable[int] = range(1, max_page + 1)
            else:
                counter = count(1)
            for i in counter:
                resp: dict = yield get_nodes({"pickcode": pickcode, "page": i}, **kwargs)
                check_response(resp)
                if ls := resp.get("list"):
                    yield Yield(ls)
                if not resp["has_next_page"]:
                    break
    else:
        sentinel = object()
        if async_:
            q: AsyncQueue | Queue = AsyncQueue(max_workers)
        else:
            q = Queue(max_workers)
            lock = Lock()
        get, put = q.get, q.put
        task_list: list = []
        task_page: list[int] = []
        task_ids: set[int] = set()
        discard_task_id = task_ids.discard
        def countdown(task_id, /):
            task_list[task_id] = None
            discard_task_id(task_id)
        def set_max_page(page: int, /):
            nonlocal max_page
            if 0 < max_page <= page:
                return
            max_page = page
            for i, p in enumerate(task_page):
                task = task_list[i]
                if task and p > page:
                    task.cancel()
                    countdown(i)
        def next_page_iter():
            i = 0
            if max_page <= 0:
                for i in count(1):
                    yield i
                    if max_page > 0:
                        break
            yield from range(max_page, i, -1)
        next_page = next_page_iter().__next__
        if max_page > 0:
            max_workers = min(max_page, max_workers)
        elif max_page < 0:
            cid = to_id(pickcode)
            if async_:
                future: Any = create_task(get_info(
                    client, 
                    cid, 
                    app=app, 
                    async_=True, 
                    **request_kwargs, 
                ))
            else:
                future = run_as_thread(
                    get_info, # type: ignore
                    client, 
                    cid, 
                    app=app, 
                    **request_kwargs, 
                )
            def callback(future=future, /):
                resp = future.result()
                if files:
                    count = int(resp["count"])
                else:
                    count = int(resp["folder_count"])
                set_max_page(-(-count // per_page))
            future.add_done_callback(callback)
        running = True
        def request(task_id, /):
            nonlocal running
            try:
                while running:
                    if async_:
                        page = next_page()
                    else:
                        with lock:
                            page = next_page()
                    if 0 < max_page < page:
                        continue
                    task_page[task_id] = page
                    resp: dict = yield get_nodes({"pickcode": pickcode, "page": page}, **kwargs)
                    check_response(resp)
                    if ls := resp.get("list"):
                        yield put(ls)
                    if not resp["has_next_page"]:
                        set_max_page(page)
            except (StopIteration, CancelledError, AsyncCancelledError):
                pass
            except BaseException as e:
                running = False
                yield put(e)
                for i, task in enumerate(task_list):
                    if task:
                        task.cancel()
                        countdown(i)
            finally:
                countdown(task_id)
                if not task_ids:
                    yield put(sentinel)
        def gen_step():
            nonlocal running
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
            exc: None | BaseException = None
            try:
                task_ids.update(range(n))
                task_list.extend(repeat(None, n))
                task_page.extend(repeat(0, n))
                for i in range(n):
                    task_list[i] = submit(run_gen_step, request(i), async_)
                while True:
                    if async_:
                        resp = yield get()
                    else:
                        resp = get()
                    if resp is sentinel:
                        break
                    elif isinstance(resp, BaseException):
                        exc = resp
                        break
                    yield Yield(resp)
            finally:
                running = False
                yield shutdown()
            if exc is not None:
                raise exc
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
def _iter_download_nodes_multi(
    client: str | PathLike | P115Client, 
    pickcodes: tuple[str, ...] = (), 
    files: bool = True, 
    ensure_name: bool = False, 
    get_raw: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    max_workers: None | int = 0, 
    per_page: int = 5000, 
    app: str = "chrome", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def _iter_download_nodes_multi(
    client: str | PathLike | P115Client, 
    pickcodes: tuple[str, ...] = (), 
    files: bool = True, 
    ensure_name: bool = False, 
    get_raw: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    max_workers: None | int = 0, 
    per_page: int = 5000, 
    app: str = "chrome", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def _iter_download_nodes_multi(
    client: str | PathLike | P115Client, 
    pickcodes: tuple[str, ...] = (), 
    files: bool = True, 
    ensure_name: bool = False, 
    get_raw: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = ..., 
    max_workers: None | int = 0, 
    per_page: int = 5000, 
    app: str = "chrome", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取网盘中所有的文件或者目录的信息（简略）

    :param client: 115 客户端或 cookies
    :param pickcodes: 若干个目录的 pickcode，如果为空，则是根目录
    :param files: 如果为 True，则只获取文件，否则只获取目录
    :param ensure_name: 确保返回数据中有 "name" 字段
    :param get_raw: 返回原始数据
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param per_page: 每一页最多拉取条数，取值范围 1~5000
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件或者目录的简略信息
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if max_workers is None or max_workers < 0:
        max_workers = 20 if async_ else min(32, (cpu_count() or 1) + 4)
    if not 0 < per_page <= 5000:
        per_page = 5000
    if files:
        get_nodes = client.download_files_app
    else:
        ensure_name = False
        get_nodes = client.download_folders_app
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
    page_idx: dict[str, int] = {}
    kwargs = dict(request_kwargs, parse=parse, app=app, async_=async_)
    if max_workers:
        sentinel = object()
        if async_:
            q: AsyncQueue | Queue = AsyncQueue(max_workers)
        else:
            q = Queue(max_workers)
            lock = Lock()
        get, put = q.get, q.put
        task_list: list = []
        task_page: list[tuple[str, int]] = []
        task_ids: set[int] = set()
        discard_task_id = task_ids.discard
        def countdown(task_id, /):
            task_list[task_id] = None
            discard_task_id(task_id)
        page_max: dict[str, int] = {}
        def set_max_page(pickcode: str, page: int, /):
            if 0 < page_max.get(pickcode, 0) <= page:
                return
            page_max[pickcode] = page
            if len(page_max) == len(page_idx):
                for i, (pc, p) in enumerate(task_page):
                    task = task_list[i]
                    if task and pc == pickcode and p > page:
                        task.cancel()
                        countdown(i)
        def next_pickcode_page_iter():
            while True:
                i = 0
                for pickcode, page in page_idx.items():
                    if 0 < page_max.get(pickcode, 0) < page:
                        i += 1
                        continue
                    yield pickcode, page
                    page_idx[pickcode] += 1
                if i and i == len(page_idx):
                    break
        next_pickcode_page = next_pickcode_page_iter().__next__
        running = True
        def request(task_id, /):
            nonlocal running
            try:
                while running:
                    if async_:
                        pickcode, page = next_pickcode_page()
                    else:
                        with lock:
                            pickcode, page = next_pickcode_page()
                    if 0 < page_max.get(pickcode, 0) < page:
                        continue
                    task_page[task_id] = (pickcode, page)
                    resp: dict = yield get_nodes({"pickcode": pickcode, "page": page}, **kwargs)
                    check_response(resp)
                    if ls := resp.get("list"):
                        yield put(ls)
                    if not resp["has_next_page"]:
                        set_max_page(pickcode, page)
            except (StopIteration, CancelledError, AsyncCancelledError):
                pass
            except BaseException as e:
                running = False
                yield put(e)
                for i, task in enumerate(task_list):
                    if task:
                        task.cancel()
                        countdown(i)
            finally:
                countdown(task_id)
                if not task_ids:
                    yield put(sentinel)
    def gen_step():
        if pickcodes:
            for pc in pickcodes:
                page_idx[pc] = 1
        else:
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
                            page_idx[attr["pickcode"]] = 1
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
                            page_idx[attr["pickcode"]] = 1
                        elif files:
                            add_attr(attr)
            if attrs:
                yield Yield(attrs)
            else:
                return
        if max_workers == 0:
            for pickcode in page_idx:
                for i in count(1):
                    resp: dict = yield get_nodes({"pickcode": pickcode, "page": i}, **kwargs)
                    check_response(resp)
                    if ls := resp.get("list"):
                        yield Yield(ls)
                    if not resp["has_next_page"]:
                        break
        else:
            nonlocal running
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
            exc: None | BaseException = None
            try:
                task_ids.update(range(n))
                task_list.extend(repeat(None, n))
                task_page.extend(zip(repeat(""), repeat(0, n)))
                for i in range(n):
                    task_list[i] = submit(run_gen_step, request(i), async_)
                while True:
                    if async_:
                        data = yield get()
                    else:
                        data = get()
                    if data is sentinel:
                        break
                    elif isinstance(data, BaseException):
                        exc = data
                        break
                    yield Yield(data)
            finally:
                running = False
                yield shutdown()
            if exc is not None:
                raise exc
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
def iter_download_files(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    ensure_name: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    path_already: bool = False, 
    max_workers: None | int = 0, 
    max_files: int = 0, 
    max_dirs: int = 0, 
    app: str = "chrome", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_download_files(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    ensure_name: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    path_already: bool = False, 
    max_workers: None | int = 0, 
    max_files: int = 0, 
    max_dirs: int = 0, 
    app: str = "chrome", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_download_files(
    client: str | PathLike | P115Client, 
    cid: int | str | Mapping = 0, 
    ensure_name: bool = False, 
    escape: None | bool | Callable[[str], str] = True, 
    with_ancestors: bool = False, 
    id_to_dirnode: None | EllipsisType | MutableMapping[int, tuple[str, int]] = None, 
    path_already: bool = False, 
    max_workers: None | int = 0, 
    max_files: int = 0, 
    max_dirs: int = 0, 
    app: str = "chrome", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """获取一个目录内所有的文件信息，不包括目录

    :param client: 115 客户端或 cookies
    :param cid: 目录 id 或 pickcode
    :param ensure_name: 确保返回数据中有 "name" 字段
    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param with_ancestors: 文件信息中是否要包含 "ancestors"
    :param id_to_dirnode: 字典，保存 id 到对应文件的 ``(name, parent_id)`` 元组的字典
    :param path_already: 如果为 True，则说明 id_to_dirnode 中已经具备构建路径所需要的目录节点，所以不会再去拉取目录节点的信息
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param max_files: 估计最大存在的文件数，<= 0 时则无限
    :param max_dirs: 估计最大存在的目录数，<= 0 时则无限
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生文件的简略信息
    """
    if isinstance(cid, Mapping):
        cid = cast(int | str, get_first(cid, "id", "pickcode"))
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if id_to_dirnode is None:
        id_to_dirnode = ID_TO_DIRNODE_CACHE[client.user_id]
    elif id_to_dirnode is ...:
        id_to_dirnode = {}
        path_already = False
    from .iterdir import make_path_binder
    bind = make_path_binder(
        id_to_dirnode, 
        escape=escape, 
        with_ancestors=with_ancestors, 
        key_of_path="path" if ensure_name else "dirname", 
        key_of_ancestors="ancestors" if ensure_name else "dir_ancestors", 
    )
    top_id = cid = to_id(cid)
    top_ancestors: list[dict]
    top_path: str
    top_prefix_len: int = 0
    def update_attr(attr: dict, /):
        nonlocal top_ancestors, top_path, top_prefix_len
        if not top_prefix_len:
            if cid:
                top_path = bind.get_path(top_id) # type: ignore
                if with_ancestors:
                    top_ancestors = bind.get_ancestors(top_id) # type: ignore
                top_prefix_len = len(top_path) + 1
            else:
                top_ancestors = [{"id": 0, "parent_id": 0, "name": ""}]
                top_path = "/"
                top_prefix_len = 1
        attr["top_id"] = top_id
        attr["top_path"] = top_path
        if with_ancestors:
            attr["top_ancestors"] = top_ancestors
        try:
            bind(attr)
            if ensure_name:
                attr["relpath"] = attr["path"][top_prefix_len:]
            else:
                attr["rel_dirname"] = attr["dirname"][top_prefix_len:]
        except KeyError:
            pass
        return attr
    if path_already:
        return do_map(update_attr, iter_download_nodes(
            client, 
            cid, 
            files=True, 
            ensure_name=ensure_name, 
            max_workers=max_workers, 
            max_page=max_files > 0 and -(-max_files // 5000), 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        ))
    else:
        class BoolRaise:
            def __init__(self, /, exception):
                self.exception = exception
            def __bool__(self, /):
                raise self.exception
        path_not_already: bool | BoolRaise = True
        def set_path_already(fu, /):
            nonlocal path_not_already
            if isinstance(fu, BaseException):
                exc = fu
            else:
                exc = fu.exception()
            if exc is None:
                path_not_already = False
            else:
                path_not_already = BoolRaise(exc)
        def gen_step():
            nonlocal path_already
            path_already = False
            def load_ancestors():
                return through(iter_download_nodes(
                    client, 
                    cid, 
                    files=False, 
                    id_to_dirnode=id_to_dirnode, 
                    max_workers=max_workers, 
                    max_page=max_dirs > 0 and -(-max_dirs // 5000), 
                    app="os_windows", 
                    async_=async_, 
                    **request_kwargs, 
                ))
            if async_:
                task: Any = create_task(load_ancestors())
            else:
                task = run_as_thread(load_ancestors)
            if cid:
                from .attr import get_ancestors
                def update_top():
                    return (yield get_ancestors(
                        client, 
                        cid, 
                        id_to_dirnode=id_to_dirnode, 
                        ensure_file=False, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    ))
                if async_:
                    task2 = async_gather(run_gen_step(update_top, True), task)
                    task2.add_done_callback(set_path_already)
                else:
                    task0 = run_as_thread(run_gen_step, update_top, False)
                    def done_callback(fu, /):
                        try:
                            task0.result()
                        except BaseException as e:
                            set_path_already(e)
                        else:
                            set_path_already(fu)
                    task.add_done_callback(done_callback)
            else:
                task.add_done_callback(set_path_already)
            cache: list[dict] = []
            add_to_cache = cache.append
            with with_iter_next(iter_download_nodes(
                client, 
                cid, 
                files=True, 
                ensure_name=ensure_name, 
                max_workers=max_workers, 
                max_page=max_files > 0 and -(-max_files // 5000), 
                app=app, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                while path_not_already:
                    add_to_cache((yield get_next()))
                if cache:
                    yield YieldFrom(do_map(update_attr, cache))
                    cache.clear()
                while True:
                    yield Yield(update_attr((yield get_next())))
            if cache:
                if async_:
                    yield task
                else:
                    task.result()
                bool(path_not_already)
                yield YieldFrom(do_map(update_attr, cache))
    return run_gen_step_iter(gen_step, async_)


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


# TODO: 再写一个 upload_file、transfer_file 等函数，也尽量支持差不多的参数
# TODO: 再写一个 download_tree 函数，用于实现批量下载
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
            if isinstance(client, P115Client):
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

