#!/usr/bin/env python3
# encoding: utf-8

__all__ = ["fs_files", "fs_files_iter"]
__doc__ = "这个模块利用 P115Client.fs_files 方法做了一些封装"

from collections.abc import AsyncIterator, Callable, Coroutine, Iterator
from itertools import cycle
from os import PathLike
from typing import overload, Any, Final, Literal
from warnings import warn

from concurrenttools import iter_offset
from errno2 import errno
from http_response import get_status_code, is_timeouterror
from iterutils import as_gen_step, run_gen_step

from ..client import check_response, P115Client, P115OpenClient
from ..exception import throw, P115Warning


# get_webapi_origin: Final = "https://webapi.115.com"
get_webapi_origin: Final = cycle((
    "https://webapi.115.com", "http://web.api.115.com", 
    "https://115cdn.com/webapi", "https://115vod.com/webapi", 
    "https://f.115.com/api/proxy/115", "https://n.115.com/api/proxy/115", 
)).__next__
#get_proapi_origin: Final = cycle(("https://proapi.115.com", "http://pro.api.115.com")).__next__
get_proapi_origin: Final = "https://proapi.115.com"


@overload
def fs_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    /, 
    page_size: int = 0, 
    app: str = "web", 
    use_media_api: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def fs_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    /, 
    page_size: int = 0, 
    app: str = "web", 
    use_media_api: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def fs_files(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    /, 
    page_size: int = 0, 
    app: str = "web", 
    use_media_api: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """拉取一个目录中的文件或目录的数据

    :param client: 115 网盘客户端对象
    :param payload: 目录的 id 或者详细的查询参数
    :param page_size: 分页大小，如果 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param use_media_api: 是否使用 ``P115Client.fs_files_media`` 接口
    :param async_: 是否异步
    :param request_kwargs: 其它 http 请求参数，会传给具体的请求函数，默认的是 httpx，可用参数 request 进行设置

    :return: 接口调用的结果
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if page_size <= 0:
        if use_media_api:
            page_size = 10_000
        else:
            page_size = 7_000
    if not isinstance(client, P115Client) or app == "open":
        page_size = min(page_size, 1150)
        fs_files: Callable = client.fs_files_open
    elif app in ("", "web", "desktop", "chrome"):
        if use_media_api:
            page_size = min(page_size, 500)
            fs_files = client.fs_files_media
        else:
            page_size = min(page_size, 1150)
            fs_files = client.fs_files
        request_kwargs.setdefault("base_url", get_webapi_origin)
    elif app == "aps":
        page_size = min(page_size, 1200)
        fs_files = client.fs_files_aps
    else:
        if use_media_api:
            fs_files = client.fs_files_media_app
        else:
            fs_files = client.fs_files_app
        request_kwargs["app"] = app
        request_kwargs.setdefault("base_url", get_proapi_origin)
    if isinstance(payload, (int, str)):
        payload = {"cid": client.to_id(payload)}
    payload = {
        "asc": 1, "cid": 0, "cur": 1, "fc_mix": 1, "o": "user_ptime", 
        "offset": 0, "limit": page_size, "show_dir": 1, **payload, 
    }
    cid = int(payload["cid"])
    def gen_step():
        resp = yield fs_files(payload, async_=async_, **request_kwargs)
        check_response(resp)
        if cid and int(resp["cid"]) != cid:
            throw(errno.ENOENT, cid)
        resp["has_next_page"] = len(resp["data"]) > 0 and payload["offset"] + len(resp["data"]) < int(resp["count"])
        return resp
    return run_gen_step(gen_step, async_)


@overload
def fs_files_iter(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    /, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    app: str = "web", 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    cooldown: None | float = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def fs_files_iter(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    /, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    app: str = "web", 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    cooldown: None | float = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def fs_files_iter(
    client: str | PathLike | P115Client | P115OpenClient, 
    payload: int | str | dict = 0, 
    /, 
    page_size: int = 0, 
    first_page_size: int = 0, 
    app: str = "web", 
    use_media_api: bool = False, 
    raise_for_changed_count: bool = False, 
    cooldown: None | float = None, 
    max_workers: None | int = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> AsyncIterator[dict] | Iterator[dict]:
    """拉取一个目录中的文件或目录的数据

    :param client: 115 网盘客户端对象
    :param payload: 目录的 id 或者详细的查询参数
    :param page_size: 分页大小，如果 <= 0，则自动确定
    :param first_page_size: 首次拉取的分页大小，如果 <= 0，则自动确定
    :param app: 使用此设备的接口
    :param use_media_api: 是否使用 ``P115Client.fs_files_media`` 接口
    :param raise_for_changed_count: 分批拉取时，发现总数发生变化后，是否报错
    :param cooldown: 冷却时间，单位为秒。如果为 None，则用默认值（非并发时为 0，并发时为 1/2）
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param async_: 是否异步
    :param request_kwargs: 其它 http 请求参数，会传给具体的请求函数，默认的是 httpx，可用参数 request 进行设置

    :return: 迭代器，每次返回一次接口调用的结果
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if page_size <= 0:
        if use_media_api:
            page_size = 10_000
        else:
            page_size = 7_000
    fs_files: Callable
    if not isinstance(client, P115Client) or app == "open":
        page_size = min(page_size, 1150)
        fs_files = client.fs_files_open
    elif app in ("", "web", "desktop", "chrome"):
        if use_media_api:
            page_size = min(page_size, 500)
            fs_files = client.fs_files_media
        else:
            page_size = min(page_size, 1150)
            fs_files = client.fs_files
        request_kwargs.setdefault("base_url", get_webapi_origin)
    elif app == "aps":
        page_size = min(page_size, 1200)
        fs_files = client.fs_files_aps
    else:
        if use_media_api:
            fs_files = client.fs_files_media_app
        else:
            fs_files = client.fs_files_app
        request_kwargs["app"] = app
        request_kwargs.setdefault("base_url", get_proapi_origin)
    if cooldown is None:
        if max_workers == 0:
            cooldown = 0
        else:
            cooldown = 1 / 2
    if isinstance(payload, (int, str)):
        payload = {"cid": client.to_id(payload)}
    payload = {
        "asc": 1, "cid": 0, "cur": 1, "fc_mix": 1, "o": "user_ptime", 
        "show_dir": 1, **payload, 
    }
    cid = int(payload["cid"])
    if async_ and (max_workers is None or max_workers <= 0):
        max_workers = 64
    count = -1
    @as_gen_step
    def call(payload: dict, /):
        nonlocal count
        resp = yield fs_files(payload, async_=async_, **request_kwargs)
        check_response(resp)
        if cid and int(resp["cid"]) != cid:
            if count < 0:
                throw(errno.ENOTDIR, cid)
            else:
                throw(errno.ENOENT, cid)
        count_new = int(resp["count"])
        if count < 0:
            if app == "aps" and count > 1200:
                warn(f"aps api can get the first 1200 pieces of data approximately, but the total number is {count}", category=P115Warning)
            count = count_new
        elif count != count_new:
            message = f"cid={cid} detected count changes during iteration: {count} -> {count_new}"
            if raise_for_changed_count:
                throw(errno.EBUSY, message)
            else:
                warn(message, category=P115Warning)
            count = count_new
        return resp
    return iter_offset(
        call, 
        payload, 
        check_for_stop=lambda offset, limit, resp, /: offset != resp["offset"] or limit > len(resp["data"]) or resp["count"] <= offset + len(resp["data"]), 
        retry_for_exception=lambda e, /: is_timeouterror(e) or isinstance(e, Exception) and get_status_code(e) < 400, 
        page_size=page_size, 
        first_page_size=first_page_size, 
        cooldown=cooldown, 
        max_workers=max_workers, 
        async_=async_, 
    )

# TODO: 如果风控比较严重，那么必要时，可以利用多个接口、域名的轮转，来实现批量拉取，因为不同接口允许的 limit 有所不同，aps 也只能拉取前 1200 条，所以只要提前规划好多个不同接口，不要超出能力范围，就一定能轻易饶过风控，还不至于用到 cookies 池。特别的，这个思路也可以用来补充 tinydav 的更新逻辑，按创建时间（推荐）或者更新时间逆序排列，从根目录拉取所有文件信息（但不需要拉取目录），然后更新到数据库，以对 life 事件可能的遗漏进行补充
