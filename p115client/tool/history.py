#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["iter_history_list_once", "iter_history_list"]
__doc__ = "这个模块提供了一些和 115 的历史记录有关的函数"

from asyncio import sleep as async_sleep
from collections.abc import AsyncIterator, Iterator
from functools import partial
from itertools import cycle
from time import time, sleep
from typing import overload, Literal

from iterutils import run_gen_step_iter, with_iter_next, Yield
from p115client import check_response, P115Client


@overload
def iter_history_list_once(
    client: str | P115Client, 
    from_time: int | float = 0, 
    from_id: int = 0, 
    type: int | str = 0, 
    first_batch_size = 0, 
    app: str = "web", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_history_list_once(
    client: str | P115Client, 
    from_time: int | float = 0, 
    from_id: int = 0, 
    type: int | str = 0, 
    first_batch_size = 0, 
    app: str = "web", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_history_list_once(
    client: str | P115Client, 
    from_time: int | float = 0, 
    from_id: int = 0, 
    type: int | str = 0, 
    first_batch_size = 0, 
    app: str = "web", 
    cooldown: int | float = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> AsyncIterator[dict] | Iterator[dict]:
    """拉取一组 115 的历史记录

    :param client: 115 客户端或 cookies
    :param from_time: 开始时间（含），若为 0 则从当前时间开始，若小于 0 则从最早开始
    :param from_id: 开始的事件 id （不含）
    :param type: 拉取指定类型的历史记录（？？表示还未搞清楚），多个用逗号 "," 隔开

        - 全部: 0
        - ？？: 1
        - 离线下载: 2
        - 播放视频: 3
        - 上传: 4
        - ？？: 5
        - ？？: 6
        - 接收: 7
        - 移动: 8

    :param first_batch_size: 首批的拉取数目
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生 115 的历史记录数据字典
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if app in ("", "web", "desktop", "harmony"):
        history_list = partial(client.fs_history_list, **request_kwargs)
    else:
        request_kwargs.setdefault("base_url", cycle(("http://proapi.115.com", "https://proapi.115.com")).__next__)
        history_list = partial(client.fs_history_list_app, app=app, **request_kwargs)
    if first_batch_size <= 0:
        first_batch_size = 64 if from_time or from_id else 1150
    def gen_step():
        payload = {"type": type, "limit": first_batch_size, "offset": 0}
        seen: set[int] = set()
        seen_add = seen.add
        ts_last_call = time()
        resp = yield history_list(payload, async_=async_)
        events = check_response(resp)["data"]["list"]
        payload["limit"] = 1150
        offset = 0
        while events:
            for event in events:
                event_id = int(event["id"])
                if from_id and event_id <= from_id or from_time and int(event["update_time"]) < from_time:
                    return
                if event_id not in seen:
                    yield Yield(event)
                    seen_add(event_id)
            offset += len(events)
            if offset >= int(resp["data"]["total"]):
                return
            payload["offset"] = offset
            if cooldown > 0 and (delta := ts_last_call + cooldown - time()) > 0:
                if async_:
                    yield async_sleep(delta)
                else:
                    sleep(delta)
            ts_last_call = time()
            resp = yield history_list(payload, async_=async_)
            events = check_response(resp)["data"]["list"]
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)


@overload
def iter_history_list(
    client: str | P115Client, 
    from_time: int | float = 0, 
    from_id: int = 0, 
    type: int | str = 0, 
    app: str = "web", 
    cooldown: int | float = 0, 
    interval: int | float = 0, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_history_list(
    client: str | P115Client, 
    from_time: int | float = 0, 
    from_id: int = 0, 
    type: int | str = 0, 
    app: str = "web", 
    cooldown: int | float = 0, 
    interval: int | float = 0, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_history_list(
    client: str | P115Client, 
    from_time: int | float = 0, 
    from_id: int = 0, 
    type: int | str = 0, 
    app: str = "web", 
    cooldown: int | float = 0, 
    interval: int | float = 0, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> AsyncIterator[dict] | Iterator[dict]:
    """持续拉取 115 的历史记录

    :param client: 115 客户端或 cookies
    :param from_time: 开始时间（含），若为 0 则从当前时间开始，若小于 0 则从最早开始
    :param from_id: 开始的事件 id （不含）
    :param type: 拉取指定类型的历史记录（？？表示还未搞清楚），多个用逗号 "," 隔开

        - 全部: 0
        - ？？: 1
        - 离线下载: 2
        - 播放视频: 3
        - 上传: 4
        - ？？: 5
        - ？？: 6
        - 接收: 7
        - 移动: 8

    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param interval: 两个批量拉取之间的睡眠时间间隔，如果小于等于 0，则不睡眠
    :param app: 使用某个 app （设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生 115 的历史记录数据字典
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    def gen_step():
        nonlocal from_time, from_id
        if from_time == 0:
            from_time = time()
        first_loop = True
        while True:
            if first_loop:
                first_loop = False
            elif interval > 0:
                if async_:
                    yield async_sleep(interval)
                else:
                    sleep(interval)
            with with_iter_next(iter_history_list_once(
                client, 
                from_time, 
                from_id, 
                type=type, 
                app=app, 
                cooldown=cooldown, 
                async_=async_, 
                **request_kwargs, 
            )) as get_next:
                sub_first_loop = True
                while True:
                    event = yield get_next()
                    if sub_first_loop:
                        from_id = int(event["id"])
                        from_time = int(event["update_time"])
                        sub_first_loop = False
                    yield Yield(event)
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)

