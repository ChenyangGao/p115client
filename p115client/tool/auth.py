#!/usr/bin/env python3
# encoding: utf-8

__all__ = ["open_deauth", "open_app_check", "open_app_name"]
__doc__ = "这个模块提供了一些和账号状况有关的函数"

from collections.abc import Callable, Coroutine
from os import PathLike
from typing import overload, Any, Literal

from iterutils import run_gen_step

from ..client import check_response, P115Client, P115OpenClient


@overload
def open_deauth(
    client: str | PathLike | P115Client, 
    predicate: None | Callable = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> None:
    ...
@overload
def open_deauth(
    client: str | PathLike | P115Client, 
    predicate: None | Callable = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, None]:
    ...
def open_deauth(
    client: str | PathLike | P115Client, 
    predicate: None | Callable = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> None | Coroutine[Any, Any, None]:
    """批量解绑开放应用

    :param client: 115 客户端或 cookies
    :param predicate: 筛选条件
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def gen_step():
        resp = yield client.login_open_auth_list(
            async_=async_, 
            **request_kwargs, 
        )
        check_response(resp)
        for info in filter(predicate, resp["data"]):
            yield client.login_open_deauth(
                info["auth_id"], 
                async_=async_, 
                **request_kwargs, 
            )
    return run_gen_step(gen_step, async_)


@overload
def open_app_check(
    app_id: int, 
    base_url: str = "http://hnqrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> bool:
    ...
@overload
def open_app_check(
    app_id: int, 
    base_url: str = "http://hnqrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, bool]:
    ...
def open_app_check(
    app_id: int, 
    base_url: str = "http://hnqrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> bool | Coroutine[Any, Any, bool]:
    """检查 open 平台的某个 ``app_id`` 是否可用

    :param app_id: AppID （也叫 `client_id`）
    :param base_url: 接口的基地址
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 是否可用
    """
    def gen_step():
        if app_id < 0 or app_id % 2 == 0:
            return False
        resp = yield P115OpenClient.login_qrcode_token_open(
            app_id, 
            base_url=base_url, 
            async_=async_, 
            **request_kwargs, 
        )
        return bool(resp["state"])
    return run_gen_step(gen_step, async_)


@overload
def open_app_name(
    client: str | PathLike | P115Client, 
    app_id: int, 
    base_url: str = "http://hnqrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> None | str:
    ...
@overload
def open_app_name(
    client: str | PathLike | P115Client, 
    app_id: int, 
    base_url: str = "http://hnqrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, None | str]:
    ...
def open_app_name(
    client: str | PathLike | P115Client, 
    app_id: int, 
    base_url: str = "http://hnqrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> None | str | Coroutine[Any, Any, None | str]:
    """获取 open 平台的某个 ``app_id`` 对应的名字

    :param client: 115 客户端或 cookies
    :param app_id: AppID （也叫 `client_id`）
    :param base_url: 接口的基地址
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 名字，如果为 None，说明此应用不可用
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    def gen_step():
        if app_id < 0 or app_id % 2 == 0:
            return None
        resp = yield P115OpenClient.login_qrcode_token_open(
            app_id, 
            base_url=base_url, 
            async_=async_, 
            **request_kwargs, 
        )
        if not resp["state"]:
            return None
        resp = yield client.login_qrcode_scan(
            resp["data"]["uid"], 
            base_url=base_url, 
            async_=async_, 
            **request_kwargs, 
        )
        check_response(resp)
        # NOTE: 后缀是 "已经过115生活认证"，长度为 10
        return resp["data"]["tip_txt"][:-10].removeprefix("\ufeff")
    return run_gen_step(gen_step, async_)

