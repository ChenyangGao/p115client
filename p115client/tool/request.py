#!/usr/bin/env python3
# coding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_request"]
__doc__ = "自定义请求函数"

from collections.abc import Callable
from functools import partial
from http.cookiejar import CookieJar
from subprocess import run
from sys import executable, modules
from typing import Literal


def make_request(
    module: Literal["", "httpx", "httpx_async", "requests", "urllib3", "urlopen", "aiohttp", "blacksheep"] = "", 
    cookiejar: None | CookieJar = None, 
    /, 
    **request_kwargs, 
) -> None | Callable:
    """创建可更新 cookies 的请求函数

    :param module: 指定所用的模块
    :param cookiejar: cookies 罐，用来存储 cookies。如果为 None，则 "urllib3" 和 "urlopen" 并不会保存 cookies，其它 `module` 则有自己的 cookies 保存机制
    :param request_kwargs: 其它的请求参数，用于绑定作为默认值

    :return: 一个请求函数，可供 `P115Client.request` 使用，所以也可传给所有基于前者的 `P115Client` 的方法，作为 `request` 参数
    """
    match module:
        case "":
            return None
        case "httpx":
            from httpx import Client, Cookies, Limits
            from httpx_request import request_sync
            if cookiejar is None:
                cookies = None
            else:
                cookies = Cookies()
                cookies.jar = cookiejar
            if "session" not in request_kwargs:
                request_kwargs["session"] = Client(cookies=cookies, limits=Limits(max_connections=128))
            return partial(request_sync, **request_kwargs)
        case "httpx_async":
            from httpx import AsyncClient, Cookies, Limits
            from httpx_request import request_async
            if cookiejar is None:
                cookies = None
            else:
                cookies = Cookies()
                cookies.jar = cookiejar
            if "session" not in request_kwargs:
                request_kwargs["session"] = AsyncClient(cookies=cookies, limits=Limits(max_connections=128))
            return partial(request_async, **request_kwargs)
        case "requests":
            try:
                from requests import Session
                from requests_request import request as requests_request
            except ImportError:
                run([executable, "-m", "pip", "install", "-U", "requests", "requests_request"], check=True)
                from requests import Session
                from requests_request import request as requests_request
            session = request_kwargs.setdefault("session", Session())
            if cookiejar is not None:
                session.cookies.__dict__ = cookiejar.__dict__
            return partial(requests_request, **request_kwargs)
        case "urllib3":
            try:
                from urllib3_request import __version__
                if __version__ < (0, 0, 8):
                    modules.pop("urllib3_request", None)
                    raise ImportError
                from urllib3.poolmanager import PoolManager
                from urllib3_request import request as urllib3_request
            except ImportError:
                run([executable, "-m", "pip", "install", "-U", "urllib3", "urllib3_request>=0.0.8"], check=True)
                from urllib3.poolmanager import PoolManager
                from urllib3_request import request as urllib3_request
            if cookiejar is not None:
                request_kwargs["cookies"] = cookiejar
            if "pool" not in request_kwargs:
                request_kwargs["pool"] = PoolManager(128)
            return partial(urllib3_request, **request_kwargs)
        case "urlopen":
            # TODO: 需要实现连接池，扩展 urllib.request.AbstractHTTPHandler
            try:
                from urlopen import request as urlopen_request
            except ImportError:
                run([executable, "-m", "pip", "install", "-U", "python-urlopen"], check=True)
                from urlopen import request as urlopen_request
            return partial(urlopen_request, cookies=cookiejar)
        case "aiohttp":
            try:
                from aiohttp_client_request import __version__
                if __version__ < (0, 0, 4):
                    modules.pop("aiohttp_client_request", None)
                    raise ImportError
                from aiohttp import ClientSession as AiohttpClientSession
                from aiohttp_client_request import request as aiohttp_request
            except ImportError:
                run([executable, "-m", "pip", "install", "-U", "aiohttp", "aiohttp_client_request>=0.0.4"], check=True)
                from aiohttp import ClientSession as AiohttpClientSession
                from aiohttp_client_request import request as aiohttp_request
            if cookiejar is not None:
                request_kwargs["cookies"] = cookiejar
            if "session" not in request_kwargs:
                request_kwargs["session"] = AiohttpClientSession()
            return partial(aiohttp_request, **request_kwargs)
        case "blacksheep":
            try:
                from blacksheep_client_request import __version__
                if __version__ < (0, 0, 4):
                    modules.pop("blacksheep_client_request", None)
                    raise ImportError
                from blacksheep.client import ClientSession as BlacksheepClientSession
                from blacksheep_client_request import request as blacksheep_request
            except ImportError:
                run([executable, "-m", "pip", "install", "-U", "blacksheep", "blacksheep_client_request>=0.0.4"], check=True)
                from blacksheep.client import ClientSession as BlacksheepClientSession
                from blacksheep_client_request import request as blacksheep_request
            if cookiejar is not None:
                request_kwargs["cookies"] = cookiejar
            if "session" not in request_kwargs:
                request_kwargs["session"] = BlacksheepClientSession()
            return partial(blacksheep_request, **request_kwargs)
        case _:
            raise ValueError(f"can't make request for {module!r}")


# TODO: 基于 http.client 实现一个 request，并且支持连接池
# TODO: 基于 https://asks.readthedocs.io/en/latest/ 实现一个 request
# TODO: 基于 https://pypi.org/project/pycurl/ 实现一个 request
# TODO: 基于 https://www.tornadoweb.org/en/stable/httpclient.html 实现一个 request
# TODO: 基于 https://pypi.org/project/treq/ 实现一个 request
# TODO: 基于 https://pypi.org/project/httplib2/ 实现一个 request
# TODO: 基于 https://github.com/geventhttpclient/geventhttpclient 实现一个 request
# TODO: 基于 https://docs.twisted.org/en/latest/web/howto/client.html 实现一个 request
# TODO: 基于 https://aiosonic.readthedocs.io/en/latest/ 实现一个 request
# TODO: 基于 https://github.com/spyoungtech/grequests/ 实现一个 request
