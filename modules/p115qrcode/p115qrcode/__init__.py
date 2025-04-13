#!/usr/bin/env python3
# encoding: utf-8

"扫码获取 115 cookies"

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 5)
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"
__all__ = [
    "AVAILABLE_ORIGINS", "AVAILABLE_APPS", "APP_TO_SSOENT", "SSOENT_TO_APP", 
    "QrcodeStatus", "QrcodeScanFuture", "QrcodeScanAsyncFuture", 
    "scan_qrcode", "auto_scan_qrcode", "qrcode_token", "qrcode_status", 
    "qrcode_scan", "qrcode_scan_confirm", "qrcode_scan_cancel", "qrcode_result", 
    "qrcode_token_open", "qrcode_access_token", "qrcode_refresh_token", "qrcode_url", 
    "qrcode_token_url", "qrcode_print", "qrcode_open", 
]

from asyncio import AbstractEventLoop
from asyncio.futures import Future as AsyncFuture
from collections.abc import Callable, Coroutine, Mapping
from concurrent.futures import Future
from enum import IntEnum
from errno import EIO
from functools import cached_property, partial
from inspect import isawaitable
from sys import stderr
from _thread import start_new_thread
from types import MappingProxyType
from typing import overload, Any, Final, Literal, Self


#: 目前发现扫码相关的接口，可用这些 origin
AVAILABLE_ORIGINS: Final[list[str]] = [
    "http://qrcodeapi.115.com", 
    "https://qrcodeapi.115.com", 
    "http://hnqrcodeapi.115.com", 
    "https://hnqrcodeapi.115.com", 
    "http://passportapi.115.com", 
    "https://passportapi.115.com", 
    "http://hnpassportapi.115.com", 
    "https://hnpassportapi.115.com", 
]
#: 目前可用的登录设备
AVAILABLE_APPS: Final[tuple[str, ...]] = (
    "web", "ios", "115ios", "android", "115android", "115ipad", "tv", "qandroid", 
    "windows", "mac", "linux", "wechatmini", "alipaymini", "harmony", 
)
#: 目前已知的登录设备和对应的 ssoent
APP_TO_SSOENT: Final[dict[str, str]] = {
    "web": "A1", 
    "desktop": "A1", # 临时
    "ios": "D1", 
    "bios": "D1", # 临时
    "115ios": "D3", 
    "android": "F1", 
    "bandroid": "F1", # 临时
    "115android": "F3", 
    "ipad": "H1", 
    "115ipad": "H3", 
    "tv": "I1", 
    "qandroid": "M1", 
    "qios": "N1", 
    "windows": "P1", 
    "mac": "P2", 
    "linux": "P3", 
    "wechatmini": "R1", 
    "alipaymini": "R2", 
    "harmony": "S1", 
}
#: 目前已知的 ssoent 和对应的登录设备，一部分因为不知道具体的设备名，所以使用目前可用的设备名，作为临时代替
SSOENT_TO_APP: Final[dict[str, str]] = {
    "A1": "web", 
    "A2": "android", # 临时代替
    "A3": "ios",     # 临时代替
    "A4": "115ipad", # 临时代替
    "B1": "android", # 临时代替
    "D1": "ios", 
    "D2": "ios",     # 临时代替
    "D3": "115ios",  
    "F1": "android", 
    "F2": "android", # 临时代替
    "F3": "115android", 
    "H1": "115ipad", # 临时代替
    "H2": "115ipad", # 临时代替
    "H3": "115ipad", 
    "I1": "tv", 
    "M1": "qandroid", 
    "N1": "ios",     # 临时代替
    "P1": "windows", 
    "P2": "mac", 
    "P3": "linux", 
    "R1": "wechatmini", 
    "R2": "alipaymini", 
    "S1": "harmony", 
}


_httpx_request = None
_httpx_request_async = None


def get_default_request(async_: bool = False):
    global _httpx_request, _httpx_request_async
    if async_:
        if _httpx_request_async is None:
            from httpx import AsyncClient, AsyncHTTPTransport
            from httpx_request import request_async
            _httpx_request_async = partial(
                request_async, 
                session=AsyncClient(transport=AsyncHTTPTransport(retries=5), verify=False), 
                timeout=30, 
            )
        return _httpx_request_async
    else:
        if _httpx_request is None:
            from httpx import Client, HTTPTransport
            from httpx_request import request_sync
            _httpx_request = partial(
                request_sync, 
                session=Client(transport=HTTPTransport(retries=5), verify=False), 
                timeout=30, 
            )
        return _httpx_request


class QrcodeStatus(IntEnum):
    """二维码的扫码状态
    """
    waiting  = 0
    scanned  = 1
    sigined  = 2
    expired  = -1
    canceled = -2
    aborted  = -99

    @classmethod
    def of(cls, val, /) -> Self:
        if isinstance(val, cls):
            return val
        elif isinstance(val, str):
            try:
                return cls[val]
            except KeyError:
                pass
        return cls(val)


class QrcodeScanFutureMixin:
    app: int | str = "alipaymini"

    @cached_property
    def message(self, /) -> dict:
        return {"msg": "等待扫码中", "status": 0}

    @cached_property
    def status(self, /) -> QrcodeStatus:
        return QrcodeStatus(0)

    @cached_property
    def token(self, /) -> MappingProxyType:
        app = self.app
        request_kwargs = getattr(self, "request_kwargs", {})
        if isinstance(app, int):
            return MappingProxyType(qrcode_token_open(app, **request_kwargs))
        else:
            return MappingProxyType(qrcode_token(**request_kwargs))

    @property
    def token_url(self, /):
        return qrcode_token_url(self.uid)

    @property
    def uid(self, /) -> str:
        return self.token["uid"]

    @property
    def url(self, /):
        return qrcode_url(self.uid)

    def open(self, /):
        return qrcode_open(self.uid)

    def print(self, /):
        return qrcode_print(self.uid)


class QrcodeScanFuture(Future, QrcodeScanFutureMixin):
    """二维码手动扫码，同步版
    """
    def __init__(
        self, 
        app: int | str = "alipaymini", 
        /, 
        console_qrcode: None | bool = True, 
        show_message: bool | Callable = False, 
        **request_kwargs, 
    ):
        super().__init__()
        self.app = app
        self.console_qrcode = console_qrcode
        if show_message is True:
            show_message = partial(print, file=stderr, flush=True)
        self.show_message = show_message
        self.request_kwargs = request_kwargs
        self.start()

    def __del__(self, /):
        self.cancel()

    def background(self, /):
        if not (self.set_running_or_notify_cancel() and 0 <= self.status < 2):
            return
        console_qrcode = self.console_qrcode
        show_message = self.show_message
        request_kwargs = self.request_kwargs
        token = self.token
        uid = token["uid"]
        try:
            if console_qrcode:
                qrcode_print(uid)
            elif console_qrcode is not None:
                qrcode_open(uid)
            if show_message:
                show_message(self.message)
            while self.running():
                resp = qrcode_status(token, **request_kwargs)
                self.message = resp
                if show_message:
                    show_message(resp)
                status = self.status = QrcodeStatus(resp.get("status", -99))
                if status < 0:
                    self.set_exception(RuntimeError(status))
                    break
                elif status == 2:
                    app = self.app
                    if isinstance(app, int):
                        resp = qrcode_access_token(uid, **request_kwargs)
                    else:
                        resp = qrcode_result(uid, app, **request_kwargs)
                    self.set_result(resp)
                    break
        except BaseException as e:
            self.message = {"msg": "扫码错误", "reason": e}
            self.set_exception(e)
            if show_message:
                show_message(self.message)
            raise

    def start(self, /):
        if self.running():
            raise RuntimeError("already running")
        elif not (0 <= self.status < 2):
            raise RuntimeError("already stopped")
        start_new_thread(self.background, ())


class QrcodeScanAsyncFuture(AsyncFuture, QrcodeScanFutureMixin):
    """二维码手动扫码，异步版
    """
    def __init__(
        self, 
        app: int | str = "alipaymini", 
        /, 
        console_qrcode: None | bool = True, 
        show_message: bool | Callable = False, 
        loop: None | AbstractEventLoop = None, 
        **request_kwargs, 
    ):
        super().__init__(loop=loop)
        self.app = app
        self.console_qrcode = console_qrcode
        if show_message is True:
            show_message = partial(print, file=stderr, flush=True)
        self.show_message = show_message
        self.request_kwargs = request_kwargs
        self.running = False
        self.start()

    def __del__(self, /):
        self.close()

    async def get_token(self, /) -> MappingProxyType:
        if token := self.__dict__.get("token"):
            return token
        app = self.app
        request_kwargs = getattr(self, "request_kwargs", {})
        if isinstance(app, int):
            resp = await qrcode_token_open(app, async_=True, **request_kwargs)
        else:
            resp = await qrcode_token(async_=True, **request_kwargs)
        token = self.token = MappingProxyType(resp)
        return token

    async def background(self, /):
        if self.running or not (0 <= self.status < 2):
            return
        self.running = True
        console_qrcode = self.console_qrcode
        show_message = self.show_message
        request_kwargs = self.request_kwargs
        token = await self.get_token()
        uid = token["uid"]
        try:
            if console_qrcode:
                qrcode_print(uid)
            elif console_qrcode is not None:
                qrcode_open(uid)
            if show_message:
                r = show_message(self.message)
                if isawaitable(r):
                    await r
            while self.running:
                resp = await qrcode_status(token, async_=True, **request_kwargs)
                self.message = resp
                if show_message:
                    r = show_message(resp)
                    if isawaitable(r):
                        await r
                status = self.status = QrcodeStatus(resp.get("status", -99)) 
                if status < 0:
                    self.set_exception(RuntimeError(status))
                    break
                elif status == 2:
                    app = self.app
                    if isinstance(app, int):
                        resp = await qrcode_access_token(uid, async_=True, **request_kwargs)
                    else:
                        resp = await qrcode_result(uid, app, async_=True, **request_kwargs)
                    self.set_result(resp)
                    break
        except BaseException as e:
            self.message = {"msg": "扫码错误", "reason": e}
            self.set_exception(e)
            if show_message:
                r = show_message(self.message)
                if isawaitable(r):
                    await r
            raise
        finally:
            self.running = False

    def close(self, /):
        self.running = False
        if task := getattr(self, "_task", None):
            task.cancel()

    def start(self, /):
        if self.running:
            raise RuntimeError("already running")
        elif not (0 <= self.status < 2):
            raise RuntimeError("already stopped")
        self.task = self.get_loop().create_task(self.background())


def parse(_, content: bytes, /):
    from orjson import loads
    json = loads(content)
    if not json["state"]:
        raise OSError(EIO, json)
    return json["data"]


def request(
    url: str, 
    method: str = "GET", 
    parse: Callable = parse, 
    request: None | Callable = None, 
    async_: bool = False,
    **request_kwargs, 
):
    if request is None:
        request = get_default_request(async_=async_)
    return request(url=url, method=method, parse=parse, **request_kwargs)


@overload
def scan_qrcode(
    app: int | str = "alipaymini", 
    console_qrcode: None | bool = True, 
    show_message: bool | Callable = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> QrcodeScanFuture:
    ...
@overload
def scan_qrcode(
    app: int | str = "alipaymini", 
    console_qrcode: None | bool = True, 
    show_message: bool | Callable = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> QrcodeScanAsyncFuture:
    ...
def scan_qrcode(
    app: int | str = "alipaymini", 
    console_qrcode: None | bool = True, 
    show_message: bool | Callable = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> QrcodeScanFuture | QrcodeScanAsyncFuture:
    """创建一个等待手动扫码的 Future 对象

    :param app: 待绑定的设备名或者开放平台应用的 AppID
    :param console_qrcode: 在命令行输出二维码，否则在浏览器中打开
    :param show_message: 是否在命令行输出信息
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 一个 Future 对象
    """
    if async_:
        return QrcodeScanAsyncFuture(
            app, 
            console_qrcode=console_qrcode, 
            show_message=show_message, 
            **request_kwargs, 
        )
    else:
        return QrcodeScanFuture(
            app, 
            console_qrcode=console_qrcode, 
            show_message=show_message, 
            **request_kwargs, 
        )


@overload
def auto_scan_qrcode(
    cookies: str, 
    app: int | str = "alipaymini", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def auto_scan_qrcode(
    cookies: str, 
    app: int | str = "alipaymini", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def auto_scan_qrcode(
    cookies: str, 
    app: int | str = "alipaymini", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """自动扫码登录

    :param cookies: 一个登录状态的 115 cookies
    :param app: 待绑定的设备名或者开放平台应用的 AppID
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口返回值
    """
    from iterutils import run_gen_step
    cookies = cookies.strip()
    def gen_step():
        headers = request_kwargs.pop("headers", None) or {}
        if isinstance(app, int):
            token = yield qrcode_token_open(app, async_=async_, headers=headers, **request_kwargs)
        else:
            token = yield qrcode_token(async_=async_, headers=headers, **request_kwargs)
        headers_with_cookies = {**headers, "Cookie": cookies}
        uid = token["uid"]
        yield qrcode_scan(uid, headers=headers_with_cookies, async_=async_, **request_kwargs)
        yield qrcode_scan_confirm(uid, headers=headers_with_cookies, async_=async_, **request_kwargs)
        if isinstance(app, int):
            return qrcode_access_token(uid, headers=headers, async_=async_, **request_kwargs)
        else:
            return qrcode_result(uid, app, headers=headers, async_=async_, **request_kwargs)
    return run_gen_step(gen_step, may_call=False, async_=async_)


@overload
def qrcode_token(
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def qrcode_token(
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def qrcode_token(
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取二维码 token

    :param base_url: 链接的基地址，包含域名和一部分路径等
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应值
    """
    request_kwargs["url"] = f"{base_url}/api/1.0/web/1.0/token/"
    return request(async_=async_, **request_kwargs)


@overload
def qrcode_status(
    payload: Mapping, 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def qrcode_status(
    payload: Mapping, 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def qrcode_status(
    payload: Mapping, 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取二维码的状态（未扫描、已扫描、已登录、已取消、已过期等）

    :param payload: 请求的查询参数，取自 `qrcode_token` 接口响应，有 3 个

        - uid:  str
        - time: int
        - sign: str

    :param base_url: 链接的基地址，包含域名和一部分路径等
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应值
    """
    request_kwargs.update(
        url=f"{base_url}/get/status/", 
        params=payload, 
    )
    request_kwargs.setdefault("timeout", None)
    return request(async_=async_, **request_kwargs)


@overload
def qrcode_scan(
    uid: str, 
    cookies: str = "", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def qrcode_scan(
    uid: str, 
    cookies: str = "", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def qrcode_scan(
    uid: str, 
    cookies: str = "", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """扫描二维码

    :param uid: 二维码的 token
    :param cookies: 一个有效（在线状态）的 cookies
    :param base_url: 链接的基地址，包含域名和一部分路径等
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口返回值
    """
    if cookies:
        if headers := request_kwargs.get("headers"):
            request_kwargs["headers"] = dict(headers, Cookie=cookies)
        else:
            request_kwargs["headers"] = {"Cookie": cookies}
    request_kwargs.update(
        url=f"{base_url}/api/2.0/prompt.php", 
        params={"uid": uid}, 
    )
    return request(async_=async_, **request_kwargs)


@overload
def qrcode_scan_confirm(
    uid: str, 
    cookies: str = "", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def qrcode_scan_confirm(
    uid: str, 
    cookies: str = "", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def qrcode_scan_confirm(
    uid: str, 
    cookies: str = "", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """确认扫描二维码

    :param uid: 二维码的 token
    :param cookies: 一个有效（在线状态）的 cookies
    :param base_url: 链接的基地址，包含域名和一部分路径等
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口返回值
    """
    if cookies:
        if headers := request_kwargs.get("headers"):
            request_kwargs["headers"] = dict(headers, Cookie=cookies)
        else:
            request_kwargs["headers"] = {"Cookie": cookies}
    request_kwargs.update(
        url=f"{base_url}/api/2.0/slogin.php", 
        params={"key": uid, "uid": uid, "client": 0}, 
    )
    return request(async_=async_, **request_kwargs)


@overload
def qrcode_scan_cancel(
    uid: str, 
    cookies: str = "", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def qrcode_scan_cancel(
    uid: str, 
    cookies: str = "", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def qrcode_scan_cancel(
    uid: str, 
    cookies: str = "", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """取消扫描二维码

    :param uid: 二维码的 token
    :param cookies: 一个有效（在线状态）的 cookies
    :param base_url: 链接的基地址，包含域名和一部分路径等
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口返回值
    """
    if cookies:
        if headers := request_kwargs.get("headers"):
            request_kwargs["headers"] = dict(headers, Cookie=cookies)
        else:
            request_kwargs["headers"] = {"Cookie": cookies}
    request_kwargs.update(
        url=f"{base_url}/api/2.0/cancel.php", 
        params={"key": uid, "uid": uid, "client": 0}, 
    )
    return request(async_=async_, **request_kwargs)


@overload
def qrcode_result(
    uid: str, 
    app: str = "alipaymini", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def qrcode_result(
    uid: str, 
    app: str = "alipaymini", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def qrcode_result(
    uid: str, 
    app: str = "alipaymini", 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取扫码登录的结果，并且绑定设备，包含 cookie

    :param uid: 二维码的 token
    :param app: 待绑定的设备名
    :param base_url: 链接的基地址，包含域名和一部分路径等
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应值
    """
    request_kwargs.update(
        url=f"{base_url}/app/1.0/{app}/1.0/login/qrcode/", 
        method="POST", 
        data={"account": uid}, 
    )
    return request(async_=async_, **request_kwargs)


@overload
def qrcode_token_open(
    app_id: int | str, 
    code_challenge: str = "EOq2AI1WQs9Cq9KqQfhHyw==", 
    code_challenge_method: str = "md5", 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def qrcode_token_open(
    app_id: int | str, 
    code_challenge: str = "EOq2AI1WQs9Cq9KqQfhHyw==", 
    code_challenge_method: str = "md5", 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def qrcode_token_open(
    app_id: int | str, 
    code_challenge: str = "EOq2AI1WQs9Cq9KqQfhHyw==", 
    code_challenge_method: str = "md5", 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取开放平台的登录二维码，扫码可用

    .. note::
        https://www.yuque.com/115yun/open/shtpzfhewv5nag11#WzRhM

        code_challenge 默认用的字符串为 64 个 0，hash 算法为 md5

    :param app_id: 开放平台应用的 AppID
    :param code_challenge: PKCE 相关参数，计算方式如下

        .. code:: python

            from base64 import b64encode
            from hashlib import sha256
            from secrets import token_bytes

            # code_verifier 可以是 43~128 位随机字符串
            code_verifier = token_bytes(64).hex()
            code_challenge = b64encode(sha256(code_verifier.encode()).digest()).decode()

    :param code_challenge_method: 计算 `code_challenge` 的 hash 算法，支持 "md5", "sha1", "sha256"
    :param base_url: 链接的基地址，包含域名和一部分路径等
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应值
    """
    request_kwargs.update(
        url=f"{base_url}/open/authDeviceCode", 
        method="POST", 
        data={
            "client_id": app_id, 
            "code_challenge": code_challenge, 
            "code_challenge_method": code_challenge_method, 
        }, 
    )
    return request(async_=async_, **request_kwargs)


@overload
def qrcode_access_token(
    uid: str, 
    code_verifier: str = "0" * 64, 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def qrcode_access_token(
    uid: str, 
    code_verifier: str = "0" * 64, 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def qrcode_access_token(
    uid: str, 
    code_verifier: str = "0" * 64, 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """绑定扫码并获取开放平台应用的 access_token 和 refresh_token

    .. note::
        https://www.yuque.com/115yun/open/shtpzfhewv5nag11#QCCVQ

    :param uid: 二维码的 token
    :param code_verifier: 确认码（一个 43~128 位随机字符串）
    :param base_url: 链接的基地址，包含域名和一部分路径等
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应值
    """
    request_kwargs.update(
        url=f"{base_url}/open/deviceCodeToToken", 
        method="POST", 
        data={"uid": uid, "code_verifier": code_verifier}, 
    )
    return request(async_=async_, **request_kwargs)


@overload
def qrcode_refresh_token(
    refresh_token: str, 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def qrcode_refresh_token(
    refresh_token: str | dict, 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def qrcode_refresh_token(
    refresh_token: str | dict, 
    /, 
    base_url: str = "http://qrcodeapi.115.com", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """用一个 refresh_token 去获取新的 access_token 和 refresh_token，然后原来的 refresh_token 作废

    .. note::
        https://www.yuque.com/115yun/open/shtpzfhewv5nag11#ve54x

    :param refresh_token: 刷新令牌
    :param base_url: 链接的基地址，包含域名和一部分路径等
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应值
    """
    request_kwargs.update(
        url=f"{base_url}/open/refreshToken", 
        method="POST", 
        data={"refresh_token": refresh_token}, 
    )
    return request(async_=async_, **request_kwargs)


def qrcode_url(uid: str, /, base_url: str = "http://qrcodeapi.115.com") -> str:
    """获取二维码图片的下载链接

    :param uid: 二维码的 token
    :param base_url: 链接的基地址，包含域名和一部分路径等

    :return: 下载链接 
    """
    return f"{base_url}/api/1.0/web/1.0/qrcode?uid=" + uid


def qrcode_token_url(uid: str, /, base_url: str = "http://115.com") -> str:
    """获取二维码图片的扫码链接

    :param uid: 二维码的 token
    :param base_url: 链接的基地址，包含域名和一部分路径等

    :return: 扫码链接 
    """
    return f"{base_url}/scan/dg-{uid}"


def qrcode_print(uid: str, /):
    """在命令行输出二维码

    :param uid: 二维码的 token
    """
    from sys import stdout
    from qrcode import QRCode # type: ignore
    qr = QRCode(border=1)
    qr.add_data(qrcode_token_url(uid))
    qr.print_ascii(tty=stdout.isatty())
    return qr


def qrcode_open(uid: str, /):
    """通过浏览器打开二维码

    :param uid: 二维码的 token
    """
    from startfile import startfile # type: ignore
    start_new_thread(startfile, (qrcode_url(uid),))

