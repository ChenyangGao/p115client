#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "upload_url", "upload_token", "upload_token_open", 
    "upload_init", "upload_init_open", 
    "upload_resume", "upload_resume_open", 
]

from asyncio import Lock as AsyncLock
from collections.abc import Buffer, Callable, Coroutine
from datetime import datetime, timedelta
from re import compile as re_compile
from threading import Lock
from typing import overload, Any, Final, Literal

from dicttools import iter_items, dict_update
from iterutils import run_gen_step
from orjson import loads
from p115cipher import ecdh_aes_decrypt, make_upload_payload


CRE_UID_in_COOKIE_search: Final = re_compile(r"(?<=\bUID=)\w+").search
_UPLOAD_TOKEN: Final[dict[str, str]] = {}
_UPLOAD_TOKEN_LOCK: Final = Lock()
_UPLOAD_TOKEN_ASYNC_LOCK: Final = AsyncLock()


def parse_json(_, content: Buffer, /):
    return loads(memoryview(content))


def get_request(request_kwargs: dict, /) -> Callable:
    request_kwargs.setdefault("parse", parse_json)
    request = request_kwargs.pop("request", None)
    if request is None:
        from urllib3_future_request import request
    return request


@overload
def upload_url(
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_url(
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_url(
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取上传目的网址和获取 ``token`` 的网址

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 网址的字典，"endpoint" 是上传目的网址，"gettokenurl" 是获取 ``token`` 的网址
    """
    api = "https://uplb.115.com/3.0/getuploadinfo.php"
    return get_request(request_kwargs)(url=api, async_=async_, **request_kwargs)


@overload
def upload_token(
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_token(
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_token(
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取上传用到的令牌信息（字典）

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 令牌信息（字典）
    """
    api = "https://uplb.115.com/3.0/gettoken.php"
    return get_request(request_kwargs)(url=api, async_=async_, **request_kwargs)


@overload
def upload_token_open(
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_token_open(
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_token_open(
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """获取上传用到的令牌信息（字典）

    .. caution::
        需要携带 "authorization" 请求头

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 令牌信息（字典）
    """
    api = "https://proapi.115.com/open/upload/get_token"
    return get_request(request_kwargs)(url=api, async_=async_, **request_kwargs)


@overload
def upload_init(
    payload: dict, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_init(
    payload: dict, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_init(
    payload: dict, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """上传初始化

    :param payload: 请求参数

        - userid: int | str     💡 用户 id
        - userkey: str          💡 用户的 key
        - fileid: str           💡 文件的 sha1
        - filename: str         💡 文件名
        - filesize: int         💡 文件大小
        - target: str = "U_1_0" 💡 保存目标，格式为 f"U_{aid}_{pid}"
        - sign_key: str = ""    💡 2 次验证的 key
        - sign_val: str = ""    💡 2 次验证的值
        - topupload: int | str = "true" 💡 上传调度文件类型调度标记

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    api = "https://uplb.115.com/4.0/initupload.php"
    data = {
        "appid": 0, 
        "target": "U_1_0", 
        "sign_key": "", 
        "sign_val": "", 
        "topupload": "true", 
        **payload, 
        "appversion": "99.99.99.99", 
    }
    request_kwargs["method"] = "POST"
    request_kwargs["headers"] = dict_update(
        dict(request_kwargs.get("headers") or ()), 
        {
            "content-type": "application/x-www-form-urlencoded", 
            "user-agent": "Mozilla/5.0 115disk/99.99.99.99 115Browser/99.99.99.99 115wangpan_android/99.99.99.99", 
        }, 
    )
    request_kwargs.update(make_upload_payload(data))
    def parse_upload_init_response(_, content: bytes, /) -> dict:
        data = ecdh_aes_decrypt(content)
        return parse_json(None, data)
    request_kwargs.setdefault("parse", parse_upload_init_response)
    return get_request(request_kwargs)(url=api, async_=async_, **request_kwargs)


@overload
def upload_init_open(
    payload: dict, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_init_open(
    payload: dict, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_init_open(
    payload: dict, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """上传初始化（开放接口）

    .. caution::
        需要携带 "authorization" 请求头

    :param payload: 请求参数

        - fileid: str              💡 文件的 sha1
        - file_name: str           💡 文件名
        - file_size: int           💡 文件大小
        - target: str = "U_1_0"    💡 保存目标，格式为 f"U_{aid}_{pid}"
        - sign_key: str = ""       💡 2 次验证的 key
        - sign_val: str = ""       💡 2 次验证的值
        - topupload: int | str = 1 💡 上传调度文件类型调度标记

            -  0: 单文件上传任务标识 1 条单独的文件上传记录
            -  1: 目录任务调度的第 1 个子文件上传请求标识 1 次目录上传记录
            -  2: 目录任务调度的其余后续子文件不作记作单独上传的上传记录 
            - -1: 没有该参数

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    api = "https://proapi.115.com/open/upload/init"
    request_kwargs.update(
        method="POST", 
        data={"target": "U_1_0", "topupload": 1, **payload}, 
    )
    return get_request(request_kwargs)(url=api, async_=async_, **request_kwargs)


@overload
def upload_resume(
    payload: dict | str, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_resume(
    payload: dict | str, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_resume(
    payload: dict | str, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """恢复上传（主要用于分块上传）

    .. note::
        ``payload`` 中包含 "callback" 或 "callback_var" 字段，则可以被自动处理（即使相关字段缺失）

        即使你仅保存了 ``upload_id`` 和 ``callback``，也能让你断点续传

    :param payload: 需要接受下面这些参数

        - pickcode: str 💡 提取码
        - userid: int   💡 用户 id
        - target: str   💡 上传目标，默认为 "U_1_0"，格式为 f"U_{aid}_{pid}"
        - fileid: str   💡 文件的 sha1 值（⚠️ 可以是任意值）
        - filesize: int 💡 文件大小，单位是字节（⚠️ 可以是任意值）

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    api = "https://uplb.115.com/3.0/resumeupload.php"
    if isinstance(payload, str):
        data: dict = {"pickcode": payload}
    else:
        data = dict(payload)
        if "pickcode" not in data:
            if "pick_code" in data:
                data["pickcode"] = data["pick_code"]
        callback_var: None | dict = None
        if "callback_var" in data:
            callback_var = loads(data["callback_var"])
        elif "callback" in data:
            callback_var = loads(data["callback"]["callback_var"])
        if callback_var:
            data.update(
                pickcode=callback_var["x:pick_code"], 
                target=callback_var["x:target"], 
                userid=callback_var["x:user_id"], 
            )
    data.setdefault("fileid", "0" * 40)
    data.setdefault("filesize", 1)
    data.setdefault("target", "U_1_0")
    if "userid" not in data:
        for k, v in iter_items(request_kwargs.get("headers") or ()):
            if k.lower() == "cookie" and (m := CRE_UID_in_COOKIE_search(v)):
                data["userid"] = m[0]
                break
    request_kwargs.update(method="POST", data=data)
    return get_request(request_kwargs)(url=api, async_=async_, **request_kwargs)


@overload
def upload_resume_open(
    payload: dict | str, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def upload_resume_open(
    payload: dict | str, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict]:
    ...
def upload_resume_open(
    payload: dict | str, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict | Coroutine[Any, Any, dict]:
    """恢复上传（主要用于分块上传）

    .. caution::
        需要携带 "authorization" 请求头

    .. note::
        ``payload`` 中包含 "callback" 或 "callback_var" 字段，则可以被自动处理（即使相关字段缺失）

        即使你仅保存了 ``upload_id`` 和 ``callback``，也能让你断点续传

    :param payload: 需要接受下面这些参数

        - pick_code: str 💡 提取码
        - target: str    💡 上传目标，默认为 "U_1_0"，格式为 f"U_{aid}_{pid}"
        - fileid: str    💡 文件的 sha1 值（⚠️ 可以是任意值）
        - file_size: int 💡 文件大小，单位是字节（⚠️ 可以是任意值）

    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 接口响应
    """
    api = "https://proapi.115.com/open/upload/resume"
    if isinstance(payload, str):
        data: dict = {"pick_code": payload}
    else:
        data = dict(payload)
        if "pick_code" not in data:
            if "pickcode" in data:
                data["pick_code"] = data["pickcode"]
        callback_var: None | dict = None
        if "callback_var" in data:
            callback_var = loads(data["callback_var"])
        elif "callback" in data:
            callback_var = loads(data["callback"]["callback_var"])
        if callback_var:
            data.update(
                pick_code=callback_var["x:pick_code"], 
                target=callback_var["x:target"], 
            )
    data.setdefault("fileid", "0" * 40)
    data.setdefault("file_size", 1)
    data.setdefault("target", "U_1_0")
    request_kwargs.update(method="POST", data=data)
    return get_request(request_kwargs)(url=api, async_=async_, **request_kwargs)


@overload
def _upload_token(
    refresh: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict[str, str]:
    ...
@overload
def _upload_token(
    refresh: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, dict[str, str]]:
    ...
def _upload_token(
    refresh: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict[str, str] | Coroutine[Any, Any, dict[str, str]]:
    request_kwargs["parse"] = parse_json
    request_kwargs.pop("headers", None)
    def gen_step():
        if async_:
            lock: AsyncLock | Lock = _UPLOAD_TOKEN_ASYNC_LOCK
        else:
            lock = _UPLOAD_TOKEN_LOCK
        try:
            yield lock.acquire()
            expiration = _UPLOAD_TOKEN.get("Expiration") or ""
            if refresh:
                deadline = datetime.now() - timedelta(hours=7, minutes=10)
            else:
                deadline = datetime.now() - timedelta(hours=7, minutes=59)
            if expiration < deadline.strftime("%FT%XZ"):
                while True:
                    try:
                        resp = yield upload_token(async_=async_, **request_kwargs)
                    except Exception:
                        continue
                    if resp.get("StatusCode") == "200":
                        break
                _UPLOAD_TOKEN.update(resp)
        finally:
            lock.release()
        return _UPLOAD_TOKEN
    return run_gen_step(gen_step, async_)

