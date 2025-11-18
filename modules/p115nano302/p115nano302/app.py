#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_application"]

from hashlib import sha1 as calc_sha1
from pathlib import Path
from re import compile as re_compile
from string import digits, hexdigits
from time import time as get_timestamp
from typing import cast, Final
from urllib.parse import parse_qsl, unquote, urlsplit

from blacksheep import json, redirect, Application, FromJSON, Request, Response, Router
from blacksheep.server.remotes.forwarding import ForwardedHeadersMiddleware
from blacksheep_client_request import request
from blacksheep_rich_log import middleware_access_log
from cachedict import LRUDict, TLRUDict
from dicttools import get_first
from errno2 import errno
from orjson import dumps, loads
from p115pickcode import is_valid_pickcode, to_id, to_pickcode, get_stable_point
from p115rsacipher import encrypt, decrypt


CRE_COOKIES_UID_search: Final = re_compile(r"(?<=\bUID=)[^\s;]+").search
CRE_name_search: Final = re_compile(r"[^&=]+(?=&|$)").match
_CACHE_DIR = Path("~/.p115client.cache.d").expanduser()
_CACHE_DIR.mkdir(exist_ok=True)
_CACHE_FILE_PICKCODE_STABLE_POINT = _CACHE_DIR / "pickcode_stable_points.resp"


async def urlopen(url: str, check: bool = True, **kwargs):
    kwargs.setdefault("parse", lambda _, data: loads(data))
    resp = await request(url, **kwargs)
    if check and not (resp and resp["state"]):
        raise OSError(errno.EIO, resp)
    return resp


def is_valid_file_id(id: int | str, /) -> bool:
    if isinstance(id, int):
        return id > 0
    return len(id) > 0 and not (id.startswith("0") or id.strip(digits))


def is_valid_sha1(sha1: str, /) -> bool:
    return len(sha1) == 40 and not sha1.strip(hexdigits)


def get_user_id_from_cookies(cookies: str, /) -> str:
    match = CRE_COOKIES_UID_search(cookies)
    if match is None:
        return ""
    return match[0].partition("_")[0]


def make_application(
    cookies: str, 
    debug: bool = False, 
    password: str = "", 
    token: str = "", 
    cache_url: bool = False, 
    cache_size: int = 65536, 
) -> Application:
    #: (user_id, sha1) 或 (user_id, sha1, size) 或 (user_id, sha1, cid) 或 (user_id, sha1, size, cid) 对应 id
    SHA1_TO_ID: LRUDict[tuple, int] = LRUDict(maxsize=cache_size)
    #: (user_id, name) 或 (user_id, name, size) 或 (user_id, name, cid) 或 (user_id, name, size, cid) 对应 id
    NAME_TO_ID: LRUDict[tuple, int] = LRUDict(maxsize=cache_size)
    #: (share_code, name) 或 (share_code, name, size) 或 (share_code, name, cid) 或 (share_code, name, size, cid) 对应 id
    SHARE_NAME_TO_ID: LRUDict[tuple, int] = LRUDict(maxsize=cache_size)
    if cache_url:
        #: id 或 (id, user_agent) 或 (id, share_code) 对应下载 url
        DOWNLOAD_URL_CACHE: TLRUDict[int | tuple[int, str], tuple[float, str]] = TLRUDict(maxsize=cache_size)
    #: 分享码 对应 接收码
    RECEIVE_CODE_MAP: dict[str, str] = {}

    PASSWORD = password
    d_cookies: dict[str, str] = {ick: ck for ck in cookies.split("\n") if (ick := get_user_id_from_cookies(ck))}
    d_pcsp: dict[str, str] = {}

    app = Application(router=Router(), show_error_details=debug)
    if debug:
        logger = getattr(app, "logger")
        logger.level = 10 # logging.DEBUG

    @app.on_middlewares_configuration
    def configure_forwarded_headers(app: Application):
        app.middlewares.insert(0, ForwardedHeadersMiddleware(accept_only_proxied_requests=False))

    middleware_access_log(app)

    def get_cookies(user_id: str = "", /) -> tuple[str, str]:
        if user_id:
            return user_id, d_cookies[user_id]
        else:
            return next(iter(d_cookies.items()))

    async def get_pickcode(id: int | str, user_id: str = "", /) -> str:
        user_id, cookies = get_cookies(user_id)
        if not (point := d_pcsp.get(user_id)):
            try:
                d_pcsp.update(loads(_CACHE_FILE_PICKCODE_STABLE_POINT.open("rb").read()))
            except OSError:
                pass
            if not (point := d_pcsp.get(user_id)):
                resp: dict = await urlopen(
                    "https://webapi.115.com/files", 
                    params={"show_dir": 1, "limit": 1, "cid": 0}, 
                    headers={"cookie": cookies}, 
                )
                point = d_pcsp[user_id] = get_stable_point(resp["data"][0]["pc"])
                try:
                    _CACHE_FILE_PICKCODE_STABLE_POINT.open("wb").write(dumps(d_pcsp))
                except Exception:
                    pass
        return to_pickcode(id, point)

    async def sha1_to_id(
        sha1: str, 
        size: int = -1, 
        cid: int = 0, 
        user_id: str = "", 
        refresh: bool = False, 
    ) -> int:
        user_id, cookies = get_cookies(user_id)
        sha1 = sha1.upper()
        if size >= 0:
            if cid:
                key: tuple = (user_id, sha1, size, cid)
            else:
                key = (user_id, sha1, size)
        elif cid:
            key = (user_id, sha1, cid)
        else:
            key = (user_id, sha1)
        if not refresh and (id := SHA1_TO_ID.get(key, 0)):
            return id
        if cid or size >= 0:
            payload = {"cid": cid, "fc": 0, "limit": 100, "search_value": sha1}
            for offset in range(0, 10_000, 100):
                if offset and resp["count"] <= offset:
                    break
                payload["offset"] = offset
                resp: dict = await urlopen(
                    "https://webapi.115.com/files/search", 
                    params=payload, 
                    headers={"cookie": cookies}, 
                )
                for info in resp["data"]:
                    if info["sha"] != sha1:
                        raise FileNotFoundError(
                            errno.ENOENT, 
                            {"user_id": user_id, "sha1": sha1, "size": size, "cid": cid, "error": "not found"}, 
                        )
                    if size >= 0 and int(info["s"]) != size:
                        continue
                    id = SHA1_TO_ID[key] = int(info["fid"])
                    return id
        else:
            resp = await urlopen(
                "https://webapi.115.com/files/shasearch", 
                params={"sha1": sha1}, 
                headers={"cookie": cookies}, 
            )
            id = SHA1_TO_ID[key] = int(resp["data"]["file_id"])
            return id
        raise FileNotFoundError(
            errno.ENOENT, 
            {"user_id": user_id, "sha1": sha1, "size": size, "cid": cid, "error": "not found"}, 
        )

    async def name_to_id(
        name: str, 
        size: int = -1, 
        cid: int = 0, 
        user_id: str = "", 
        refresh: bool = False, 
    ) -> int:
        user_id, cookies = get_cookies(user_id)
        if size >= 0:
            if cid:
                key: tuple = (user_id, name, size, cid)
            else:
                key = (user_id, name, size)
        elif cid:
            key = (user_id, name, cid)
        else:
            key = (user_id, name)
        if not refresh and (id := NAME_TO_ID.get(key, 0)):
            return id
        payload = {"cid": cid, "fc": 0, "limit": 10_000, "search_value": name}
        suffix = name.rpartition(".")[-1]
        if suffix.isalnum():
            payload["suffix"] = suffix
        resp: dict = await urlopen(
            "https://webapi.115.com/files/search", 
            params=payload, 
            headers={"cookie": cookies}, 
            check=False, 
        )
        if get_first(resp, "errno", "errNo", default=0) == 20021:
            payload.pop("suffix")
            resp = await urlopen(
                "https://webapi.115.com/files/search", 
                params=payload, 
                headers={"cookie": cookies}, 
            )
        elif not resp["state"]:
            raise OSError(errno.EIO, resp)
        for info in resp["data"]:
            if info["n"] == name and (size < 0 and int(info["s"]) == size):
                id = NAME_TO_ID[key] = int(info["fid"])
                return id
        raise FileNotFoundError(
            errno.ENOENT, 
            {"user_id": user_id, "name": name, "size": size, "cid": cid, "error": "not found"}, 
        )

    async def share_name_to_id(
        name: str, 
        share_code: str, 
        receive_code: str = "", 
        size: int = -1, 
        cid: int = 0, 
        user_id: str = "", 
        refresh: bool = False, 
    ) -> int:
        user_id, cookies = get_cookies(user_id)
        if size >= 0:
            if cid:
                key: tuple = (share_code, name, size, cid)
            else:
                key = (share_code, name, size)
        elif cid:
            key = (share_code, name, cid)
        else:
            key = (share_code, name)
        if not refresh and (id := SHARE_NAME_TO_ID.get(key, 0)):
            return id
        if not receive_code:
            receive_code = await get_receive_code(share_code, user_id=user_id)
        payload = {
            "cid": cid, 
            "fc": 0, 
            "limit": 10_000, 
            "receive_code": receive_code, 
            "search_value": name, 
            "share_code": share_code, 
        }
        suffix = name.rpartition(".")[-1]
        if suffix.isalnum():
            payload["suffix"] = suffix
        resp: dict = await urlopen(
            "https://webapi.115.com/share/search", 
            params=payload, 
            headers={"cookie": cookies}, 
            check=False, 
        )
        if get_first(resp, "errno", "errNo", default=0) == 20021:
            payload.pop("suffix")
            resp = await urlopen(
                "https://webapi.115.com/share/search", 
                params=payload, 
                headers={"cookie": cookies}, 
            )
        elif not resp["state"]:
            raise OSError(errno.EIO, resp)
        for info in resp["data"]["list"]:
            if info["n"] == name and (size < 0 or int(info["s"]) == size):
                id = SHARE_NAME_TO_ID[key] = int(info["fid"])
                return id
        raise FileNotFoundError(
            errno.ENOENT, 
            {"share_code": share_code, "name": name, "size": size, "cid": cid, "error": "not found"}, 
        )

    async def get_url(
        id: int, 
        /, 
        user_agent: str = "", 
        user_id: str = "", 
        refresh: bool = False, 
        app: str = "android", 
    ) -> str:
        user_id, cookies = get_cookies(user_id)
        if cache_url and not refresh and (
            (r := DOWNLOAD_URL_CACHE.get(id)) or 
            (r := DOWNLOAD_URL_CACHE.get((id, user_agent)))
        ):
            return r[1]
        pickcode = await get_pickcode(id, user_id)
        if app in ("", "chrome"):
            resp: dict = await urlopen(
                "https://proapi.115.com/app/chrome/downurl", 
                method="POST", 
                data={"data": encrypt(f'{{"pickcode":"{pickcode}"}}').decode("utf-8")}, 
                headers={"user-agent": user_agent, "cookie": cookies}, 
            )
        else:
            resp = await urlopen(
                f"https://proapi.115.com/{app or 'android'}/2.0/ufile/download", 
                method="POST", 
                data={"data": encrypt(f'{{"pick_code":"{pickcode}"}}').decode("utf-8")}, 
                headers={"user-agent": user_agent, "cookie": cookies}, 
            )
        data = loads(decrypt(resp["data"]))
        if app in ("", "chrome"):
            info = next(iter(data.values()))
            url_info = info["url"]
            if not url_info:
                raise FileNotFoundError(
                    errno.ENOENT, 
                    {"user_id": user_id, "id": id, "user_agent": user_agent, "error": "not found"}, 
                )
            url = url_info["url"]
        else:
            url = data["url"]
        if cache_url:
            expire_ts = int(next(v for k, v in parse_qsl(urlsplit(url).query) if k == "t")) - 60 * 5
            if "&c=0&f=&" in url:
                DOWNLOAD_URL_CACHE[id] = (expire_ts, url)
            else:
                DOWNLOAD_URL_CACHE[(id, user_agent)] = (expire_ts, url)
        return url

    async def share_get_url(
        file_id: int, 
        /, 
        share_code: str, 
        receive_code: str = "", 
        user_id: str = "", 
        refresh: bool = False, 
        app: str = "", 
    ) -> str:
        user_id, cookies = get_cookies(user_id)
        if cache_url and not refresh and (r := DOWNLOAD_URL_CACHE.get((file_id, share_code))):
            return r[1]
        if not receive_code:
            receive_code = await get_receive_code(share_code, user_id=user_id)
        payload = {
            "share_code": share_code, 
            "receive_code": receive_code, 
            "file_id": file_id, 
        }
        if app in ("", "chrome"):
            resp: dict = await urlopen(
                "https://proapi.115.com/app/share/downurl", 
                method="POST", 
                data={"data": encrypt(dumps(payload)).decode("utf-8")}, 
                headers={"cookie": cookies}, 
                check=False, 
            )
        else:
            resp = await urlopen(
                f"https://proapi.115.com/{app}/2.0/share/downurl", 
                params=payload, 
                headers={"cookie": cookies}, 
                check=False, 
            )
        if not resp["state"]:
            if resp.get("errno") == 4100008 and RECEIVE_CODE_MAP.pop(share_code, "") == receive_code:
                return await share_get_url(
                    file_id, 
                    share_code=share_code, 
                    user_id=user_id, 
                    refresh=refresh, 
                    app=app, 
                )
            raise OSError(errno.EIO, resp)
        if app in ("", "chrome"):
            data = loads(decrypt(resp["data"]))
        else:
            data = resp["data"]
        if not (data and (url_info := data["url"])):
            raise FileNotFoundError(
                errno.ENOENT, 
                {"share_code": share_code, "id": id, "error": "not found"}, 
            )
        url = url_info["url"]
        if cache_url:
            expire_ts = int(next(v for k, v in parse_qsl(urlsplit(url).query) if k == "t")) - 60 * 5
            DOWNLOAD_URL_CACHE[(file_id, share_code)] = (expire_ts, url)
        return url

    async def get_receive_code(share_code: str, user_id: str = "") -> str:
        user_id, cookies = get_cookies(user_id)
        if receive_code := RECEIVE_CODE_MAP.get(share_code, ""):
            return receive_code
        resp: dict = await urlopen(
            "https://webapi.115.com/share/shareinfo", 
            params={"share_code": share_code}, 
            headers={"cookie": cookies}, 
        )
        receive_code = RECEIVE_CODE_MAP[share_code] = resp["data"]["receive_code"]
        return receive_code

    @app.router.route("/", methods=["GET", "HEAD", "POST"])
    @app.router.route("/<path:name2>", methods=["GET", "HEAD", "POST"])
    async def index(
        request: Request, 
        share_code: str = "", 
        receive_code: str = "", 
        id: int = 0, 
        pickcode: str = "", 
        sha1: str = "", 
        name: str = "", 
        name2: str = "", 
        size: int = -1, 
        cid: int = 0, 
        user_id: str = "", 
        refresh: bool = False, 
        app: str = "", 
        sign: str = "", 
        t: int = 0, 
    ) -> Response:
        def check_sign(val, /) -> None | Response:
            if token:
                if sign != calc_sha1(bytes(f"302@115-{token}-{t}-{val}", "utf-8")).hexdigest():
                    return json({"state": False, "message": "invalid sign"}, 403)
                elif t > 0 and t <= get_timestamp():
                    return json({"state": False, "message": "url was expired"}, 401)
            return None
        if share_code:
            if id:
                if resp := check_sign(id):
                    return resp
            else:
                if not name:
                    if match := CRE_name_search(unquote(request.url.query or b"")):
                        name = match[0]
                    else:
                        name = name2
                    if is_valid_file_id(name):
                        id = int(name)
                if resp := check_sign(name):
                    return resp
                if not id and name:
                    id = await share_name_to_id(
                        name, 
                        share_code=share_code, 
                        receive_code=receive_code, 
                        size=size, 
                        cid=cid, 
                        user_id=user_id, 
                        refresh=refresh, 
                    )
            if not id:
                raise FileNotFoundError(
                    errno.ENOENT, 
                    f"please specify id or name: share_code={share_code!r}", 
                )
            url = await share_get_url(
                id, 
                share_code=share_code, 
                receive_code=receive_code, 
                user_id=user_id, 
                refresh=refresh, 
                app=app, 
            )
        else:
            if id:
                if resp := check_sign(id):
                    return resp
            elif pickcode:
                if resp := check_sign(pickcode):
                    return resp
                if not is_valid_pickcode(pickcode):
                    raise ValueError(f"bad pickcode: {pickcode!r}")
                id = to_id(pickcode)
            elif sha1:
                if resp := check_sign(sha1):
                    return resp
                if not is_valid_sha1(sha1):
                    raise ValueError(f"bad sha1: {sha1!r}")
                id = await sha1_to_id(
                    sha1, 
                    size=size, 
                    cid=cid, 
                    user_id=user_id, 
                    refresh=refresh, 
                )
            elif name:
                if resp := check_sign(name):
                    return resp
                id = await sha1_to_id(
                    name, 
                    size=size, 
                    cid=cid, 
                    user_id=user_id, 
                    refresh=refresh, 
                )
            else:
                remains = ""
                if match := CRE_name_search(unquote(request.url.query or b"")):
                    name = match[0]
                elif (idx := name2.find("/")) > 0:
                    name, remains = name2[:idx], name2[idx:]
                else:
                    name = name2
                if name:
                    if is_valid_file_id(name):
                        if resp := check_sign(name):
                            return resp
                        id = int(name)
                    elif is_valid_pickcode(name):
                        if resp := check_sign(name):
                            return resp
                        id = to_id(name)
                    elif is_valid_sha1(name):
                        if resp := check_sign(name):
                            return resp
                        id = await sha1_to_id(
                            name, 
                            size=size, 
                            cid=cid, 
                            user_id=user_id, 
                            refresh=refresh, 
                        )
                if not id:
                    name += remains
                    if resp := check_sign(name):
                        return resp
                    id = await name_to_id(
                        name, 
                        size=size, 
                        cid=cid, 
                        user_id=user_id, 
                        refresh=refresh, 
                    )
            if not id:
                raise FileNotFoundError(
                    errno.ENOENT, 
                    f"not found: {str(request.url)!r}", 
                )
            user_agent = (request.get_first_header(b"user-agent") or b"").decode("latin-1")
            url = await get_url(
                id, 
                user_agent=user_agent, 
                user_id=user_id, 
                refresh=refresh, 
                app=app, 
            )
        return redirect(url)

    if PASSWORD:
        @app.router.route("/%3Ccookies", methods=["GET"])
        async def get_cookies(request: Request, password: str = ""):
            """获取一组 cookies

            :param password: 口令
            """
            if PASSWORD != password:
                return json({"state": False, "message": "password does not match"}, 401)
            return json({"state": True, "cookies": list(d_cookies.values())})

        @app.router.route("/%3Ccookies", methods=["POST"])
        async def set_cookies(request: Request, password: str = "", body: None | FromJSON = None):
            """更新一组 cookies

            :param password: 口令
            :param body: 请求体为 JSON 格式 <code>{"cookies"&colon; "新的 cookies"}</code>
            """
            if PASSWORD != password:
                return json({"state": False, "message": "password does not match"}, 401)
            if body:
                if isinstance(body, dict):
                    body = body["cookies"]
                if isinstance(body, str):
                    cookies = body.strip().split("\n")
                else:
                    cookies = cast(list[str], body)
                try:
                    d_cookies.update(
                        (ick, ck) for ck in cookies 
                        if (ick := get_user_id_from_cookies(ck))
                    )
                    return json({"state": True, "message": "ok"})
                except Exception as e:
                    return json({"state": False, "message": f"{type(e).__qualname__}: {e}"})
            return json({"state": True, "message": "skip"})
    return app


if __name__ == "__main__":
    import uvicorn

    cookies = open("115-cookies.txt", encoding="latin-1").read().strip()
    uvicorn.run(
        make_application(cookies, debug=True), 
        host="0.0.0.0", 
        port=8000, 
        proxy_headers=True, 
        server_header=False, 
        forwarded_allow_ips="*", 
        timeout_graceful_shutdown=1, 
        access_log=False, 
    )

