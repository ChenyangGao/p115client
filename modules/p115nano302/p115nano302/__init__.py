#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 1, 1)
__all__ = ["make_application"]
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"

import logging

from collections.abc import Buffer, Callable, Mapping
from errno import EIO, ENOENT
from hashlib import sha1 as calc_sha1
from http import HTTPStatus
from itertools import cycle
from re import compile as re_compile
from string import digits, hexdigits
from time import time
from typing import cast, Any, Final, Self
from urllib.parse import parse_qsl, quote, urlencode, unquote, urlsplit, urlunsplit

from blacksheep import json, text, Application, FromJSON, Request, Response, Router
from blacksheep.client import ClientSession
from blacksheep.contents import Content, FormContent
from blacksheep.exceptions import HTTPException
from blacksheep.server.remotes.forwarding import ForwardedHeadersMiddleware
from cachedict import LRUDict, TLRUDict
from orjson import dumps, loads, OPT_INDENT_2, OPT_SORT_KEYS
from p115rsacipher import encrypt, decrypt
from rich.box import ROUNDED
from rich.console import Console
from rich.highlighter import JSONHighlighter
from rich.panel import Panel
from rich.text import Text
from uvicorn.config import LOGGING_CONFIG


CRE_COOKIES_UID_search: Final = re_compile(r"(?<=\bUID=)[^\s;]+").search
CRE_name_search: Final = re_compile(r"[^&=]+(?=&|$)").match

LOGGING_CONFIG["formatters"]["default"]["fmt"] = "[\x1b[1m%(asctime)s\x1b[0m] %(levelprefix)s %(message)s"
LOGGING_CONFIG["formatters"]["access"]["fmt"] = '[\x1b[1m%(asctime)s\x1b[0m] %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s'


class ColoredLevelNameFormatter(logging.Formatter):

    def format(self, record):
        match record.levelno:
            case logging.DEBUG:
                # blue
                record.levelname = f"\x1b[34m{record.levelname}\x1b[0m:".ljust(18)
            case logging.INFO:
                # green
                record.levelname = f"\x1b[32m{record.levelname}\x1b[0m:".ljust(18)
            case logging.WARNING:
                # yellow
                record.levelname = f"\x1b[33m{record.levelname}\x1b[0m:".ljust(18)
            case logging.ERROR:
                # red
                record.levelname = f"\x1b[31m{record.levelname}\x1b[0m:".ljust(18)
            case logging.CRITICAL:
                # magenta
                record.levelname = f"\x1b[35m{record.levelname}\x1b[0m:".ljust(18)
            case _:
                # dark grey
                record.levelname = f"\x1b[2m{record.levelname}\x1b[0m: ".ljust(18)
        return super().format(record)


def default(obj, /):
    if isinstance(obj, Buffer):
        return str(obj, "utf-8")
    raise TypeError


def highlight_json(val, /, default=default, highlighter=JSONHighlighter()) -> Text:
    if isinstance(val, Buffer):
        val = str(val, "utf-8")
    if not isinstance(val, str):
        val = dumps(val, default=default, option=OPT_INDENT_2 | OPT_SORT_KEYS).decode("utf-8")
    return highlighter(val)


def get_first(m: Mapping, *keys, default=None):
    for k in keys:
        if k in m:
            return m[k]
    return default


def get_user_id_from_cookies(cookies: str, /) -> int:
    match = CRE_COOKIES_UID_search(cookies)
    if match is None:
        return 0
    return int(match[0].partition("_")[0])


def check_response(resp: Response, /) -> Response:
    if resp.status >= 400:
        raise HTTPException(resp.status)
    return resp


class Url(str):

    def __new__(cls, val: Any = "", /, *args, **kwds):
        return super().__new__(cls, val)

    def __init__(self, val: Any = "", /, *args, **kwds):
        self.__dict__.update(*args, **kwds)

    def __getattr__(self, attr: str, /):
        try:
            return self.__dict__[attr]
        except KeyError as e:
            raise AttributeError(attr) from e

    def __getitem__(self, key, /):
        try:
            if isinstance(key, str):
                return self.__dict__[key]
        except KeyError:
            return super().__getitem__(key) # type: ignore

    def __repr__(self, /) -> str:
        cls = type(self)
        if (module := cls.__module__) == "__main__":
            name = cls.__qualname__
        else:
            name = f"{module}.{cls.__qualname__}"
        return f"{name}({super().__repr__()}, {self.__dict__!r})"

    @classmethod
    def of(cls, val: Any = "", /, ns: None | dict = None) -> Self:
        self = cls.__new__(cls, val)
        if ns is not None:
            self.__dict__ = ns
        return self

    def get(self, key, /, default=None):
        return self.__dict__.get(key, default)

    def items(self, /):
        return self.__dict__.items()

    def keys(self, /):
        return self.__dict__.keys()

    def values(self, /):
        return self.__dict__.values()


def make_application(
    cookies: str, 
    debug: bool = False, 
    password: str = "", 
    token: str = "", 
    cache_url: bool = False, 
    cache_size: int = 65536, 
) -> Application:
    ID_TO_PICKCODE:   LRUDict[tuple[int, int], str] = LRUDict(maxsize=cache_size)
    SHA1_TO_PICKCODE: LRUDict[tuple[int, str], str] = LRUDict(maxsize=cache_size)
    NAME_TO_PICKCODE: LRUDict[tuple[int, str], str] = LRUDict(maxsize=cache_size)
    DIR_TO_CID: LRUDict[tuple[int, str], int] = LRUDict(maxsize=cache_size)
    CID_NAME_TO_PICKCODE: LRUDict[tuple[int, int, str], str] = LRUDict(maxsize=cache_size)
    SHARE_NAME_TO_ID: LRUDict[tuple[str, str], int] = LRUDict(maxsize=cache_size)
    if cache_url:
        DOWNLOAD_URL_CACHE: TLRUDict[tuple[int, str, str], tuple[float, Url]] = TLRUDict(maxsize=cache_size)
    DOWNLOAD_URL_CACHE1: TLRUDict[tuple[int, str] | tuple[str, int], tuple[float, Url]] = TLRUDict(maxsize=cache_size)
    DOWNLOAD_URL_CACHE2: TLRUDict[tuple[int, str, str], tuple[float, Url]] = TLRUDict(maxsize=1024)
    RECEIVE_CODE_MAP: dict[str, str] = {}

    PASSWORD = password
    d_cookies = {ick: ck for ck in cookies.split("\n") if (ick := get_user_id_from_cookies(ck))}
    client: ClientSession

    app = Application(router=Router(), show_error_details=debug)
    logger = getattr(app, "logger")
    handler = logging.StreamHandler()
    handler.setFormatter(ColoredLevelNameFormatter("[\x1b[1m%(asctime)s\x1b[0m] %(levelname)s %(message)s"))
    logger.addHandler(handler)

    async def redirect_exception_response(
        self, 
        request: Request, 
        exc: Exception, 
    ):
        if isinstance(exc, HTTPException):
            return text(str(exc), exc.status)
        elif isinstance(exc, ValueError):
            return text(str(exc), 400)
        elif isinstance(exc, FileNotFoundError):
            return text(str(exc), 404)
        elif isinstance(exc, OSError):
            return text(str(exc), 503)
        else:
            return text(str(exc), 500)

    if debug:
        logger.level = logging.DEBUG

    @app.on_middlewares_configuration
    def configure_forwarded_headers(app: Application):
        app.middlewares.insert(0, ForwardedHeadersMiddleware(accept_only_proxied_requests=False))

    @app.lifespan
    async def register_http_client():
        nonlocal client
        async with ClientSession(default_headers={"Cookie": next(iter(d_cookies.values()))}) as client:
            app.services.register(ClientSession, instance=client)
            yield

    @app.middlewares.append
    async def access_log(request: Request, handler) -> Response:
        start_t = time()
        def get_message(response: Response, /) -> str:
            remote_attr = request.scope["client"]
            status = response.status
            if status < 300:
                status_color = 32
            elif status < 400:
                status_color = 33
            else:
                status_color = 31
            message = f'\x1b[5;35m{remote_attr[0]}:{remote_attr[1]}\x1b[0m - "\x1b[1;36m{request.method}\x1b[0m \x1b[1;4;34m{request.url}\x1b[0m \x1b[1mHTTP/{request.scope["http_version"]}\x1b[0m" - \x1b[{status_color}m{status} {HTTPStatus(status).phrase}\x1b[0m - \x1b[32m{(time() - start_t) * 1000:.3f}\x1b[0m \x1b[3mms\x1b[0m'
            if debug:
                console = Console()
                with console.capture() as capture:
                    urlp = urlsplit(str(request.url))
                    url = urlunsplit(urlp._replace(path=unquote(urlp.path), scheme=request.scheme, netloc=request.host))
                    console.print(
                        Panel.fit(
                            f"[b cyan]{request.method}[/] [u blue]{url}[/] [b]HTTP/[red]{request.scope["http_version"]}",
                            box=ROUNDED,
                            title="[b red]URL", 
                            border_style="cyan", 
                        ), 
                    )
                    headers = {str(k, 'latin-1'): str(v, 'latin-1') for k, v in request.headers}
                    console.print(
                        Panel.fit(
                            highlight_json(headers), 
                            box=ROUNDED, 
                            title="[b red]HEADERS", 
                            border_style="cyan", 
                        )
                    )
                    scope = {k: v for k, v in request.scope.items() if k != "headers"}
                    console.print(
                        Panel.fit(
                            highlight_json(scope), 
                            box=ROUNDED, 
                            title="[b red]SCOPE", 
                            border_style="cyan", 
                        )
                    )
                message += "\n" + capture.get()
            return message
        try:
            response = await handler(request)
            logger.info(get_message(response))
        except Exception as e:
            response = await redirect_exception_response(app, request, e)
            logger.error(get_message(response))
            if debug:
                raise
        return response

    async def get_pickcode_to_id(id: int, user_id: int = 0) -> str:
        if user_id:
            cookies = d_cookies[user_id]
        else:
            user_id, cookies = next(iter(d_cookies.items()))
        if pickcode := ID_TO_PICKCODE.get((user_id, id), ""):
            return pickcode
        resp = await client.get(f"http://web.api.115.com/files/file?file_id={id}", headers={"Cookie": cookies})
        check_response(resp)
        json = loads(cast(bytes, await resp.read()))
        if not (json and json["state"]):
            raise FileNotFoundError(ENOENT, json)
        pickcode = ID_TO_PICKCODE[(user_id, id)] = json["data"][0]["pick_code"]
        return pickcode

    async def get_pickcode_for_sha1(sha1: str, user_id: int = 0) -> str:
        if user_id:
            cookies = d_cookies[user_id]
        else:
            user_id, cookies = next(iter(d_cookies.items()))
        if pickcode := SHA1_TO_PICKCODE.get((user_id, sha1), ""):
            return pickcode
        resp = await client.get(f"http://web.api.115.com/files/shasearch?sha1={sha1}", headers={"Cookie": cookies})
        check_response(resp)
        json = loads(cast(bytes, await resp.read()))
        if not (json and json["state"]):
            raise FileNotFoundError(ENOENT, json)
        pickcode = SHA1_TO_PICKCODE[(user_id, sha1)] = json["data"]["pick_code"]
        return pickcode

    async def get_pickcode_for_path(
        path: str, 
        user_id: int = 0, 
        refresh: bool = False, 
        get_base_url: Callable[[], str] = cycle(
            ("http://web.api.115.com", "http://pro.api.115.com/android", "http://proapi.115.com/android")
        ).__next__, 
    ) -> str:
        if user_id:
            cookies = d_cookies[user_id]
        else:
            user_id, cookies = next(iter(d_cookies.items()))
        path = "/" + path.strip("/")
        dir_, _, name = path.rpartition("/")
        if not name:
            raise FileNotFoundError(ENOENT, path)
        if dir_:
            if refresh or not (parent_id := DIR_TO_CID.get((user_id, dir_), 0)):
                resp = await client.get(
                    f"{get_base_url()}/files/getid?{urlencode({'path': dir_})}", 
                    headers={"Cookie": cookies}, 
                )
                check_response(resp)
                json = loads(cast(bytes, await resp.read()))
                parent_id = int(json.get("id") or 0)
                if not parent_id:
                    raise FileNotFoundError(ENOENT, json)
                DIR_TO_CID[(user_id, dir_)] = parent_id
        else:
            parent_id = 0
        if not refresh and (pickcode := CID_NAME_TO_PICKCODE.get((user_id, parent_id, name))):
            return pickcode
        pickcode = CID_NAME_TO_PICKCODE[(user_id, parent_id, name)] = await get_pickcode_for_name(
            name, user_id=user_id, parent_id=parent_id, refresh=None)
        return pickcode

    async def get_pickcode_for_name(
        name: str, 
        user_id: int = 0, 
        parent_id: int = 0, 
        refresh: None | bool = False, 
    ) -> str:
        if user_id:
            cookies = d_cookies[user_id]
        else:
            user_id, cookies = next(iter(d_cookies.items()))
        if refresh is False and (pickcode := NAME_TO_PICKCODE.get((user_id, name), "")):
            return pickcode
        api = "http://web.api.115.com/files/search"
        payload = {"search_value": name, "limit": 1, "type": 99, "cid": parent_id}
        suffix = name.rpartition(".")[-1]
        if suffix.isalnum():
            payload["suffix"] = suffix
        resp = await client.get(f"{api}?{urlencode(payload)}", headers={"Cookie": cookies})
        check_response(resp)
        json = loads(cast(bytes, await resp.read()))
        if get_first(json, "errno", "errNo") == 20021:
            payload.pop("suffix")
            resp = await client.get(f"{api}?{urlencode(payload)}", headers={"Cookie": cookies})
            check_response(resp)
            json = loads(cast(bytes, await resp.read()))
        if not json["state"] or not json["count"]:
            raise FileNotFoundError(ENOENT, json)
        info = json["data"][0]
        if info["n"] != name:
            raise FileNotFoundError(ENOENT, f"name not found: {name!r}")
        pickcode = info["pc"]
        if refresh is not None:
            NAME_TO_PICKCODE[(user_id, name)] = pickcode
        return pickcode

    async def share_name_to_id(
        name: str, 
        share_code: str, 
        receive_code: str = "", 
        parent_id: int = 0, 
        user_id: int = 0, 
        refresh: None | bool = False, 
    ) -> int:
        if user_id:
            cookies = d_cookies[user_id]
        else:
            user_id, cookies = next(iter(d_cookies.items()))
        if refresh is False and (id := SHARE_NAME_TO_ID.get((share_code, name), 0)):
            return id
        api = "http://web.api.115.com/share/search"
        payload = {
            "share_code": share_code, 
            "receive_code": receive_code, 
            "search_value": name, 
            "cid": parent_id, 
            "limit": 1, 
            "type": 99, 
        }
        suffix = name.rpartition(".")[-1]
        if suffix.isalnum():
            payload["suffix"] = suffix
        resp = await client.get(f"{api}?{urlencode(payload)}", headers={"Cookie": cookies})
        check_response(resp)
        json = loads(cast(bytes, await resp.read()))
        if get_first(json, "errno", "errNo") == 20021:
            payload.pop("suffix")
            resp = await client.get(f"{api}?{urlencode(payload)}", headers={"Cookie": cookies})
            check_response(resp)
            json = loads(cast(bytes, await resp.read()))
        if not json["state"] or not json["data"]["count"]:
            raise FileNotFoundError(ENOENT, json)
        info = json["data"]["list"][0]
        if info["n"] != name:
            raise FileNotFoundError(ENOENT, f"name not found: {name!r}")
        id = int(info["fid"])
        if refresh is not None:
            SHARE_NAME_TO_ID[(share_code, name)] = id
        return id

    async def get_downurl(
        pickcode: str, 
        user_agent: str = "", 
        app: str = "android", 
        user_id: int = 0, 
    ) -> Url:
        if user_id:
            cookies = d_cookies[user_id]
        else:
            user_id, cookies = next(iter(d_cookies.items()))
        if (cache_url and (r := DOWNLOAD_URL_CACHE.get((user_id, pickcode, user_agent)))
            or (r := DOWNLOAD_URL_CACHE1.get((user_id, pickcode)))
            or (r := DOWNLOAD_URL_CACHE2.get((user_id, pickcode, user_agent)))
        ):
            return r[1]
        if app == "chrome":
            resp = await client.post(
                "http://proapi.115.com/app/chrome/downurl", 
                content=FormContent([("data", encrypt(f'{{"pickcode":"{pickcode}"}}').decode("utf-8"))]), 
                headers={"User-Agent": user_agent, "Cookie": cookies}, 
            )
        else:
            resp = await client.post(
                f"http://proapi.115.com/{app or 'android'}/2.0/ufile/download", 
                content=FormContent([("data", encrypt(f'{{"pick_code":"{pickcode}"}}').decode("utf-8"))]), 
                headers={"User-Agent": user_agent, "Cookie": cookies}, 
            )
        check_response(resp)
        json = loads(cast(bytes, await resp.read()))
        if not json["state"]:
            raise OSError(EIO, json)
        data = json["data"] = loads(decrypt(json["data"]))
        if app == "chrome":
            info = next(iter(data.values()))
            url_info = info["url"]
            if not url_info:
                raise FileNotFoundError(ENOENT, dumps(json).decode("utf-8"))
            url = Url.of(url_info["url"], info)
        else:
            data["file_name"] = unquote(urlsplit(data["url"]).path.rpartition("/")[-1])
            url = Url.of(data["url"], data)
        expire_ts = int(next(v for k, v in parse_qsl(urlsplit(url).query) if k == "t")) - 60 * 5
        if "&c=0&f=&" in url:
            DOWNLOAD_URL_CACHE1[(user_id, pickcode)] = (expire_ts, url)
        elif "&c=0&f=1&" in url:
            DOWNLOAD_URL_CACHE2[(user_id, pickcode, user_agent)] = (expire_ts, url)
        elif cache_url:
            DOWNLOAD_URL_CACHE[(user_id, pickcode, user_agent)] = (expire_ts, url)
        return url

    async def get_share_downurl(
        share_code: str, 
        receive_code: str, 
        file_id: int, 
        app: str = "", 
        user_id: int = 0, 
    ) -> Url:
        if user_id:
            cookies = d_cookies[user_id]
        else:
            user_id, cookies = next(iter(d_cookies.items()))
        if r := DOWNLOAD_URL_CACHE1.get((share_code, file_id)):
            return r[1]
        payload = {"share_code": share_code, "receive_code": receive_code, "file_id": file_id}
        if app:
            resp = await client.get(
                f"http://proapi.115.com/{app}/2.0/share/downurl?{urlencode(payload)}", 
                headers={"Cookie": cookies}, 
            )
        else:
            resp = await client.post(
                f"http://proapi.115.com/app/share/downurl", 
                content=FormContent([("data", encrypt(dumps(payload)).decode("utf-8"))]), 
                headers={"Cookie": cookies}, 
            )
        check_response(resp)
        json = loads(cast(bytes, await resp.read()))
        if not json["state"]:
            if json.get("errno") == 4100008 and RECEIVE_CODE_MAP.pop(share_code, None):
                receive_code = await get_receive_code(share_code, user_id=user_id)
                return await get_share_downurl(share_code, receive_code, file_id, app=app, user_id=user_id)
            raise OSError(EIO, json)
        if app:
            data = json["data"]
        else:
            data = json["data"] = loads(decrypt(json["data"]))
        if not (data and (url_info := data["url"])):
            raise FileNotFoundError(ENOENT, json)
        data["file_id"] = data.pop("fid")
        data["file_name"] = data.pop("fn")
        data["file_size"] = int(data.pop("fs"))
        url = Url.of(url_info["url"], data)
        if "&c=0&f=&" in url:
            expire_ts = int(next(v for k, v in parse_qsl(urlsplit(url).query) if k == "t")) - 60 * 5
            DOWNLOAD_URL_CACHE1[(share_code, file_id)] = (expire_ts, url)
        return url

    async def get_receive_code(share_code: str, user_id: int = 0) -> str:
        if user_id:
            cookies = d_cookies[user_id]
        else:
            user_id, cookies = next(iter(d_cookies.items()))
        if receive_code := RECEIVE_CODE_MAP.get(share_code, ""):
            return receive_code
        resp = await client.get(
            f"http://web.api.115.com/share/shareinfo?share_code={share_code}", 
            headers={"Cookie": cookies}, 
        )
        check_response(resp)
        json = loads(cast(bytes, await resp.read()))
        if not json["state"]:
            raise FileNotFoundError(ENOENT, json)
        receive_code = RECEIVE_CODE_MAP[share_code] = json["data"]["receive_code"]
        return receive_code

    @app.router.route("/", methods=["GET", "HEAD", "POST"])
    @app.router.route("/<path:name2>", methods=["GET", "HEAD", "POST"])
    async def index(
        request: Request, 
        share_code: str = "", 
        receive_code: str = "", 
        pickcode: str = "", 
        id: int = 0, 
        sha1: str = "", 
        name: str = "", 
        name2: str = "", 
        user_id: int = 0, 
        is_path: bool = False, 
        refresh: bool = False, 
        app: str = "", 
        sign: str = "", 
        t: int = 0, 
    ):
        def check_sign(value, /):
            if not token:
                return None
            if sign != calc_sha1(bytes(f"302@115-{token}-{t}-{value}", "utf-8")).hexdigest():
                return json({"state": False, "message": "invalid sign"}, 403)
            elif t > 0 and t <= time():
                return json({"state": False, "message": "url was expired"}, 401)
        file_name = name or name2
        if share_code:
            if resp := check_sign(id if id else file_name):
                return resp
            if not receive_code:
                receive_code = await get_receive_code(share_code, user_id=user_id)
            elif len(receive_code) != 4:
                raise ValueError(f"bad receive_code: {receive_code!r}")
            if not id:
                if file_name:
                    id = await share_name_to_id(file_name, share_code, receive_code, user_id=user_id, refresh=refresh)
            if not id:
                raise FileNotFoundError(ENOENT, f"please specify id or name: share_code={share_code!r}")
            url = await get_share_downurl(share_code, receive_code, id, app=app, user_id=user_id)
        else:
            if pickcode:
                if resp := check_sign(pickcode):
                    return resp
                if not (len(pickcode) == 17 and pickcode.isalnum()):
                    raise ValueError(f"bad pickcode: {pickcode!r}")
            elif id:
                if resp := check_sign(id):
                    return resp
                pickcode = await get_pickcode_to_id(id, user_id=user_id)
            elif sha1:
                if resp := check_sign(sha1):
                    return resp
                if len(sha1) != 40 or sha1.strip(hexdigits):
                    raise ValueError(f"bad sha1: {sha1!r}")
                pickcode = await get_pickcode_for_sha1(sha1.upper(), user_id=user_id)
            else:
                remains = ""
                if match := CRE_name_search(unquote(request.url.query or b"")):
                    file_name = match[0]
                elif not name and (idx := file_name.find("/")) > 0:
                    file_name, remains = file_name[:idx], file_name[idx:]
                if file_name:
                    if resp := check_sign(file_name + remains):
                        return resp
                    if len(file_name) == 17 and file_name.isalnum():
                        pickcode = file_name.lower()
                    elif not file_name.strip(digits):
                        pickcode = await get_pickcode_to_id(int(file_name), user_id=user_id)
                    elif len(file_name) == 40 and not file_name.strip(hexdigits):
                        pickcode = await get_pickcode_for_sha1(file_name.upper(), user_id=user_id)
                    elif is_path:
                        pickcode = await get_pickcode_for_path(file_name + remains, user_id=user_id, refresh=refresh)
                    else:
                        pickcode = await get_pickcode_for_name(file_name + remains, user_id=user_id, refresh=refresh)
            if not pickcode:
                raise FileNotFoundError(ENOENT, f"not found: {str(request.url)!r}")
            user_agent = (request.get_first_header(b"User-agent") or b"").decode("latin-1")
            url = await get_downurl(pickcode.lower(), user_agent, app=app, user_id=user_id)

        return Response(302, [
            (b"Location", bytes(url, "utf-8")), 
            (b"Content-Disposition", b'attachment; filename="%s"' % bytes(quote(url["file_name"], safe=""), "latin-1")), 
        ], Content(b"application/json; charset=utf-8", dumps(url.__dict__)))

    if PASSWORD:
        @app.router.route("/%3Ccookies", methods=["GET"])
        async def get_cookies(request: Request, password: str = ""):
            """获取一组 cookies

            :param password: 口令
            """
            if PASSWORD != password:
                return json({"state": False, "message": "password does not match"}, 401)
            return json({"state": True, "cookies": "\n".join(d_cookies.values())})

        @app.router.route("/%3Ccookies", methods=["POST"])
        async def set_cookies(request: Request, password: str = "", body: None | FromJSON[dict] = None):
            """更新一组 cookies

            :param password: 口令
            :param body: 请求体为 json 格式 <code>{"cookies"&colon; "新的 cookies"}</code>
            """
            if PASSWORD != password:
                return json({"state": False, "message": "password does not match"}, 401)
            if body and (cookies := body.value.get("cookies")):
                try:
                    d_cookies.update((ick, ck) for ck in cookies.split("\n") if (ick := get_user_id_from_cookies(ck)))
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

# TODO: 那个单 js 的文件可以发布到 nodejs 上
# TODO: 再写一个 rust 版本的，发布到 cargo 上
# TODO: 优先使用 id 而不是 pickcode
# TODO: 功能追平 p115open302
# TODO: 允许把缓存保存到 sqlite 数据库中，以便下次继续使用
# TODO: 搜索路径时，再提供一个参数，以支持精确匹配，这时就不会使用查询接口了，而是通过罗列目录列表来进行匹配
# TODO: share 也支持用 path 查询，但是速度会慢一些（要缓存各个节点，这个可能会导致内存占用较高，怎么优化）
