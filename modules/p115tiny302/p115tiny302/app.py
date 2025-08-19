#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_application"]

import logging

from collections.abc import Buffer, Callable, Mapping
from errno import ENOENT
from functools import partial
from hashlib import sha1 as calc_sha1
from http import HTTPStatus
from re import compile as re_compile
from string import digits, hexdigits
from time import time as get_timestamp
from typing import Final
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit

from blacksheep import json, redirect, text, Application, Request, Response, Router
from blacksheep.contents import Content
from blacksheep.server.remotes.forwarding import ForwardedHeadersMiddleware
from cachedict import LRUDict, TLRUDict, TTLDict
from orjson import dumps, OPT_INDENT_2, OPT_SORT_KEYS
from posixpatht import normpath, joins
from p115client import (
    check_response, normalize_attr, P115Client, P115ID, P115URL, P115OSError, 
)
from p115client.tool import get_id_to_path, share_get_id_to_path
from p115pickcode import is_valid_pickcode
from rich.box import ROUNDED
from rich.console import Console
from rich.highlighter import JSONHighlighter
from rich.panel import Panel
from rich.text import Text
from uvicorn.config import LOGGING_CONFIG


CRE_name_search: Final = re_compile("[^&=]+(?=&|$)").match
CRE_def_sub: Final = re_compile(r"(?<=definition=)\d+").sub
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


def make_application(
    client: P115Client, 
    debug: bool = False, 
    token: str = "", 
    cache_url: bool = False, 
    cache_size: int = 65536, 
) -> Application:
    """创建 blacksheep 后台服务对象

    :param client: 115 客户端对象
    :param debug: 是否开启调试信息
    :param token: 如果不为空，则支持链接签名
    :param cache_url: 是否缓存下载链接
    :param cache_size: 缓存大小（所有有关的缓存各自的大小，而不是总的大小）

    :return: blacksheep 服务对象
    """
    #: sha1 或 (sha1, size) 对应 id
    SHA1_TO_ID: LRUDict[str | tuple[str, int], int] = LRUDict(maxsize=cache_size)
    #: name 或 (name, size) 对应 id
    NAME_TO_ID: LRUDict[str | tuple[str, int], int] = LRUDict(maxsize=cache_size)
    #: path 对应 id
    PATH_TO_ID: TTLDict[str, int] = TTLDict(maxsize=cache_size, ttl=3600)
    #: (share_code, name) 或 (share_code, name, size) 对应 id
    SHARE_NAME_TO_ID: LRUDict[tuple[str, str] | tuple[str, str, int], int] = LRUDict(maxsize=cache_size)
    #: (share_code, path) 对应 id
    SHARE_PATH_TO_ID: TTLDict[tuple[str, str], int] = TTLDict(maxsize=cache_size, ttl=3600)
    if cache_url:
        #: (id, user_agent) 对应下载 url
        DOWNLOAD_URL_CACHE: TLRUDict[tuple[int, str], tuple[float, P115URL]] = TLRUDict(maxsize=cache_size)
    #: id 或 (share_code, id) 对应 id
    DOWNLOAD_URL_CACHE1: TLRUDict[int | tuple[str, int], tuple[float, P115URL]] = TLRUDict(maxsize=cache_size)
    #: (id, user_agent) 对应下载 url
    DOWNLOAD_URL_CACHE2: TLRUDict[tuple[int, str], tuple[float, P115URL]] = TLRUDict(maxsize=1024)
    #: 分享码 对应 接收码
    CODE_SHARE_TO_RECEIVE: dict[str, str] = {}

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
        if isinstance(exc, ValueError):
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

    @app.middlewares.append
    async def access_log(request: Request, handler) -> Response:
        start_t = get_timestamp()
        def get_message(response: Response, /) -> str:
            remote_attr = request.scope["client"]
            status = response.status
            if status < 300:
                status_color = 32
            elif status < 400:
                status_color = 33
            else:
                status_color = 31
            message = f'\x1b[5;35m{remote_attr[0]}:{remote_attr[1]}\x1b[0m - "\x1b[1;36m{request.method}\x1b[0m \x1b[1;4;34m{request.url}\x1b[0m \x1b[1mHTTP/{request.scope["http_version"]}\x1b[0m" - \x1b[{status_color}m{status} {HTTPStatus(status).phrase}\x1b[0m - \x1b[32m{(get_timestamp() - start_t) * 1000:.3f}\x1b[0m \x1b[3mms\x1b[0m'
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

    async def sha1_to_id(
        sha1: str, 
        size: int = -1, 
        refresh: bool = False, 
        app: str = "", 
    ) -> int:
        key = sha1 if size < 0 else (sha1, size)
        if not refresh:
            if id := SHA1_TO_ID.get(key):
                return id
        if size < 0 and not app:
            resp = await client.fs_shasearch(sha1, async_=True)
            check_response(resp)
            attr = normalize_attr(resp["data"])
            id = SHA1_TO_ID[key] = attr["id"]
            return P115ID(id, attr)
        if app in ("", "web", "desktop", "harmony"):
            fs_search: Callable = client.fs_search
        else:
            fs_search = partial(client.fs_search_app, app=app)
        resp = await fs_search(
            {"search_value": sha1, "fc": 2, "limit": 16, "show_dir": 0, "type": 99}, 
            async_=True, 
        )
        check_response(resp)
        if data := resp["data"]:
            for attr in map(normalize_attr, data):
                if attr["sha1"] == sha1:
                    if size >= 0 and attr["size"] != size:
                        continue
                    id = attr["id"]
                    SHA1_TO_ID[key] = id
                    return P115ID(id, attr)
        raise FileNotFoundError(ENOENT, {"sha1": sha1, "size": size, "error": "not found"})

    async def name_to_id(
        name: str, 
        size: int = -1, 
        refresh: bool = False, 
        app: str = "", 
    ) -> int:
        key = name if size < 0 else (name, size)
        if not refresh:
            if id := NAME_TO_ID.get(key):
                return id
        if app in ("", "web", "desktop", "harmony"):
            fs_search: Callable = client.fs_search
        else:
            fs_search = partial(client.fs_search_app, app=app)
        payload = {"search_value": name, "fc": 2, "limit": 16, "show_dir": 0, "type": 99}
        suffix = name.rpartition(".")[-1]
        if suffix.isalnum():
            payload["suffix"] = suffix
        resp = await fs_search(payload, async_=True)
        if get_first(resp, "errno", "errNo") == 20021:
            payload.pop("suffix")
            resp = await fs_search(payload, async_=True)
        check_response(resp)
        if data := resp["data"]:
            for attr in map(normalize_attr, data):
                if attr["name"] == name:
                    if size >= 0 and attr["size"] != size:
                        continue
                    id = attr["id"]
                    NAME_TO_ID[key] = id
                    return P115ID(id, attr)
        raise FileNotFoundError(ENOENT, {"name": name, "size": size, "error": "not found"})

    async def path_to_id(
        path: str, 
        refresh: bool = False, 
        app: str = "", 
    ) -> int:
        if ">" in path:
            path2 = path[2:]
            if path.startswith("> ") and path2.count(">") == path2.count(" > "):
                patht = path2.split(" > ")
            else:
                patht = path.split(">")
            path = joins(patht)
        else:
            path = normpath(path)
        if not path.startswith("/"):
            path = "/" + path
        if not refresh:
            if id := PATH_TO_ID.get(path):
                return id
        id = await get_id_to_path(
            client, 
            path, 
            ensure_file=True, 
            id_to_dirnode=..., 
            app=app, 
            async_=True, 
        )
        PATH_TO_ID[path] = int(id)
        return id

    async def share_name_to_id(
        name: str, 
        share_code: str, 
        receive_code: str = "", 
        size: int = -1, 
        refresh: bool = False, 
    ) -> int:
        key = (share_code, name) if size < 0 else (share_code, name, size)
        if not refresh:
            if id := SHARE_NAME_TO_ID.get(key):
                return id
        payload = {
            "share_code": share_code, 
            "receive_code": receive_code, 
            "search_value": name, 
            "limit": 16, 
            "type": 99, 
        }
        suffix = name.rpartition(".")[-1]
        if suffix.isalnum():
            payload["suffix"] = suffix
        resp = await client.share_search(payload, async_=True)
        if get_first(resp, "errno", "errNo") == 20021:
            payload.pop("suffix")
            resp = await client.share_search(payload, async_=True)
        check_response(resp)
        if data := resp["data"]["list"]:
            for attr in map(normalize_attr, data):
                if attr["name"] == name:
                    if size >= 0 and attr["size"] != size:
                        continue
                    id = attr["id"]
                    SHARE_NAME_TO_ID[key] = id
                    return P115ID(id, attr)
        raise FileNotFoundError(ENOENT, {
            "share_code": share_code, 
            "receive_code": receive_code, 
            "name": name, 
            "size": size, 
            "error": "not found", 
        })

    async def share_path_to_id(
        path: str, 
        share_code: str, 
        receive_code: str = "", 
        refresh: bool = False, 
    ) -> int:
        if ">" in path:
            path2 = path[2:]
            if path.startswith("> ") and path2.count(">") == path2.count(" > "):
                patht = path2.split(" > ")
            else:
                patht = path.split(">")
            path = joins(patht)
        else:
            path = normpath(path)
        if not path.startswith("/"):
            path = "/" + path
        key = (share_code, path)
        if not refresh:
            if id := SHARE_PATH_TO_ID.get(key):
                return id
        id = await share_get_id_to_path(
            client, 
            share_code, 
            receive_code, 
            path, 
            ensure_file=True, 
            app=app, 
            async_=True, 
        )
        SHARE_PATH_TO_ID[key] = int(id)
        return id

    async def get_downurl(
        id: int, 
        user_agent: str = "", 
        app: str = "", 
    ) -> P115URL:
        if (cache_url and (r := DOWNLOAD_URL_CACHE.get((id, user_agent)))
            or (r := DOWNLOAD_URL_CACHE1.get(id))
            or (r := DOWNLOAD_URL_CACHE2.get((id, user_agent)))
        ):
            return r[1]
        pickcode = client.to_pickcode(id)
        url = await client.download_url(
            pickcode, 
            headers={"user-agent": user_agent}, 
            app=app or "android", 
            async_=True, 
        )
        expire_ts = int(next(v for k, v in parse_qsl(urlsplit(url).query) if k == "t")) - 60 * 5
        if "&c=0&f=&" in url:
            DOWNLOAD_URL_CACHE1[id] = (expire_ts, url)
        elif "&c=0&f=1&" in url:
            DOWNLOAD_URL_CACHE2[(id, user_agent)] = (expire_ts, url)
        elif cache_url:
            DOWNLOAD_URL_CACHE[(id, user_agent)] = (expire_ts, url)
        return url

    async def get_share_downurl(
        id: int, 
        share_code: str, 
        receive_code: str = "", 
        app: str = "", 
    ) -> P115URL:
        if r := DOWNLOAD_URL_CACHE1.get((share_code, id)):
            return r[1]
        payload = {"share_code": share_code, "receive_code": receive_code, "file_id": id}
        try:
            url = await client.share_download_url(payload, app=app, async_=True)
        except P115OSError as e:
            if not (e.args[1].get("errno") == 4100008 and CODE_SHARE_TO_RECEIVE.pop(share_code, None)):
                raise
            receive_code = await get_receive_code(share_code)
            return await get_share_downurl(id, share_code, receive_code, app=app)
        if "&c=0&f=&" in url:
            expire_ts = int(next(v for k, v in parse_qsl(urlsplit(url).query) if k == "t")) - 60 * 5
            DOWNLOAD_URL_CACHE1[(share_code, id)] = (expire_ts, url)
        return url

    async def get_receive_code(share_code: str) -> str:
        if receive_code := CODE_SHARE_TO_RECEIVE.get(share_code, ""):
            return receive_code
        resp = await client.share_info(share_code, async_=True)
        check_response(resp)
        receive_code = CODE_SHARE_TO_RECEIVE[share_code] = resp["data"]["receive_code"]
        return receive_code

    @app.router.route("/", methods=["GET", "HEAD", "POST"])
    @app.router.route("/<path:name2>", methods=["GET", "HEAD", "POST"])
    async def index(
        request: Request, 
        id: int = 0, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
        name: str = "", 
        name2: str = "", 
        value: str = "", 
        share_code: str = "", 
        receive_code: str = "", 
        size: int = -1, 
        method: str = "", 
        time: int = -1, 
        watch_end: int = -1, 
        audio_track: int = -1, 
        definition: int = -1, 
        refresh: bool = False, 
        app: str = "", 
        sign: str = "", 
        t: int = 0, 
    ):
        def check_sign(val, /):
            if value:
                val = value
            if not token:
                return None
            if sign != calc_sha1(bytes(f"302@115-{token}-{t}-{val}", "utf-8")).hexdigest():
                return json({"state": False, "message": "invalid sign"}, 403)
            elif t > 0 and t <= get_timestamp():
                return json({"state": False, "message": "url was expired"}, 401)
        url: str
        if share_code:
            if not receive_code:
                receive_code = await get_receive_code(share_code)
            if id:
                if resp := check_sign(id):
                    return resp
            elif name:
                if resp := check_sign(name):
                    return resp
                id = await share_name_to_id(
                    name, 
                    share_code, 
                    receive_code, 
                    size=size, 
                    refresh=refresh, 
                )
            elif path:
                if resp := check_sign(path):
                    return resp
                id = await share_path_to_id(
                    path, 
                    share_code, 
                    receive_code, 
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
                    fullname = name + remains
                    if resp := check_sign(fullname):
                        return resp
                    if not (name.startswith("0") or name.strip(digits)):
                        id = int(name)
                else:
                    fullname = name2
                    if fullname and (resp := check_sign(fullname)):
                        return resp
                if not id and fullname:
                    if ">" in fullname or "/" in fullname:
                        id = await share_path_to_id(
                            fullname, 
                            share_code, 
                            receive_code, 
                            refresh=refresh, 
                        )
                    else:
                        id = await share_name_to_id(
                            fullname, 
                            share_code, 
                            receive_code, 
                            size=size, 
                            refresh=refresh, 
                        )
            if not id:
                raise FileNotFoundError(ENOENT, f"please specify id or name: share_code={share_code!r}")
            url = await get_share_downurl(id, share_code, receive_code, app=app)
        else:
            if id:
                if resp := check_sign(id):
                    return resp
            elif pickcode:
                if resp := check_sign(pickcode):
                    return resp
                if not is_valid_pickcode(pickcode):
                    raise ValueError(f"bad pickcode: {pickcode!r}")
                id = client.to_id(pickcode)
            elif sha1:
                if resp := check_sign(sha1):
                    return resp
                if len(sha1) != 40 or sha1.strip(hexdigits):
                    raise ValueError(f"bad sha1: {sha1!r}")
                id = await sha1_to_id(sha1.upper(), size, refresh=refresh, app=app)
            elif name:
                if resp := check_sign(name):
                    return resp
                id = await name_to_id(name, size, refresh=refresh, app=app)
            elif path:
                if resp := check_sign(path):
                    return resp
                id = await path_to_id(path, refresh=refresh, app=app)
            else:
                remains = ""
                if match := CRE_name_search(unquote(request.url.query or b"")):
                    name = match[0]
                elif (idx := name2.find("/")) > 0:
                    name, remains = name2[:idx], name2[idx:]
                else:
                    name = name2
                if name:
                    fullname = name + remains
                    if resp := check_sign(fullname):
                        return resp
                    if not (name.startswith("0") or name.strip(digits)):
                        id = int(name)
                    elif is_valid_pickcode(name):
                        id = client.to_id(name)
                    elif len(name) == 40 and not name.strip(hexdigits):
                        id = await sha1_to_id(name.upper(), size, refresh=refresh, app=app)
                else:
                    fullname = name2
                    if fullname and (resp := check_sign(fullname)):
                        return resp
                if not id and fullname:
                    if ">" in fullname or "/" in fullname:
                        id = await path_to_id(fullname, refresh=refresh, app=app)
                    else:
                        id = await name_to_id(fullname, size, refresh=refresh, app=app)
            if not id:
                raise FileNotFoundError(ENOENT, f"not found: {str(request.url)!r}")
            pickcode = client.to_pickcode(id)
            match method:
                # 视频字幕列表
                case "subs" | "subtitle" | "subtitles":
                    resp = await client.fs_video_subtitle(pickcode, async_=True)
                    check_response(resp)
                    return json(resp["data"])
                # 获取视频在线播放地址
                case "tran" | "transcode" | "m3u8":
                    resp = await client.fs_video_app(pickcode, async_=True)
                    check_response(resp)
                    if method == "m3u8":
                        try:
                            url = resp["data"]["video_url"][0]["url"]
                        except KeyError:
                            return json(resp, 500)
                        if audio_track >= 0:
                            url += f"&audio_track={audio_track}"
                        if definition >= 0:
                            url = CRE_def_sub(str(definition), url)
                        return redirect(url)
                    return json(resp["data"])
                # 获取或修改视频播放进度
                case "hist" | "history":
                    payload: dict = {}
                    if time >= 0:
                        payload["time"] = time
                    if watch_end >= 0:
                        payload["watch_end"] = watch_end
                    if payload:
                        payload["pick_code"] = pickcode
                        resp = await client.fs_video_history_set(payload, async_=True)
                        return json(resp)
                    else:
                        resp = await client.fs_video_history(pickcode, async_=True)
                        check_response(resp)
                        return json(resp["data"] or {})
                # 获取文件信息
                case "info":
                    if isinstance(id, P115ID):
                        return json(id.__dict__)
                    resp = await client.fs_file(id, async_=True)
                    check_response(resp)
                    if not resp["data"]:
                        raise FileNotFoundError(ENOENT, {"id": id, "error": "not found"})
                    return json(normalize_attr(resp["data"][0]))
            user_agent = (request.get_first_header(b"user-agent") or b"").decode("latin-1")
            url = await get_downurl(id, user_agent, app=app)
        return Response(302, [
            (b"location", bytes(url, "utf-8")), 
            (b"content-Disposition", b'attachment; filename="%s"' % bytes(quote(url["name"], safe=""), "latin-1")), 
        ], Content(b"application/json; charset=utf-8", dumps(url.__dict__)))

    return app


if __name__ == "__main__":
    from pathlib import Path
    from uvicorn import run

    client = P115Client(Path("115-cookies.txt"), ensure_cookies=True, check_for_relogin=True)
    run(
        make_application(client, debug=True), 
        host="0.0.0.0", 
        port=8000, 
        proxy_headers=True, 
        server_header=False, 
        forwarded_allow_ips="*", 
        timeout_graceful_shutdown=1, 
        access_log=False, 
    )

# TODO: 功能需要和 p115nano302 和 p115open302 追平，并支持读写 cookies，支持多用户的 cookies 等
