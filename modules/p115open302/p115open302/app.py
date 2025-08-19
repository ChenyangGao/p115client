#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_application"]

import logging

from collections.abc import Buffer, Mapping
from errno import ENOENT, ENOTDIR
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
from p115client import check_response, P115OpenClient, P115ID, P115URL
from p115pickcode import is_valid_pickcode
from posixpatht import splits
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
    client: P115OpenClient, 
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
    if cache_url:
        #: (id, user_agent) 对应下载 url
        DOWNLOAD_URL_CACHE: TLRUDict[tuple[int, str], tuple[float, P115URL]] = TLRUDict(maxsize=cache_size)
    #: id 对应下载 url（此 url 不限定 user_agent）
    DOWNLOAD_URL_CACHE1: TLRUDict[int, tuple[float, P115URL]] = TLRUDict(maxsize=cache_size)
    #: (id, user_agent) 对应下载 url
    DOWNLOAD_URL_CACHE2: TLRUDict[tuple[int, str], tuple[float, P115URL]] = TLRUDict(maxsize=1024)

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
    ) -> int:
        key = sha1 if size < 0 else (sha1, size)
        if not refresh:
            if id := SHA1_TO_ID.get(key):
                return id
        resp = await client.fs_search_open(
            {"search_value": sha1, "fc": 2, "limit": 16}, 
            async_=True, 
        )
        check_response(resp)
        if data := resp["data"]:
            for info in data:
                if info["sha1"] == sha1:
                    if size >= 0 and int(info["file_size"]) != size:
                        continue
                    id = int(info["file_id"])
                    SHA1_TO_ID[key] = id
                    return P115ID(id, info)
        raise FileNotFoundError(ENOENT, {"sha1": sha1, "size": size, "error": "not found"})

    async def name_to_id(
        name: str, 
        size: int = -1, 
        refresh: bool = False, 
    ) -> int:
        key = name if size < 0 else (name, size)
        if not refresh:
            if id := NAME_TO_ID.get(key):
                return id
        payload = {"search_value": name, "fc": 2, "limit": 16}
        suffix = name.rpartition(".")[-1]
        if suffix.isalnum():
            payload["suffix"] = suffix
        resp = await client.fs_search_open(payload, async_=True)
        if get_first(resp, "errno", "errNo") == 20021:
            payload.pop("suffix")
            resp = await client.fs_search_open(payload, async_=True)
        check_response(resp)
        if data := resp["data"]:
            for info in data:
                if info["file_name"] == name:
                    if size >= 0 and int(info["file_size"]) != size:
                        continue
                    id = int(info["file_id"])
                    NAME_TO_ID[key] = id
                    return P115ID(id, info)
        raise FileNotFoundError(ENOENT, {"name": name, "size": size, "error": "not found"})

    async def path_to_id(
        path: str, 
        refresh: bool = False, 
    ) -> int:
        if ">" in path:
            path = path.strip(">")
            if ">>" in path:
                path = ">".join(p for p in path.split(">") if p)
            path = ">" + path
        else:
            patht, _ = splits(path)
            path = ">".join(patht)
            if patht[0]:
                path = ">" + path
        if not refresh:
            if id := PATH_TO_ID.get(path):
                return id
        resp = await client.fs_info_open(path, timeout=5, async_=True)
        check_response(resp)
        data = resp["data"]
        if not data:
            raise FileNotFoundError(ENOENT, {"path": path, "error": "not found"})
        elif not data["sha1"]:
            raise NotADirectoryError(ENOTDIR, {"path": path, "error": "not a directory"})
        id = PATH_TO_ID[path] = int(data["file_id"])
        return P115ID(id, data)

    async def get_downurl(
        id: int, 
        user_agent: str = "", 
    ) -> P115URL:
        if (cache_url and (r := DOWNLOAD_URL_CACHE.get((id, user_agent)))
            or (r := DOWNLOAD_URL_CACHE1.get(id))
            or (r := DOWNLOAD_URL_CACHE2.get((id, user_agent)))
        ):
            return r[1]
        pickcode = client.to_pickcode(id)
        url = await client.download_url_open(
            pickcode, 
            headers={"user-agent": user_agent}, 
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
        size: int = -1, 
        method: str = "", 
        time: int = -1, 
        watch_end: int = -1, 
        audio_track: int = -1, 
        definition: int = -1, 
        refresh: bool = False, 
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
            id = await sha1_to_id(sha1.upper(), size, refresh=refresh)
        elif name:
            if resp := check_sign(name):
                return resp
            id = await name_to_id(name, size, refresh=refresh)
        elif path:
            if resp := check_sign(path):
                return resp
            id = await path_to_id(path, refresh=refresh)
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
                    id = await sha1_to_id(name.upper(), size, refresh=refresh)
            else:
                fullname = name2
                if fullname and (resp := check_sign(fullname)):
                    return resp
            if not id and fullname:
                if ">" in fullname or "/" in fullname:
                    id = await path_to_id(fullname, refresh=refresh)
                else:
                    id = await name_to_id(fullname, size, refresh=refresh)
        if not id:
            raise FileNotFoundError(ENOENT, f"not found: {str(request.url)!r}")
        pickcode = client.to_pickcode(id)
        match method:
            # 视频字幕列表
            case "subs" | "subtitle" | "subtitles":
                resp = await client.fs_video_subtitle_open(pickcode, async_=True)
                check_response(resp)
                return json(resp["data"])
            # 获取视频在线播放地址
            case "tran" | "transcode" | "m3u8":
                resp = await client.fs_video_open(pickcode, async_=True)
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
            # 提交视频转码
            case "push":
                resp = await client.fs_video_push_open(pickcode, async_=True)
                return json(resp)
            # 获取或修改视频播放进度
            case "hist" | "history":
                payload: dict = {}
                if time >= 0:
                    payload["time"] = time
                if watch_end >= 0:
                    payload["watch_end"] = watch_end
                if payload:
                    payload["pick_code"] = pickcode
                    resp = await client.fs_video_history_set_open(payload, async_=True)
                    return json(resp)
                else:
                    resp = await client.fs_video_history_open(pickcode, async_=True)
                    check_response(resp)
                    return json(resp["data"] or {})
            # 获取文件信息
            case "info":
                if isinstance(id, P115ID):
                    data = id.__dict__
                else:
                    data = {}
                if "paths" not in data:
                    resp = await client.fs_info_open(id, async_=True)
                    check_response(resp)
                    if not resp["data"]:
                        raise FileNotFoundError(ENOENT, {"id": id, "error": "not found"})
                    data.update(resp["data"])
                return json(data)
        user_agent = (request.get_first_header(b"user-agent") or b"").decode("latin-1")
        url = await get_downurl(id, user_agent)
        return Response(302, [
            (b"location", bytes(url, "utf-8")), 
            (b"content-disposition", b'attachment; filename="%s"' % bytes(quote(url["name"], safe=""), "latin-1")), 
        ], Content(b"application/json; charset=utf-8", dumps(url.__dict__)))

    return app


if __name__ == "__main__":
    from pathlib import Path
    from p115client import P115Client
    from uvicorn import run

    client = P115Client(Path("115-cookies.txt"), ensure_cookies=True, check_for_relogin=True)
    client.login_another_open(replace=True)
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

# TODO: 需要更新，以追平 p115tiny302，但有些功能可以没有，这个模块必须足够简单

