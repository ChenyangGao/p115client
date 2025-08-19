#!/usr/bin/env python3
# encoding: utf-8

from __future__ import annotations

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_application"]

import logging

from asyncio import (
    create_task, get_running_loop, run_coroutine_threadsafe, sleep as async_sleep, 
    AbstractEventLoop, Lock, 
)
from collections import deque
from collections.abc import AsyncIterator, Buffer, Callable, Mapping, Sequence
from contextlib import closing, suppress
from errno import ENOENT, EBUSY
from http import HTTPStatus
from io import BytesIO
from itertools import cycle
from math import isinf, isnan
from pathlib import Path
from posixpath import split as splitpath, splitext
from queue import SimpleQueue
from os import environ, remove
from re import compile as re_compile
from sqlite3 import connect, PARSE_COLNAMES, PARSE_DECLTYPES, Connection
from string import hexdigits
from time import time
from _thread import start_new_thread
from typing import cast, Any
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit
from weakref import WeakValueDictionary

from a2wsgi import WSGIMiddleware
from asynctools import to_list
from blacksheep import redirect, text, Application, Router
from blacksheep.contents import Content, StreamedContent
from blacksheep.messages import Request, Response
from blacksheep.server.compression import use_gzip_compression
from blacksheep.server.rendering.jinja2 import JinjaRenderer
from blacksheep.settings.html import html_settings
from blacksheep.settings.json import json_settings
from blacksheep.server.openapi.common import ParameterInfo
from blacksheep.server.openapi.ui import ReDocUIProvider
from blacksheep.server.openapi.v3 import OpenAPIHandler
from blacksheep.server.remotes.forwarding import ForwardedHeadersMiddleware
from blacksheep.server.responses import view_async
from cachedict import LRUDict, TTLDict, TLRUDict
from encode_uri import encode_uri, encode_uri_component_loose
from dictattr import AttrDict
# NOTE: 其它可用模块
# - https://pypi.org/project/user-agents/
# - https://github.com/faisalman/ua-parser-js
from httpagentparser import detect as detect_ua # type: ignore
from openapidocs.v3 import Info # type: ignore
from orjson import dumps, loads, OPT_INDENT_2, OPT_SORT_KEYS
from p115client import check_response, CLASS_TO_TYPE, SUFFIX_TO_TYPE, P115Client, P115URL
from p115client.exception import AuthenticationError, BusyOSError
from p115client.type import P115ID
from p115client.tool import (
    get_id_to_path, get_id_to_sha1, share_iterdir, 
    share_get_id_to_path, get_ancestors, 
)
from p115client.tool.util import get_status_code, reduce_image_url_layers
from p115pickcode import id_to_pickcode, pickcode_to_id
from path_predicate import MappingPath
from posixpatht import escape, normpath
from property import locked_cacheproperty
# NOTE: 其它可用模块
# - https://pypi.org/project/ass/
# - https://pypi.org/project/srt/
from pysubs2 import SSAFile # type: ignore
from rich.box import ROUNDED
from rich.console import Console
from rich.highlighter import JSONHighlighter
from rich.panel import Panel
from rich.text import Text
from sqlitedict import SqliteTableDict
from sqlitetools import upsert_items
from texttools import format_size, format_timestamp
from uvicorn.config import LOGGING_CONFIG
from wsgidav.wsgidav_app import WsgiDAVApp # type: ignore
from wsgidav.dav_error import DAVError # type: ignore
from wsgidav.dav_provider import DAVCollection, DAVNonCollection, DAVProvider # type: ignore

from . import db


CRE_URL_T_search = re_compile(r"(?<=(?:\?|&)t=)\d+").search
LOGGING_CONFIG["formatters"]["default"]["fmt"] = "[\x1b[1m%(asctime)s\x1b[0m] %(levelprefix)s %(message)s"
LOGGING_CONFIG["formatters"]["access"]["fmt"] = '[\x1b[1m%(asctime)s\x1b[0m] %(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s'

environ["APP_JINJA_PACKAGE_NAME"] = "p115dav"
html_settings.use(JinjaRenderer(enable_async=True))
json_settings.use(loads=loads)
jinja_env = getattr(html_settings.renderer, "env")
jinja2_filters = jinja_env.filters
jinja2_filters["format_size"] = format_size
jinja2_filters["encode_uri"] = encode_uri
jinja2_filters["encode_uri_component"] = encode_uri_component_loose
jinja2_filters["json_dumps"] = lambda data: dumps(data).decode("utf-8").replace("'", "&apos;")
jinja2_filters["format_timestamp"] = format_timestamp
jinja2_filters["escape_name"] = lambda name, default="/": escape(name) or default


class TooManyRequests(OSError):
    pass


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


def get_origin(request: Request, /) -> str:
    return f"{request.scheme}://{request.host}"


def get_first(m: Mapping, /, *keys, default=None):
    for k in keys:
        if k in m:
            return m[k]
    return default


def contains_any(m: Mapping, /, *keys):
    return any(k in m for k in keys)


def default(obj, /):
    if isinstance(obj, Buffer):
        return str(obj, "utf-8")
    raise TypeError


def highlight_json(
    val, 
    /, 
    default=default, 
    highlighter=JSONHighlighter(), 
) -> Text:
    if isinstance(val, Buffer):
        val = str(val, "utf-8")
    if not isinstance(val, str):
        val = dumps(val, default=default, option=OPT_INDENT_2 | OPT_SORT_KEYS).decode("utf-8")
    return highlighter(val)


def make_application(
    dbfile: str | Path = "", 
    cookies_path: str | Path = "", 
    app_id: None | int = None, 
    ttl: int | float = 0, 
    strm_origin: str = "", 
    predicate = None, 
    strm_predicate = None, 
    cache_url: bool = False, 
    cache_size: int = 65536, 
    debug: bool = False, 
    wsgidav_config: dict = {}, 
    only_webdav: bool = False, 
    default_web_page: bool = True, 
    load_libass: bool = False, 
    check_for_relogin: bool = False, 
) -> Application:
    """创建一个 blacksheep 应用

    :param dbfile: 数据库路径，如果为空则自动确定
    :param cookies_path: 115 的 cookies 的保存路径
    :param app_id: 开放接口的应用 id
    :param ttl: 拉取到的文件信息数据的缓存有效时间，如果小于 0，则永久有效
    :param strm_origin: strm 下载链接的 base_url，意味着可以用另一个服务器来承担 302 服务
    :param predicate: 筛选断言，如果文件信息能符合此断言，则被展示，否则会被忽略掉
    :param strm_predicate: strm 断言，如果文件信息能符合此断言，则会被显示为 strm（打开后为下载链接，会 302）
    :param cache_url: 是否缓存下载链接
    :param cache_size: 缓存数量（内部的每个字典都限制为此规模，而不是所有的字典总共限制为此规模），<= 0 时无限
    :param debug: 是否启用调试
    :param wsgidav_config: WebDAV 配置信息，具体请参考：https://wsgidav.readthedocs.io/en/latest/user_guide_configure.html
    :param only_webdav: 是否仅启用 WebDAV
    :param default_web_page: 是否启用默认的网页版界面（仅在 `only_webdav` 为 True 时可用）
    :param load_libass: 是否加载 libass（仅在 `default_web_page` 为 True 时有效）
    :param check_for_relogin: 是否在登录失效后，尝试重新登录

    :return: blacksheep 应用
    """
    from . import __version__

    if cookies_path:
        cookies_path = Path(cookies_path)
    else:
        cookies_path = Path("115-cookies.txt")

    app = Application(router=Router(), show_error_details=debug)
    use_gzip_compression(app)
    if default_web_page:
        app.serve_files(
            Path(__file__).with_name("static"), 
            root_path="/%3Cpic", 
            fallback_document="index.html", 
        )
    docs = OpenAPIHandler(info=Info(
        title="p115dav backend", 
        version=".".join(map(str, __version__)), 
    ))
    docs.ui_providers.append(ReDocUIProvider())
    docs.bind_app(app)

    logger = getattr(app, "logger")
    handler = logging.StreamHandler()
    handler.setFormatter(ColoredLevelNameFormatter("[\x1b[1m%(asctime)s\x1b[0m] %(levelname)s %(message)s"))
    logger.addHandler(handler)

    # NOTE: 缓存图片的 CDN 直链，缓存 59 分钟
    IMAGE_URL_CACHE: TTLDict[str | tuple[str, int], str] = TTLDict(maxsize=cache_size, ttl=60*59)
    # NOTE: 缓存直链（主要是音乐链接）
    if cache_url:
        DOWNLOAD_URL_CACHE: TLRUDict[tuple[str, str], tuple[float, P115URL]] = TLRUDict(maxsize=cache_size)
    DOWNLOAD_URL_CACHE1: TLRUDict[str | tuple[str, int], tuple[float, P115URL]] = TLRUDict(maxsize=cache_size)
    DOWNLOAD_URL_CACHE2: TLRUDict[tuple[str, str], tuple[float, P115URL]] = TLRUDict(maxsize=1024)
    # NOTE: 缓存文件列表数据
    CACHE_ID_TO_LIST: LRUDict[int | tuple[str, int], dict] = LRUDict(maxsize=64)
    # NOTE: 缓存文件信息数据
    CACHE_ID_TO_ATTR: LRUDict[int | tuple[str, int], AttrDict] = LRUDict(maxsize=1024)
    # NOTE: 缓存文件信息数据，但是弱引用
    ID_TO_ATTR: WeakValueDictionary[int | tuple[str, int], AttrDict] = WeakValueDictionary()
    # NOTE: 获取文件列表数据时加锁，实现了对任何 1 个目录 id，只允许同时运行 1 个拉取
    ID_TO_LIST_LOCK: WeakValueDictionary[int | tuple[str, int], Lock] = WeakValueDictionary()
    # NOTE: 缓存 115 分享链接的提取码到接收码（密码）的映射
    SHARE_CODE_MAP: dict[str, dict] = {}
    # NOTE: 后台任务队列
    QUEUE: SimpleQueue[None | tuple[str | Callable, Any]] = SimpleQueue()
    # NOTE: webdav 的文件对象缓存
    DAV_FILE_CACHE: LRUDict[str, DAVNonCollection] = LRUDict(cache_size)

    put_task = QUEUE.put_nowait
    get_task = QUEUE.get
    client: P115Client
    fs_files: Callable
    con: Connection
    loop: AbstractEventLoop

    def skip_if_only_webdav(deco, /):
        def wrapped(func, /):
            if not only_webdav:
                deco(func)
            return func
        return wrapped

    def queue_execute():
        cur = con.cursor()
        execute = cur.execute
        executemany = cur.executemany
        while (task := get_task()) is not None:
            try:
                sql, params = task
                if callable(sql):
                    sql(con, params)
                elif params is None:
                    execute(sql)
                elif isinstance(params, (tuple, Mapping)):
                    execute(sql, params)
                elif isinstance(params, list):
                    executemany(sql, params)
                else:
                    execute(sql, (params,))
                con.commit()
            except:
                logger.exception(f"can't process task: {task!r}")

    def push_task_file_list(id: int, children: Sequence[dict]):
        put_task(("INSERT OR REPLACE INTO list(id, data) VALUES (?, ?)", (id, children)))

    def push_task_share_file_list(share_code: str, id: int, file_list: dict):
        put_task(("INSERT OR REPLACE INTO share_list(share_code, id, data) VALUES (?, ?, ?)", (share_code, id, file_list)))

    def push_task_attr(attr: P115ID | dict | Sequence[dict]):
        if isinstance(attr, P115ID):
            match attr.get("about"):
                case "path":
                    attr = attr["attr"] = normalize_attr(attr.__dict__)
                    attr = {
                        "id": attr["id"], 
                        "parent_id": attr["parent_id"], 
                        "pickcode": attr["pickcode"], 
                        "sha1": attr["sha1"], 
                        "name": attr["name"], 
                        "is_dir": attr["is_dir"], 
                    }
                case "sha1":
                    attr = {
                        "id": int(attr["file_id"]), 
                        "parent_id": int(attr["category_id"]), 
                        "pickcode": attr["pick_code"], 
                        "sha1": attr["file_sha1"], 
                        "name": attr["file_name"], 
                        "is_dir": False, 
                    }
                case "pickcode":
                    attr = {
                        "id": int(attr["file_id"]), 
                        "pickcode": attr["pickcode"], 
                        "name": attr["file_name"], 
                        "is_dir": attr["is_dir"], 
                    }
                case _:
                    return
        if attr and isinstance(attr, (dict, Sequence)):
            if isinstance(attr, dict) or isinstance(attr[0], dict):
                put_task((upsert_items, attr))
 
    @app.on_middlewares_configuration
    def configure_forwarded_headers(app: Application):
        app.middlewares.insert(0, ForwardedHeadersMiddleware(accept_only_proxied_requests=False))

    @app.on_start
    async def get_loop(app: Application):
        nonlocal loop
        loop = get_running_loop()

    @app.lifespan
    async def register_client(app: Application):
        nonlocal client, fs_files
        client = P115Client(
            cookies_path, 
            app="alipaymini", 
            check_for_relogin=check_for_relogin, 
        )
        if app_id is None:
            get_base_url = cycle((
                "http://webapi.115.com", 
                "https://webapi.115.com", 
                "http://proapi.115.com", 
                "https://proapi.115.com", 
                "http://webapi.115.com", 
                "http://115cdn.com/webapi", 
                "http://proapi.115.com", 
                "http://115vod.com/webapi", 
            )).__next__
            def get_files(*args, **kwds):
                base_url = kwds["base_url"] = get_base_url()
                if "proapi" in base_url:
                    return client.fs_files_app(*args, **kwds)
                else:
                    return client.fs_files(*args, **kwds)
            fs_files = get_files
        else:
            fs_files = client.fs_files_open
        async with client.async_session:
            if app_id:
                await client.login_another_open(app_id, replace=True, async_=True)
            app.services.register(P115Client, instance=client)
            yield

    if app_id:
        async def refresh_access_token(app: Application):
            async def run_periodically():
                while True:
                    await async_sleep(3600)
                    await client.refresh_access_token(async_=True)
            try:
                task = create_task(run_periodically())
                yield
            finally:
                task.cancel()

    @app.lifespan
    async def register_connection(app: Application):
        nonlocal con
        remove_done = False
        path = dbfile
        if not path:
            from uuid import uuid4
            from tempfile import mktemp
            path = mktemp(prefix=str(uuid4()) + "-", suffix=".db")
            remove_done = True
        try:
            with closing(connect(
                path, 
                autocommit=True, 
                check_same_thread=False, 
                detect_types=PARSE_DECLTYPES | PARSE_COLNAMES, 
                uri=isinstance(path, str) and path.startswith("file:"), 
            )) as con:
                app.services.register(Connection, instance=con)
                db.init_db(con)
                yield
        finally:
            if remove_done:
                path = cast(str, path)
                with suppress(OSError):
                    remove(path)
                with suppress(OSError):
                    remove(path+"-shm")
                with suppress(OSError):
                    remove(path+"-wal")

    @app.lifespan
    async def start_tasks(app: Application):
        start_new_thread(queue_execute, ())
        try:
            yield
        finally:
            put_task(None)

    def make_response_for_exception(
        exc: BaseException, 
        status_code: int = 500, 
    ) -> Response:
        if (len(exc.args) == 1 and isinstance(exc.args[0], (dict, list, tuple)) or 
            isinstance(exc, OSError) and len(exc.args) == 2 and isinstance(exc.args[1], (dict, list, tuple))
        ):
            return Response(
                status_code, 
                None, 
                Content(b"application/json", dumps(exc.args[-1])), 
            )
        return text(str(exc), status_code)

    async def redirect_exception_response(
        self, 
        request: Request, 
        exc: Exception, 
    ) -> Response:
        code = get_status_code(exc)
        if code is not None:
            return make_response_for_exception(exc, code)
        elif isinstance(exc, ValueError):
            return make_response_for_exception(exc, 400) # Bad Request
        elif isinstance(exc, AuthenticationError):
            return make_response_for_exception(exc, 401) # Unauthorized
        elif isinstance(exc, PermissionError):
            return make_response_for_exception(exc, 403) # Forbidden
        elif isinstance(exc, FileNotFoundError):
            return make_response_for_exception(exc, 404) # Not Found
        elif isinstance(exc, (IsADirectoryError, NotADirectoryError)):
            return make_response_for_exception(exc, 406) # Not Acceptable
        elif isinstance(exc, (TooManyRequests, BusyOSError)):
            return make_response_for_exception(exc, 429) # Too Many Requests
        elif isinstance(exc, OSError):
            return make_response_for_exception(exc, 500) # Internal Server Error
        else:
            return make_response_for_exception(exc, 503) # Service Unavailable

    if debug:
        logger.level = logging.DEBUG

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

    # NOTE: 下面是一些工具函数

    def normalize_attr(info: Mapping, /) -> AttrDict:
        """文件信息规范化
        """
        def typeof(attr: Mapping, /) -> int:
            if attr["is_dir"]:
                return 0
            if (
                int(get_first(info, "iv", "isv", "is_video", default=0)) or 
                contains_any(info, "def", "def2", "v_img", "definition", "definition2", "video_img_url", "vdi")
            ):
                return 4
            elif contains_any(info, "muc", "music_cover", "play_url"):
                return 3
            elif contains_any(info, "thumb_url"):
                return 2
            if fclass := info.get("class", ""):
                if type := CLASS_TO_TYPE.get(fclass):
                    return type
            if type := SUFFIX_TO_TYPE.get(splitext(attr["name"])[1].lower()):
                return type
            return 99
        if "share_code" in info:
            share_code = info["share_code"]
            receive_code = info.get("receive_code", "")
            sha1 = info.get("sha", "")
            is_dir = not sha1
            attr: AttrDict = AttrDict({
                "share_code": share_code, 
                "receive_code": receive_code, 
                "is_dir": is_dir, 
                "id": info["cid"] if is_dir else info["fid"], 
                "parent_id": str(info["pid"] if is_dir else info["cid"]), 
                "name": info["n"], 
                "sha1": sha1, 
                "mtime": int(info["t"]), 
                "size": int(info.get("s", 0)), 
                "is_collect": int(info.get("c", 0)) == 1, 
                "thumb": info.get("u", ""), 
            })
        elif "fn" in info:
            sha1 = info.get("sha1", "")
            is_dir = not sha1
            attr = AttrDict({
                "is_dir": is_dir, 
                "id": info["fid"], 
                "parent_id": info["pid"], 
                "pickcode": info["pc"], 
                "name": info["fn"], 
                "sha1": sha1, 
                "mtime": int(info["upt"]), 
                "size": int(info.get("fs", 0)), 
                "is_collect": int(info.get("ic", 0)) == 1, 
                "thumb": info.get("thumb", ""), 
            })
        elif "n" in info:
            sha1 = info.get("sha", "")
            is_dir = not sha1
            attr = AttrDict({
                "is_dir": is_dir, 
                "id": info["cid"] if is_dir else info["fid"], 
                "parent_id": info["pid"] if is_dir else info["cid"], 
                "pickcode": info["pc"], 
                "name": info["n"], 
                "sha1": sha1, 
                "mtime": int(info["te"]), 
                "size": int(info.get("s", 0)), 
                "is_collect": int(info.get("c", 0)) == 1, 
                "thumb": info.get("u", ""), 
            })
        else:
            raise ValueError(f"can't process: {info!r}")
        id = int(attr["id"])
        if "share_code" in attr:
            key: str | tuple[str, int] = (share_code, id)
            url = f"/<share?share_code={share_code}&receive_code={receive_code}&id={id}"
        else:
            pickcode = cast(str, attr["pickcode"])
            key = pickcode
            if is_dir:
                url = "/%s?id=%d" % (encode_uri_component_loose(attr["name"]), id)
            else:
                url = "/%s?pickcode=%s" % (encode_uri_component_loose(attr["name"]), pickcode)
        file_type = attr["type"] = typeof(attr)
        if is_dir:
            url += "&file=false"
        else:
            url += "&file=true"
            if attr["is_collect"] and attr["size"] < 1024 * 1024 * 115:
                url += "&web=true"
        attr["url"] = url
        if is_dir:
            attr["ico"] = "folder"
        else:
            attr["ico"] = splitext(attr["name"])[1][1:].lower()
        if thumb := attr["thumb"]:
            if thumb.startswith("?"):
                thumb = f"https://imgjump.115.com{thumb}&sha1={attr['sha1']}"
            else:
                thumb = reduce_image_url_layers(thumb)
            if thumb.startswith("https://imgjump.115.com"):
                attr["thumb"] = thumb + "&size=200"
                thumb += "&size=0"
                cached_thumb = IMAGE_URL_CACHE.get(key, "")
                if isinstance(cached_thumb, P115URL):
                    cached_thumb = cached_thumb["thumb"]
                if thumb != cached_thumb:
                    IMAGE_URL_CACHE[key] = thumb
            else:
                attr["thumb"] = thumb
        elif thumb := info.get("muc"):
            attr["thumb"] = thumb
        return attr

    def wrap_url(
        url: str, 
        /, 
        url_detail: None | bool = False, 
    ) -> str | dict | Response:
        """包装下载链接，以供某些用途
        """
        if url_detail is None:
            if isinstance(url, P115URL):
                return Response(302, [
                    (b"Location", bytes(url, "utf-8")), 
                    (b"Content-Disposition", b'attachment; filename="%s"' % bytes(quote(url["name"], safe=""), "latin-1")), 
                ], Content(b"application/json; charset=utf-8", dumps(url.__dict__)))
            return redirect(url)
        elif url_detail:
            if isinstance(url, P115URL):
                return {"type": "file", "url": url, "headers": url.get("headers")}
            else:
                return {"type": "image", "url": url}
        else:
            return url

    async def iterdir(
        cid: int = 0, 
        first_page_size: int = 0, 
        page_size: int = 10_000, 
    ) -> tuple[int, list[dict], AsyncIterator[AttrDict]]:
        """网盘目录迭代
        """
        ancestors: list[dict] = [{"id": "0", "parent_id": "0", "name": ""}]
        count = 0
        async def get_data():
            nonlocal count
            resp = await fs_files(payload, async_=True)
            check_response(resp)
            if cid and int(resp["path"][-1]["cid"]) != cid:
                raise FileNotFoundError(ENOENT, {"id": cid})
            ancestors[1:] = (
                {"id": a["cid"], "parent_id": a["pid"], "name": a["name"]} 
                for a in resp["path"][1:]
            )
            if count == 0:
                count = resp["count"]
            elif count != resp["count"]:
                raise BusyOSError(EBUSY, f"count changes during iteration: {cid}")
            return resp["data"]
        if first_page_size <= 0:
            first_page_size = page_size
        payload = {
            "asc": 0, "cid": cid, "cur": 1, "fc_mix": 1, "limit": first_page_size, 
            "o": "user_utime", "offset": 0, "show_dir": 1, 
        }
        data = await get_data()
        payload["limit"] = page_size
        async def iter():
            nonlocal data
            offset = 0
            while True:
                push_task_attr(ancestors[1:])
                for attr in map(normalize_attr, data):
                    yield attr
                offset += len(data)
                if offset >= count:
                    break
                payload["offset"] = offset
                data = await get_data()
        return count, ancestors, iter()

    async def update_file_list_partial(cid: int, file_list: dict):
        """增量更新文件列表
        """
        try:
            count, ancestors, it = await iterdir(cid, 16)
        except FileNotFoundError:
            put_task(("DELETE FROM list WHERE id=?", cid))
            raise
        children = file_list["children"]
        remains = len(children)
        if count:
            if remains:
                mtime_groups: dict[int, dict[str, AttrDict]] = {}
                for a in children:
                    try:
                        mtime_groups[a["mtime"]][a["id"]] = a
                    except KeyError:
                        mtime_groups[a["mtime"]] = {a["id"]: a}
                his_it = iter(sorted(mtime_groups.items(), reverse=True))
                his_mtime, his_items = next(his_it)
            try:
                n = 0
                children = []
                children_add = children.append
                async for attr in it:
                    children_add(attr)
                    if remains:
                        n += 1
                        cur_id = attr["id"]
                        cur_mtime = attr["mtime"]
                        try:
                            while his_mtime > cur_mtime:
                                remains -= len(his_items)
                                his_mtime, his_items = next(his_it)
                        except StopIteration:
                            continue
                        if his_mtime == cur_mtime:
                            if cur_id in his_items:
                                his_items.pop(cur_id)
                                remains -= 1
                                if n + remains == count:
                                    children_extend = children.extend
                                    children_extend(his_items.values())
                                    for his_mtime, his_items in his_it:
                                        children_extend(his_items.values())
                                    break
            except FileNotFoundError:
                put_task(("DELETE FROM list WHERE id=?", cid))
                raise
            children.sort(key=lambda a: (not a["is_dir"], a["name"]))
            file_list["children"][:] = children
        else:
            if remains:
                children.clear()
                push_task_file_list(cid, [])
        file_list["ancestors"][:] = ancestors
        return file_list

    async def get_file_list(
        cid: int, 
        /, 
        refresh_thumbs: bool = False, 
    ) -> dict:
        """获取目录中的文件信息列表，包括祖先节点列表和子节点信息列表
        """
        children: None | list[AttrDict]
        async with ID_TO_LIST_LOCK.setdefault(cid, Lock()):
            file_list = CACHE_ID_TO_LIST.get(cid)
            if file_list is None:
                file_list = await db.get_file_list(con, cid, async_=True)
                if file_list:
                    CACHE_ID_TO_LIST[cid] = file_list
                    ID_TO_ATTR.update((int(attr["id"]), attr) for attr in file_list["children"])
            will_full_update = file_list is None
            if file_list:
                if refresh_thumbs:
                    earliest_thumb_ts = min((
                        int(CRE_URL_T_search(urlsplit(attr["thumb"]).query)[0]) # type: ignore
                        for attr in file_list["children"] if attr["type"] == 2
                    ), default=0)
                    will_full_update = earliest_thumb_ts > 0 and earliest_thumb_ts - time() < 600
            if not will_full_update:
                file_list = cast(dict, file_list)
                if isnan(ttl) or isinf(ttl) or ttl < 0:
                    return file_list
                elif ttl > 0:
                    updated_at = await db.get_updated_at(con, cid, async_=True)
                    if not updated_at or time() - updated_at <= ttl:
                        return file_list
                await update_file_list_partial(cid, file_list)
                return file_list
            try:
                _, ancestors, it = await iterdir(cid)
            except FileNotFoundError:
                put_task(("DELETE FROM list WHERE id=?", cid))
                raise
            children = [a async for a in it]
            children.sort(key=lambda a: (not a["is_dir"], a["name"]))
            push_task_attr(ancestors[1:])
            push_task_file_list(cid, children)
            file_list = CACHE_ID_TO_LIST[cid] = {"ancestors": ancestors, "children": children}
            ID_TO_ATTR.update((int(attr["id"]), attr) for attr in children)
            return file_list

    async def get_share_file_list(
        share_code: str, 
        receive_code: str, 
        cid: int, 
        page_size: int = 10_000, 
        refresh_thumbs: bool = False, 
    ) -> dict:
        """获取分享的某个目录的文件信息列表，包括祖先节点列表和子节点信息列表
        """
        key = (share_code, cid)
        if key not in CACHE_ID_TO_LIST:
            attr = await share_get_attr(share_code, id=cid, receive_code=receive_code)
        async with ID_TO_LIST_LOCK.setdefault(key, Lock()):
            file_list = CACHE_ID_TO_LIST.get(key)
            if file_list is None:
                file_list = await db.share_get_file_list(con, share_code, cid, async_=True)
                if file_list:
                    CACHE_ID_TO_LIST[key] = file_list
                    ID_TO_ATTR.update(((share_code, int(attr["id"])), attr) for attr in file_list["children"])
            if file_list:
                if not refresh_thumbs:
                    return file_list
                else:
                    earliest_thumb_ts = min((
                        int(CRE_URL_T_search(urlsplit(attr["thumb"]).query)[0]) # type: ignore
                        for attr in file_list["children"] if attr["type"] == 2
                    ), default=0)
                    if not earliest_thumb_ts or earliest_thumb_ts - time() >= 600:
                        return file_list
            if cid == 0:
                ancestors: list[dict] = []
            else:
                parent_id = int(attr["parent_id"])
                if plist := CACHE_ID_TO_LIST.get((share_code, parent_id)):
                    ancestors = list(plist["ancestors"])
                else:
                    ancestors = cast(list[dict], await db.share_get_ancestors(
                        con, share_code, parent_id, async_=True))
            ancestors.append({
                "id": str(cid), 
                "parent_id": attr["parent_id"], 
                "name": attr["name"] if cid else "", 
            })
            children = await to_list(cast(AsyncIterator[AttrDict], share_iterdir(
                client, 
                share_code, 
                receive_code, 
                cid, 
                page_size=page_size, 
                normalize_attr=normalize_attr, 
                async_=True, 
            )))
            dirname = "/".join(escape(a["name"]) for a in ancestors)
            for attr in children:
                attr["path"] = dirname + "/" + escape(attr["name"])
            children.sort(key=lambda a: (not a["is_dir"], a["name"]))
            file_list = CACHE_ID_TO_LIST[key] = {"ancestors": ancestors, "children": children}
            push_task_share_file_list(share_code, cid, file_list)
            ID_TO_ATTR.update(((share_code, int(attr["id"])), attr) for attr in children)
            return file_list

    async def get_share_file_tree(
        share_code: str, 
        receive_code: str, 
        cid: int = 0, 
        page_size: int = 10_000, 
    ) -> AsyncIterator[AttrDict]:
        """迭代整个分享的所有节点信息
        """
        start_from_root = cid == 0
        dq: deque[int] = deque((cid,))
        push, pop = dq.append, dq.popleft
        while dq:
            cid = pop()
            file_list = await get_share_file_list(share_code, receive_code, cid, page_size=page_size)
            for attr in file_list["children"]:
                yield attr
                if attr["is_dir"]:
                    push(int(attr["id"]))
        if start_from_root:
            put_task(("INSERT OR REPLACE INTO share_list_loaded(share_code, loaded) VALUES (?, TRUE)", share_code))

    async def get_file_url(
        pickcode: str, 
        /, 
        user_agent: str = "", 
        use_web_api: bool = False, 
    ) -> P115URL:
        """获取文件的下载链接
        """
        if app_id and not use_web_api:
            return await client.download_url_open(
                pickcode, 
                headers={"User-Agent": user_agent}, 
                async_=True, 
            )
        else:
            return await client.download_url(
                pickcode, 
                headers={"User-Agent": user_agent}, 
                use_web_api=use_web_api, 
                app="android", 
                async_=True, 
            )

    async def get_image_url(pickcode: str, /) -> str:
        """获取图片的下载链接，走 CDN
        """
        if not (url := IMAGE_URL_CACHE.get(pickcode, "")):
            resp = await client.fs_image(pickcode, async_=True)
            resp = check_response(resp)
            data = resp["data"]
            url = IMAGE_URL_CACHE[pickcode] = cast(str, data["origin_url"])
        return url

    async def list_my_shares() -> list[dict]:
        """获取你自己的分享列表
        """
        share_get_list = client.share_list
        shares: list[dict] = []
        add_share = shares.append
        offset = 0
        payload = {"offset": offset, "limit": 1150}
        while True:
            resp = await share_get_list(payload, async_=True)
            check_response(resp)
            for share in resp["list"]:
                SHARE_CODE_MAP[share["share_code"]] = share
                add_share(share)
            offset += len(resp["list"])
            if offset >= resp["count"]:
                break
            payload["offset"] = offset
        return shares

    async def get_share_info(
        share_code: str, 
        /, 
        receive_code: str = "", 
    ) -> dict:
        """获取分享链接的接收码（必须是你自己的分享）
        """
        share_code = share_code.lower()
        try:
            return SHARE_CODE_MAP[share_code]
        except KeyError:
            if receive_code:
                resp = await client.share_snap(
                    {"share_code": share_code, "receive_code": receive_code, "cid": 0, "limit": 1}, 
                    async_=True, 
                )
                if resp["state"]:
                    share_info = resp["data"]["shareinfo"]
            else:
                resp = await client.share_info(share_code, async_=True)
                if resp["state"]:
                    share_info = resp["data"]
            check_response(resp)
            share_info["share_code"] = share_code
            SHARE_CODE_MAP[share_code] = share_info
            return share_info

    async def get_share_file_url(
        share_code: str, 
        receive_code: str, 
        id: int | str, 
        /, 
        use_web_api: bool = False, 
    ) -> P115URL:
        """获取分享的文件的下载链接
        """
        return await client.share_download_url(
            {"share_code": share_code, "receive_code": receive_code, "file_id": id}, 
            use_web_api=use_web_api, 
            async_=True, 
        )

    async def get_share_image_url(
        share_code: str, 
        receive_code: str, 
        id: int, 
    ) -> str:
        """获取分享的图片的下载链接，走 CDN
        """
        if url := IMAGE_URL_CACHE.get((share_code, id), ""):
            return url
        attr = await share_get_attr(share_code, id=id, receive_code=receive_code)
        try:
            return attr["thumb"]
        except KeyError:
            raise ValueError("has no thumb picture")

    # NOTE: 下面的接口用来从你的网盘获取信息

    @skip_if_only_webdav(app.router.get("/%3Cid"))
    @skip_if_only_webdav(app.router.get("/%3Cid/*"))
    async def get_id(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
    ) -> int:
        """获取对应的 id

        :param id: 优先级低于 `pickcode`
        :param pickcode: 优先级最高
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`

        :return: 对应的 id
        """
        fid = 0
        if pickcode:
            fid = await db.get_id(con, pickcode=pickcode.lower(), async_=True)
            if fid is None:
                fid = pickcode_to_id(pickcode)
        elif id >= 0:
            fid = id
        elif sha1:
            fid = await db.get_id(con, sha1=sha1.upper(), async_=True)
            if fid is None:
                fid = await get_id_to_sha1(client, sha1, async_=True)
                push_task_attr(fid)
        elif path:
            fid = await db.get_id(con, path=path, async_=True)
            if fid is None:
                fid = await get_id_to_path(
                    client, 
                    path, 
                    id_to_dirnode=SqliteTableDict(con, table="data", key="id", value=("name", "parent_id")), 
                    async_=True, 
                )
                push_task_attr(cast(P115ID, fid))
        return fid

    @skip_if_only_webdav(app.router.get("/%3Cpickcode"))
    @skip_if_only_webdav(app.router.get("/%3Cpickcode/*"))
    async def get_pickcode(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
    ) -> str:
        """获取对应的提取码

        :param id: 优先级低于 `pickcode`
        :param pickcode: 优先级最高
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`

        :return: 对应的提取码
        """
        if pickcode:
            if not 17 <= len(pickcode) <= 18 or not pickcode.isalnum():
                raise ValueError(f"bad pickcode: {pickcode!r}")
            return pickcode.lower()
        elif id > 0:
            pickcode = await db.get_pickcode(con, id=id, async_=True)
            if pickcode is None:
                pickcode = id_to_pickcode(id, client.pickcode_stable_point)
            return pickcode
        elif sha1:
            pickcode = await db.get_pickcode(con, sha1=sha1.upper(), async_=True)
            if pickcode is None:
                id = await get_id(sha1=sha1)
                if isinstance(id, P115ID):
                    return get_first(id, "pickcode", "pick_code", "pc", default="")
                attr = await get_attr(id, skim=True)
                return attr["pickcode"]
            return pickcode
        elif path:
            pickcode = await db.get_pickcode(con, path=path, async_=True)
            if pickcode is None:
                id = await get_id(path=path)
                if isinstance(id, P115ID):
                    return get_first(id, "pickcode", "pick_code", "pc", default="")
                attr = await get_attr(id, skim=True)
                return attr["pickcode"]
            return pickcode
        raise FileNotFoundError(ENOENT, "does not have pickcode")

    @skip_if_only_webdav(app.router.get("/%3Csha1"))
    @skip_if_only_webdav(app.router.get("/%3Csha1/*"))
    async def get_sha1(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
    ) -> str:
        """获取对应的文件的 sha1 摘要值

        :param id: 优先级低于 `pickcode`
        :param pickcode: 优先级最高
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`

        :return: 对应的 sha1 摘要值
        """
        if pickcode:
            sha1 = await db.get_sha1(con, pickcode=pickcode.lower(), async_=True)
            if sha1 is None:
                id = await get_id(pickcode=pickcode)
                if isinstance(id, P115ID):
                    return get_first(id, "sha1", "file_sha1", "sha", default="")
                attr = await get_attr(id, skim=True)
                return attr["sha1"]
            return sha1
        elif id > 0:
            sha1 = await db.get_sha1(con, id=id, async_=True)
            if sha1 is None:
                attr = await get_attr(id, skim=True)
                return attr["sha1"]
            return sha1
        elif sha1:
            if len(sha1) != 40 or sha1.strip(hexdigits):
                raise ValueError(f"bad sha1: {sha1!r}")
            return sha1.upper()
        elif path:
            sha1 = await db.get_sha1(con, path=path, async_=True)
            if sha1 is None:
                id = await get_id(path=path)
                if isinstance(id, P115ID):
                    return get_first(id, "sha1", "file_sha1", "sha", default="")
                attr = await get_attr(id, skim=True)
                return attr["sha1"]
            return sha1
        raise FileNotFoundError(ENOENT, "does not have sha1")

    @skip_if_only_webdav(app.router.get("/%3Cpath"))
    @skip_if_only_webdav(app.router.get("/%3Cpath/*"))
    async def get_path(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
    ):
        """获取对应的路径

        :param id: 优先级低于 `pickcode`
        :param pickcode: 优先级最高
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`

        :return: 对应的路径
        """
        if pickcode:
            id = await get_id(pickcode=pickcode)
        elif id >= 0:
            if not id:
                return "/"
        elif sha1:
            id = await get_id(sha1=sha1)
        elif path:
            return normpath(path)
        if id > 0:
            path = await db.get_path(con, id, async_=True)
            if path is None:
                ancestors = await get_ancestors(client, id, async_=True)
                push_task_attr(ancestors)
                return "/".join(escape(info["name"]) for info in ancestors)
            return path
        raise FileNotFoundError(ENOENT, "does not have path")

    @skip_if_only_webdav(app.router.get("/%3Cattr"))
    @skip_if_only_webdav(app.router.get("/%3Cattr/*"))
    async def get_attr(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
        skim: bool = False, 
    ) -> dict:
        """获取对应的属性

        :param id: 优先级低于 `pickcode`
        :param pickcode: 优先级最高
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`
        :param skim: 当进行查询时，是否用简化版的接口（可避免风控）

        :return: 对应的属性
        """
        id = await get_id(id=id, pickcode=pickcode, sha1=sha1, path=path)
        if isinstance(id, P115ID) and id.get("about") == "path":
            attr: AttrDict = AttrDict(id.__dict__)
            attr.pop("about")
            skim = False
        else:
            if not id:
                return {"id": "0", "parent_id": "0", "is_dir": True, "name": ""}
            if id not in ID_TO_ATTR:
                pid = await db.get_parent_id(con, id, async_=True)
                if pid is not None:
                    await get_file_list(pid)
            if ID_TO_ATTR.get(id):
                attr = ID_TO_ATTR[id]
                if attr["type"] != 2 or int(CRE_URL_T_search(urlsplit(attr["thumb"]).query)[0]) - time() >= 60: # type: ignore
                    return attr
            from p115client.tool import get_attr
            attr = cast(AttrDict, await get_attr(client, id, skim=skim, async_=True))
        if skim:
            push_task_attr(attr)
        else:
            id = int(id)
            CACHE_ID_TO_ATTR[id] = ID_TO_ATTR[id] = attr
            push_task_attr({
                "id": id, 
                "parent_id": attr["parent_id"], 
                "pickcode": attr["pickcode"], 
                "sha1": attr["sha1"], 
                "name": attr["name"], 
                "is_dir": attr["is_dir"], 
            })
        return attr

    @skip_if_only_webdav(app.router.get("/%3Clist"))
    @skip_if_only_webdav(app.router.get("/%3Clist/*"))
    async def get_list(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
    ) -> dict:
        """获取对应的祖先节点列表和子节点信息列表

        :param id: 优先级低于 `pickcode`
        :param pickcode: 优先级最高
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`

        :return: 对应的祖先节点列表和子节点信息列表
        """
        id = await get_id(id=id, pickcode=pickcode, sha1=sha1, path=path)
        return await get_file_list(id)

    @skip_if_only_webdav(app.router.get("/%3Cm3u8"))
    @skip_if_only_webdav(app.router.get("/%3Cm3u8/*"))
    async def get_m3u8(pickcode: str) -> None | str:
        """获取 m3u8 文件链接

        :param pickcode: 对应视频文件的提取码

        :return: m3u8 文件下载链接
        """
        resp = await client.fs_video_app(pickcode, async_=True)
        if data := resp.get("data"):
            push_task_attr({
                "id": int(data["file_id"]), 
                "parent_id": int(data["parent_id"]), 
                "pickcode": data["pick_code"], 
                "sha1": data["file_sha1"], 
                "name": data["file_name"], 
                "is_dir": False, 
            })
        check_response(resp)
        return data and data.get("video_url")

    @skip_if_only_webdav(app.router.get("/%3Csubtitles"))
    @skip_if_only_webdav(app.router.get("/%3Csubtitles/*"))
    async def get_subtitles(pickcode: str) -> None | list[dict]:
        """获取字幕（随便提供此文件夹内的任何一个文件的提取码即可）

        :param pickcode: 提取码，可以是和对应视频相同目录下的任何文件的提取码

        :return: 字幕文件列表，包含下载链接和其它信息
        """
        resp = await client.fs_video_subtitle(pickcode, async_=True)
        data = check_response(resp).get("data")
        if data:
            push_task_attr([
                {
                    "id": int(a["file_id"]), 
                    "pickcode": a["pick_code"], 
                    "sha1": a["sha1"], 
                    "name": a["file_name"], 
                    "is_dir": False, 
                } 
                for a in data["list"] if "file_id" in a
            ])
        return data

    @app.router.get("/%3Curl")
    @app.router.get("/%3Curl/*")
    async def get_url(
        pickcode: str, 
        image: bool = False, 
        web: bool = False, 
        user_agent: str = "", 
        url_detail: None | bool = None, 
        request: None | Request = None, 
    ) -> str | dict | Response:
        """获取下载链接

        :param pickcode: 文件的 pickcode
        :param image: 是否为图片
        :param web: 是否使用 web 接口
        :param user_agent: User-Agent 请求头（不需要传，会自动确定，不用管）
        :param url_detail: 链接信息完整度设置（内部开发使用，不用管）
        :param request: 请求对象（不用管）

        :return: 下载链接的信息
        """
        if image:
            return {"type": "image", "url": await get_image_url(pickcode)}
        if not user_agent and request is not None:
            user_agent = (request.get_first_header(b"User-agent") or b"").decode("latin-1")
        if (cache_url and (r := DOWNLOAD_URL_CACHE.get((pickcode, user_agent)))
            or (r := DOWNLOAD_URL_CACHE1.get(pickcode))
            or (r := DOWNLOAD_URL_CACHE2.get((pickcode, user_agent)))
        ):
            return wrap_url(r[1], url_detail)
        url = await get_file_url(pickcode, user_agent=user_agent, use_web_api=web)
        expire_ts = int(next(v for k, v in parse_qsl(urlsplit(url).query) if k == "t")) - 60 * 5
        if "&c=0&f=&" in url:
            DOWNLOAD_URL_CACHE1[pickcode] = (expire_ts, url)
        elif "&c=0&f=1&" in url:
            DOWNLOAD_URL_CACHE2[(pickcode, user_agent)] = (expire_ts, url)
        elif cache_url:
            DOWNLOAD_URL_CACHE[(pickcode, user_agent)] = (expire_ts, url)
        return wrap_url(url, url_detail)

    if default_web_page:
        @skip_if_only_webdav(app.router.route("/", methods=["GET", "HEAD"]))
        @skip_if_only_webdav(app.router.route("/<path:path2>", methods=["GET", "HEAD"]))
        async def get_page(
            request: Request, 
            id: int = -1, 
            pickcode: str = "", 
            sha1: str = "", 
            path: str = "", 
            path2: str = "", 
            search: str = "", 
            file: None | bool = None, 
            image: bool = False, 
            web: bool = False, 
        ) -> Response:
            """根据实际情况分流到具体接口

            :param id: 文件或目录的 id，优先级高于 `sha1`
            :param pickcode: 文件或目录的 pickcode，优先级高于 `id`，为最高
            :param sha1: 文件的 sha1，优先级高于 `path`
            :param path: 文件或目录的 path，优先级高于 `path2`
            :param path2: 文件或目录的 path，优先级最低
            :param search: 搜索关键词
            :param file: 是否为文件，如果为 None，则需要进一步确定
            :param image: 是否为图片
            :param web: 是否使用 web 接口
            """
            if str(request.url) == "/service-worker.js":
                raise FileNotFoundError(ENOENT, {"url": f"{request.scheme}://{request.host}{request.url}"})
            if file is None:
                attr = await get_attr(
                    id=id, 
                    pickcode=pickcode, 
                    sha1=sha1, 
                    path=path or path2, 
                )
                is_dir = attr["is_dir"]
                if is_dir:
                    id = int(attr["id"])
                else:
                    pickcode = attr["pickcode"]
            elif file:
                is_dir = False
                pickcode = await get_pickcode(
                    id=id, 
                    pickcode=pickcode, 
                    sha1=sha1, 
                    path=path or path2, 
                )
            else:
                is_dir = True
                id = await get_id(
                    id=id, 
                    pickcode=pickcode, 
                    sha1=sha1, 
                    path=path or path2, 
                )
            if not is_dir:
                resp = await get_url(
                    pickcode=pickcode, 
                    image=image, 
                    web=web, 
                    user_agent=(request.get_first_header(b"User-agent") or b"").decode("latin-1"), 
                    url_detail=True, 
                )
                url: P115URL = resp["url"]
                if web:
                    cookie = resp["headers"]["Cookie"]
                    return Response(
                        302, 
                        headers=[
                            (b"Location", bytes(f"/<download/{quote(url['name'])}?url={quote(url)}", "latin-1")), 
                            (b"Set-Cookie", bytes(cookie[:cookie.find(";")], "latin-1")), 
                        ], 
                    )
                else:
                    return Response(302, [
                        (b"Location", bytes(url, "utf-8")), 
                        (b"Content-Disposition", b'attachment; filename="%s"' % bytes(quote(url["name"], safe=""), "latin-1")), 
                    ], Content(b"application/json; charset=utf-8", dumps(url.__dict__)))
            if search:
                resp = await client.fs_search({"search_value": search, "cid": id, "limit": 10000}, async_=True)
                check_response(resp)
                children = list(map(normalize_attr, resp["data"]))
                folder = resp["folder"]
                ancestors = [
                    {"id": folder["cid"], "parent_id": folder["pid"], "name": folder["name"] if int(folder["pid"]) else ""}, 
                    {"id": folder["cid"], "parent_id": folder["pid"], "name": "目录信息"}
                ]
            else:
                file_list = await get_list(id=id)
                ancestors = file_list["ancestors"]
                children  = file_list["children"]
            return await view_async(
                "list", 
                ancestors=ancestors, 
                children=children, 
                origin=get_origin(request), 
                load_libass=load_libass, 
                user_agent=detect_ua((request.get_first_header(b"User-agent") or b"").decode("latin-1")), 
                IMAGE_URL_CACHE=IMAGE_URL_CACHE, 
            )

    # NOTE: 下面的接口用来从分享获取信息

    @skip_if_only_webdav(app.router.get("/%3Cshare/%3Cid"))
    @skip_if_only_webdav(app.router.get("/%3Cshare/%3Cid/*"))
    async def share_get_id(
        share_code: str, 
        id: int = -1, 
        sha1: str = "", 
        path: str = "", 
        receive_code: str = "", 
    ):
        """从分享获取对应的 id

        :param share_code: 分享码
        :param id: 文件或目录的 id
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`
        :param receive_code: 提取码，如果是你自己的分享，可以不传

        :return: 对应的 id
        """
        if id >= 0:
            fid = id
        elif sha1:
            fid = await db.share_get_id(con, share_code, sha1=sha1.upper(), async_=True)
            if fid is None:
                if not receive_code:
                    share_info = await get_share_info(share_code)
                    receive_code = share_info["receive_code"]
                async for attr in get_share_file_tree(share_code, receive_code):
                    if not attr["is_dir"] and attr["sha1"] == sha1:
                        return attr["id"]
                else:
                    raise FileNotFoundError(ENOENT, {"share_code": share_code, "sha1": sha1})
        elif path:
            fid = await db.share_get_id(con, share_code, path=path, async_=True)
            if fid is None:
                if not receive_code:
                    share_info = await get_share_info(share_code)
                    receive_code = share_info["receive_code"]
                try:
                    fid = await share_get_id_to_path(
                        client, 
                        share_code, 
                        receive_code=receive_code, 
                        path=path, 
                        id_to_dirnode=..., 
                        async_=True, 
                    )
                except OSError as e:
                    raise FileNotFoundError(ENOENT, {"share_code": share_code, "path": path}) from e
        else:
            fid = 0
        return fid

    @skip_if_only_webdav(app.router.get("/%3Cshare/%3Csha1"))
    @skip_if_only_webdav(app.router.get("/%3Cshare/%3Csha1/*"))
    async def share_get_sha1(
        share_code: str, 
        id: int = -1, 
        sha1: str = "", 
        path: str = "", 
        receive_code: str = "", 
    ):
        """从分享获取对应的 sha1 摘要值

        :param share_code: 分享码
        :param id: 文件的 id
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`
        :param receive_code: 提取码，如果是你自己的分享，可以不传

        :return: 对应的 sha1 摘要值
        """
        if id >= 0:
            if not id:
                return ""
            sha1 = await db.share_get_sha1(con, share_code, id=id, async_=True)
            if sha1 is None:
                if not receive_code:
                    share_info = await get_share_info(share_code)
                    receive_code = share_info["receive_code"]
                async for attr in get_share_file_tree(share_code, receive_code):
                    if attr["id"] == id:
                        return attr["sha1"]
                else:
                    raise FileNotFoundError(ENOENT, {"share_code": share_code, "id": id})
        elif sha1:
            return sha1.upper()
        elif path:
            sha1 = await db.share_get_sha1(con, share_code, path=path, async_=True)
            if sha1 is None:
                if not receive_code:
                    share_info = await get_share_info(share_code)
                    receive_code = share_info["receive_code"]
                path = normpath(path)
                async for attr in get_share_file_tree(share_code, receive_code):
                    if attr["path"] == path:
                        return attr["sha1"]
                else:
                    raise FileNotFoundError(ENOENT, {"share_code": share_code, "path": path})
        else:
            sha1 = ""
        return sha1

    @skip_if_only_webdav(app.router.get("/%3Cshare/%3Cpath"))
    @skip_if_only_webdav(app.router.get("/%3Cshare/%3Cpath/*"))
    async def share_get_path(
        share_code: str, 
        id: int = -1, 
        sha1: str = "", 
        path: str = "", 
        receive_code: str = "", 
    ):
        """从分享获取对应的路径

        :param share_code: 分享码
        :param id: 文件或目录的 id
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`
        :param receive_code: 提取码，如果是你自己的分享，可以不传

        :return: 对应的路径
        """
        if id >= 0:
            if not id:
                return "/"
            path = await db.share_get_path(con, share_code, id=id, async_=True)
            if not path:
                if not receive_code:
                    share_info = await get_share_info(share_code)
                    receive_code = share_info["receive_code"]
                async for attr in get_share_file_tree(share_code, receive_code):
                    if attr["id"] == id:
                        return attr["path"]
                else:
                    raise FileNotFoundError(ENOENT, {"share_code": share_code, "id": id})

        elif sha1:
            path = await db.share_get_path(con, share_code, sha1=sha1, async_=True)
            if not path:
                if not receive_code:
                    share_info = await get_share_info(share_code)
                    receive_code = share_info["receive_code"]
                async for attr in get_share_file_tree(share_code, receive_code):
                    if attr["sha1"] == sha1:
                        return attr["path"]
                else:
                    raise FileNotFoundError(ENOENT, {"share_code": share_code, "id": id})
        elif path:
            return normpath(path)
        else:
            path = "/"
        return path

    @skip_if_only_webdav(app.router.get("/%3Cshare/%3Cattr"))
    @skip_if_only_webdav(app.router.get("/%3Cshare/%3Cattr/*"))
    async def share_get_attr(
        share_code: str, 
        id: int = -1, 
        sha1: str = "", 
        path: str = "", 
        receive_code: str = "", 
    ) -> dict:
        """从分享获取对应的属性

        :param share_code: 分享码
        :param id: 文件或目录的 id
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`
        :param receive_code: 提取码，如果是你自己的分享，可以不传

        :return: 对应的属性
        """
        if not share_code:
            return {"is_dir": True, "id": "0"}
        if id < 0:
            id = await share_get_id(share_code, sha1=sha1, path=path, receive_code=receive_code)
        if id == 0:
            share_info = await get_share_info(share_code, receive_code)
            return {
                "id": "0", 
                "parent_id": "0", 
                "is_dir": True, 
                "mtime": int(share_info.get("create_time") or 0), 
                "size": int(share_info.get("file_size") or share_info.get("total_size", 0)), 
                "name": share_info["share_title"], 
                "ico": "folder", 
                "share_code": share_code, 
                "receive_code": share_info["receive_code"], 
                "url": f"/<share?share_code={share_code}&id=0", 
            }
        if not receive_code:
            share_info = await get_share_info(share_code)
            receive_code = share_info["receive_code"]
        attr = ID_TO_ATTR.get((share_code, id))
        if attr is None:
            parent_id = await db.share_get_parent_id(con, share_code, id=id, async_=True)
            if parent_id is None:
                resp = await client.share_download_url_app(
                    {"share_code": share_code, "receive_code": receive_code, "file_id": id}, 
                    async_=True, 
                )
                if not resp["state"]:
                    if resp.get("errno") != 4100013:
                        check_response(resp)
                elif not resp["data"]:
                    raise FileNotFoundError(ENOENT, {"id": id})
                async for attr in get_share_file_tree(share_code, receive_code):
                    if int(attr["id"]) == id:
                        return attr
                else:
                    raise FileNotFoundError(ENOENT, {"share_code": share_code, "id": id})
            _ = await get_share_file_list(share_code, receive_code, parent_id)
            attr = ID_TO_ATTR[(share_code, id)]
        else:
            parent_id = attr["parent_id"]
        if attr["type"] != 2 or time() - int(CRE_URL_T_search(urlsplit(attr["thumb"]).query)[0]) >= 60: # type: ignore
            return attr
        _ = await get_share_file_list(share_code, receive_code, parent_id, refresh_thumbs=True)
        return ID_TO_ATTR[(share_code, id)]

    @skip_if_only_webdav(app.router.get("/%3Cshare/%3Clist"))
    @skip_if_only_webdav(app.router.get("/%3Cshare/%3Clist/*"))
    async def share_get_list(
        share_code: str = "", 
        id: int = -1, 
        sha1: str = "", 
        path: str = "", 
        receive_code: str = "", 
    ) -> dict:
        """从分享获取对应的祖先节点列表和子节点信息列表

        :param share_code: 分享码
        :param id: 文件或目录的 id
        :param sha1: 优先级低于 `id`
        :param path: 优先级低于 `sha1`
        :param receive_code: 提取码，如果是你自己的分享，可以不传

        :return: 对应的祖先节点列表和子节点信息列表
        """
        if not share_code:
            shares = await list_my_shares()
            return {
                "ancestors": [{"id": "0", "parent_id": "0", "name": ""}], 
                "children": [{
                    "id": "0", 
                    "parent_id": "0", 
                    "is_dir": True, 
                    "mtime": int(s["create_time"]), 
                    "size": int(s["file_size"]), 
                    "name": s["share_title"], 
                    "ico": "folder", 
                    "share_code": s["share_code"], 
                    "receive_code": s["receive_code"], 
                    "url": f"/<share?share_code={s['share_code']}&id=0", 
                } for s in shares], 
            }
        if not receive_code:
            share_info = await get_share_info(share_code)
            receive_code = share_info["receive_code"]
        if id < 0:
            id = await share_get_id(share_code, sha1=sha1, path=path, receive_code=receive_code)
        return await get_share_file_list(share_code, receive_code, id, refresh_thumbs=True)

    @app.router.get("/%3Cshare/%3Curl")
    @app.router.get("/%3Cshare/%3Curl/*")
    async def share_get_url(
        share_code: str, 
        id: int, 
        receive_code: str = "", 
        image: bool = False, 
        web: bool = False, 
        url_detail: None | bool = None, 
    ) -> str | dict | Response:
        """从分享获取下载链接

        :param share_code: 分享码
        :param id: 文件的 id
        :param receive_code: 提取码，如果是你自己的分享，可以不传
        :param image: 是否为图片
        :param web: 是否使用 web 接口
        :param url_detail: 链接信息完整度设置（内部开发使用，不用管）

        :return: 下载链接的信息
        """
        if not receive_code:
            share_info = await get_share_info(share_code)
            receive_code = share_info["receive_code"]
        if image:
            url = await get_share_image_url(share_code, receive_code, id)
            return wrap_url(url, url_detail)
        if r := DOWNLOAD_URL_CACHE1.get((share_code, id)):
            return wrap_url(r[1], url_detail)
        url = await get_share_file_url(share_code, receive_code, id, use_web_api=web)
        if "&c=0&f=&" in url:
            expire_ts = int(next(v for k, v in parse_qsl(urlsplit(url).query) if k == "t")) - 60 * 5
            DOWNLOAD_URL_CACHE1[(share_code, id)] = (expire_ts, url)
        return wrap_url(url, url_detail)

    if default_web_page:
        @skip_if_only_webdav(app.router.route("/%3Cshare", methods=["GET", "HEAD"]))
        @skip_if_only_webdav(app.router.route("/%3Cshare/<path:path2>", methods=["GET", "HEAD"]))
        async def share_get_page(
            request: Request, 
            share_code: str = "", 
            receive_code: str = "", 
            id: int = -1, 
            sha1: str = "", 
            path: str = "", 
            path2: str = "", 
            search: str = "", 
            file: None | bool = None, 
            image: bool = False, 
            web: bool = False, 
        ) -> Response:
            """对于分享，根据实际情况分流到具体接口

            :param share_code: 分享码
            :param receive_code: 提取码，如果是你自己的分享，可以不传
            :param id: 文件或目录的 id，优先级高于 `sha1`
            :param sha1: 文件的 sha1，优先级高于 `path`
            :param path: 文件或目录的 path，优先级高于 `path2`
            :param path2: 文件或目录的 path，优先级最低
            :param search: 搜索关键词
            :param file: 是否为文件，如果为 None，则需要进一步确定
            :param image: 是否为图片
            :param web: 是否使用 web 接口
            """
            if str(request.url) == "/service-worker.js":
                return text("not found 'service-worker.js'", 404)
            if file is None:
                attr = await share_get_attr(
                    share_code, 
                    id=id, 
                    sha1=sha1, 
                    path=path or path2, 
                    receive_code=receive_code, 
                )
                is_dir = attr["is_dir"]
                id = int(attr["id"])
            else:
                is_dir = not file
                id = await share_get_id(
                    share_code, 
                    id=id, 
                    sha1=sha1, 
                    path=path or path2, 
                    receive_code=receive_code, 
                )
            if not is_dir:
                resp = await share_get_url(
                    share_code, 
                    id=id, 
                    image=image, 
                    web=web, 
                    receive_code=receive_code, 
                    url_detail=True, 
                )
                url: P115URL = resp["url"]
                if web:
                    cookie = resp["headers"]["Cookie"]
                    return Response(
                        302, 
                        headers=[
                            (b"Location", bytes(f"/<download/{quote(url['name'])}?url={quote(url)}", "latin-1")), 
                            (b"Set-Cookie", bytes(cookie[:cookie.find(";")], "latin-1")), 
                        ], 
                    )
                else:
                    return Response(302, [
                        (b"Location", bytes(url, "utf-8")), 
                        (b"Content-Disposition", b'attachment; filename="%s"' % bytes(quote(url["name"], safe=""), "latin-1")), 
                    ], Content(b"application/json; charset=utf-8", dumps(url.__dict__)))
            if search and share_code:
                resp = await client.share_search(
                    {
                        "share_code": share_code, 
                        "receive_code": receive_code, 
                        "cid": id, 
                        "search_value": search, 
                        "limit": 10000, 
                    }, 
                    async_=True, 
                )
                children = resp["data"]["list"]
                for i, info in enumerate(children):
                    info["share_code"] = share_code
                    info["receive_code"] = receive_code
                    children[i] = normalize_attr(info)
                ancestors = [{"id": 0, "parent_id": 0, "name": ""}, {"id": id, "parent_id": 0, "name": "回到分享"}, {"id": id, "parent_id": 0, "name": "目录信息"}]
            else:
                file_list = await share_get_list(share_code, id=id, receive_code=receive_code)
                ancestors = file_list["ancestors"]
                children  = file_list["children"]
            return await view_async(
                "share_list", 
                share_code=share_code, 
                ancestors=ancestors, 
                children=children, 
                origin=get_origin(request), 
                load_libass=load_libass, 
                user_agent=detect_ua((request.get_first_header(b"User-agent") or b"").decode("latin-1")), 
                int=int, 
                IMAGE_URL_CACHE=IMAGE_URL_CACHE, 
            )

    # NOTE: 下面是一些其它的工具接口

    @app.router.route("/%3Cdownload", methods=["GET", "HEAD", "POST"])
    @app.router.route("/%3Cdownload/*", methods=["GET", "HEAD", "POST"])
    async def do_download(request: Request, url: str) -> Response:
        """打开某个下载链接后，对数据流进行转发

        :param url: 下载链接
        """
        resp = await client.request(
            url, 
            method=request.method, 
            data=request.stream(), 
            headers=[
                (str(k, "latin-1").title(), str(v, "latin-1"))
                for k, v in request.headers
                if k.lower() != b"host"
            ], 
            follow_redirects=True, 
            raise_for_status=False, 
            parse=None, 
            async_=True, 
        )
        async def stream():
            stream = resp.aiter_raw()
            try:
                async for chunk in stream:
                    if await request.is_disconnected():
                        break
                    yield chunk
            finally:
                await resp.aclose()
        content_type = resp.headers.get("content-type") or "application/octent-stream"
        headers = [
            (bytes(k, "latin-1"), bytes(v, "latin-1")) 
            for k, v in resp.headers.items()
            if k.lower() not in (
                b"access-control-allow-methods", 
                b"access-control-allow-origin", 
                b"date", 
                b"content-type", 
                b"transfer-encoding", 
            )
        ]
        headers.append((b"access-control-allow-methods", b"PUT, GET, HEAD, POST, DELETE, OPTIONS"))
        headers.append((b"access-control-allow-origin", b"*"))
        return Response(
            status=resp.status_code, 
            headers=headers, 
            content=StreamedContent(bytes(content_type, "latin-1"), stream), 
        )

    @app.router.route("/%3Credirect", methods=["GET", "HEAD", "POST"])
    @app.router.route("/%3Credirect/*", methods=["GET", "HEAD", "POST"])
    async def do_redirect(url: str) -> Response:
        """对给定的链接进行 302 重定向，可用于某些通过链接中的路径部分来进行判断，但原来的链接缺乏必要信息的情况

        :param url: 下载链接
        """
        return redirect(url)

    @app.router.route("/%3Csub2ass", methods=["GET", "HEAD", "POST"])
    @app.router.route("/%3Csub2ass/*", methods=["GET", "HEAD", "POST"])
    async def sub2ass(request: Request, url: str, format: str = "srt") -> str:
        """把字幕转换为 ASS 格式

        :param url: 下载链接
        :param format: 源文件的字幕格式，默认为 "srt"

        :return: 转换后的字幕文本
        """
        content = await client.request(
            url, 
            method=request.method, 
            data=request.stream(), 
            headers=[
                (str(k, "latin-1").title(), str(v, "latin-1"))
                for k, v in request.headers
                if k.lower() != b"host"
            ], 
            follow_redirects=True, 
            parse=False, 
            async_=True, 
        )
        return SSAFile.from_string(content.decode("utf-8"), format_=format).to_string("ass")

    # NOTE: 下面是 WebDAV 的实现

    class DavPathBase:

        def __getattr__(self, attr: str, /):
            try:
                return self.attr[attr]
            except KeyError as e:
                raise AttributeError(attr) from e

        @locked_cacheproperty
        def mtime(self, /) -> int | float:
            return self.attr.get("mtime", 0)

        @locked_cacheproperty
        def name(self, /) -> str:
            return self.attr["name"]

        @locked_cacheproperty
        def size(self, /) -> int:
            return self.attr.get("size") or 0

        def get_display_name(self, /) -> str:
            return self.name

        def get_etag(self, /) -> str:
            return "%s-%s-%s" % (
                self.attr["id"], 
                self.mtime, 
                self.size, 
            )

        def get_last_modified(self, /) -> float:
            return self.mtime

        def is_link(self, /) -> bool:
            return False

        def support_etag(self, /) -> bool:
            return True

        def support_modified(self, /) -> bool:
            return True

    class FileResource(DavPathBase, DAVNonCollection):

        def __init__(
            self, 
            /, 
            path: str, 
            environ: dict, 
            attr: Mapping, 
            is_strm: bool = False, 
        ):
            super().__init__(path, environ)
            self.attr = attr
            self.is_strm = is_strm
            DAV_FILE_CACHE[path] = self

        if strm_origin:
            origin = strm_origin
        else:
            @locked_cacheproperty
            def origin(self, /) -> str:
                if origin := self.environ.get("STRM_ORIGIN"):
                    return origin
                return f"{self.environ['wsgi.url_scheme']}://{self.environ['HTTP_HOST']}"

        @locked_cacheproperty
        def size(self, /) -> int:
            if self.is_strm:
                return len(self.strm_data)
            return self.attr["size"]

        @locked_cacheproperty
        def strm_data(self, /) -> bytes:
            attr = self.attr
            name = encode_uri_component_loose(attr["name"])
            if share_code := attr.get("share_code"):
                url = f"{self.origin}/<share/<url/{name}?share_code={share_code}&id={attr['id']}"
            else:
                url = f"{self.origin}/<url/{name}?pickcode={attr['pickcode']}&id={attr['id']}&sha1={attr['sha1']}"
            return bytes(url, "utf-8")

        @locked_cacheproperty
        def url(self, /) -> str:
            attr = self.attr
            name = encode_uri_component_loose(attr["name"])
            if share_code := attr.get("share_code"):
                return f"/<share/<url?share_code={share_code}&id={attr['id']}"
            else:
                return f"/<url?pickcode={attr['pickcode']}"

        def get_content(self, /):
            if self.is_strm:
                return BytesIO(self.strm_data)
            raise DAVError(302, add_headers=[("Location", self.url)])

        def get_content_length(self, /) -> int:
            return self.size

        def support_content_length(self, /) -> bool:
            return True

        def support_ranges(self, /) -> bool:
            return True

    class FolderResource(DavPathBase, DAVCollection):

        def __init__(
            self, 
            /, 
            path: str, 
            environ: dict, 
            attr: Mapping, 
        ):
            super().__init__(path, environ)
            self.attr = attr

        @locked_cacheproperty
        def children(self, /) -> dict[str, FileResource | FolderResource]:
            children: dict[str, FileResource | FolderResource] = {}
            environ = self.environ
            dir_ = self.path
            if dir_ != "/":
                dir_ += "/"
            if dir_ == "/<share/":
                shares = run_coroutine_threadsafe(list_my_shares(), loop).result()
                for share in shares:
                    share_code = share["share_code"]
                    children[share["share_code"]] = FolderResource(
                        f"/<share/{share_code}@{share['share_title'].replace('/', ':')}"[:256], 
                        environ, 
                        {
                            "id": 0, 
                            "parent_id": 0, 
                            "is_dir": True, 
                            "mtime": int(share["create_time"]), 
                            "size": int(share["file_size"]), 
                            "name": share["share_title"], 
                            "ico": "folder", 
                            "share_code": share_code, 
                            "receive_code": share["receive_code"], 
                        }, 
                    )
            else:
                is_root = False
                id = int(self.attr["id"])
                if dir_.startswith("/<share/"):
                    share_code = self.attr["share_code"]
                    coro = share_get_list(share_code, id, receive_code=self.attr["receive_code"])
                else:
                    is_root = dir_ == "/"
                    coro = get_list(id)
                try:
                    file_list = run_coroutine_threadsafe(coro, loop).result()
                except FileNotFoundError:
                    raise DAVError(404, dir_)
                for attr in file_list["children"]:
                    is_dir = attr["is_dir"]
                    is_strm = False
                    name = attr["name"].replace("/", "|")
                    if not is_dir and strm_predicate and strm_predicate(MappingPath(attr)):
                        is_strm = True
                        name = splitext(name)[0] + ".strm"
                        path = dir_ + name
                    elif predicate and not predicate(MappingPath(attr)):
                        continue
                    else:
                        path = dir_ + name
                    if is_dir:
                        children[name] = FolderResource(path, environ, attr)
                    else:
                        children[name] = FileResource(path, environ, attr, is_strm=is_strm)
                if is_root:
                    children["<share"] = FolderResource(
                        "/<share", environ, {"id": 0, "name": "<share", "size": 0})
            return children

        def get_member(self, /, name: str) -> FileResource | FolderResource:
            if attr := self.children.get(name):
                return attr
            raise DAVError(404, self.path + "/" + name)

        def get_member_list(self, /) -> list[FileResource | FolderResource]:
            return list(self.children.values())

        def get_member_names(self, /) -> list[str]:
            return list(self.children)

        def get_property_value(self, /, name: str):
            if name == "{DAV:}getcontentlength":
                return 0
            elif name == "{DAV:}iscollection":
                return True
            return super().get_property_value(name)

    class P115FileSystemProvider(DAVProvider):

        def get_resource_inst(
            self, 
            /, 
            path: str, 
            environ: dict, 
        ) -> FolderResource | FileResource:
            is_dir = path.endswith("/")
            path = "/" + path.strip("/")
            if not strm_origin:
                origin = environ["STRM_ORIGIN"] = f"{environ['wsgi.url_scheme']}://{environ['HTTP_HOST']}"
            will_get_from_list = "|" in path
            dir_, name = splitpath(path)
            if not is_dir:
                if inst := DAV_FILE_CACHE.get(path):
                    if not strm_origin and origin != inst.origin:
                        inst = FileResource(path, environ, inst.attr, is_strm=inst.is_strm)
                    return inst
                will_get_from_list = will_get_from_list or path.endswith(".strm")
            if will_get_from_list:
                inst = self.get_resource_inst(dir_ + "/", environ)
                if not isinstance(inst, FolderResource):
                    raise DAVError(404, path)
                return inst.get_member(name)
            if path == "/<share":
                return FolderResource("/<share", environ, {"id": 0, "name": "<share", "size": 0})
            else:
                if path.startswith("/<share/"):
                    share_code, _, share_path = path[8:].partition("/")
                    share_code = share_code.partition("@")[0]
                    coro = share_get_attr(share_code=share_code, path=share_path)
                else:
                    coro = get_attr(path=path)
                try:
                    attr = run_coroutine_threadsafe(coro, loop).result()
                except FileNotFoundError:
                    raise DAVError(404, path)
                is_strm = False
                is_dir = attr["is_dir"]
                if not is_dir and strm_predicate and strm_predicate(MappingPath(attr)):
                    is_strm = True
                    path = splitext(path)[0] + ".strm"
                elif predicate and not predicate(MappingPath(attr)):
                    raise DAVError(404, path)
                if is_dir:
                    return FolderResource(path, environ, attr)
                else:
                    return FileResource(path, environ, attr, is_strm=is_strm)

        def is_readonly(self, /) -> bool:
            return True

    @app.router.route("/*", methods=["PROPFIND"])
    def index(request: Request):
        return redirect(f"/<dav{request.url}")

    if only_webdav:
        app.router.route("/*", methods=["GET", "HEAD"])(index)

    @app.router.route("/*", methods=["OPTIONS"])
    def options(request: Request):
        return ""

    # NOTE: https://wsgidav.readthedocs.io/en/latest/user_guide_configure.html
    wsgidav_config = {
        "host": "0.0.0.0", 
        "port": 0, 
        "mount_path": "/<dav", 
        "simple_dc": {"user_mapping": {"*": True}}, 
        **wsgidav_config, 
        "provider_mapping": {"/": P115FileSystemProvider()}, 
    }
    mount_path = quote(wsgidav_config["mount_path"])
    wsgidav_app = WsgiDAVApp(wsgidav_config)
    app.mount(mount_path, WSGIMiddleware(wsgidav_app, workers=128, send_queue_size=256))

    return app


if __name__ == "__main__":
    import sys
    sys.path[0] = str(Path(__file__).parents[1])

    import uvicorn

    app = make_application(debug=True, load_libass=True, dbfile="p115dav-test.db")
    try:
        uvicorn.run(
            app, 
            host="0.0.0.0", 
            port=8000, 
            proxy_headers=True, 
            server_header=False, 
            forwarded_allow_ips="*", 
            timeout_graceful_shutdown=1, 
            access_log=False, 
        )
    finally:
        with suppress(OSError):
            remove("p115dav-test.db")
        with suppress(OSError):
            remove("p115dav-test.db-shm")
        with suppress(OSError):
            remove("p115dav-test.db-wal")

# TODO: 支持自定义挂载分享链接（可以取名字以及目录结构，通过子应用挂载到特定路径下，但也可以直接由 share_code 获取）
# TODO: IMAGE_URL_CACHE 用 id 作key，各种都用 id 作 key

# TODO: 更完整信息的支持，类似 xattr
# TODO: 支持 fuse 挂载
# TODO: 虽然115分享的图片也能获去cdn图片，但是并不能单独获取某个文件的属性，因此并不能给图片更新，除非这张图片被转存了，然后缓存转存后的pickcode，以后就可以反复更新了
# TODO: 加上搜索框和分页，加上图库浏览功能
# TODO: 播放器实现，播放列表，字幕或歌词绑定，弹幕、封面、元数据等功能
# TODO: 网页版支持播放 m3u8，自动绑定字幕等，这样可以避免那种没有声音的情况，默认使用最高画质，如果没有m3u8，则会退到原始视频
# TODO: 使用115接口保存播放进度
# TODO: 使用 aplayer 播放音乐
# TODO: 在线文本查看器、阅读器
# TODO: 在线播放：播放列表、字幕列表（自动执行绑定视频）、多码率列表
# TODO: 支持自定义转换规则，把 srt 转换为 ass 时，添加样式和字体，或者添加一个在线的样式选择框，就像 115
# TODO: 直接用 m3u8 实现播放列表和各种附加，这样一切都是流媒体
# TODO: 可选参数：文件缓存，文件大小小于一定值的时候，把整个文件下载到数据库，使用 sha1 和 size 作为 key
# TODO: webdav 支持读写？
# TODO: 使用多接口+多cookies进行分流，如果是 web 或 harmony，则只分配网页版接口
# TODO: 把数据库操作的模块专门分拆出来，db.py，原始行为就不是异步
# TODO: 依然要支持 ctime，不再使用 aps 接口
# TODO: 图片 CDN 链接
# TODO: 缓存 m3u8 和 subtitles

# TODO: 如果没有 client，则字幕文件使用 listdir
# TODO: 支持 p115tiny302 的链接格式
# TODO: 网页版支持另一套更现代化观感的 UI
