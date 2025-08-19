#!/usr/bin/env python3
# encoding: utf-8

from __future__ import annotations

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_application"]

from asyncio import to_thread
from collections.abc import Callable, Mapping, MutableMapping
from datetime import datetime
from inspect import getsource
from io import BytesIO
from os import environ, PathLike
from pathlib import Path
from posixpath import splitext, split as splitpath
from sqlite3 import connect, register_adapter, register_converter, Connection
from string import hexdigits
from threading import Lock
from urllib.parse import quote
from weakref import WeakValueDictionary

from a2wsgi import WSGIMiddleware
from blacksheep import redirect, text, Application, Router
from blacksheep.contents import Content, StreamedContent
from blacksheep.messages import Request, Response
from blacksheep.server.compression import use_gzip_compression
from blacksheep.server.remotes.forwarding import ForwardedHeadersMiddleware
from blacksheep.server.rendering.jinja2 import JinjaRenderer
from blacksheep.server.responses import view_async
from blacksheep.settings.html import html_settings
from blacksheep.settings.json import json_settings
from cachedict import LRUDict
from encode_uri import encode_uri, encode_uri_component_loose
from httpagentparser import detect as detect_ua # type: ignore
from httpx import Client, AsyncClient
from orjson import dumps as json_dumps, loads as json_loads
from p115client import check_response, P115Client, P115URL
from p115client.exception import AuthenticationError, BusyOSError
from path_predicate import MappingPath
from posixpatht import escape
from property import locked_cacheproperty
from pysubs2 import SSAFile # type: ignore
from sqlitetools import execute, find
from texttools import format_size, format_timestamp
from wsgidav.wsgidav_app import WsgiDAVApp # type: ignore
from wsgidav.dav_error import DAVError # type: ignore
from wsgidav.dav_provider import DAVCollection, DAVNonCollection, DAVProvider # type: ignore

from .db import (
    attr_to_path, get_id_from_db, get_pickcode_from_db, get_sha1_from_db, 
    get_ancestors_from_db, get_attr_from_db, get_children_from_db, 
)


register_adapter(dict, json_dumps)
register_adapter(list, json_dumps)
register_converter("JSON", json_loads)

environ["APP_JINJA_PACKAGE_NAME"] = "p115servedb"
html_settings.use(JinjaRenderer(enable_async=True))
json_settings.use(loads=json_loads)
jinja_env = getattr(html_settings.renderer, "env")
jinja2_filters = jinja_env.filters
jinja2_filters["format_size"] = format_size
jinja2_filters["encode_uri"] = encode_uri
jinja2_filters["encode_uri_component"] = encode_uri_component_loose
jinja2_filters["json_dumps"] = lambda data: json_dumps(data).decode("utf-8").replace("'", "&apos;")
jinja2_filters["format_timestamp"] = format_timestamp
jinja2_filters["escape_name"] = lambda name, default="/": escape(name) or default


def get_status_code(e: BaseException, /) -> None | int:
    status = (
        getattr(e, "status", None) or 
        getattr(e, "code", None) or 
        getattr(e, "status_code", None)
    )
    if status is None and hasattr(e, "response"):
        response = e.response
        status = (
            getattr(response, "status", None) or 
            getattr(response, "code", None) or 
            getattr(response, "status_code", None)
        )
    return status


def get_origin(request: Request) -> str:
    return f"{request.scheme}://{request.host}"


def check_pickcode(pickcode: str, /, raise_for_false: bool = True):
    result = 17 <= len(pickcode) <= 18 and pickcode.isalnum()
    if raise_for_false and not result:
        raise ValueError(f"bad pickcode: {pickcode!r}")
    return result


def check_sha1(sha1: str, /, raise_for_false: bool = True):
    result = len(sha1) == 40 and not sha1.strip(hexdigits)
    if raise_for_false and not result:
        raise ValueError(f"bad sha1: {sha1!r}")
    return result


def make_application(
    dbfile: bytes | str | PathLike, 
    cookies_path: str | Path = "", 
    strm_origin: str = "", 
    predicate: None | Callable[[MappingPath], bool] = None, 
    strm_predicate: None | Callable[[MappingPath], bool] = None, 
    load_libass: bool = False, 
    debug: bool = False, 
    wsgidav_config: dict = {}, 
) -> Application:
    if cookies_path:
        cookies_path = Path(cookies_path)
    else:
        cookies_path = Path("115-cookies.txt")
        if not cookies_path.exists():
            cookies_path = ""

    app = Application(router=Router(), show_error_details=debug)
    use_gzip_compression(app)
    app.serve_files(
        Path(__file__).parent.with_name("static"), 
        root_path="/%3Cstatic", 
        fallback_document="index.html", 
    )
    client = P115Client(cookies_path, app="alipaymini", check_for_relogin=True) if cookies_path else None
    session: Client
    async_session: AsyncClient
    con: Connection
    con_file: Connection

    # NOTE: webdav 的文件对象缓存
    DAV_FILE_CACHE: MutableMapping[str, DAVNonCollection] = LRUDict(maxsize=65536)
    # NOTE: 文件缓存的读写锁
    FILE_LOCK_CACHE: MutableMapping[tuple[str, int], Lock] = WeakValueDictionary()
    # NOTE: 缓存文件数据
    FILE_DATA_CACHE: MutableMapping[tuple[str, int], bytes] = LRUDict(maxsize=128)

    @app.on_middlewares_configuration
    def configure_forwarded_headers(app: Application):
        app.middlewares.insert(0, ForwardedHeadersMiddleware(accept_only_proxied_requests=False))

    @app.lifespan
    async def register_client(app: Application):
        nonlocal session
        with Client() as session:
            app.services.register(Client, instance=session)
            yield

    @app.lifespan
    async def register_async_client(app: Application):
        nonlocal async_session
        async with AsyncClient() as async_session:
            app.services.register(AsyncClient, instance=async_session)
            yield

    @app.lifespan
    async def register_connection(app: Application):
        nonlocal con
        with connect(
            dbfile, 
            check_same_thread=False, 
            uri=isinstance(dbfile, str) and dbfile.startswith("file:"), 
        ) as con:
            app.services.register(Connection, instance=con)
            yield

    @app.lifespan
    async def register_file_connection(app: Application):
        nonlocal con_file
        con = app.services.resolve(Connection)
        path = find(con, "SELECT file FROM pragma_database_list() WHERE name='main';")
        if path:
            dbpath = "%s-file%s" % splitext(path)
            uri = False
        else:
            dbpath = "file:file?mode=memory&cache=shared"
            uri = True
        with connect(
            dbpath, 
            autocommit=True, 
            check_same_thread=False, 
            uri=uri, 
        ) as con_file:
            con_file.executescript("""\
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS data (
    sha1 TEXT NOT NULL,
    size INTEGER NOT NULL,
    data BLOB
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sha1_size ON data(sha1, size);""")
            yield

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
                Content(b"application/json", json_dumps(exc.args[-1])), 
            )
        return text(str(exc), status_code)

    if debug:
        getattr(app, "logger").level = 10
    else:
        @app.exception_handler(Exception)
        async def redirect_exception_response(
            self, 
            request: Request, 
            exc: BaseException, 
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
            elif isinstance(exc, BusyOSError):
                return make_response_for_exception(exc, 503) # Service Unavailable
            elif isinstance(exc, OSError):
                return make_response_for_exception(exc, 500) # Internal Server Error
            else:
                return make_response_for_exception(exc, 503) # Service Unavailable

    @app.router.get("/%3Cid")
    @app.router.get("/%3Cid/*")
    async def get_id(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
    ) -> int:
        if pickcode:
            check_pickcode(pickcode)
            return await to_thread(get_id_from_db, con, pickcode=pickcode.lower())
        elif id >= 0:
            return id
        elif sha1:
            check_sha1(sha1)
            return await to_thread(get_id_from_db, con, sha1=sha1.upper())
        else:
            return await to_thread(get_id_from_db, con, path=path)

    @app.router.get("/%3Cpickcode")
    @app.router.get("/%3Cpickcode/*")
    async def get_pickcode(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
    ) -> str:
        if pickcode:
            check_pickcode(pickcode)
            return pickcode.lower()
        elif id >= 0:
            return await to_thread(get_pickcode_from_db, con, id=id)
        elif sha1:
            check_sha1(sha1)
            return await to_thread(get_pickcode_from_db, con, sha1=sha1.upper())
        else:
            return await to_thread(get_pickcode_from_db, con, path=path)

    @app.router.get("/%3Csha1")
    @app.router.get("/%3Csha1/*")
    async def get_sha1(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
    ) -> str:
        if pickcode:
            check_pickcode(pickcode)
            return await to_thread(get_sha1_from_db, con, pickcode=pickcode.lower())
        elif id >= 0:
            return await to_thread(get_sha1_from_db, con, id=id)
        elif sha1:
            check_sha1(sha1)
            return sha1.upper()
        else:
            return await to_thread(get_sha1_from_db, con, path=path)

    @app.router.get("/%3Cattr")
    @app.router.get("/%3Cattr/*")
    async def get_attr(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
    ) -> dict:
        id = await get_id(id=id, pickcode=pickcode, sha1=sha1, path=path)
        return await to_thread(get_attr_from_db, con, id)

    @app.router.get("/%3Clist")
    @app.router.get("/%3Clist/*")
    async def get_list(
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
    ) -> dict:
        id = await get_id(id=id, pickcode=pickcode, sha1=sha1, path=path)
        return {
            "ancestors": await to_thread(get_ancestors_from_db, con, id), 
            "children": await to_thread(get_children_from_db, con, id), 
        }

    if client is not None:
        @app.router.get("/%3Cm3u8")
        @app.router.get("/%3Cm3u8/*")
        async def get_m3u8(pickcode: str = ""):
            """获取 m3u8 文件链接
            """
            resp = await client.fs_video_app(pickcode, async_=True)
            check_response(resp)
            return resp["data"]["video_url"]

        @app.router.get("/%3Csubtitles")
        @app.router.get("/%3Csubtitles/*")
        async def get_subtitles(pickcode: str):
            """获取字幕（随便提供此文件夹内的任何一个文件的提取码即可）
            """
            resp = await client.fs_video_subtitle(pickcode, async_=True)
            return check_response(resp).get("data")

    @app.router.get("/%3Curl")
    @app.router.get("/%3Curl/*")
    async def get_url(
        request: Request, 
        pickcode: str, 
        web: bool = False, 
    ) -> dict:
        """获取下载链接

        :param pickcode: 文件的 pickcode
        :param web: 是否使用 web 接口
        """
        if client is None:
            return {"type": "file", "url": f"{strm_origin}?pickcode={pickcode}"}
        else:
            url = await client.download_url(
                pickcode, 
                headers={"User-Agent": (request.get_first_header(b"User-agent") or b"").decode("latin-1")}, 
                use_web_api=web, 
                app="android", 
                async_=True, 
            )
            return {"type": "file", "url": url, "headers": url.get("headers")}

    @app.router.route("/", methods=["GET", "HEAD"])
    @app.router.route("/<path:path2>", methods=["GET", "HEAD"])
    async def get_page(
        request: Request, 
        id: int = -1, 
        pickcode: str = "", 
        sha1: str = "", 
        path: str = "", 
        path2: str = "", 
        file: None | bool = None, 
        web: bool = False, 
    ) -> Response:
        """根据实际情况分流到具体接口

        :param id: 文件或目录的 id，优先级高于 `sha1`
        :param pickcode: 文件或目录的 pickcode，优先级高于 `id`，为最高
        :param sha1: 文件的 sha1，优先级高于 `path`
        :param path: 文件或目录的 path，优先级高于 `path2`
        :param path2: 文件或目录的 path，优先级最低
        :param file: 是否为文件，如果为 None，则需要进一步确定
        :param web: 是否使用 web 接口
        """
        if path2 == "service-worker.js" and str(request.url) == "/service-worker.js":
            return text("not found 'service-worker.js'", 404)
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
        elif file:
            is_dir = False
            attr = await get_attr(
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
            def get_ranged_data(data, /):
                bytes_range = request.get_first_header(b"Range") or b""
                if bytes_range:
                    b = bytearray()
                    m = memoryview(data)
                    for rng in bytes_range.decode("latin-1").removeprefix("bytes=").split(", "):
                        if rng.startswith("-"):
                            b += data[int(rng):]
                        elif rng.endswith("-"):
                            b += data[int(rng[:-1]):]
                        else:
                            start, end = map(int, rng.split("-", 1))
                            b += data[start:end+1]
                    return Response(
                        206, 
                        headers=[(b"Content-Length", b"%d" % len(b)), (b"Accept-Ranges", b"bytes"), (b"Range", bytes_range)], 
                        content=Content(b"application/octent-stream", data=b), 
                    )
                else:
                    return Response(
                        200, 
                        headers=[(b"Content-Length", b"%d" % size)], 
                        content=Content(b"application/octent-stream", data=data), 
                    )
            sha1, size, pickcode = attr["sha1"], attr["size"], attr["pickcode"]
            key = (sha1, size)
            if size <= 1024 * 64:
                if data := FILE_DATA_CACHE.get(key):
                    return get_ranged_data(data)
                else:
                    data = await to_thread(
                        find, 
                        con_file, 
                        "SELECT data FROM data WHERE sha1=:sha1 AND size=:size", 
                        locals(), 
                    )
                if data is not None:
                    FILE_DATA_CACHE[key] = data
                    return get_ranged_data(data)
            resp = await get_url(
                request, 
                pickcode=pickcode, 
                web=web, 
            )
            url: P115URL = resp["url"]
            if size <= 1024 * 64:
                with FILE_LOCK_CACHE.setdefault(key, Lock()):
                    if data := FILE_DATA_CACHE.get(key):
                        return get_ranged_data(data)
                    else:
                        data = await to_thread(
                            find, 
                            con_file, 
                            "SELECT data FROM data WHERE sha1=:sha1 AND size=:size", 
                            locals(), 
                        )
                        if data is not None:
                            FILE_DATA_CACHE[key] = data
                            return get_ranged_data(data)
                    if client is None:
                        resp = await async_session.request("GET", url, headers=url.get("headers"))
                        data = await resp.aread()
                    else:
                        data = await client.read_bytes(url, async_=True)
                    FILE_DATA_CACHE[key] = data
                    await to_thread(execute, con_file, """\
INSERT INTO data(sha1, size, data) VALUES(:sha1, :size, :data) 
ON CONFLICT DO UPDATE SET data = excluded.data;""", locals())
                    return get_ranged_data(data)
            if web:
                cookie = resp["headers"]["Cookie"]
                return Response(
                    302, 
                    headers=[
                        (b"Location", bytes(f"/<download/{encode_uri_component_loose(url['name'])}?url={quote(url)}", "latin-1")), 
                        (b"Set-Cookie", bytes(cookie[:cookie.find(";")], "latin-1")), 
                    ], 
                )
            else:
                return redirect(url)
        file_list = await get_list(id=id)
        return await view_async(
            "list", 
            ancestors=file_list["ancestors"], 
            children=file_list["children"], 
            origin=get_origin(request), 
            load_libass=load_libass, 
            user_agent=detect_ua((request.get_first_header(b"User-agent") or b"").decode("latin-1")), 
        )

    @app.router.route("/%3Cdownload", methods=["GET", "HEAD", "POST"])
    @app.router.route("/%3Cdownload/*", methods=["GET", "HEAD", "POST"])
    async def do_download(
        request: Request, 
        session: AsyncClient, 
        url: str, 
        timeout: None | float = None, 
    ) -> Response:
        """打开某个下载链接后，对数据流进行转发

        :param url: 下载链接
        """
        resp = await session.send(
            request=session.build_request(
                method=request.method, 
                url=url, 
                data=request.stream(), # type: ignore
                headers=[
                    (str(k, "latin-1").title(), str(v, "latin-1"))
                    for k, v in request.headers
                    if k.lower() != b"host"
                ], 
                timeout=timeout, 
            ), 
            stream=True, 
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
            if k.lower() not in (b"access-control-allow-methods", b"access-control-allow-origin", b"date", b"content-type", b"transfer-encoding")
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
    async def sub2ass(
        request: Request, 
        session: AsyncClient, 
        url: str, 
        format: str = "srt", 
    ) -> str:
        """把字幕转换为 ASS 格式

        :param url: 下载链接
        :param format: 源文件的字幕格式，默认为 "srt"

        :return: 转换后的字幕文本
        """
        resp = await session.send(
            request=session.build_request(
                method=request.method, 
                url=url, 
                data=request.stream(), # type: ignore
                headers=[
                    (str(k, "latin-1").title(), str(v, "latin-1"))
                    for k, v in request.headers
                    if k.lower() != b"host"
                ], 
            ), 
        )
        data = await resp.aread()
        return SSAFile.from_string(data.decode("utf-8"), format_=format).to_string("ass")

    class DavPathBase:

        def __getattr__(self, attr: str, /):
            try:
                return self.attr[attr]
            except KeyError as e:
                raise AttributeError(attr) from e

        @locked_cacheproperty
        def creationdate(self, /) -> float:
            return self.attr["ctime"]

        @locked_cacheproperty
        def mtime(self, /) -> int | float:
            return self.attr["mtime"]

        @locked_cacheproperty
        def name(self, /) -> str:
            return self.attr["name"]

        @locked_cacheproperty
        def size(self, /) -> int:
            return self.attr.get("size") or 0

        def get_creation_date(self, /) -> float:
            return self.creationdate

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
        def file_data(self, /) -> bytes:
            attr = self.attr
            size = attr["size"]
            if size > 1024 * 64:
                raise DAVError(302, add_headers=[("Location", self.url)])
            sha1 = attr["sha1"]
            key = (sha1, size)
            if data := FILE_DATA_CACHE.get(key):
                return data
            with FILE_LOCK_CACHE.setdefault(key, Lock()):
                data = find(
                    con_file, 
                    "SELECT data FROM data WHERE sha1=:sha1 AND size=:size", 
                    locals(), 
                )
                if data is not None:
                    FILE_DATA_CACHE[key] = data
                    return data
                data = FILE_DATA_CACHE[key] = session.request("GET", self.url).read()
                execute(con_file, """\
INSERT INTO data(sha1, size, data) VALUES(:sha1, :size, :data) 
ON CONFLICT DO UPDATE SET data = excluded.data;""", locals())
                return data

        @locked_cacheproperty
        def size(self, /) -> int:
            if self.is_strm:
                return len(self.strm_data)
            return self.attr["size"]

        @locked_cacheproperty
        def strm_data(self, /) -> bytes:
            attr = self.attr
            name = encode_uri_component_loose(attr["name"])
            return bytes(f"{self.origin}/{name}?file=true&pickcode={attr['pickcode']}&id={attr['id']}&sha1={attr['sha1']}", "utf-8")

        @locked_cacheproperty
        def url(self, /) -> str:
            return f"{self.origin}/?file=true&pickcode={self.attr['pickcode']}"

        def get_content(self, /):
            if self.is_strm:
                return BytesIO(self.strm_data)
            return BytesIO(self.file_data)

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
            try:
                ls = get_children_from_db(con, int(self.attr["id"]))
            except FileNotFoundError:
                raise DAVError(404, dir_)
            for attr in ls:
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
            try:
                attr = attr_to_path(con, path, ensure_file=False if is_dir else None)
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

# TODO: 目前 webdav 是只读的，之后需要支持写入和删除，写入小文件不会上传，因此需要一个本地的 id，如果路径上原来有记录，则替换掉此记录（删除记录，生成本地 id 的数据，插入数据）
# TODO: 如果需要写入文件，会先把数据存入临时文件，等到关闭文件，再自动写入数据库。如果文件未被修改，则忽略，如果修改了，就用我本地的id替代原来的数据
# TODO: 文件可以被 append 写，这时打开时，会先把数据库的数据写到硬盘，然后打开这个临时文件
# TODO: 实现 get_properties: https://wsgidav.readthedocs.io/en/latest/_autosummary/wsgidav.dav_provider.DAVNonCollection.get_properties.html#wsgidav.dav_provider.DAVNonCollection.get_properties
# TODO: 应该可以自行指定缓存文件的大小（默认为 64 KB），也可以根据是不是本地网络，来决定走缓存还是走直链
