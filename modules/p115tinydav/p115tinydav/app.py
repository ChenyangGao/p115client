#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_application"]

from asyncio import Lock
from collections.abc import AsyncIterator
from html import escape
from mimetypes import guess_type
from os import PathLike
from pathlib import Path
from posixpath import split as splitpath
from sqlite3 import connect, Connection
from time import time
from urllib.parse import quote, unquote

from blacksheep import redirect, Application, Request, Response, Router
from blacksheep.contents import Content
from blacksheep.server.remotes.forwarding import ForwardedHeadersMiddleware
from blacksheep_rich_log import middleware_access_log
from cachedict import LRUDict, TTLDict
from datefmt import timestamp2isoformat, timestamp2gmtformat
from errno2 import errno
from p115client import check_response, P115Client
from p115client.exception import throw
from p115client.tool import (
    get_id_to_path, iterdir, normalize_attr_simple, traverse_tree_with_path, 
    P115QueryDB, 
)
from sqlitedict import SqliteTableDict
from yarl import URL


def make_application(
    client: str | PathLike | P115Client = Path("~/115-cookies.txt").expanduser(), 
    debug: bool = False, 
    cache_dir_ttl: float = 300, 
    cache_url: bool = True, 
    cache_propfind: bool = True, 
):
    CACHE_ATTR: LRUDict[int | str, dict] = LRUDict(65536)
    CACHE_CHILDREN: TTLDict[int, dict[str, dict]] = TTLDict(cache_dir_ttl, maxsize=1024)
    CACHE_LOCK: LRUDict[int, Lock] = LRUDict(1024)
    CACHE_URL: TTLDict[tuple[int, str], str] = TTLDict(3600, maxsize=1024)
    CACHE_PROPFIND: TTLDict = TTLDict(cache_dir_ttl, maxsize=128)

    con: Connection
    id_to_dirnode: SqliteTableDict
    querydb: P115QueryDB
    if not isinstance(client, P115Client):
        client = P115Client(client, check_for_relogin=True)

    app = Application(router=Router(), show_error_details=debug)
    app.services.register(P115Client, instance=client)
    middleware_access_log(app)
    if debug:
        logger = getattr(app, "logger")
        logger.level = 10 # logging.DEBUG

    async def get_attr(path: int | str, /) -> dict:
        if isinstance(path, str):
            path = "/" + path.strip("/")
            if path == "/":
                return {"id": 0, "parent_id": 0, "is_dir": True, "name": "", "path": "/"}
            if attr := CACHE_ATTR.get(path):
                return attr
            dir_, name = splitpath(path)
            try:
                pid = querydb.get_id(path=dir_, is_alive=False)
            except FileNotFoundError:
                pass
            else:
                if (children := CACHE_CHILDREN.get(pid)) is not None:
                    try:
                        return children[name]
                    except KeyError:
                        throw(errno.ENOENT, path)
            id = await get_id_to_path(client, path, async_=True)
        else:
            id = path
            if attr := CACHE_ATTR.get(id):
                return attr
        resp = await client.fs_file(id, async_=True)
        check_response(resp)
        attr = CACHE_ATTR[id] = CACHE_ATTR[path] = normalize_attr_simple(resp["data"][0])
        return attr

    async def get_children(id: int, /, refresh: bool = False) -> dict[str, dict]:
        start = time()
        async with CACHE_LOCK.setdefault(id, Lock()):
            children: None | dict[str, dict]
            if time() - start > 0.05:
                refresh = False
            if not refresh and (children := CACHE_CHILDREN.get(id)) is not None:
                return children
            children = {}
            async for attr in iterdir(
                client, 
                id, 
                id_to_dirnode=id_to_dirnode, 
                escape=None, 
                normalize_attr=normalize_attr_simple, 
                async_=True, 
            ):
                CACHE_ATTR.pop(attr["id"], None)
                CACHE_ATTR.pop(attr["path"], None)
                children[attr["name"]] = attr
            CACHE_CHILDREN[id] = children
            CACHE_PROPFIND.pop(id, None)
            return children

    async def iter_descentants(id: int, /) -> AsyncIterator[dict]:
        async for attr in traverse_tree_with_path(
            client, 
            id, 
            id_to_dirnode=id_to_dirnode, 
            escape=None, 
            async_=True, 
        ):
            CACHE_ATTR[attr["id"]] = CACHE_ATTR[attr["path"]] = attr
            yield attr

    async def get_url(id: int | str, /, user_agent: str = "", refresh: bool = False) -> str:
        pickcode = client.to_pickcode(id)
        id = client.to_id(pickcode)
        if not refresh and cache_url and (url := CACHE_URL.get((id, user_agent))):
            if int(URL(url).query["t"]) - time() > 60 * 5:
                if debug:
                    logger.debug(f"\x1b[1;32mGET\x1b[0m \x1b[3;5;35mcached\x1b[0m url for id \x1b[1;36m{id}\x1b[0m: \x1b[4;34m{url}\x1b[0m")
                return url
        resp = await client.download_url_app(
            pickcode, app="android", headers={"user-agent": user_agent}, async_=True)
        if not resp["state"]:
            if resp.get("error") == "文件上传不完整":
                throw(errno.EISDIR, id)
            check_response(resp)
        url = resp["data"]["url"]
        if cache_url:
            CACHE_URL[(id, user_agent)] = url
        if debug:
            logger.debug(f"\x1b[1;32mGET\x1b[0m \x1b[3;5;36mfresh\x1b[0m url for id \x1b[1;36m{id}\x1b[0m: \x1b[4;34m{url}\x1b[0m")
        return url

    def iter_response_parts(attr):
        if attr['id']:
            href = f"/<{attr["id"]}/{quote(attr["name"])}"
        else:
            href = "/"
        yield f"<d:response><d:href>{escape(href)}</d:href><d:propstat><d:prop>"
        yield f"<d:displayname>{escape(attr["name"])}</d:displayname>"
        yield f"<d:creationdate>{timestamp2isoformat(attr.get("ctime", 0))}</d:creationdate>"
        yield f"<d:getlastmodified>{timestamp2gmtformat(attr.get("mtime", 0))}</d:getlastmodified>"
        if attr["is_dir"]:
            #yield "<d:getetag></d:getetag>"
            #yield "<d:getcontentlength></d:getcontentlength>"
            #yield "<d:getcontenttype></d:getcontenttype>"
            yield "<d:resourcetype><d:collection/></d:resourcetype>"
        else:
            yield f"<d:getetag>&quot;{attr.get("sha1", "")}&quot;</d:getetag>"
            yield f"<d:getcontentlength>{attr.get("size", 0)}</d:getcontentlength>"
            yield f"<d:getcontenttype>{guess_type(attr["name"])[0] or ""}</d:getcontenttype>"
            yield f"<d:resourcetype></d:resourcetype>"
        yield "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"

    @app.on_middlewares_configuration
    def configure_forwarded_headers(app: Application):
        app.middlewares.insert(0, ForwardedHeadersMiddleware(accept_only_proxied_requests=False))

    @app.lifespan
    async def initdb(app: Application):
        nonlocal con, id_to_dirnode, querydb
        with connect(":memory:", autocommit=True, check_same_thread=False) as con:
            con.executescript("""\
PRAGMA journal_mode = WAL;
CREATE TABLE data (
    id INTEGER NOT NULL PRIMARY KEY, 
    parent_id INTEGER NOT NULL, 
    name STRING NOT NULL, 
    is_dir INTEGER AS (1) VIRTUAL, 
    is_alive INTEGER AS (1) VIRTUAL
);
CREATE INDEX IF NOT EXISTS idx_data_pid ON data(parent_id);
CREATE INDEX IF NOT EXISTS idx_data_utime ON data(parent_id, name);
""")
            id_to_dirnode = SqliteTableDict(con, value=("parent_id", "name"))
            querydb = P115QueryDB(con)
            app.services.register(Connection, instance=con)
            yield

    @app.router.route("/<path:path>", methods=["PROPFIND"])
    async def propfind(
        request: Request, 
        id: int = -1, 
        pickcode: str = "", 
        path: str = "/", 
        refresh: bool = False, 
    ):
        if id >= 0:
            fid: int | str = id
        elif pickcode:
            fid = client.to_id(fid)
        elif path.lstrip("/").startswith("<"):
            fid = client.to_id(path.lstrip("/<").partition("/")[0])
        else:
            fid = path
        attr = await get_attr(fid)
        id = attr["id"]
        depth = request.headers.get_first(b"depth")
        origin = f"{request.scheme}://{request.host}"
        if will_cache_propfind := cache_propfind and depth == b'1' and attr["is_dir"]:
            if (content := CACHE_PROPFIND.get(id)) is not None:
                if debug:
                    logger.debug(f"\x1b[1;32mPROPFIND\x1b[0m a \x1b[3;5;35mcached\x1b[0m xml for \x1b[4;34m{origin}{unquote(str(request.url))}\x1b[0m")
                return Response(207, content=Content(b"application/xml; charset=utf-8", content))
        parts = ['<?xml version="1.0" ?>\n<d:multistatus xmlns:d="DAV:">']
        push_parts = parts.extend
        push_parts(iter_response_parts(attr))
        if depth != b'0' and attr["is_dir"]:
            if depth == b'1':
                children = await get_children(id, refresh=refresh)
                for attr in children.values():
                    push_parts(iter_response_parts(attr))
            else:
                async for attr in iter_descentants(id):
                    push_parts(iter_response_parts(attr))
        parts.append("</d:multistatus>")
        content = "".join(parts).encode("utf-8")
        if will_cache_propfind:
            CACHE_PROPFIND[id] = content
        if debug:
            logger.debug(f"\x1b[1;32mPROPFIND\x1b[0m a \x1b[3;5;36mfresh\x1b[0m xml for \x1b[4;34m{origin}{unquote(str(request.url))}\x1b[0m")
        return Response(207, content=Content(b"application/xml; charset=utf-8", content))

    @app.router.route("/<path:path>", methods=["GET"])
    async def get(
        request: Request, 
        id: int = -1, 
        pickcode: str = "", 
        path: str = "/", 
        refresh: bool = False, 
    ):
        if id >= 0:
            pickcode = client.to_pickcode(id)
        elif pickcode:
            id = client.to_id(pickcode)
        elif path.lstrip("/").startswith("<"):
            fid = path.lstrip("/<").partition("/")[0]
            id = client.to_id(fid)
            pickcode = client.to_pickcode(fid)
        else:
            attr = await get_attr(path)
            id = attr["id"]
            pickcode = client.to_pickcode(id, prefix="fa" if attr["is_dir"] else "a")
        if not pickcode.startswith("f"):
            user_agent = (request.get_first_header(b"user-agent") or b"").decode("latin-1")
            try:
                return redirect(await get_url(id, user_agent, refresh=refresh))
            except IsADirectoryError:
                pass
        return await get_children(id, refresh=refresh)

    @app.router.route("/<path:path>", methods=["OPTIONS"])
    async def options():
        return b""

    return app


if __name__ == "__main__":
    from uvicorn import run

    run(
        make_application(debug=__debug__), 
        host="0.0.0.0", 
        port=8000, 
        proxy_headers=True, 
        server_header=False, 
        forwarded_allow_ips="*", 
        timeout_graceful_shutdown=1, 
        access_log=False, 
    )

# TODO: 实现各种接口，包括搜索、上传等

