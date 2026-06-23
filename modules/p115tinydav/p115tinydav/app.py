#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_application"]

from asyncio import create_task, sleep, to_thread, Task, Queue
from contextlib import suppress
from html import escape
from mimetypes import guess_type
from os import fsdecode, PathLike
from posixpath import join as joinpath
from pathlib import Path
from sqlite3 import Connection
from time import time
from urllib.parse import quote

from blacksheep import redirect, Application, Request, Response, Router
from blacksheep.contents import Content
from blacksheep.server.remotes.forwarding import ForwardedHeadersMiddleware
from blacksheep_rich_log import middleware_access_log
from cachedict import TTLDict, LRUDict
from p115client import P115Client, P115URL
from p115client.tool import get_pic_url, P115QueryDB
from yarl import URL

with suppress(ImportError, AttributeError):
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    soft_new = min(max(soft, 65536), hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft_new, hard))

from .db import get_con, init_db, updatedb_tree, updatedb_life


def make_application(
    client: str | PathLike | P115Client = Path("~/115-cookies.txt").expanduser(), 
    dbfile: str | PathLike = "", 
    debug: bool = False, 
    cache_url: bool = True, 
) -> Application:
    CACHE_IMAGE_URL: LRUDict[str, str] = LRUDict(65536)
    CACHE_URL: TTLDict[tuple[int, str], P115URL] = TTLDict(3600, maxsize=1024)
    if not isinstance(client, P115Client):
        client = P115Client(client)
    dbfile = fsdecode(dbfile)
    if not dbfile:
        dbfile = f"p115tinydav-{client.user_id}.db"
    task_queue: Queue = Queue()
    put_task = task_queue.put_nowait
    DB_READ_URI  = f"file:{quote(dbfile)}?mode=ro"
    DB_WRITE_URI = f"file:{quote(dbfile)}?mode=rwc"
    app = Application(router=Router(), show_error_details=debug)
    app.services.register(P115Client, instance=client)
    middleware_access_log(app)
    logger = getattr(app, "logger")
    if debug:
        logger.level = 10 # logging.DEBUG

    @app.on_middlewares_configuration
    def configure_forwarded_headers(app: Application):
        app.middlewares.insert(0, ForwardedHeadersMiddleware(accept_only_proxied_requests=False))

    @app.lifespan
    async def initdb(app: Application):
        con = get_con(DB_WRITE_URI)
        app.services.register(Connection, instance=con)
        init_db(con)
        yield

    async def hour_life_update():
        while True:
            await sleep(3600)
            put_task("life")

    async def run_background_tasks(app: Application, con: Connection):
        last_update_ts, = con.execute("SELECT val FROM keystore WHERE key='last_update_ts'").fetchone()
        if not last_update_ts:
            put_task("top")
        put_task("life")
        hour_task = create_task(hour_life_update())
        get_task = task_queue.get
        last_life_ts: float = 0
        try:
            i = 0
            while True:
                i += 1
                task = await get_task()
                try:
                    logger.debug(f"task[{i}]={task!r} \x1b[1;5;35mstarting\x1b[0m")
                    match task:
                        case "life":
                            if time() - last_life_ts > 1:
                                await updatedb_life(client, con)
                                last_life_ts = time()
                            else:
                                logger.debug(f"task[{i}]={task!r} \x1b[1;33mskipped\x1b[0m")
                                continue
                        case "top":
                            await updatedb_tree(client, con)
                        case ("tree", id):
                            await updatedb_tree(client, con, id)
                        case ("dir", id):
                            await updatedb_tree(client, con, id, recursive=False)
                        case _:
                            logger.debug(f"task[{i}]={task!r} \x1b[1;33mskipped\x1b[0m")
                            continue
                    logger.info(f"task[{i}]={task!r} \x1b[1;32msucceeded\x1b[0m")
                except Exception as e:
                    e_type = type(e)
                    module = e_type.__module__
                    name   = e_type.__qualname__
                    if module not in ("builtins", "__main__"):
                        name = module + "." + name
                    msg = f"task[{i}]={task!r} \x1b[1;31mfailed\x1b[0m with \x1b[1;31m{name}\x1b[0m: {e}"
                    if debug:
                        logger.exception(msg)
                    else:
                        logger.error(msg)
                    if task == "top":
                        put_task(task)
        finally:
            hour_task.cancel()

    @app.on_start
    async def start_background_tasks(app: Application):
        background_tasks = create_task(run_background_tasks(app, app.services.resolve(Connection)))
        app.services.register(Task, isinstance=background_tasks)

    @app.on_stop
    async def stop_background_tasks(app: Application):
        background_tasks = app.services.resolve(Task)
        background_tasks.cancel()

    def iter_response_parts(attr: dict, /):
        yield f"<d:response><d:href>{escape(quote(attr["path"]))}</d:href><d:propstat><d:prop>"
        yield f"<d:displayname>{escape(quote(attr["name"]))}</d:displayname>"
        if attr["is_dir"]:
            yield "<d:resourcetype><d:collection/></d:resourcetype>"
        else:
            yield f"<d:getetag>&quot;{attr.get("sha1", "")}&quot;</d:getetag>"
            yield f"<d:getcontentlength>{attr.get("size", 0)}</d:getcontentlength>"
            yield f"<d:getcontenttype>{guess_type(attr["name"])[0] or ""}</d:getcontenttype>"
            yield f"<d:resourcetype></d:resourcetype>"
        yield "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"

    @app.router.route("/<path:path>", methods=["PROPFIND"])
    async def propfind(
        request: Request, 
        id: int = -1, 
        pickcode: str = "", 
        path: str = "/", 
    ):
        put_task("life")
        querydb = P115QueryDB(get_con(DB_READ_URI))
        top_path = ""
        if id < 0:
            if pickcode:
                id = client.to_id(pickcode)
            else:
                id = querydb.get_id(path=path)
                top_path = "/" + path.strip("/")
        attr = querydb.get_attr(id)
        if not top_path:
            top_path = querydb.get_path(id)
        attr["path"] = top_path
        depth = request.headers.get_first(b"depth")
        parts = ['<?xml version="1.0" ?>\n<d:multistatus xmlns:d="DAV:">']
        push_parts = parts.extend
        push_parts(iter_response_parts(attr))
        if depth != b"0" and attr["is_dir"]:
            def load_ancesttors():
                if depth == b"1":
                    for attr in querydb.iter_children(id):
                        attr["path"] = joinpath(top_path, attr["name"])
                        push_parts(iter_response_parts(attr))
                else:
                    for attr in querydb.iter_descendants(id, fields=("id", "parent_id", "name", "sha1", "size", "is_dir", "relpath")):
                        attr["path"] = joinpath(top_path, attr["relpath"])
                        push_parts(iter_response_parts(attr))
            await to_thread(load_ancesttors)
        parts.append("</d:multistatus>")
        content = "".join(parts).encode("utf-8")
        return Response(207, content=Content(b"application/xml; charset=utf-8", content))

    async def get_image_url(sha1: str, /) -> str:
        if cache_url and (url := CACHE_IMAGE_URL.get(sha1)):
            return url
        url = await get_pic_url(client, sha1, async_=True)
        if cache_url:
            CACHE_IMAGE_URL[sha1] = url
        return url

    async def get_url(id: int, /, user_agent: str = "") -> P115URL:
        if cache_url and (url := CACHE_URL.get((id, user_agent))):
            if int(URL(url).query["t"]) - time() > 60 * 5:
                return url
        url = await client.download_url(
            client.to_pickcode(id), 
            app="android", 
            headers={"user-agent": user_agent}, 
            async_=True, 
        )
        if cache_url:
            CACHE_URL[(id, user_agent)] = url
        return url

    # TODO: 后续此方法对于目录，会返回一个网页
    @app.router.route("/<path:path>", methods=["GET", "HEAD"])
    async def get(
        request: Request, 
        id: int = -1, 
        pickcode: str = "", 
        path: str = "/", 
    ):
        querydb = P115QueryDB(get_con(DB_READ_URI))
        if id <= 0:
            if pickcode:
                id = client.to_id(pickcode)
            else:
                id = querydb.get_id(path=path)
        attr = querydb.get_attr(id)
        if attr["is_dir"]:
            raise IsADirectoryError(21, attr)
        if attr["size"] <= 1024 * 1024 * 50:
            url = await get_image_url(attr["sha1"])
        else:
            user_agent = (request.get_first_header(b"user-agent") or b"").decode("latin-1")
            url = await get_url(id, user_agent)
        return redirect(url)

    @app.router.route("/<path:path>", methods=["OPTIONS"])
    async def options():
        return Response(200, [
            (b"DAV", b"1,2"), 
            #(b"Allow", b"OPTIONS, HEAD, GET, PROPFIND, DELETE, COPY, MOVE, PROPPATCH, LOCK, UNLOCK"), 
            (b"Allow", b"OPTIONS, HEAD, GET, PROPFIND"), 
        ])

    return app


if __name__ == "__main__":
    from uvicorn import run

    run(
        make_application(debug=__debug__), 
        host="0.0.0.0", 
        port=8115, 
        proxy_headers=True, 
        server_header=False, 
        forwarded_allow_ips="*", 
        timeout_graceful_shutdown=1, 
        access_log=False, 
    )

# TODO: 实现各种接口，包括搜索、上传等
# TODO: 搜索页面，最上面的三个点，应该返回到被搜索id页（而不是它的更上级）
# TODO: 用户执行请求，如果遇到问题，立即返回错误，至于解决问题，会在后台尝试，什么时候解决，什么时候显示（任务不会重复提交）
# TODO: 有一个在持续运行的后台任务执行器，用来执行 update_life、update_tree 等，而且不会发生冲突
