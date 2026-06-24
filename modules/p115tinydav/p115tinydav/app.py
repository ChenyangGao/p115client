#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_application"]

from asyncio import create_task, sleep, Task, Queue
from collections.abc import Iterator
from contextlib import suppress
from email.utils import formatdate
from html import escape
from mimetypes import guess_type
from os import fsdecode, PathLike
from posixpath import join as joinpath
from pathlib import Path
from sqlite3 import Connection
from time import time, perf_counter
from urllib.parse import quote

from blacksheep import Application, Request, Response, Router
from blacksheep.contents import Content
from blacksheep.server.remotes.forwarding import ForwardedHeadersMiddleware
from blacksheep_rich_log import middleware_access_log
from cachedict import TTLDict
from p115client import P115Client
from p115client.tool import get_pic_url, P115QueryDB
from p115client.util import load_final_image
from yarl import URL

__import__("mimetype_more").load()

with suppress(ImportError, AttributeError):
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    soft_new = min(max(soft, 65536), hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft_new, hard))

from .db import get_con, init_db, updatedb_tree, updatedb_life


def guess_mimetype(name: str, /) -> bytes:
    mimetype = guess_type(name)[0] 
    if not mimetype:
        return b"application/octet-stream"
    return bytes(mimetype, "ascii")


def make_application(
    client: str | PathLike | P115Client = Path("~/115-cookies.txt").expanduser(), 
    dbfile: str | PathLike = "", 
    debug: bool = False, 
    cache_url: bool = True, 
) -> Application:
    CACHE_IMAGE_URL: TTLDict[str, str] = TTLDict(3600-60, maxsize=4096)
    CACHE_URL: TTLDict[tuple[int, str], str] = TTLDict(3600, maxsize=1024)
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
                    logger.debug(f"task[\x1b[1;36m{i}\x1b[0m]=\x1b[1m{task!r}\x1b[0m \x1b[1;5;35mstarting\x1b[0m")
                    start_t = perf_counter()
                    match task:
                        case "life":
                            if perf_counter() - last_life_ts > 1:
                                await updatedb_life(client, con)
                                last_life_ts = perf_counter()
                            else:
                                logger.debug(f"task[\x1b[1;36m{i}\x1b[0m]=\x1b[1m{task!r}\x1b[0m \x1b[1;33mskipped\x1b[0m")
                                continue
                        case "top":
                            await updatedb_tree(client, con)
                        case ("tree", id):
                            await updatedb_tree(client, con, id)
                        case ("dir", id):
                            await updatedb_tree(client, con, id, recursive=False)
                        case _:
                            logger.debug(f"task[\x1b[1;36m{i}\x1b[0m]=\x1b[1m{task!r}\x1b[0m \x1b[1;33mskipped\x1b[0m")
                            continue
                    logger.info(f"task[\x1b[1;36m{i}\x1b[0m]=\x1b[1m{task!r}\x1b[0m \x1b[1;32msucceeded\x1b[0m(took \x1b[32m{perf_counter()-start_t:.3f}\x1b[0m s)")
                except Exception as e:
                    e_type = type(e)
                    module = e_type.__module__
                    name   = e_type.__qualname__
                    if module not in ("builtins", "__main__"):
                        name = module + "." + name
                    msg = f"task[\x1b[1;36m{i}\x1b[0m]=\x1b[1m{task!r}\x1b[0m \x1b[1;31mfailed\x1b[0m(took \x1b[32m{perf_counter()-start_t:.3f}\x1b[0m s) with \x1b[1;31m{name}\x1b[0m: {e}"
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

    def iter_attr_content(attr: dict, /) -> Iterator[bytes]:
        name = attr["name"]
        yield b"<d:response><d:href>"
        yield escape(quote(attr["path"])).encode("utf-8")
        yield b"</d:href><d:propstat><d:prop>"
        yield b"<d:displayname>"
        yield escape(quote(name)).encode("utf-8")
        yield b"</d:displayname>"
        yield b"<d:getlastmodified>"
        yield formatdate(attr.get("mtime", 0), usegmt=True).encode("ascii")
        yield b"</d:getlastmodified>"
        if attr["is_dir"]:
            yield b"<d:resourcetype><d:collection/></d:resourcetype>"
        else:
            yield b"<d:getetag>&quot;"
            yield attr.get("sha1", "").encode("ascii")
            yield b"&quot;</d:getetag>"
            yield b"<d:getcontentlength>"
            yield str(attr.get("size", 0)).encode("ascii")
            yield b"</d:getcontentlength>"
            yield b"<d:getcontenttype>"
            yield guess_mimetype(name)
            yield b"</d:getcontenttype>"
            yield b"<d:resourcetype></d:resourcetype>"
        yield b"</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"

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
        async def iter_content():
            yield b'<?xml version="1.0" ?>\n<d:multistatus xmlns:d="DAV:">'
            for part in iter_attr_content(attr):
                yield part
            if depth != b"0" and attr["is_dir"]:
                if depth == b"1":
                    relpath_key = "name"
                    it = querydb.iter_children(id)
                else:
                    relpath_key = "relpath"
                    it = querydb.iter_descendants(id, fields=("id", "parent_id", "name", "sha1", "size", "mtime", "is_dir", "relpath"))
                for sub_attr in it:
                    sub_attr["path"] = joinpath(top_path, sub_attr[relpath_key])
                    for part in iter_attr_content(sub_attr):
                        yield part
            yield b"</d:multistatus>"
        # NOTE: 本想流式发送数据 blacksheep.contents.StreamedContent，但总是报错，说数据未发送完响应已经关闭，只好自己拼接了
        text = b"".join([p async for p in iter_content()])
        return Response(207, content=Content(b"application/xml; charset=utf-8", text))

    async def get_image_url(sha1: str, /) -> str:
        if cache_url and (url := CACHE_IMAGE_URL.get(sha1)):
            return url
        url = await get_pic_url(client, sha1, async_=True)
        value = await load_final_image(url, async_=True)
        if not isinstance(value, str):
            raise FileNotFoundError(2, sha1)
        url = value
        if cache_url:
            CACHE_IMAGE_URL[sha1] = url
        return url

    async def get_url(id: int, /, user_agent: str = "") -> str:
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
    @app.router.route("/<path:path>", methods=["GET", "HEAD", "POST"])
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
        name = attr["name"]
        return Response(302, [
            (b"accept-ranges", b"bytes"), 
            (b"cache-control", b"max-age=300, must-revalidate"), 
            (b"content-disposition", b'''attachment; filename*=UTF-8''%s''' % quote(name).encode("ascii")), 
            (b"content-type", guess_mimetype(attr["name"])), 
            (b"etag", attr["sha1"].encode("ascii")), 
            (b"location", url.encode("utf-8")), 
        ])

    @app.router.route("/<path:path>", methods=["COPY"])
    async def copy(
        request: Request, 
        path: str = "/", 
    ):
        raise NotImplementedError

    @app.router.route("/<path:path>", methods=["DELETE"])
    async def delete(
        request: Request, 
        path: str = "/", 
    ):
        raise NotImplementedError

    @app.router.route("/<path:path>", methods=["MKCOL"])
    async def mkcol(
        request: Request, 
        path: str = "/", 
    ):
        raise NotImplementedError

    @app.router.route("/<path:path>", methods=["MOVE"])
    async def move(
        request: Request, 
        path: str = "/", 
    ):
        raise NotImplementedError

    @app.router.route("/<path:path>", methods=["SEARCH"])
    async def search(
        request: Request, 
        path: str = "/", 
    ):
        raise NotImplementedError

    @app.router.route("/<path:path>", methods=["OPTIONS"])
    async def options():
        return Response(200, [
            (b"DAV", b"1,2"), 
            (b"Allow", b"COPY, DELETE, GET, HEAD, OPTIONS, PROPFIND, MKCOL, MOVE, SEARCH"), 
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

# TODO: 搜索支持使用正则表达式，需要以 / 开头
# TODO: 用户罗列某个不存在于数据库的目录，则会用 client.fs_dir_getid2 查看是否存在，存在则会触发一次 update_tree
# TODO: 用户罗列某个在数据库中的目录，但是没有子元素项，也就是看起来是空目录，或许应该触发一次 update_tree
# TODO: 偶尔也会用 fs_info 来检查一下目录里面的文件和目录总数，如果和数据库中的不匹配，则会触发一次 update_tree
# TODO: propfind 某个路径，发现不在数据库，但是用 client 查看发现是存在的，应该如何处理？（路径level < 3，update_dir，>= 3 update_tree）
# TODO: get 某个文件，发现已经删除，数据库里面也要相应删除
# TODO: 用户可以对目录进行改名，以触发更新，如果名字里面带 >，则 update_dir，<，则是 update_tree，由于根目录不能被改名，所以根目录总是要被刷新
# TODO: 根目录也要能被懒惰更新（冷却时间 1s）
