#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_application"]

from asyncio import create_task, sleep, to_thread, Lock, Task, Queue
from contextlib import suppress
from email.utils import formatdate
from html import escape
from io import BytesIO
from mimetypes import guess_type
from os import fsdecode, PathLike
from posixpath import basename, dirname, join as joinpath
from pathlib import Path
from time import time, perf_counter
from urllib.parse import quote, unquote, urlsplit

from apsw import Connection, SQLITE_OPEN_READONLY
from blacksheep import Application, Request, Response, Router
from blacksheep.contents import Content, StreamedContent
from blacksheep.server.compression import use_gzip_compression
from blacksheep.server.remotes.forwarding import ForwardedHeadersMiddleware
from blacksheep.server.responses import json
from blacksheep_rich_log import middleware_access_log
from cachedict import TTLDict
from p115client import check_response, P115Client
from p115client.tool import (
    dir_getid, get_file_count, get_pic_url, tinydb_initdb, tinydb_update, 
    tinydb_update_event, makedir, update_name, P115QueryDB, 
)
from p115client.util import load_final_image
from sqlitetools import execute, upsert_items
from yarl import URL

__import__("mimetype_more").load()

with suppress(ImportError, AttributeError):
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    soft_new = min(max(soft, 65536), hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft_new, hard))


theme = (Path(__file__).parent / "themes" / "crazy-universe.html").open("rb").read()


def guess_mimetype(name: str, /) -> bytes:
    mimetype = guess_type(name)[0] 
    if not mimetype:
        return b"application/octet-stream"
    return bytes(mimetype, "ascii")


def ensure_str_id(attr, /):
    attr["id"] = str(attr["id"])
    attr["parent_id"] = str(attr["parent_id"])
    if "ancestors" in attr:
        for subattr in attr["ancestors"]:
            ensure_str_id(subattr)
    if "children" in attr:
        for subattr in attr["children"].values():
            ensure_str_id(subattr)


def make_application(
    client: str | PathLike | P115Client = Path("~/115-cookies.txt").expanduser(), 
    dbfile: str | PathLike = "", 
    debug: bool = False, 
    cache_url: bool = True, 
    use_gzip: bool = True, 
) -> Application:
    CACHE_IMAGE_URL: TTLDict[str, str] = TTLDict(3600-60, maxsize=4096)
    CACHE_URL: TTLDict[tuple[int, str], str] = TTLDict(3600, maxsize=1024)
    RENAME_DICT: dict[int, str] = {}
    MOVE_DICT: dict[int, int] = {}
    if not isinstance(client, P115Client):
        client = P115Client(client)
    dbfile = fsdecode(dbfile)
    if not dbfile:
        dbfile = f"p115tinydav-{client.user_id}.db"
    task_queue: Queue = Queue()
    put_task = task_queue.put_nowait
    app = Application(router=Router(), show_error_details=debug)
    if use_gzip:
        use_gzip_compression(app)
    app.services.register(P115Client, instance=client)
    middleware_access_log(app)
    logger = getattr(app, "logger")
    if debug:
        logger.level = 10 # logging.DEBUG
    write_lock = Lock()

    @app.on_middlewares_configuration
    def configure_forwarded_headers(app: Application):
        app.middlewares.insert(0, ForwardedHeadersMiddleware(accept_only_proxied_requests=False))

    @app.lifespan
    async def initdb(app: Application):
        con = Connection(dbfile)
        app.services.register(Connection, instance=con)
        tinydb_initdb(con)
        yield

    async def hour_life_update():
        while True:
            await sleep(3600)
            put_task("life")

    async def run_background_tasks(app: Application, con: Connection):
        data = dict(con.execute("SELECT key, val FROM keystore"))
        last_life_id = data.get("last_life_id", 0)
        last_update_life_ts = data.get("last_update_life_ts", 0)
        first_task = "top"
        if last_life_id or last_update_life_ts:
            resp = await client.life_behavior_detail_app({"limit": 1, "offset": 999}, async_=True)
            check_response(resp)
            ls = resp["data"]["list"]
            if ls:
                event = ls[0]
                if last_life_id and last_life_id > int(event["id"]) or last_update_life_ts and last_update_life_ts > int(event["update_time"]):
                    first_task = "life"
        put_task(first_task)
        hour_task = create_task(hour_life_update())
        get_task = task_queue.get
        last_life_ts: float = 0
        last_update_tree: dict[int, float] = {}
        try:
            i = 0
            ignore = lambda e: (
                e["type"] in (20, 24) and int(e["file_id"]) in RENAME_DICT or 
                e["type"] in (5, 6) and int(e["file_id"]) in MOVE_DICT
            )
            while True:
                i += 1
                task = await get_task()
                try:
                    logger.debug(f"task[\x1b[1;36m{i}\x1b[0m]=\x1b[1m{task!r}\x1b[0m \x1b[1;5;35mstarting\x1b[0m")
                    start_t = perf_counter()
                    match task:
                        case "life":
                            if perf_counter() - last_life_ts > 5:
                                await tinydb_update_event(
                                    client, 
                                    con, 
                                    ignore=ignore, 
                                    lock=write_lock, 
                                    async_=True, 
                                )
                                last_life_ts = perf_counter()
                            else:
                                logger.debug(f"task[\x1b[1;36m{i}\x1b[0m]=\x1b[1m{task!r}\x1b[0m \x1b[1;33mskipped\x1b[0m")
                                continue
                        case "top":
                            await tinydb_update(client, con, lock=write_lock, async_=True)
                        case ("tree", id, True):
                            if perf_counter() - last_update_tree.get(id, 0) > 1:
                                try:
                                    count_file = await get_file_count(client, id, async_=True)
                                except FileNotFoundError:
                                    async with write_lock:
                                        execute(con, "UPDATE data SET mtime=?, is_alive=FALSE WHERE id=?", (int(time()), id), commit=True)
                                else:
                                    try:
                                        resp = P115QueryDB(con).get_count_tree(id)
                                        count_file0 = resp["file_count"]
                                    except FileNotFoundError:
                                        count_file0 = 0
                                    if count_file == count_file0:
                                        logger.debug(f"task[\x1b[1;36m{i}\x1b[0m]=\x1b[1m{task!r}\x1b[0m \x1b[1;33mskipped\x1b[0m")
                                        continue
                                    else:
                                        await tinydb_update(client, con, id, lock=write_lock, async_=True)
                                last_update_tree[id] = perf_counter()
                            else:
                                logger.debug(f"task[\x1b[1;36m{i}\x1b[0m]=\x1b[1m{task!r}\x1b[0m \x1b[1;33mskipped\x1b[0m")
                                continue
                        case ("tree", id) | ("tree", id, _):
                            await tinydb_update(client, con, id, lock=write_lock, async_=True)
                        case ("dir", id):
                            await tinydb_update(client, con, id, recursive=False, lock=write_lock, async_=True)
                        # TODO: delete 和 move 是比较耗时的，或许应该专门再搞一个任务队列，避免阻塞 evnet 的执行
                        case ("delete", id):
                            await client.fs_delete_app(id, async_=True)
                        case "move":
                            try:
                                while True:
                                    await client.fs_move_app(*MOVE_DICT.popitem(), async_=True)
                            except KeyError:
                                pass
                        case "rename":
                            if RENAME_DICT:
                                pairs = tuple(RENAME_DICT.items())
                                RENAME_DICT.clear()
                                await update_name(client, pairs, batch_size=1_000, async_=True)
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

    def write_attr_content(write, attr: dict, /):
        name = attr["name"]
        write(b"<d:response><d:href>")
        write(escape(quote(attr["path"])).encode("utf-8"))
        write(b"</d:href><d:propstat><d:prop>")
        write(b"<d:displayname>")
        write(escape(quote(name)).encode("utf-8"))
        write(b"</d:displayname>")
        write(b"<d:getlastmodified>")
        write(formatdate(attr.get("mtime", 0), usegmt=True).encode("ascii"))
        write(b"</d:getlastmodified>")
        if attr["is_dir"]:
            write(b"<d:resourcetype><d:collection/></d:resourcetype>")
        else:
            write(b"<d:getetag>&quot;")
            write(attr.get("sha1", "").encode("ascii"))
            write(b"&quot;</d:getetag>")
            write(b"<d:getcontentlength>")
            write(str(attr.get("size", 0)).encode("ascii"))
            write(b"</d:getcontentlength>")
            write(b"<d:getcontenttype>")
            write(guess_mimetype(name))
            write(b"</d:getcontenttype>")
            write(b"<d:resourcetype></d:resourcetype>")
        write(b"</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>")

    @app.router.route("/<path:path>", methods=["PROPFIND"])
    async def propfind(
        request: Request, 
        id: int = -1, 
        pickcode: str = "", 
        path: str = "/", 
    ):
        put_task("life")
        querydb = P115QueryDB(Connection(dbfile, flags=SQLITE_OPEN_READONLY))
        top_path = ""
        if id < 0:
            if pickcode:
                id = client.to_id(pickcode)
            else:
                id = querydb.get_id(path=path)
                top_path = "/" + path.strip("/")
        attr = querydb.get_attr(id)
        if not attr["parent_id"] and attr["name"] in ("云下载", "最近接收"):
            put_task(("tree", attr["id"], True))
        if not top_path:
            top_path = querydb.get_path(id)
        attr["path"] = top_path
        depth = request.headers.get_first(b"depth")
        def make_content():
            file = BytesIO()
            write = file.write
            write(b'<?xml version="1.0" ?>\n<d:multistatus xmlns:d="DAV:">')
            write_attr_content(write, attr)
            if depth != b"0" and attr["is_dir"]:
                if depth == b"1":
                    relpath_key = "name"
                    it = querydb.iter_children(id)
                else:
                    relpath_key = "relpath"
                    it = querydb.iter_descendants(id, fields=("id", "parent_id", "name", "sha1", "size", "mtime", "is_dir", "relpath"))
                for sub_attr in it:
                    sub_attr["path"] = joinpath(top_path, sub_attr[relpath_key])
                    write_attr_content(write, sub_attr)
            write(b"</d:multistatus>")
            return file.getvalue()
        return Response(207, content=Content(b"application/xml", await to_thread(make_content)))

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

    @app.router.route("/<path:path>", methods=["HEAD"])
    async def head(
        request: Request, 
        id: int = -1, 
        pickcode: str = "", 
        path: str = "/", 
    ):
        put_task("life")
        querydb = P115QueryDB(Connection(dbfile, flags=SQLITE_OPEN_READONLY))
        if id <= 0:
            if pickcode:
                id = client.to_id(pickcode)
            else:
                id = querydb.get_id(path=path)
        attr = querydb.get_attr(id)
        if attr["is_dir"]:
            return b""
        name = attr["name"]
        async def fake_gen():
            yield
        return Response(200, [
            (b"accept-ranges", b"bytes"), 
            (b"content-disposition", b'''attachment; filename*=UTF-8''%s''' % quote(name).encode("ascii")), 
            (b"etag", b'"%s"'%attr["sha1"].encode("ascii")), 
        ], content=StreamedContent(guess_mimetype(name), fake_gen, attr["size"]))

    @app.router.route("/<path:path>", methods=["GET"])
    async def get(
        request: Request, 
        id: int = -1, 
        pickcode: str = "", 
        path: str = "/", 
        format: str = "", 
        image: bool = True, 
    ):
        put_task("life")
        querydb = P115QueryDB(Connection(dbfile, flags=SQLITE_OPEN_READONLY))
        if id <= 0:
            if pickcode:
                id = client.to_id(pickcode)
            else:
                id = querydb.get_id(path=path)
        attr = querydb.get_attr(id)
        attr["path"] = querydb.get_path(id)
        if attr["is_dir"]:
            if not attr["parent_id"] and attr["name"] in ("云下载", "最近接收"):
                put_task(("tree", attr["id"], True))
            if format == "json":
                attr["ancestors"] = list(querydb.get_ancestors(id))
                attr["children"] = {str(a["id"]): a for a in querydb.iter_children(id)}
                ensure_str_id(attr)
                for subattr in attr["children"].values():
                    subattr["path"] = joinpath(attr["path"], subattr["name"])
                return json(attr)
            return Response(200, content=Content(b"text/html", theme))
        if image and attr["size"] <= 1024 * 1024 * 50:
            url = await get_image_url(attr["sha1"])
        else:
            user_agent = (request.get_first_header(b"user-agent") or b"").decode("latin-1")
            url = await get_url(id, user_agent)
        name = attr["name"]
        return Response(302, [
            (b"accept-ranges", b"bytes"), 
            (b"cache-control", b"max-age=300, must-revalidate"), 
            (b"content-disposition", b'''attachment; filename*=UTF-8''%s''' % quote(name).encode("ascii")), 
            (b"content-type", guess_mimetype(name)), 
            (b"etag", b'"%s"'%attr["sha1"].encode("ascii")), 
            (b"location", url.encode("utf-8")), 
        ])

    @app.router.route("/<path:path>", methods=["POST"])
    async def post_task(
        request: Request, 
        id: int = -1, 
        pickcode: str = "", 
        path: str = "/", 
        tree: bool = False, 
        check_count: bool = True, 
    ):
        if id <= 0:
            if pickcode:
                id = client.to_id(pickcode)
            elif path := path.strip("/"):
                id = await dir_getid(client, path, app="web2", async_=True)
            else:
                id = 0
        put_task((("dir", "tree")[tree], id, check_count))

    # TODO: 实际上是创建 link，可以被 move、rename、delete 和 copy
    @app.router.route("/<path:path>", methods=["COPY"])
    async def copy(
        request: Request, 
        path: str = "/", 
    ):
        raise NotImplementedError

    @app.router.route("/<path:path>", methods=["DELETE"])
    async def delete(
        request: Request, 
        con: Connection, 
        path: str = "/", 
    ):
        id = P115QueryDB(con).get_id(path=path)
        async with write_lock:
            execute(con, "UPDATE data SET mtime=?, is_alive=FALSE WHERE id=? AND is_alive", (int(time()), id), commit=True)
        put_task(("delete", id))
        return Response(204)

    @app.router.route("/<path:path>", methods=["MKCOL"])
    async def mkcol(
        request: Request, 
        con: Connection, 
        path: str = "/", 
    ):
        path = path.strip("/")
        if path:
            try:
                P115QueryDB(con).get_id(path=path)
                return Response(409)
            except FileNotFoundError:
                pid = P115QueryDB(con).get_id(path=dirname(path))
                name = basename(path)
                cid = await makedir(client, name, pid=pid, contain_dir=True, async_=True)
                upsert_items(con, [{"id": cid, "parent_id": pid, "name": name, "is_alive": True}])
        return Response(201)

    @app.router.route("/<path:path>", methods=["MOVE"])
    async def move(
        request: Request, 
        con: Connection, 
        path: str = "/", 
    ):
        path = path.strip("/")
        if not path:
            return Response(400)
        dest = unquote(urlsplit(request.get_first_header(b"destination") or b"").path).strip("/")
        if not dest:
            return Response(400)
        overwrite = request.get_first_header(b"overwrite") != b"F"
        querydb = P115QueryDB(con)
        id = querydb.get_id(path=path)
        cid = querydb.get_parent_id(id)
        try:
            to_cid = querydb.get_id(path=dirname(dest))
        except FileNotFoundError:
            return Response(409)
        try:
            to_id = querydb.get_id(path=dest)
            if not overwrite:
                return Response(412)
            async with write_lock:
                execute(con, "UPDATE data SET mtime=?, is_alive=FALSE WHERE id=? AND is_alive", (int(time()), to_id), commit=True)
            put_task(("delete", to_id))
            status = 204
        except FileNotFoundError:
            status = 201
        name = basename(dest)
        async with write_lock:
            execute(con, "UPDATE data SET name=?, parent_id=?, mtime=?, is_alive=TRUE WHERE id=?", (name, to_cid, int(time()), id), commit=True)
        if basename(path) != name:
            if ">" in name:
                if querydb.get_attr(id)["is_dir"]:
                    put_task(("dir", id, True))
            elif "<" in name:
                if querydb.get_attr(id)["is_dir"]:
                    put_task(("tree", id, True))
            else:
                RENAME_DICT[id] = name
                put_task("rename")
        if cid != to_cid:
            MOVE_DICT[id] = to_cid
            put_task("move")
        return Response(status)

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

# TODO: 如果有一堆 move、rename、delete 等任务，原则上可以合并（使用队列即可，执行时提取当前所有已经提交的）
# TODO: 搜索支持使用正则表达式，需要以 / 开头
# TODO: 用户罗列某个不存在于数据库的目录，则会用 client.fs_dir_getid2 查看是否存在，存在则会触发一次 update_tree
# TODO: 用户罗列某个在数据库中的目录，但是没有子元素项，也就是看起来是空目录，或许应该触发一次 update_tree
# TODO: 偶尔也会用 fs_info 来检查一下目录里面的文件和目录总数，如果和数据库中的不匹配，则会触发一次 update_tree（主要是云下载和最近接收）
# TODO: propfind 某个路径，发现不在数据库，但是用 client 查看发现是存在的，应该如何处理？（路径level < 3，update_dir，>= 3 update_tree）
# TODO: get 某个文件，发现已经删除，数据库里面也要相应删除
# TODO: 用户可以对目录进行改名，以触发更新，如果名字里面带 >，则 update_dir，<，则是 update_tree，由于根目录不能被改名，所以根目录总是要被刷新
