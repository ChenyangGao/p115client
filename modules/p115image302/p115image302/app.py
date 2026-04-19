#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["make_application"]

from collections.abc import MutableMapping
from string import ascii_letters, digits
from typing import Final

from blacksheep import json, redirect, Application, Request, Router
from blacksheep.server.remotes.forwarding import ForwardedHeadersMiddleware
from blacksheep_rich_log import middleware_access_log
from cachedict import TTLDict
from errno2 import errno
from p115client import P115Client, check_response
from p115client.exception import throw
from p115client.tool import get_attr, get_pic_url, load_final_image
from p115pickcode import is_valid_pickcode
from sqlitedict import SqliteDict


LETTERS: Final = ascii_letters + digits + "_"


def make_application(
    client: P115Client, 
    debug: bool = False, 
    dbfile: str = "p115image302.db"
) -> Application:
    """创建 blacksheep 后台服务对象

    :param client: 115 客户端对象
    :param debug: 是否开启调试信息

    :return: blacksheep 服务对象
    """
    CACHE_KEY_TO_IMMOTAL_URL: MutableMapping[str, str] = SqliteDict(dbfile, uri=dbfile.startswith("file:"))
    KEY_TO_URL: TTLDict[str, str] = TTLDict(3600-10)

    app = Application(router=Router(), show_error_details=debug)
    if debug:
        logger = getattr(app, "logger")
        logger.level = 10 # logging.DEBUG

    @app.on_middlewares_configuration
    def configure_forwarded_headers(app: Application):
        app.middlewares.insert(0, ForwardedHeadersMiddleware(accept_only_proxied_requests=False))

    middleware_access_log(app)

    @app.router.route("/<path:path>", methods=["GET"])
    async def downlaod(path: str):
        key = path.lstrip("/").split("/", 1)[0]
        if not key or key.lstrip(LETTERS):
            raise ValueError("please pass `id`, `pickcode`, `sha1` or `oss`")
        if image_url := KEY_TO_URL.get(key):
            return redirect(image_url)
        permanent_url = CACHE_KEY_TO_IMMOTAL_URL.get(key)
        if permanent_url == "":
            throw(errno.ENOENT, f"{key}: not found")
        elif not permanent_url:
            if is_valid_pickcode(key) or not (key.startswith("0") or key.strip(digits)):
                try:
                    info = await get_attr(client, key, skim=True, async_=True)
                except FileNotFoundError:
                    CACHE_KEY_TO_IMMOTAL_URL[key] = ""
                    raise
                if info["is_dir"]:
                    throw(errno.EISDIR, f"{key}: is a directory")
                elif info["size"] > 1024 * 1024 * 50:
                    throw(errno.E2BIG, f"{key}: file too big")
                sha1 = info["sha1"]
            else:
                sha1 = key
            permanent_url = await get_pic_url(client, sha1, async_=True)
        url = await load_final_image(permanent_url, async_=True)
        if isinstance(url, str):
            CACHE_KEY_TO_IMMOTAL_URL[key] = permanent_url
            if key != sha1:
                CACHE_KEY_TO_IMMOTAL_URL[sha1] = permanent_url
            KEY_TO_URL[key] = url
        else:
            if url != 404 or len(sha1) != 40:
                CACHE_KEY_TO_IMMOTAL_URL[key] = ""
            throw(errno.EIO, f"{key}: {url} {url.phrase}")
        return redirect(url)

    @app.router.route("/", methods=["PUT"])
    @app.router.route("/<path>", methods=["PUT"])
    async def upload(request: Request):
        resp = await client.upload_file_image(
            request.stream(), # type: ignore
            filename="x.jpg", 
            async_=True, 
        )
        check_response(resp)
        sha1 = resp["img_info"]["sha1"]
        oss = resp["data"]["sha1"]
        url = resp["data"]["thumb_url"]
        url = KEY_TO_URL[sha1] = KEY_TO_URL[oss] = url[:url.index("?")]
        if debug:
            logger.debug("[\x1b[1;32mUPLOADED\x1b[0m] sha1=\x1b[4;34m%r\x1b[0m oss=\x1b[4;34m%r\x1b[0m", sha1, oss)
        return json({
            "size": resp["img_info"]["filesize"], 
            "md5": resp["md5_key"], 
            "sha1": sha1, 
            "oss": oss, 
            "oss_endpoint": resp["img_info"]["oss_endpoint"], 
            "oss_bucket": resp["img_info"]["oss_bucket"], 
            "oss_object": resp["img_info"]["oss_object"], 
            "url": url, 
        })

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

