#!/usr/bin/env python3
# encoding: utf-8

__all__ = ["attr", "ancestors", "path", "listdir", "search", "dictdir", "pic_url", "url", "m3u8"]

from argparse import ArgumentParser
from collections.abc import Callable
from functools import partial
from shlex import split as shlex_split

from .client import P115Client
from .tool import get_id
from .util import is_valid_id, is_valid_pickcode


def attr(client: P115Client, argv: str | list[str]):
    parser = ArgumentParser(prog="获取信息")
    parser.add_argument("values", metavar="value", nargs="*", help="取值，id、pickcode 或 path")
    parser.add_argument("-r", "--refresh", action="store_true", help="是否刷新")

    if isinstance(argv, str):
        argv = shlex_split(argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return

    if not (values := args.values):
        values = 0,
    for value in values:
        id = get_id(client, value=value)
        print(client.fs.get_attr(id, refresh=args.refresh))


def ancestors(client: P115Client, argv: str | list[str]):
    parser = ArgumentParser(prog="获取祖先列表")
    parser.add_argument("values", metavar="value", nargs="*", help="取值，id、pickcode 或 path")
    parser.add_argument("-r", "--refresh", action="store_true", help="是否刷新")

    if isinstance(argv, str):
        argv = shlex_split(argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return

    if not (values := args.values):
        values = 0,
    for value in values:
        if is_valid_id(value):
            value = int(value)
        elif is_valid_pickcode(value):
            value = client.to_id(value)
        print(client.fs.get_ancestors(value, refresh=args.refresh))


def path(client: P115Client, argv: str | list[str]):
    parser = ArgumentParser(prog="获取路径")
    parser.add_argument("values", metavar="value", nargs="*", help="取值，id、pickcode 或 path")
    parser.add_argument("-r", "--refresh", action="store_true", help="是否刷新")

    if isinstance(argv, str):
        argv = shlex_split(argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return

    if not (values := args.values):
        values = 0,
    for value in values:
        if is_valid_id(value):
            value = int(value)
        elif is_valid_pickcode(value):
            value = client.to_id(value)
        print(client.fs.get_path(value, refresh=args.refresh))


def listdir(client: P115Client, argv: str | list[str]):
    parser = ArgumentParser(prog="罗列目录，获取名字")
    parser.add_argument("value", nargs="?", default=0, help="取值，id、pickcode 或 path")
    parser.add_argument("-r", "--refresh", action="store_true", help="是否刷新")

    if isinstance(argv, str):
        argv = shlex_split(argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return

    id = get_id(client, value=args.value)
    for a in client.fs.readdir(id, refresh=args.refresh):
        print(a["name"]+"/"[:a["is_dir"]], flush=True)


def dictdir(client: P115Client, argv: str | list[str]):
    parser = ArgumentParser(prog="罗列目录，获取id 和 名字")
    parser.add_argument("value", nargs="?", default=0, help="取值，id、pickcode 或 path")
    parser.add_argument("-r", "--refresh", action="store_true", help="是否刷新")

    if isinstance(argv, str):
        argv = shlex_split(argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return

    id = get_id(client, value=args.value)
    for a in client.fs.readdir(id, refresh=args.refresh):
        print(a["id"], a["name"]+"/"[:a["is_dir"]], flush=True)


def search(client: P115Client, argv: str | list[str]):
    parser = ArgumentParser(prog="搜索，支持网盘和分享")
    parser.add_argument("value", help="关键词")
    parser.add_argument("-c", "--cid", type=int, default=0, help="顶层目录 id")
    parser.add_argument("-s", "--share-code", help="分享码")
    parser.add_argument("-r", "--receive-code", default="", help="提取码，也就是分享密码")
    parser.add_argument("-sf", "--suffix", default="", help="后缀，即扩展名")
    parser.add_argument("-tp", "--type", default=0, type=int, help="文件类型")
    parser.add_argument("-a", "--app", default="web", help="使用指定 app（设备）的接口")

    if isinstance(argv, str):
        argv = shlex_split(argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return

    if value := args.value:
        cid = args.cid
        suffix = args.suffix
        type = args.type
        app = args.app
        if share_code := args.share_code:
            from .tool import share_search_iter
            it = share_search_iter(
                client, 
                share_code=share_code, 
                receive_code=args.receive_code, 
                search_value=value, 
                cid=cid, 
                suffix=suffix, 
                type=type, 
            )
        else:
            from .tool import search_iter
            it = search_iter(
                client, 
                search_value=value, 
                cid=cid, 
                suffix=suffix, 
                type=type, 
                app=app, 
            )
        for a in it:
            print(a["id"], a["name"]+"/"[:a["is_dir"]], flush=True)


def pic_url(client: P115Client, argv: str | list[str]):
    parser = ArgumentParser(prog="批量获取不大于 50 MB 文件的下载链接（视为图片处理）")
    parser.add_argument("values", nargs="+", help="参数，可以是 sha1、id、pickcode、path 等")

    if isinstance(argv, str):
        argv = shlex_split(argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return

    from os import stat
    from os.path import isdir, isfile

    from iterdir import iterdir

    from .tool import upload_host_image, get_id, get_attr, get_pic_url
    from .util import is_valid_sha1

    for value in args.values:
        if isdir(value):
            for p in iterdir(value, predicate=lambda p: not p.name.startswith("."), max_depth=-1, follow_symlinks=True):
                if p.is_file() and p.stat().st_size <= 1024 * 1024 * 50:
                    print(upload_host_image(client, p, base_url=True), "#path=", p.path, sep="")
        elif isfile(value):
            if stat(value).st_size <= 1024 * 1024 * 50:
                print(upload_host_image(client, value, base_url=True), "#path=", value, sep="")
        else:
            if is_valid_sha1(value) or value.startswith("fhnimg_"):
                sha1 = value
                print(get_pic_url(client, sha1), "#sha1=", sha1, sep="")
            else:
                id = get_id(client, value=value)
                attr = get_attr(client, id, skim=True)
                if attr["is_dir"]:
                    from .tool import iter_files
                    for a in iter_files(client, attr["id"], type=2, max_size=1024 * 1024 * 50, max_workers=0, app="web"):
                        print(get_pic_url(client, a["sha1"]), "#sha1=", a["sha1"], "&id=", a["id"], "&name=", a["name"], sep="")
                    continue
                elif attr["size"] >= 1024 * 1024 * 50:
                    continue
                sha1 = attr["sha1"]
                print(get_pic_url(client, sha1), "#sha1=", sha1, "&id=", attr["id"], "&name=", attr["name"], sep="")


def url(client: P115Client, argv: str | list[str]):
    parser = ArgumentParser(prog="批量获取下载链接")
    parser.add_argument("values", metavar="value", nargs="+", help="取值，id、pickcode 或 path")
    parser.add_argument("-c", "--cid", type=int, default=0, help="顶层目录 id")
    parser.add_argument("-s", "--share-code", help="分享码")
    parser.add_argument("-r", "--receive-code", default="", help="提取码，也就是分享密码")
    parser.add_argument("-u", "--user-agent", default="", help="请求头中的 User-Agent")
    parser.add_argument("-a", "--app", default="web", help="使用指定 app（设备）的接口")

    if isinstance(argv, str):
        argv = shlex_split(argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return

    from .tool import get_url

    share_code = args.share_code
    receive_code = args.receive_code
    cid = args.cid
    user_agent = args.user_agent
    app = args.app
    for value in args.values: 
        url = get_url(
            client, 
            value, 
            share_code=share_code, 
            receive_code=receive_code, 
            cid=cid, 
            user_agent=user_agent, 
            app=app, 
        )
        print(url, "#value=", value, sep="")


def m3u8(client: P115Client, argv: str | list[str]):
    parser = ArgumentParser(prog="批量获取 M3U8 链接")
    parser.add_argument("values", metavar="value", nargs="+", help="取值，id、pickcode 或 path")
    parser.add_argument("-a", "--app", default="android", help="使用指定 app（设备）的接口")

    if isinstance(argv, str):
        argv = shlex_split(argv)
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return

    from json import dumps

    app = args.app
    if app == "open":
        fs_video: Callable = client.fs_video_open
    elif app in ("", "web", "desktop", "aps"):
        fs_video = client.fs_video
    else:
        fs_video = partial(client.fs_video_app, app=app)

    for value in args.values:
        id = get_id(client, value=value)
        resp = fs_video(id)
        if resp["state"]:
            if "data" in resp:
                print("#", dumps(resp["data"], ensure_ascii=False))
                print(max(resp["data"]["video_url"], key=lambda a: a["width"])["url"])
            else:
                print("#", dumps(resp, ensure_ascii=False))
                print(resp["video_url"])
            print()

# TODO: 增加 %download, %upload，上传和下载允许指定数据库，以便下次继续
