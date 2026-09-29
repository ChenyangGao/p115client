#!/usr/bin/env python3
# encoding: utf-8

from shlex import split as _shlex_split
from argparse import ArgumentParser as _ArgumentParser

try:
    _ipython = get_ipython() # type: ignore
except NameError:
    pass
else:
    from p115client import P115Client
    from p115client.tool import *
    try:
        client = P115Client.from_path()
        fs = client.fs
    except OSError:
        pass

    def _load_magics():
        __all__ = ["get_pic_url", "get_url", "listdir", "dictdir", "search", "attr"]
        from IPython.core.magic import register_line_magic

        @register_line_magic
        def get_pic_url(line):
            from os import stat
            from os.path import isdir, isfile
            from iterdir import iterdir
            from p115client.tool import upload_host_image, get_id, get_attr, get_pic_url
            from p115client.util import is_valid_sha1
            client = _ipython.user_ns["client"]
            for path in _shlex_split(line):
                if isdir(path):
                    for p in iterdir(path, predicate=lambda p: not p.name.startswith("."), max_depth=-1, follow_symlinks=True):
                        if p.is_file() and p.stat().st_size <= 1024 * 1024 * 50:
                            print(upload_host_image(client, p, base_url=True), "#path=", p.path, sep="")
                elif isfile(path):
                    if stat(path).st_size <= 1024 * 1024 * 50:
                        print(upload_host_image(client, path, base_url=True), "#path=", path, sep="")
                else:
                    if is_valid_sha1(path) or path.startswith("fhnimg_"):
                        sha1 = path
                        print(get_pic_url(client, sha1), "#sha1=", sha1, sep="")
                    else:
                        id = get_id(client, value=path)
                        attr = get_attr(client, id, skim=True)
                        if attr["is_dir"]:
                            from p115client.tool import iter_files
                            for a in iter_files(client, attr["id"], type=2, max_size=1024 * 1024 * 50, max_workers=0, app="web"):
                                print(get_pic_url(client, a["sha1"]), "#sha1=", a["sha1"], "&id=", a["id"], "&name=", a["name"], sep="")
                            continue
                        elif attr["size"] >= 1024 * 1024 * 50:
                            continue
                        sha1 = attr["sha1"]
                        print(get_pic_url(client, sha1), "#sha1=", sha1, "&id=", attr["id"], "&name=", attr["name"], sep="")

        @register_line_magic
        def get_url(line):
            from p115client.tool import get_url
            client = _ipython.user_ns["client"]
            parts = _shlex_split(line)
            parser = _ArgumentParser(prog="批量获取下载链接")
            parser.add_argument("values", metavar="value", nargs="+", help="取值，id、pickcode 或 path")
            parser.add_argument("-c", "--cid", type=int, default=0, help="顶层目录 id")
            parser.add_argument("-s", "--share-code", help="分享码")
            parser.add_argument("-r", "--receive-code", default="", help="提取码，也就是分享密码")
            parser.add_argument("-u", "--user-agent", default="", help="请求头中的 User-Agent")
            try:
                args = parser.parse_args(parts)
            except SystemExit:
                return
            share_code = args.share_code
            receive_code = args.receive_code
            cid = args.cid
            user_agent = args.user_agent
            for value in args.values: 
                url = get_url(
                    client, 
                    value, 
                    share_code=share_code, 
                    receive_code=receive_code, 
                    cid=cid, 
                    user_agent=user_agent, 
                )
                print(url, "#value=", value, sep="")

        @register_line_magic
        def listdir(line="/"):
            from p115client.tool import get_id
            id = get_id(client, value=line)
            fs = _ipython.user_ns["client"].fs
            for a in fs.iterdir(id):
                print(a["name"]+"/"[:a["is_dir"]], flush=True)

        @register_line_magic
        def dictdir(line="/"):
            from p115client.tool import get_id
            id = get_id(client, value=line)
            fs = _ipython.user_ns["client"].fs
            for a in fs.iterdir(id):
                print(a["id"], a["name"]+"/"[:a["is_dir"]], flush=True)

        @register_line_magic
        def search(line):
            client = _ipython.user_ns["client"]
            parts = _shlex_split(line)
            parser = _ArgumentParser(prog="搜索")
            parser.add_argument("value", help="关键词")
            parser.add_argument("-c", "--cid", type=int, default=0, help="顶层目录 id")
            parser.add_argument("-s", "--share-code", help="分享码")
            parser.add_argument("-r", "--receive-code", default="", help="提取码，也就是分享密码")
            parser.add_argument("-sf", "--suffix", default="", help="后缀，即扩展名")
            parser.add_argument("-tp", "--type", default=0, type=int, help="文件类型")
            try:
                args = parser.parse_args(parts)
            except SystemExit:
                return
            if value := args.value:
                cid = args.cid
                suffix = args.suffix
                type = args.type
                if share_code := args.share_code:
                    from p115client.tool import share_search_iter
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
                    from p115client.tool import search_iter
                    it = search_iter(
                        client, 
                        search_value=value, 
                        cid=cid, 
                        suffix=suffix, 
                        type=type, 
                    )
                for a in it:
                    print(a["id"], a["name"]+"/"[:a["is_dir"]], flush=True)

        @register_line_magic
        def attr(line):
            from p115client.tool import iter_nodes_by_file_skim
            client = _ipython.user_ns["client"]
            parts = _shlex_split(line)
            for a in iter_nodes_by_file_skim(client, parts):
                print(a)

        print(f"检测到你正在使用 ipython，已自动加载魔法函数 {__all__}")

    _load_magics()
    _ipython.user_ns.update((k, v) for k, v in globals().items() if not k.startswith("_"))

