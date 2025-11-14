#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 3)
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"
__all__ = ["P115FuseOperations"]

import errno
import logging

from collections.abc import Callable
from functools import update_wrapper
from inspect import signature
from itertools import count
from os import PathLike
from os.path import exists
from pathlib import Path
from posixpath import split as splitpath
from shutil import rmtree
from stat import S_IFDIR, S_IFREG
from _thread import allocate_lock
from textwrap import indent
from time import time
from traceback import format_exc
from typing import Any, Concatenate
from uuid import uuid4

from cachedict import LRUDict
from httpfile import HTTPFileReader
from mfusepy import FUSE, FuseOSError, Operations # type: ignore
from orjson import dumps
from p115client import check_response, P115Client, P115URL
from p115client.exception import P115BusyOSError
from p115client.tool import iterdir, normalize_attr
from rich.console import Console
from yarl import URL


class ColoredLevelNameFormatter(logging.Formatter):

    def format(self, record):
        match record.levelno:
            case logging.DEBUG:
                # blue
                record.levelname = f"\x1b[1;34m{record.levelname}\x1b[0m"
            case logging.INFO:
                # green
                record.levelname = f"\x1b[1;32m{record.levelname}\x1b[0m"
            case logging.WARNING:
                # yellow
                record.levelname = f"\x1b[1;33m{record.levelname}\x1b[0m"
            case logging.ERROR:
                # red
                record.levelname = f"\x1b[1;31m{record.levelname}\x1b[0m"
            case logging.CRITICAL:
                # magenta
                record.levelname = f"\x1b[1;35m{record.levelname}\x1b[0m"
            case _:
                # dark grey
                record.levelname = f"\x1b[1;2m{record.levelname}\x1b[0m"
        return super().format(record)


logger = logging.getLogger("p115fuse")
handler = logging.StreamHandler()
formatter = ColoredLevelNameFormatter(
    "[\x1b[1m%(asctime)s\x1b[0m] \x1b[1;36m%(name)s\x1b[0m(%(levelname)s) \x1b[5;31m➜\x1b[0m %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


def debug_access_log[I, **Args, T](
    func: Callable[Concatenate[I, Args], T], /
) -> Callable[Concatenate[I, Args], T]:
    args: list[str] = []
    add_arg = args.append
    defaults: dict[int, Any] = {}
    params = tuple(signature(func).parameters.items())[1:]
    for i, (key, val) in enumerate(params):
        if val.default is not val.empty:
            defaults[i] = val.default
        if key in ("path", "name", "old", "new", "src", "dst"):
            add_arg(f"{key}=\x1b[4;34m%r\x1b[0m")
        elif key in ("size", "position", "offset", "fh"):
            add_arg(f"{key}=\x1b[36m%r\x1b[0m")
        else:
            add_arg(f"{key}=%r")
    template = f"{func.__name__}({", ".join(args)})"
    debug = logger.debug
    error = logger.error
    def wrapper(self: I, /, *args: Args.args, **kwds: Args.kwargs) -> T:
        if len(args) < len(params):
            extra = tuple(defaults[i] for i in range(len(args), len(params)))
        else:
            extra = ()
        is_debug = logger.level is logging.DEBUG
        if is_debug:
            debug(template, *args, *extra)
        try:
            return func(self, *args, **kwds)
        except BaseException as e:
            console = Console()
            with console.capture() as capture:
                if is_debug:
                    console.print(indent(format_exc().strip(), "    ├ "))
                else:
                    console.print(indent(f"[bold magenta]{type(e).__qualname__}[/bold magenta]: {e}", "    ├ "))
            error(template+"\n%s", *args, *extra, capture.get().rstrip())
            if isinstance(e, OSError):
                raise
            raise FuseOSError(errno.EIO) from e
    return update_wrapper(wrapper, func)


def attr_to_stat(attr: dict, /) -> dict:
    return {
        "st_mode": (S_IFDIR if attr["is_dir"] else S_IFREG) | 0o777, 
        "st_ino": attr["id"], 
        "st_dev": 0, 
        "st_nlink": 1, 
        "st_uid": 0, 
        "st_gid": 0, 
        "st_size": attr.get("size", 0), 
        "st_atime": attr.get("atime") or attr.get("mtime", 0), 
        "st_mtime": attr.get("mtime", 0), 
        "st_ctime": attr.get("ctime", 0), 
        "xattr": attr, 
    }


class P115FuseOperations(Operations):

    def __init__(
        self, 
        /, 
        client: str | PathLike | P115Client = Path("~/115-cookies.txt").expanduser(), 
        readdir_ttl: float = 5, 
    ):
        if not isinstance(client, P115Client):
            client = P115Client(client, check_for_relogin=True)
        self.client = client
        self.readdir_ttl = readdir_ttl
        self._fs_cache: dict[str, dict[str, dict[str, Any]]] = LRUDict(65536)
        self._attr_cache: dict[str, dict[str, Any]] = LRUDict(1024)
        self._url_cache: LRUDict[int, P115URL] = LRUDict(1024)
        self._opened: dict[int, HTTPFileReader] = {}
        self._get_id: Callable[[], int] = count(1).__next__
        self._readdir_last_called: dict[str, float] = {}
        self._readdir_lock: LRUDict[str, Any] = LRUDict(1024, default_factory=allocate_lock)
        self._move_lock = allocate_lock()
        self._remove_lock = allocate_lock()

    @debug_access_log
    def getattr(self, /, path: str, fh: int = 0) -> dict[str, Any]:
        if path == "/":
            return attr_to_stat({"id": 0, "parent_id": 0, "name": "", "is_dir": True})
        if attr := self._attr_cache.get(path):
            if attr["path"] == path:
                return attr
            else:
                self._attr_cache.pop(path)
        dir_, name = splitpath(path)
        if not (siblings := self._fs_cache.get(dir_)):
            self.readdir(dir_)
            siblings = self._fs_cache[dir_]
        try:
            return siblings[name]
        except KeyError:
            raise FileNotFoundError(errno.ENOENT, path) from None

    @debug_access_log
    def getxattr(self, /, path: str, name: str, position: int = 0) -> bytes:
        attr = self.getattr(path)["xattr"]
        if name in attr:
            return dumps(attr[name])
        return b""

    @debug_access_log
    def listxattr(self, /, path: str) -> list[str]:
        attr = self.getattr(path)["xattr"]
        return list(attr)

    @debug_access_log
    def mkdir(self, /, path: str, mode: int = 0) -> int:
        dir_, name = splitpath(path)
        dirattr = self.getattr(dir_)["xattr"]
        if not dirattr["is_dir"]:
            raise NotADirectoryError(errno.ENOTDIR, dir_)
        resp = check_response(self.client.fs_mkdir_app(name, pid=dirattr["id"]))
        attr = attr_to_stat(normalize_attr(resp["data"]))
        attr["path"] = path
        self._attr_cache[path] = attr
        try:
            self._fs_cache[dir_][name] = attr
        except KeyError:
            pass
        return 0

    @debug_access_log
    def open(self, /, path: str, flags: int) -> int:
        attr = self.getattr(path)["xattr"]
        if attr["is_dir"]:
            raise IsADirectoryError(errno.EISDIR, path)
        cache = self._url_cache
        client = self.client
        fid = attr["id"]
        if url := cache.get(fid):
            if int(URL(url).query["t"]) - time() < 60 * 5:
                url = None
        if not url:
            if attr.get("is_collect"):
                if attr["size"] > 1024 * 1024 * 200:
                    raise OSError(errno.EIO, f"file {path!r} (id={fid}) has been censored")
                url = cache[fid] = self.client.download_url(
                    attr["pickcode"], headers={"user-agent": ""}, app="web")
            else:
                url = cache[fid] = client.download_url(
                    attr["pickcode"], headers={"user-agent": ""}, app="android")
        try:
            file = client.open(url, headers=url.headers)
        except:
            cache.pop(fid, None)
            raise
        else:
            fh = self._get_id()
            self._opened[fh] = file
            return fh

    @debug_access_log
    def opendir(self, /, path: str) -> int:
        return 0

    @debug_access_log
    def read(self, /, path: str, size: int, offset: int, fh: int) -> bytes:
        file = self._opened[fh]
        file.seek(offset)
        return file.read(size)

    @debug_access_log
    def readdir(self, /, path: str, fh: int = 0) -> list[str]:
        readdir_last_called = self._readdir_last_called
        last_called = readdir_last_called.get(path)
        with self._readdir_lock[path]:
            if last_called and (
                last_called != readdir_last_called.get(path) or 
                last_called + self.readdir_ttl > time()
            ):
                try:
                    return [".", "..", *self._fs_cache[path]]
                except KeyError:
                    pass
            attr_cache = self._attr_cache
            if path == "/":
                cid = 0
            elif (attr := attr_cache.get(path)) and (path == attr["path"]):
                cid = attr["id"]
            else:
                dir_, name = splitpath(path)
                try:
                    attr = self._fs_cache[dir_][name]
                    cid = attr["id"]
                except KeyError:
                    resp = check_response(self.client.fs_dir_getid_app(path, base_url="http://pro.api.115.com"))
                    cid = int(resp["id"])
                    if not cid:
                        raise FileNotFoundError(errno.ENOENT, path)
            dir_ = path
            if not dir_.endswith("/"):
                dir_ += "/"
            children: dict[str, dict[str, Any]] = {}
            for attr in iterdir(self.client, cid, app="android"):
                name = attr["name"]
                attr_cache.pop(dir_ + name, None)
                children[name] = attr_to_stat(attr)
            readdir_last_called[path] = time()
            self._fs_cache[path] = children
            return [".", "..", *children]

    @debug_access_log
    def release(self, /, path: str, fh: int) -> int:
        if file := self._opened.pop(fh, None):
            file.close()
        return 0

    @debug_access_log
    def releasedir(self, /, path: str, fh: int) -> int:
        return 0

    @debug_access_log
    def rename(self, /, old: str, new: str) -> int:
        if old == new:
            return 0
        client = self.client
        dir0, name0 = splitpath(old)
        dir1, name1 = splitpath(new)
        attr = self.getattr(old)["xattr"]
        if dir0 != dir1:
            if dir1 == "/":
                cid = 0
            else:
                dstdir_attr = self.getattr(dir1)["xattr"]
                if not dstdir_attr["is_dir"]:
                    raise NotADirectoryError(errno.ENOTDIR, dir1)
                cid = dstdir_attr["id"]
            with self._move_lock:
                while True:
                    try:
                        check_response(client.fs_move_app(attr["id"], pid=cid))
                        break
                    except P115BusyOSError:
                        pass
        if name0 != name1:
            check_response(client.fs_rename_app((attr["id"], name1)))
        self._attr_cache.pop(old, None)
        cache = self._fs_cache
        try:
            cache[new] = cache.pop(old)
        except KeyError:
            pass
        try:
            cache[dir1][name1] = cache[dir0].pop(name0)
        except KeyError:
            pass
        return 0

    @debug_access_log
    def unlink(self, /, path: str) -> int:
        attr = self.getattr(path)["xattr"]
        with self._move_lock:
            while True:
                try:
                    check_response(self.client.fs_delete_app(attr["id"]))
                    break
                except P115BusyOSError:
                    pass
        self._attr_cache.pop(path, None)
        cache = self._fs_cache
        cache.pop(path, None)
        if path != "/":
            dir_, name = splitpath(path)
            try:
                cache[dir_].pop(name, None)
            except KeyError:
                pass
        return 0

    @debug_access_log
    def rmdir(self, /, path: str) -> int:
        return self.unlink.__wrapped__(self, path) # type: ignore

    def run_forever(self, /, mountpoint: None | str = None, **options):
        if not mountpoint:
            mountpoint = str(uuid4())
        will_remove_mountpoint = not exists(mountpoint)
        try:
            print(f"🏠 mountpoint: \x1b[4;34m{mountpoint!r}\x1b[0m")
            print(f"🔨 options: {options}")
            return FUSE(self, mountpoint, **options)
        finally:
            if will_remove_mountpoint:
                rmtree(mountpoint)


if __name__ == "__main__":
    logger.setLevel(logging.DEBUG)
    P115FuseOperations().run_forever(
        foreground=True, 
        max_readahead=0, 
        noauto_cache=True, 
    )

