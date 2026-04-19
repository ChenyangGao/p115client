#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 3)
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"
__all__ = ["P115FuseOperations"]

import errno
import logging

from collections.abc import Callable, Mapping
from itertools import count
from os import PathLike
from os.path import exists
from pathlib import Path
from posixpath import split as splitpath
from shutil import rmtree
from stat import S_IFDIR, S_IFREG
from typing import Any
from uuid import uuid4

from cachedict import TTLDict
from mfusepy import FUSE, Operations # type: ignore
from orjson import dumps
from p115client import P115Client
from richlog_fs import access_log, get_logger


logger = get_logger("p115fuse")
log = access_log(logger=logger, level=None)


def attr_to_stat(attr: Mapping, /) -> dict:
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
        readdir_ttl: float = 60, 
    ):
        if not isinstance(client, P115Client):
            client = P115Client(client, check_for_relogin=True)
        self.client = client
        self.fs = client.get_fs(id_to_readdir=TTLDict(readdir_ttl))
        self._opened: dict[int, Any] = {}
        self._get_id: Callable[[], int] = count(1).__next__

    @log
    def getattr(self, /, path: str, fh: int = 0) -> dict[str, Any]:
        return attr_to_stat(self.fs.get_attr(path))

    @log
    def getxattr(self, /, path: str, name: str, position: int = 0) -> bytes:
        attr = self.getattr(path)["xattr"]
        if name in attr:
            return dumps(attr[name])
        return b""

    @log
    def listxattr(self, /, path: str) -> list[str]:
        attr = self.getattr(path)["xattr"]
        return list(attr)

    @log
    def mkdir(self, /, path: str, mode: int = 0) -> int:
        dir_, name = splitpath(path)
        self.fs.mkdir(dir_, name)
        return 0

    @log
    def open(self, /, path: str, flags: int) -> int:
        file = self.fs.open(path)
        fh = self._get_id()
        self._opened[fh] = file
        return fh

    @log
    def opendir(self, /, path: str) -> int:
        return 0

    @log
    def read(self, /, path: str, size: int, offset: int, fh: int) -> bytes:
        file = self._opened[fh]
        file.seek(offset)
        return file.read(size)

    @log
    def readdir(self, /, path: str, fh: int = 0) -> list[str]:
        children = self.fs.readdir(path)
        return [".", "..", *(a["name"] for a in children)]

    @log
    def release(self, /, path: str, fh: int) -> int:
        if file := self._opened.pop(fh, None):
            file.close()
        return 0

    @log
    def releasedir(self, /, path: str, fh: int) -> int:
        return 0

    @log
    def rename(self, /, src: str, dst: str) -> int:
        if src != dst:
            src_dir, src_name = splitpath(src)
            dst_dir, dst_name = splitpath(dst)
            attr = self.fs.get_attr(src)
            if src_dir != dst_dir:
                if dst_dir == "/":
                    cid = 0
                else:
                    dstdir_attr = self.fs.get_attr(dst_dir)
                    if not dstdir_attr["is_dir"]:
                        raise NotADirectoryError(errno.ENOTDIR, dst_dir)
                    cid = dstdir_attr["id"]
                self.fs.move(attr, cid)
            if src_name != dst_name:
                self.fs.rename(attr, dst_name)
        return 0

    @log
    def unlink(self, /, path: str) -> int:
        self.fs.remove(path)
        return 0

    @log
    def rmdir(self, /, path: str) -> int:
        self.fs.remove(path)
        return 0

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

