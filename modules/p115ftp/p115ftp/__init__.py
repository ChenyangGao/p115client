#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 4)
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"
__all__ = ["P115FS"]

import logging
import time

from collections.abc import Callable
from functools import update_wrapper
from inspect import signature
from os import stat_result, PathLike
from pathlib import Path
from posixpath import commonpath, join as joinpath, normpath, split as splitpath
from stat import filemode, S_IFDIR, S_IFREG
from _thread import allocate_lock
from textwrap import indent
from traceback import format_exc
from typing import Any

from cachedict import LRUDict
from errno2 import errno
from p115client import check_response, P115Client, P115URL
from p115client.exception import P115BusyOSError
from p115client.tool import iterdir, normalize_attr, type_of_attr
from pyftpdlib.authorizers import DummyAuthorizer # type: ignore
from pyftpdlib.handlers import FTPHandler # type: ignore
from pyftpdlib.servers import FTPServer # type: ignore
from rich.console import Console
from yarl import URL


LISTDIR_TTL: float = 5


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


logger = logging.getLogger("p115ftp")
handler = logging.StreamHandler()
formatter = ColoredLevelNameFormatter(
    "[\x1b[1m%(asctime)s\x1b[0m] \x1b[1;36m%(name)s\x1b[0m(%(levelname)s) \x1b[5;31m➜\x1b[0m %(message)s"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


def debug_access_log[I, *Args, T](func: Callable[[I, *Args], T], /) -> Callable[[I, *Args], T]:
    args: list[str] = []
    add_arg = args.append
    defaults: dict[int, Any] = {}
    params = tuple(signature(func).parameters.items())[1:]
    for i, (key, val) in enumerate(params):
        if val.default is not val.empty:
            defaults[i] = val.default
        add_arg(f"{key}=%r")
    template = f"{func.__name__}({", ".join(args)})"
    debug = logger.debug
    error = logger.error
    def wrapper(self: I, /, *args: *Args) -> T:
        if len(args) < len(params):
            extra = tuple(defaults[i] for i in range(len(args), len(params)))
        else:
            extra = ()
        is_debug = logger.level is logging.DEBUG
        if is_debug:
            console = Console()
            with console.capture() as capture:
                console.print(template % (*args, *extra))
            debug(capture.get().rstrip())
        try:
            return func(self, *args) # type: ignore
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
            raise OSError(errno.EIO, "") from e
    return update_wrapper(wrapper, func) # type: ignore


def absnorm(path: str, /) -> str:
    path = normpath(path)
    if path.startswith("//"):
        path = path[1:]
    elif not path.startswith("/"):
        path = "/" + path
    return path


class P115FS:

    def __init__(
        self, 
        /, 
        root: str, 
        cmd_channel: FTPHandler, 
    ):
        self.cwd = "/"
        self.root = absnorm(root)
        self.cmd_channel = cmd_channel
        self.client: P115Client = getattr(cmd_channel, "client")
        self._fs_cache: dict[str, dict[str, dict[str, Any]]] = LRUDict(65536)
        self._attr_cache: dict[str, dict[str, Any]] = LRUDict(1024)
        self._url_cache: LRUDict[int, P115URL] = LRUDict(1024)
        self._listdir_last_called: dict[str, float] = {}
        self._listdir_lock: LRUDict[str, Any] = LRUDict(1024, default_factory=allocate_lock)
        self._move_lock = allocate_lock()
        self._remove_lock = allocate_lock()

    @debug_access_log
    def getattr(self, /, path: str) -> dict:
        path = self.ftpnorm(path)
        if path == "/":
            return {"id": 0, "parent_id": 0, "is_dir": True, "size": 0}
        if attr := self._attr_cache.get(path):
            if attr["path"] == path:
                return attr
            else:
                self._attr_cache.pop(path)
        dir_, name = splitpath(path)
        if not (siblings := self._fs_cache.get(dir_)):
            self.listdirinfo(dir_)
            siblings = self._fs_cache[dir_]
        try:
            return siblings[name]
        except KeyError:
            raise FileNotFoundError(errno.ENOENT, path) from None

    def ftpnorm(self, /, ftppath: str) -> str:
        """Normalize a "virtual" ftp pathname (typically the raw string
        coming from client) depending on the current working directory.

        Example (having "/foo" as current working directory):
        >>> ftpnorm('bar')
        '/foo/bar'

        Note: directory separators are system independent ("/").
        Pathname returned is always absolutized.
        """
        return absnorm(joinpath(self.cwd, ftppath))

    def ftp2fs(self, /, ftppath: str) -> str:
        """Translate a "virtual" ftp pathname (typically the raw string
        coming from client) into equivalent absolute "real" filesystem
        pathname.

        Example (having "/home/user" as root directory):
        >>> ftp2fs("foo")
        '/home/user/foo'

        Note: directory separators are system dependent.
        """
        return joinpath(self.root, self.ftpnorm(ftppath)[1:])

    def fs2ftp(self, /, fspath: str) -> str:
        """Translate a "real" filesystem pathname into equivalent
        absolute "virtual" ftp pathname depending on the user's
        root directory.

        Example (having "/home/user" as root directory):
        >>> fs2ftp("/home/user/foo")
        '/foo'

        As for ftpnorm, directory separators are system independent
        ("/") and pathname returned is always absolutized.

        On invalid pathnames escaping from user's root directory
        (e.g. "/home" when root is "/home/user") always return "/".
        """
        p = normpath(joinpath(self.root, fspath))
        if not self.validpath(p):
            return "/"
        p = p[len(self.root):]
        if not p.startswith("/"):
            p = "/" + p
        return p

    def validpath(self, /, path: str) -> bool:
        """Check whether the path belongs to user's home directory.
        Expected argument is a "real" filesystem pathname.

        If path is a symbolic link it is resolved to check its real
        destination.

        Pathnames escaping from user's root directory are considered
        not valid.
        """
        root = self.root
        return commonpath((absnorm(path), root)) == root

    @debug_access_log
    def open(self, /, path: str, mode: str):
        """Open a file returning its handler."""
        if "w" in mode or "x" in mode:
            raise OSError(errno.ENOTSUP, mode)
        attr = self.getattr(path)
        if attr["is_dir"]:
            raise IsADirectoryError(errno.EISDIR, path)
        client = self.client
        if (self.cmd_channel.use_thumbs and 
            type_of_attr(attr) == 2 and 
            (thumb := attr.get("thumb"))
        ):
            url = thumb
            try:
                file = client.open(url)
            except:
                attr.pop("thumb", None)
                raise
        else:
            cache = self._url_cache
            fid = attr["id"]
            if url := cache.get(fid):
                if int(URL(url).query["t"]) - time.time() < 60 * 5:
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
            if "b" not in mode:
                return file.wrap(True)
        return file

    @debug_access_log
    def chdir(self, /, path: str):
        """Change the current directory. If this method is overridden
        it is vital that `cwd` attribute gets set.
        """
        self.cwd = self.ftpnorm(path)

    @debug_access_log
    def mkdir(self, /, path: str):
        """Create the specified directory."""
        path = self.ftpnorm(path)
        dir_, name = splitpath(path)
        dirattr = self.getattr(dir_)
        if not dirattr["is_dir"]:
            raise NotADirectoryError(errno.ENOTDIR, dir_)
        resp = check_response(self.client.fs_mkdir_app(name, pid=dirattr["id"]))
        attr = normalize_attr(resp["data"])
        attr["path"] = path
        self._attr_cache[path] = attr
        try:
            self._fs_cache[dir_][name] = attr
        except KeyError:
            pass

    @debug_access_log
    def listdir(self, /, path: str) -> list[str]:
        """List the content of a directory."""
        return [a["name"] for a in self.listdirinfo(path)]

    @debug_access_log
    def listdirinfo(self, /, path: str) -> list[dict]:
        """List the content of a directory."""
        listdir_last_called = self._listdir_last_called
        last_called = listdir_last_called.get(path)
        with self._listdir_lock[path]:
            if last_called and (
                last_called != listdir_last_called.get(path) or 
                last_called + LISTDIR_TTL > time.time()
            ):
                try:
                    return list(self._fs_cache[path].values())
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
                children[name] = attr
            listdir_last_called[path] = time.time()
            self._fs_cache[path] = children
            return list(children.values())

    @debug_access_log
    def rmdir(self, /, path: str):
        """Remove the specified directory."""
        self.remove.__wrapped__(self, path) # type: ignore

    @debug_access_log
    def remove(self, /, path: str):
        """Remove the specified file."""
        attr = self.getattr(path)
        with self._remove_lock:
            while True:
                try:
                    check_response(self.client.fs_delete_app(attr["id"]))
                    break
                except P115BusyOSError:
                    pass
        cache = self._fs_cache
        cache.pop(path, None)
        if path != "/":
            dir_, name = splitpath(path)
            try:
                cache[dir_].pop(name, None)
            except KeyError:
                pass

    @debug_access_log
    def rename(self, /, src: str, dst: str):
        """Rename the specified src file to the dst filename."""
        src = self.ftpnorm(src)
        dst = self.ftpnorm(dst)
        if src == dst:
            return
        client = self.client
        src_dir, src_name = splitpath(src)
        dst_dir, dst_name = splitpath(dst)
        attr = self.getattr(src)
        if src_dir != dst_dir:
            if dst_dir == "/":
                cid = 0
            else:
                dstdir_attr = self.getattr(dst_dir)
                if not dstdir_attr["is_dir"]:
                    raise NotADirectoryError(errno.ENOTDIR, dst_dir)
                cid = dstdir_attr["id"]
            with self._move_lock:
                while True:
                    try:
                        check_response(client.fs_move_app(attr["id"], cid))
                        break
                    except P115BusyOSError:
                        pass
        if src_name != dst_name:
            check_response(client.fs_rename_app((attr["id"], dst_name)))
        self._attr_cache.pop(src, None)
        cache = self._fs_cache
        try:
            cache[dst] = cache.pop(src)
        except KeyError:
            pass
        try:
            cache[dst_dir][dst_name] = cache[src_dir].pop(src_name)
        except KeyError:
            pass

    @debug_access_log
    def stat(self, /, path: str) -> stat_result:
        """Perform a stat() system call on the given path."""
        attr = self.getattr(path)
        return stat_result((
            (S_IFDIR if attr["is_dir"] else S_IFREG) | 0o555, 
            attr["id"], 
            0, 
            1, 
            self.client.user_id, 
            115, 
            attr["size"], 
            attr.get("atime", 0) or attr.get("mtime", 0), 
            attr.get("mtime", 0), 
            attr.get("ctime", 0), 
        ))

    lstat = stat

    @debug_access_log
    def isfile(self, /, path: str) -> bool:
        """Return True if path is a file."""
        if not path or path == "/":
            return False
        return not self.getattr(path)["is_dir"]

    @debug_access_log
    def islink(self, /, path: str) -> bool:
        """Return True if path is a symbolic link."""
        return False

    @debug_access_log
    def isdir(self, /, path: str) -> bool:
        """Return True if path is a directory."""
        if not path or path == "/":
            return True
        return self.getattr(path)["is_dir"]

    @debug_access_log
    def getsize(self, /, path: str) -> int:
        """Return the size of the specified file in bytes."""
        return self.getattr(path)["size"]

    @debug_access_log
    def getmtime(self, /, path: str) -> int:
        """Return the last modified time as a number of seconds since
        the epoch."""
        return self.getattr(path)["mtime"]

    @debug_access_log
    def realpath(self, /, path: str) -> str:
        """Return the canonical version of path eliminating any
        symbolic links encountered in the path (if they are
        supported by the operating system).
        """
        return self.ftp2fs(path)

    @debug_access_log
    def exists(self, /, path: str) -> bool:
        """Return True if path refers to an existing path.
        """
        try:
            self.getattr(path)
            return True
        except FileNotFoundError:
            return False

    lexists = exists

    def get_user_by_uid(self, /, uid: int) -> str:
        """Return the username associated with user id.
        """
        return str(self.client.user_id)

    def get_group_by_gid(self, /, gid: int) -> str:
        """Return the group name associated with group id.
        """
        return "115"

    @debug_access_log
    def format_list(
        self, 
        /, 
        basedir: str, 
        listing: list[str], 
        ignore_err: bool = True, 
    ):
        """Return an iterator object that yields the entries of given
        directory emulating the "/bin/ls -lA" UNIX command output.

         - (str) basedir: the absolute dirname.
         - (list) listing: the names of the entries in basedir
         - (bool) ignore_err: when False raise exception if os.lstat()
         call fails.

        On platforms which do not support the pwd and grp modules (such
        as Windows), ownership is printed as "owner" and "group" as a
        default, and number of hard links is always "1". On UNIX
        systems, the actual owner, group, and number of links are
        printed.

        This is how output appears to client:

        -rw-rw-rw-   1 owner   group    7045120 Sep 02  3:47 music.mp3
        drwxrwxrwx   1 owner   group          0 Aug 31 18:50 e-books
        -rw-rw-rw-   1 owner   group        380 Sep 02  3:40 module.py
        """
        months = ("", 
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        )
        if self.cmd_channel.use_gmt_times:
            timefunc = time.gmtime
        else:
            timefunc = time.localtime
        SIX_MONTHS = 180 * 24 * 60 * 60
        now = time.time()
        uname = str(self.client.user_id)
        gname = "115"
        for basename in listing:
            file = joinpath(basedir, basename)
            try:
                st = self.lstat(file)
            except OSError:
                if ignore_err:
                    continue
                raise
            perms = filemode(st.st_mode)
            nlinks = 1
            size = st.st_size
            mtime = timefunc(st.st_mtime)
            # if modification time > 6 months shows "month year"
            # else "month hh:mm";  this matches proftpd format, see:
            # https://github.com/giampaolo/pyftpdlib/issues/187
            fmtstr = "%d  %Y" if now - st.st_mtime > SIX_MONTHS else "%d %H:%M"
            try:
                mtimestr = "%s %s" % (
                    months[mtime.tm_mon],
                    time.strftime(fmtstr, mtime),
                )
            except ValueError:
                # It could be raised if last mtime happens to be too
                # old (prior to year 1900) in which case we return
                # the current time as last mtime.
                mtime = timefunc()
                mtimestr = "%s %s" % (
                    months[mtime.tm_mon],
                    time.strftime("%d %H:%M", mtime),
                )
            # formatting is matched with proftpd ls output
            line = "%s %3s %-8s %-8s %8s %s %s\r\n" % (
                perms,
                nlinks,
                uname,
                gname,
                size,
                mtimestr,
                basename,
            )
            yield line.encode(
                self.cmd_channel.encoding, self.cmd_channel.unicode_errors
            )

    @debug_access_log
    def format_mlsx(
        self, 
        /, 
        basedir: str, 
        listing: list[str], 
        perms: str, 
        facts: str, 
        ignore_err: bool = True, 
    ):
        """Return an iterator object that yields the entries of a given
        directory or of a single file in a form suitable with MLSD and
        MLST commands.

        Every entry includes a list of "facts" referring the listed
        element.  See RFC-3659, chapter 7, to see what every single
        fact stands for.

         - (str) basedir: the absolute dirname.
         - (list) listing: the names of the entries in basedir
         - (str) perms: the string referencing the user permissions.
         - (str) facts: the list of "facts" to be returned.
         - (bool) ignore_err: when False raise exception if os.stat()
         call fails.

        Note that "facts" returned may change depending on the platform
        and on what user specified by using the OPTS command.

        This is how output could appear to the client issuing
        a MLSD request:

        type=file;size=156;perm=r;modify=20071029155301;unique=8012; music.mp3
        type=dir;size=0;perm=el;modify=20071127230206;unique=801e33; ebooks
        type=file;size=211;perm=r;modify=20071103093626;unique=192; module.py
        """
        if self.cmd_channel.use_gmt_times:
            timefunc = time.gmtime
        else:
            timefunc = time.localtime
        permdir = "".join([x for x in perms if x not in "arw"])
        permfile = "".join([x for x in perms if x not in "celmp"])
        if ("w" in perms) or ("a" in perms) or ("f" in perms):
            permdir += "c"
        if "d" in perms:
            permdir += "p"
        show_type = "type" in facts
        show_perm = "perm" in facts
        show_size = "size" in facts
        show_modify = "modify" in facts
        show_create = "create" in facts
        show_mode = "unix.mode" in facts
        show_uid = "unix.uid" in facts
        show_gid = "unix.gid" in facts
        show_unique = "unique" in facts
        for basename in listing:
            retfacts: dict = {}
            file = joinpath(basedir, basename)
            # in order to properly implement 'unique' fact (RFC-3659,
            # chapter 7.5.2) we are supposed to follow symlinks, hence
            # use os.stat() instead of os.lstat()
            try:
                st = self.stat(file)
            except OSError:
                if ignore_err:
                    continue
                raise
            # type + perm
            # same as stat.S_ISDIR(st.st_mode) but slightly faster
            isdir = (st.st_mode & 61440) == S_IFDIR
            if isdir:
                if show_type:
                    if basename == ".":
                        retfacts["type"] = "cdir"
                    elif basename == "..":
                        retfacts["type"] = "pdir"
                    else:
                        retfacts["type"] = "dir"
                if show_perm:
                    retfacts["perm"] = permdir
            else:
                if show_type:
                    retfacts["type"] = "file"
                if show_perm:
                    retfacts["perm"] = permfile
            if show_size:
                retfacts["size"] = st.st_size  # file size
            # last modification time
            if show_modify:
                try:
                    retfacts["modify"] = time.strftime(
                        "%Y%m%d%H%M%S", timefunc(st.st_mtime)
                    )
                # it could be raised if last mtime happens to be too old
                # (prior to year 1900)
                except ValueError:
                    pass
            if show_create:
                # on Windows we can provide also the creation time
                try:
                    retfacts["create"] = time.strftime(
                        "%Y%m%d%H%M%S", timefunc(st.st_ctime)
                    )
                except ValueError:
                    pass
            # UNIX only
            if show_mode:
                retfacts["unix.mode"] = oct(st.st_mode & 511)
            if show_uid:
                retfacts["unix.uid"] = st.st_uid
            if show_gid:
                retfacts["unix.gid"] = st.st_gid

            # We provide unique fact (see RFC-3659, chapter 7.5.2) on
            # posix platforms only; we get it by mixing st_dev and
            # st_ino values which should be enough for granting an
            # uniqueness for the file listed.
            # The same approach is used by pure-ftpd.
            # Implementors who want to provide unique fact on other
            # platforms should use some platform-specific method (e.g.
            # on Windows NTFS filesystems MTF records could be used).
            if show_unique:
                retfacts["unique"] = f"{st.st_dev:x}g{st.st_ino:x}"

            # facts can be in any order but we sort them by name
            factstring = "".join(
                [f"{x}={retfacts[x]};" for x in sorted(retfacts.keys())]
            )
            line = f"{factstring} {basename}\r\n"
            yield line.encode(
                self.cmd_channel.encoding, self.cmd_channel.unicode_errors
            )

    @classmethod
    def run_forever(
        cls, 
        /, 
        client: str | PathLike | P115Client = Path("~/115-cookies.txt").expanduser(), 
        host: str = "0.0.0.0", 
        port: int = 7115, 
        authorizer = None, 
        use_thumbs: bool = False, 
    ):
        if not isinstance(client, P115Client):
            client = P115Client(client, check_for_relogin=True)
        class Handler(FTPHandler):
            abstracted_fs = P115FS
        Handler.client = client
        if authorizer is None:
            authorizer = DummyAuthorizer()
            authorizer.add_anonymous("/")
        Handler.authorizer = authorizer
        Handler.use_thumbs = use_thumbs
        server = FTPServer((host, port), Handler)
        server.serve_forever()


if __name__ == "__main__":
    logger.setLevel(logging.DEBUG)
    P115FS.run_forever()

