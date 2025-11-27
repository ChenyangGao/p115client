#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 5)
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"
__all__ = ["P115FS"]

from collections.abc import MutableMapping
from os import stat_result, PathLike
from pathlib import Path
from posixpath import commonpath, join as joinpath, normpath, split as splitpath
from stat import filemode, S_IFDIR
from time import gmtime, localtime, strftime, time

from cachedict import TTLDict
from errno2 import errno
from p115client import P115Client, P115FileSystem
from pyftpdlib.authorizers import DummyAuthorizer # type: ignore
from pyftpdlib.handlers import FTPHandler # type: ignore
from pyftpdlib.servers import FTPServer # type: ignore
from richlog_fs import access_log, get_logger


logger = get_logger("p115ftp")
log = access_log(logger=logger, level=None)


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
        self.fs: P115FileSystem = getattr(cmd_channel, "fs")

    @log
    def getattr(self, /, path: str) -> MutableMapping:
        return self.fs.get_attr(self.ftpnorm(path))

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

    @log
    def open(self, /, path: str, mode: str = "rb"):
        """Open a file returning its handler."""
        return self.fs.open(self.ftpnorm(path), mode=mode) # type: ignore

    @log
    def chdir(self, /, path: str):
        """Change the current directory. If this method is overridden
        it is vital that `cwd` attribute gets set.
        """
        self.cwd = self.ftpnorm(path)

    @log
    def mkdir(self, /, path: str):
        """Create the specified directory."""
        path = self.ftpnorm(path)
        dir_, name = splitpath(path)
        return self.fs.mkdir(dir_, name)

    @log
    def listdir(self, /, path: str) -> list[str]:
        """List the content of a directory."""
        return [a["name"] for a in self.listdirinfo(path)]

    @log
    def listdirinfo(self, /, path: str) -> list[MutableMapping]:
        """List the content of a directory."""
        return self.fs.readdir(path)

    @log
    def rmdir(self, /, path: str):
        """Remove the specified directory."""
        return self.fs.remove(path)

    @log
    def remove(self, /, path: str):
        """Remove the specified file."""
        return self.fs.remove(path)

    @log
    def rename(self, /, src: str, dst: str):
        """Rename the specified src file to the dst filename."""
        src = self.ftpnorm(src)
        dst = self.ftpnorm(dst)
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

    @log
    def stat(self, /, path: str) -> stat_result:
        """Perform a stat() system call on the given path."""
        return self.fs.stat(path)

    lstat = stat

    @log
    def isfile(self, /, path: str) -> bool:
        """Return True if path is a file."""
        return self.fs.isfile(path)

    @log
    def islink(self, /, path: str) -> bool:
        """Return True if path is a symbolic link."""
        return False

    @log
    def isdir(self, /, path: str) -> bool:
        """Return True if path is a directory."""
        return self.fs.isdir(path)

    @log
    def getsize(self, /, path: str) -> int:
        """Return the size of the specified file in bytes."""
        return self.getattr(path).get("size", 0)

    @log
    def getmtime(self, /, path: str) -> int:
        """Return the last modified time as a number of seconds since
        the epoch."""
        return self.getattr(path).get("mtime", 0)

    @log
    def realpath(self, /, path: str) -> str:
        """Return the canonical version of path eliminating any
        symbolic links encountered in the path (if they are
        supported by the operating system).
        """
        return self.ftp2fs(path)

    @log
    def exists(self, /, path: str) -> bool:
        """Return True if path refers to an existing path.
        """
        return self.fs.exists(path)

    lexists = exists

    @log
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
            timefunc = gmtime
        else:
            timefunc = localtime
        SIX_MONTHS = 180 * 24 * 60 * 60
        now = time()
        uname = str(self.fs.user_id)
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
                    strftime(fmtstr, mtime),
                )
            except ValueError:
                # It could be raised if last mtime happens to be too
                # old (prior to year 1900) in which case we return
                # the current time as last mtime.
                mtime = timefunc()
                mtimestr = "%s %s" % (
                    months[mtime.tm_mon],
                    strftime("%d %H:%M", mtime),
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

    @log
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
            timefunc = gmtime
        else:
            timefunc = localtime
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
                    retfacts["modify"] = strftime(
                        "%Y%m%d%H%M%S", timefunc(st.st_mtime)
                    )
                # it could be raised if last mtime happens to be too old
                # (prior to year 1900)
                except ValueError:
                    pass
            if show_create:
                # on Windows we can provide also the creation time
                try:
                    retfacts["create"] = strftime(
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
        readdir_ttl: float = 60, 
    ):
        if not isinstance(client, P115Client):
            client = P115Client(client, check_for_relogin=True)
        _P115FTPHandler.client = client
        _P115FTPHandler.fs = client.get_fs(id_to_readdir=TTLDict(readdir_ttl))
        if authorizer is None:
            authorizer = DummyAuthorizer()
            authorizer.add_anonymous("/", perm="elradfmw")
        _P115FTPHandler.authorizer = authorizer
        server = FTPServer((host, port), _P115FTPHandler)
        server.serve_forever()


class _P115FTPHandler(FTPHandler):
    abstracted_fs = P115FS


if __name__ == "__main__":
    P115FS.run_forever()

