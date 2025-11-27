#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 1)
__all__ = ["P115Server", "P115SFTPHandle", "P115SFTPServer", "P115RequestHandler"]

from functools import partial
from os import PathLike
from pathlib import Path
from posixpath import split as splitpath
from socketserver import BaseRequestHandler, BaseServer, ThreadingTCPServer
from time import sleep

from cachedict import TTLDict
from errno2 import errno
from decotools import decorated
from p115client import P115Client, P115FileSystem
from paramiko import (
    ServerInterface, SFTPServerInterface, SFTPAttributes, 
    SFTPServer, SFTPHandle, RSAKey, Transport, 
)
from paramiko.common import AUTH_SUCCESSFUL, OPEN_SUCCEEDED
from paramiko.sftp import SFTP_FAILURE, SFTP_OK
from richlog_fs import access_log, get_logger


logger = get_logger("p115sftp")
log = access_log(logger=logger, level=None)


@decorated
def clean_response(func, /, *args, **kwds):
    try:
        value = func(*args, **kwds)
    except OSError as e:
        if errno := e.errno:
            return SFTPServer.convert_errno(errno)
        return SFTP_FAILURE
    if value is None:
        return SFTP_OK
    return value


class P115Server(ServerInterface):
    def __init__(
        self, 
        /, 
        client: str | PathLike | P115Client =  Path("~/115-cookies.txt").expanduser(), 
        readdir_ttl: float = 60, 
    ):
        if not isinstance(client, P115Client):
            client = P115Client(client, check_for_relogin=True)
        self.client = client
        self.fs = client.get_fs(id_to_readdir=TTLDict(readdir_ttl))

    def check_auth_password(self, username, password):
        return AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password,publickey"


class P115SFTPHandle(SFTPHandle):
    _stat: SFTPAttributes

    def stat(self, /) -> SFTPAttributes:
        return self._stat


class P115SFTPServer(SFTPServerInterface):
    fs: P115FileSystem

    def __init__(self, /, server: P115Server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.server = server
        self.fs = server.fs

    @clean_response
    @log
    def stat(self, /, path: str) -> SFTPAttributes:
        path = self.canonicalize(path)
        attr = self.fs.get_attr(path)
        stat = SFTPAttributes.from_stat(self.fs.attr_to_stat(attr), filename=attr["name"])
        return stat

    lstat = stat

    @clean_response
    @log
    def list_folder(self, /, path: str) -> list[SFTPAttributes]:
        path = self.canonicalize(path)
        children: list[SFTPAttributes] = []
        add_child = children.append
        attr_to_stat = self.fs.attr_to_stat
        for attr in self.fs.readdir(path):
            stat = SFTPAttributes.from_stat(attr_to_stat(attr), filename=attr["name"])
            add_child(stat)
        return children

    @clean_response
    @log
    def open(
        self, 
        /, 
        path: str, 
        flags: int = 0, 
        attr: None | SFTPAttributes = None, 
    ) -> P115SFTPHandle:
        if flags:
            raise PermissionError(errno.EACCES, path)
        path = self.canonicalize(path)
        file = self.fs.open(path)
        fobj = P115SFTPHandle(0)
        setattr(fobj, "readfile", file)
        setattr(fobj, "filename", path)
        fobj._stat = self.stat(path)
        return fobj

    @clean_response
    @log
    def mkdir(
        self, 
        /, 
        path: str, 
        attr: None | SFTPAttributes = None, 
    ):
        path = self.canonicalize(path)
        dir_, name = splitpath(path)
        self.fs.mkdir(dir_, name)

    # TODO: upload
    # def put(self, /, localpath: str, remotepath: str, callback=None, confirm=True):
    #     ...

    @clean_response
    @log
    def rename(self, /, src: str, dst: str):
        src = self.canonicalize(src)
        dst = self.canonicalize(dst)
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

    posix_rename = rename

    @clean_response
    @log
    def remove(self, /, path: str):
        path = self.canonicalize(path)
        self.fs.remove(path)

    @clean_response
    @log
    def rmdir(self, /, path: str):
        path = self.canonicalize(path)
        self.fs.remove(path)


class P115RequestHandler(BaseRequestHandler):

    def __init__(
        self, 
        /, 
        request, 
        client_address, 
        server, 
        *, 
        client: str | PathLike | P115Client =  Path("~/115-cookies.txt").expanduser(), 
        readdir_ttl: float = 60, 
        server_key = None, 
    ):
        self.client = client
        self.readdir_ttl = readdir_ttl
        if not server_key:
            server_key = RSAKey.generate(1024)
        self.server_key = server_key
        super().__init__(request, client_address, server)

    def handle(self, /):
        logger.info("Connection from %s", self.client_address)
        transport = Transport(self.request)
        transport.add_server_key(self.server_key)
        transport.set_subsystem_handler("sftp", SFTPServer, P115SFTPServer)
        server = P115Server(client=self.client, readdir_ttl=self.readdir_ttl)
        transport.start_server(server=server)
        channel = transport.accept()
        while transport.is_active():
            sleep(1)

    @classmethod
    def serve_forever(
        cls, 
        /, 
        host: str = "0.0.0.0", 
        port: int = 6115, 
        client: str | PathLike | P115Client =  Path("~/115-cookies.txt").expanduser(), 
        readdir_ttl: float = 60, 
        server_key = None, 
        tcp_server_class: type[BaseServer] = ThreadingTCPServer, 
    ):
        setattr(tcp_server_class, "allow_reuse_address", True)
        serv = tcp_server_class(
            (host, port), 
            partial(cls, client=client, readdir_ttl=readdir_ttl, server_key=server_key), 
        )
        serv.serve_forever()


if __name__ == "__main__":
    P115RequestHandler.serve_forever()

