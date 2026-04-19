#!/usr/bin/env python3
# encoding: utf-8

from __future__ import annotations

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 3)
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"
__all__ = ["FileResource", "FolderResource", "P115FileSystemProvider"]

from collections.abc import Callable, Mapping
from functools import cached_property
from mimetypes import guess_type
from os import PathLike
from pathlib import Path
from posixpath import commonpath, split as splitpath
from _thread import allocate_lock
from time import time
from typing import Any
from urllib.parse import urlencode
from weakref import WeakKeyDictionary

from cachedict import LRUDict, TTLDict
from p115client import check_response, P115Client
from p115client.exception import P115BusyOSError
from p115client.tool import iterdir, normalize_attr, traverse_tree_with_path, type_of_attr
from wsgidav.wsgidav_app import WsgiDAVApp # type: ignore
from wsgidav.dav_error import DAVError # type: ignore
from wsgidav.dav_provider import DAVCollection, DAVNonCollection, DAVProvider # type: ignore
from wsgidav.server.server_cli import SUPPORTED_SERVERS # type: ignore
from yarl import URL


class ttl_property:

    def __init__(self, func: Callable, /, ttl: float = 0):
        self.__func__ = func
        self.__name__ = getattr(func, "__name__", "")
        self.ttl = ttl
        self.__lock_cache__: WeakKeyDictionary[Any, Any] = WeakKeyDictionary()
        self.__state_cache__: WeakKeyDictionary[Any, dict] = WeakKeyDictionary()

    def __set_name__(self, cls, name: str, /):
        self.__name__ = name

    def __get__(self, instance, cls, /):
        if instance is None:
            return self
        state = self.__state_cache__.setdefault(instance, {})
        last_ts = state.get("last_called")
        with self.__lock_cache__.setdefault(instance, allocate_lock()):
            last_called = state.get("last_called")
            if last_called != last_ts:
                return state["value"]
            if not last_called or last_called + self.ttl < time():
                state["value"] = self.__func__(instance)
                state["last_called"] = time()
            return state["value"]

    @classmethod
    def of(cls, /, ttl: float = 0):
        return lambda func: cls(func, ttl=ttl)


class DavPathBase:

    def __getattr__(self, attr: str, /):
        try:
            value = self.__dict__[attr] = self.attr[attr]
            return value
        except KeyError as e:
            raise AttributeError(attr) from e

    @cached_property
    def client(self, /) -> P115Client:
        return self.provider.client

    @cached_property
    def ctime(self, /) -> int:
        return self.attr.get("ctime") or 0

    @cached_property
    def etag(self, /) -> str:
        return str(self.id)

    @cached_property
    def mtime(self, /) -> int:
        return self.attr.get("mtime") or 0

    @cached_property
    def size(self, /) -> int:
        return self.attr.get("size") or 0

    def delete(self, /):
        with self.provider._remove_lock:
            while True:
                try:
                    check_response(self.client.fs_delete_app(self.id))
                    break
                except P115BusyOSError:
                    pass
        self.path = None

    def get_available_bytes(self, /) -> int:
        return int(self.provider.space_info["all_remain"]["size"])

    def get_content_length(self, /) -> int:
        return self.size

    def get_content_type(self, /) -> None | str:
        if self.is_collection:
            return None
        return guess_type(self.name)[0]

    def get_creation_date(self, /) -> int:
        return self.ctime

    def get_display_info(self, /) -> dict:
        if self.is_collection:
            return {"type": "Directory"}
        ext = self.name.rpartition(".")[-1].upper()
        if ext:
            return {"type": f"{ext}-File"}
        return {"type": "File"}

    def get_display_name(self, /) -> str:
        return self.name

    def get_etag(self, /) -> str:
        return self.etag

    def get_last_modified(self, /) -> int:
        return self.mtime

    def get_property_names(self, *, is_allprop: bool = True) -> list[str]:
        props = [
            "{DAV:}creationdate", "{DAV:}displayname", "{DAV:}getcontentlength", 
            "{DAV:}getcontenttype", "{DAV:}getlastmodified", "{DAV:}getetag", 
            "{DAV:}resourcetype", "{DAV:}quota-used-bytes", "{DAV:}quota-available-bytes", 
        ]
        if self.provider.lock_manager and not self.prevent_locking():
            props.append("{DAV:}lockdiscovery")
            props.append("{DAV:}supportedlock")
        if self.provider.prop_manager:
            url = self.get_ref_url()
            props.extend(self.provider.prop_manager.get_properties(url, self.environ))
        return props

    def get_used_bytes(self, /) -> int:
        return int(self.provider.space_info["all_use"]["size"])

    # def finalize_headers(self, /, environ: dict, response_headers: dict):
    #     # https://wsgidav.readthedocs.io/en/latest/_autosummary/wsgidav.dav_provider.DAVCollection.finalize_headers.html#wsgidav.dav_provider.DAVCollection.finalize_headers
    #     return super().finalize_headers(environ, response_headers)

    # def handle_copy(self, /, dest_path: str, *, depth_infinity: bool):
    #     # https://wsgidav.readthedocs.io/en/latest/_autosummary/wsgidav.dav_provider.DAVCollection.handle_copy.html#wsgidav.dav_provider.DAVCollection.handle_copy
    #     return super().handle_copy(dest_path, depth_infinity=depth_infinity)

    # def handle_delete(self, /):
    #     # https://wsgidav.readthedocs.io/en/latest/_autosummary/wsgidav.dav_provider.DAVCollection.handle_delete.html#wsgidav.dav_provider.DAVCollection.handle_delete
    #     return super().handle_delete()

    # def handle_move(self, /, dest_path: str):
    #     # https://wsgidav.readthedocs.io/en/latest/_autosummary/wsgidav.dav_provider.DAVCollection.handle_move.html#wsgidav.dav_provider.DAVCollection.handle_move
    #     return super().handle_move(dest_path)

    def is_link(self, /) -> bool:
        return False

    def move_recursive(self, /, dest_path: str):
        if not self.path:
            raise DAVError(404)
        dest_path = dest_path.rstrip("/")
        if self.path == dest_path:
            return
        client = self.client
        fid = self.id
        dir0, name0 = splitpath(self.path)
        dir1, name1 = splitpath(dest_path)
        if dir0 != dir1:
            if dir1 == "/":
                cid = 0
            elif (inst := self.provider.get_resource_inst(dir1, self.environ)) and inst.is_collection:
                cid = inst.id
            else:
                resp = check_response(client.fs_makedirs_app(dir1))
                cid = int(resp["cid"])
            with self.provider._move_lock:
                while True:
                    try:
                        check_response(client.fs_move_app(fid, pid=cid))
                        break
                    except P115BusyOSError:
                        pass
        if name0 != name1:
            check_response(client.fs_rename_app((fid, name1)))
        self.path = dest_path

    def support_etag(self, /) -> bool:
        return True

    def support_modified(self, /) -> bool:
        return True

    def support_recursive_delete(self, /) -> bool:
        return True

    def support_recursive_move(self, /, dest_path: str) -> bool:
        return True


class FileResource(DavPathBase, DAVNonCollection):

    def __init__(
        self, 
        /, 
        path: str, 
        environ: dict, 
        attr: Mapping, 
    ):
        super().__init__(path, environ)
        self.attr = attr
        self.provider._instance_cache[path] = self

    def copy_move_single(self, dest_path: str, *, is_move: bool):
        if is_move:
            return self.move_recursive(dest_path)
        if not self.path:
            raise DAVError(404)
        dest_path = dest_path.rstrip("/")
        if self.path == dest_path:
            return
        client = self.client
        fid = self.id
        dir0, name0 = splitpath(self.path)
        dir1, name1 = splitpath(dest_path)
        if dir1 == "/":
            cid = 0
        elif dir0 == dir1:
            cid = self.parent_id
        elif (inst := self.provider.get_resource_inst(dir1, self.environ)) and inst.is_collection:
            cid = inst.id
        else:
            resp = check_response(client.fs_makedirs_app(dir1))
            cid = int(resp["cid"])
        if name0 == name1:
            with self.provider._copy_lock:
                while True:
                    try:
                        check_response(client.fs_copy_app(fid, pid=cid))
                        break
                    except P115BusyOSError:
                        pass
        else:
            # TODO: 如果文件已经被和谐，要怎么处理
            url = client.download_url(self.attr["pickcode"], app="android")
            check_response(client.upload_file(
                file=url, 
                pid=cid, 
                filename=name1, 
                filesize=self.size, 
                filesha1=self.attr["sha1"], 
            ))

    def get_content(self, /):
        attr = self.attr
        if (self.provider.use_thumbs and 
            type_of_attr(attr) == 2 and 
            (thumb := attr.get("thumb"))
        ):
            raise DAVError(302, add_headers=[("location", thumb)])
        is_collect = attr.get("is_collect", False)
        if origin_302 := self.provider.origin_302:
            url = origin_302 + "?" + urlencode({
                "id": attr["id"], 
                "pickcode": attr["pickcode"], 
                "is_collect": is_collect, 
            })
            raise DAVError(302, add_headers=[("location", url)])
        environ = self.environ
        url_cache = self.provider._url_cache or {}
        if is_collect:
            if attr["size"] > 1024 * 1024 * 200:
                raise DAVError(403)
            if url := url_cache.get(self.id):
                if int(URL(url).query["t"]) - time() < 60 * 5:
                    url = None
            if not url:
                url = url_cache[self.id] = self.client.download_url(
                    attr["pickcode"], headers={"user-agent": ""}, app="web")
            try:
                return self.client.open(url, headers={"range": environ.get("HTTP_RANGE", ""), "user-agent": ""})
            except OSError:
                url_cache.pop(self.id, None)
                raise
        else:
            user_agent = environ.get("HTTP_USER_AGENT", "")
            if url := url_cache.get((self.id, user_agent)):
                if int(URL(url).query["t"]) - time() < 60 * 5:
                    url = None
            if not url:
                url = url_cache[(self.id, user_agent)] = self.client.download_url(
                    attr["pickcode"], headers={"user-agent": user_agent}, app="android")
            raise DAVError(302, add_headers=[("location", url)])

    def support_content_length(self, /) -> bool:
        return True

    def support_ranges(self, /) -> bool:
        return True


class FolderResource(DavPathBase, DAVCollection):

    def __init__(
        self, 
        /, 
        path: str, 
        environ: dict, 
        attr: Mapping, 
    ):
        super().__init__(path, environ)
        self.attr = attr
        self.provider._instance_cache[path] = self

    def copy_move_single(self, dest_path: str, *, is_move: bool):
        if is_move:
            return self.move_recursive(dest_path)
        if not self.path:
            raise DAVError(404)
        dest_path = dest_path.rstrip("/")
        if self.path == dest_path:
            return
        _, name0 = splitpath(self.path)
        dir1, name1 = splitpath(dest_path)
        if name0 != name1:
            raise DAVError(403)
        client = self.client
        fid = self.id
        if dir1 == "/":
            cid = 0
        elif (inst := self.provider.get_resource_inst(dir1, self.environ)) and inst.is_collection:
            cid = inst.id
        else:
            resp = check_response(client.fs_makedirs_app(dir1))
            cid = int(resp["cid"])
        with self.provider._copy_lock:
            while True:
                try:
                    check_response(client.fs_copy_app(fid, pid=cid))
                    break
                except P115BusyOSError:
                    pass

    def create_collection(self, /, name: str):
        check_response(self.client.fs_mkdir_app(name, pid=self.id))

    # TODO: 默认情况下，缓存很长时间，但是发生移动或删除，则会清掉此缓存
    @ttl_property.of(1)
    def children(self, /) -> dict[str, FileResource | FolderResource]:
        if not self.path:
            raise DAVError(404)
        children: dict[str, FileResource | FolderResource] = {}
        environ = self.environ
        dir_ = self.path
        if not dir_.endswith("/"):
            dir_ += "/"
        try:
            for attr in iterdir(
                self.client, 
                self.id, 
                app="android", 
            ):
                name = attr["name"]
                path = dir_ + attr["name"]
                if attr["is_dir"]:
                    children[name] = FolderResource(path, environ, attr)
                else:
                    children[name] = FileResource(path, environ, attr)
        except NotADirectoryError as e:
            raise DAVError(404) from e
        return children

    @ttl_property.of(1)
    def descendants(self, /) -> list[FileResource | FolderResource]:
        if not self.path:
            raise DAVError(404)
        descendants: list[FileResource | FolderResource] = []
        add_descendant = descendants.append
        environ = self.environ
        try:
            for attr in traverse_tree_with_path(self.client, self.id, escape=None):
                if attr["is_dir"]:
                    add_descendant(FolderResource(attr["path"], environ, attr))
                else:
                    add_descendant(FileResource(attr["path"], environ, attr))
        except NotADirectoryError as e:
            raise DAVError(404) from e
        return descendants

    def get_descendants(
        self, 
        /, 
        collections: bool = True, 
        resources: bool = True, 
        depth_first: bool = False, 
        depth: str = "infinity", 
        add_self: bool = False, 
    ) -> list[FileResource | FolderResource]:
        descendants: list[FileResource | FolderResource] = []
        add_descendant = descendants.append
        if add_self:
            add_descendant(self)
        if depth != "0":
            items = self.children.values() if depth == "1" else self.descendants
            for item in items:
                if collections if item.is_collection else resources:
                    add_descendant(item)
        if depth_first and len(descendants) > 1:
            d: dict[int, int] = {a.id: a.parent_id for a in descendants}
            depth_d: dict[int, int] = {}
            def get_depth(id: int, /) -> int:
                try:
                    return depth_d[id]
                except KeyError:
                    if id in d:
                        return 1 + get_depth(d[id])
                    return 0
            descendants.sort(key=lambda a: get_depth(a.id), reverse=True)
        return descendants

    def get_member(self, /, name: str) -> None | FileResource | FolderResource:
        if not (dir_ := self.path):
            raise DAVError(404)
        if inst := self.children.get(name):
            if inst.path and commonpath((inst.path, dir_)) == dir_:
                return inst
        return None

    def get_member_list(self, /) -> list[FileResource | FolderResource]:
        if not (dir_ := self.path):
            raise DAVError(404)
        return [a for a in self.children.values() if a.path and commonpath((a.path, dir_)) == dir_]

    def get_member_names(self, /) -> list[str]:
        if not (dir_ := self.path):
            raise DAVError(404)
        return [n for n, a in self.children.items() if a.path and commonpath((a.path, dir_)) == dir_]


class P115FileSystemProvider(DAVProvider):
    """提供 115 的 WebDAV 服务

    :param client: 115 的 cookies 或客户端对象
    :param origin_302: 设置 302

        - 如果为 False 或空（即 bool 测试为 False），则每次都获取全新链接
        - 如果为 True 或数字，则对链接进行缓存（一定时间）
        - 如果为字符串，则视为 302 服务，会将下载请求转发过去

    :param use_thumbs: 是否使用图片缩略图
    """
    def __init__(
        self, 
        /, 
        client: str | PathLike | P115Client = Path("~/115-cookies.txt").expanduser(), 
        origin_302: bool | float | str = True, 
        use_thumbs: bool = True, 
        check_for_relogin: bool = False, 
    ):
        super().__init__()
        if not isinstance(client, P115Client):
            client = P115Client(client, check_for_relogin=check_for_relogin)
        self.client = client
        self.origin_302 = ""
        if not origin_302:
            self._url_cache = None
        elif isinstance(origin_302, str):
            self.origin_302 = origin_302
        elif origin_302 is True or origin_302 < 0:
            self._url_cache = LRUDict(1024)
        else:
            self._url_cache = TTLDict(origin_302, maxsize=1024)
        self.use_thumbs = use_thumbs
        self._instance_cache: dict[str, FileResource | FolderResource] = {}
        self._move_lock = allocate_lock()
        self._copy_lock = allocate_lock()
        self._remove_lock = allocate_lock()

    @ttl_property.of(60)
    def space_info(self, /) -> dict:
        resp = check_response(self.client.user_space_info())
        return resp["data"]

    def get_resource_inst(
        self, 
        /, 
        path: str, 
        environ: dict, 
        must_be_folder: bool = False, 
    ) -> None | FileResource | FolderResource:
        if not path:
            return None
        if path == "/":
            return FolderResource(
                "/", 
                environ, 
                {"id": 0, "parent_id": 0, "name": "", "is_dir": True, "path": "/"}, 
            )
        path = path.rstrip("/")
        inst = self._instance_cache.get(path)
        if inst and path != inst.path:
            self._instance_cache.pop(path, None)
            inst = None
        if inst and not must_be_folder or isinstance(inst, FolderResource):
            return inst
        client = self.client
        resp = check_response(client.fs_dir_getid_app(path))
        if cid := int(resp["id"]):
            resp = check_response(client.fs_file(cid))
            return FolderResource(path, environ, normalize_attr(resp["data"][0]))
        dir_, name = splitpath(path)
        inst = self.get_resource_inst(dir_, environ, must_be_folder=True)
        if isinstance(inst, FolderResource):
            return inst.get_member(name)
        return None

    def run_forever(
        self, 
        /, 
        config: None | Mapping = None, 
        handler: None | Callable = None, 
    ):
        config = {
            "host": "0.0.0.0", 
            "port": 8115, 
            "simple_dc": {"user_mapping": {"*": True}}, 
            "server": "cheroot", 
            "provider_mapping": {"/": self}, 
            **(config or {}), 
        }
        app = WsgiDAVApp(config)
        server = config["server"]
        if handler is None:
            handler = SUPPORTED_SERVERS[server]
        print("\n    💥 Welcome to Python 115 WsgiDAV 🚀\n")
        handler(app, config, server)


if __name__ == "__main__":
    P115FileSystemProvider().run_forever()

# http://www.webdav.org
# https://wsgidav.readthedocs.io
# https://wsgidav.readthedocs.io/en/latest/user_guide_configure.html
# https://wsgidav.readthedocs.io/en/latest/_modules/wsgidav/dav_provider.html#DAVCollection

# TODO: 提供对拉取到数据库的缓存机制（使用数据库实现，默认是内存数据库，也可以把数据库保存到本地目录）
# TODO: 这个数据库模块，做一个单独的模块，以便提供给 p115wsgidav,p115ftp,p115fuse 等共用
