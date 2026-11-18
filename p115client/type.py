#!/usr/bin/env python3
# encoding: utf-8

from __future__ import annotations

__all__ = [
    "DirNode", "P115UID", "P115Cookies", "P115DictAttrLikeMixin", 
    "P115DictAttrLike", "P115ID", "P115StrID", "P115URL", 
    "TaskResultTuple", 
]
__doc__ = "各种通用的类型"

from collections.abc import Buffer, Iterable, Mapping
from http.cookiejar import CookieJar, Cookie
from http.cookies import Morsel
from typing import Any, NamedTuple, Self

from cookietools import cookies_to_dict
from dicttools import iter_items
from undefined import undefined

from .const import SSOENT_TO_APP
from .exception import P115BadDownloadUrl


def match_115_domain(domain: None | str, /) -> bool:
    if not domain:
        return True
    return domain == "115.com" or domain.endswith(".115.com")


class DirNode(NamedTuple):
    """用来保存某个 id 对应的 name 和 parent_id 的元组
    """
    name: str
    parent_id: int


class P115UID(str):

    def __init__(self, uid: str, /):
        user_id, ssoent, timestamp = uid.split("_")
        self.user_id = int(user_id)
        self.ssoent = ssoent
        self.timestamp = int(timestamp)
        self.app = SSOENT_TO_APP.get(self.ssoent or "")

    def __repr__(self, /) -> str:
        cls = type(self)
        return f"{cls.__module__}.{cls.__qualname__}({super().__repr__()})"


class P115Cookies(str):
    """115 的 cookies 的封装
    """
    UID: P115UID
    CID: str
    KID: str
    SEID: str

    def __new__(
        cls, 
        cookies: Buffer | str | Mapping[str, str | Morsel | Cookie] | Iterable[tuple[str, str | Morsel | Cookie]] | CookieJar, 
        /, 
    ):
        ns = {}
        if isinstance(cookies, Buffer):
            cookies = str(cookies, "latin-1")
        if isinstance(cookies, str):
            cookies = cookies_to_dict(cookies.strip().rstrip(";"))
        elif isinstance(cookies, CookieJar):
            cookies = ((cookie.name, cookie) for cookie in cookies)
        for name, cookie in iter_items(cookies):
            if not name.endswith("ID"):
                continue
            if isinstance(cookie, Morsel):
                if not match_115_domain(cookie["domain"]):
                    continue
                cookie = cookie.value or ""
            elif isinstance(cookie, Cookie):
                if not match_115_domain(cookie.domain):
                    continue
                cookie = cookie.value or ""
            if name == "UID":
                cookie = P115UID(cookie)
            ns[name] = cookie
        self = super().__new__(cls, "; ".join(f"{k.upper()}={v}" for k, v in ns.items()))
        self.__dict__ = ns
        return self

    def __repr__(self, /) -> str:
        cls = type(self)
        return f"{cls.__module__}.{cls.__qualname__}({super().__repr__()})"


class P115DictAttrLikeMixin:

    def __getattr__(self, attr: str, /):
        try:
            return self.__dict__[attr]
        except KeyError as e:
            raise AttributeError(attr) from e

    def __delitem__(self, key: str, /):
        del self.__dict__[key]

    def __getitem__(self, key, /):
        try:
            if isinstance(key, str):
                return self.__dict__[key]
        except KeyError:
            return super().__getitem__(key) # type: ignore

    def __setitem__(self, key: str, val, /):
        self.__dict__[key] = val

    def __repr__(self, /) -> str:
        cls = type(self)
        if (module := cls.__module__) not in ("__main__", "builtins"):
            name = cls.__qualname__
        else:
            name = f"{module}.{cls.__qualname__}"
        return f"{name}({super().__repr__()}, {self.__dict__!r})"

    @property
    def mapping(self, /) -> dict[str, Any]:
        return self.__dict__

    def get(self, key, /, default=None):
        return self.__dict__.get(key, default)

    def items(self, /):
        return self.__dict__.items()

    def keys(self, /):
        return self.__dict__.keys()

    def values(self, /):
        return self.__dict__.values()


class P115DictAttrLike(P115DictAttrLikeMixin):

    def __new__(cls, val: Any = undefined, /, *args, **kwds):
        if val is undefined:
            return super().__new__(cls)
        else:
            return super().__new__(cls, val) # type: ignore

    def __init__(self, val: Any = undefined, /, *args, **kwds):
        self.__dict__.update(*args, **kwds)

    @classmethod
    def of(cls, val: Any = undefined, /, ns: None | dict = None) -> Self:
        if val is undefined:
            self = cls.__new__(cls)
        else:
            self = cls.__new__(cls, val)
        if ns is not None:
            self.__dict__ = ns
        return self

    @classmethod
    def derive(cls, base: type, name: str = "", /, **ns) -> type[Self]:
        return type(name, (cls, base), ns)

    @classmethod
    def derive_backend(cls, base: type, name: str = "", /, **ns) -> type[Self]:
        return type(name, (base, cls), ns)


class P115ID(P115DictAttrLike, int):
    """整数 id 的封装
    """
    def __str__(self, /) -> str:
        return int.__repr__(self)


class P115StrID(P115DictAttrLike, str):
    """字符串 id 的封装
    """


class P115URL(P115DictAttrLike, str):
    """下载链接的封装
    """
    def __init__(self, /, *args, **kwds):
        super().__init__(*args, **kwds)
        P115BadDownloadUrl.raise_for_bad(self)

    def geturl(self, /) -> str:
        return str(self)

    url = property(geturl)


class TaskResultTuple(NamedTuple):
    """任务的执行结果

    - indeed: 是否实际执行并成功完成了任务

        - 如果为 True，表示成功完成了任务，此时 `error` 必为 None
        - 如果为 False，则分两种情况讨论

            1. `error` 为 None，则表示可能已经成功执行过此任务
            2. `error` 为异常实例，就是发生了错误导致执行失败（但任务的产出未必会被清理，例如中断的下载文件可能不会会被保留以待断点续传）

    - error: 被捕获的异常，如果为 None，则没有发生异常
    """
    indeed: bool = True
    error: None | BaseException = None

    def __bool__(self, /) -> bool:
        return self.indeed

