#!/usr/bin/env python3
# encoding: utf-8

__all__ = ["tinydb_initdb", "tinydb_update", "tinydb_update_event"]
__doc__ = "这个模块提供了一些和更新小型数据库有关的函数"

from collections.abc import Callable, Coroutine
from os import PathLike
from time import time
from typing import overload, Any, Literal

from iterutils import foreach, run_gen_step
from sqlitetools import connect, execute, executescript, query, upsert_items

from .history import iter_history_once
from .iterdir import iter_dirs, iter_life_behavior_once
from .querydb import P115QueryDB
from .updatedb import locked_gen_step, updatedb, event_normalize_attr, wrap_async


from ..client import P115Client


_init_ts = int(time())


def tinydb_initdb(con, /):
    """执行一些 SQL 语句以初始化数据库，并返回游标
    """
    sql = """\
PRAGMA journal_mode = WAL;
PRAGMA auto_vacuum  = NONE;
PRAGMA foreign_keys = OFF;
PRAGMA synchronous  = NORMAL;

CREATE TABLE IF NOT EXISTS data (
    id INTEGER NOT NULL PRIMARY KEY,       -- 文件或目录的 id
    parent_id INTEGER NOT NULL DEFAULT 0,  -- 上级目录的 id
    name TEXT NOT NULL DEFAULT '',         -- 名字
    sha1 TEXT NOT NULL DEFAULT '',         -- 文件 sha1 值
    size INTEGER NOT NULL DEFAULT 0,       -- 文件大小
    mtime INTEGER NOT NULL DEFAULT 0,      -- 数据更新时间（需由用户传入）
    is_dir BOOLEAN AS (sha1 = ''),         -- 是否目录
    is_alive BOOLEAN NOT NULL DEFAULT TRUE -- 是否存活
);
CREATE TABLE IF NOT EXISTS keystore (
    key TEXT NOT NULL PRIMARY KEY,
    val ANY NOT NULL
);

INSERT OR IGNORE INTO keystore VALUES ('last_history_id', 0);
INSERT OR IGNORE INTO keystore VALUES ('last_update_history_ts', 0);
INSERT OR IGNORE INTO keystore VALUES ('last_life_id', 0);
INSERT OR IGNORE INTO keystore VALUES ('last_update_life_ts', 0);

CREATE INDEX IF NOT EXISTS idx_data_pid_name ON data(parent_id, name);
CREATE INDEX IF NOT EXISTS idx_data_mtime ON data(mtime);"""
    return executescript(con, sql)


@overload
def tinydb_update(
    client: str | PathLike | P115Client, 
    con = "", 
    cid: int | str = 0, 
    recursive: bool = True, 
    only_alive: bool = False, 
    lock = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> None:
    ...
@overload
def tinydb_update(
    client: str | PathLike | P115Client, 
    con = "", 
    cid: int | str = 0, 
    recursive: bool = True, 
    only_alive: bool = False, 
    lock = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, None]:
    ...
def tinydb_update(
    client: str | PathLike | P115Client, 
    con = "", 
    cid: int | str = 0, 
    recursive: bool = True, 
    only_alive: bool = False, 
    lock = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> None | Coroutine[Any, Any, None]:
    """拉取一个目录

    :param client: 115 客户端或 cookies
    :param con: 数据库链接、游标或路径
    :param cid: 目录的 id 或 pickcode
    :param recursive: 是否拉取目录树
    :param only_alive: 只更新 ``is_alive=True`` 的条目
    :param lock: 更新数据库时加锁
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if isinstance(con, (bytes, str, PathLike)):
        con = connect(con or f"p115-tinydb-{client.user_id}.db")
        tinydb_initdb(con)
    def gen_step():
        mtime: int = yield updatedb(
            client, 
            con, 
            cid, 
            recursive=recursive, 
            only_alive=only_alive, 
            lock=lock, 
            async_=async_, 
            **request_kwargs, 
        )
        if mtime:
            yield from locked_gen_step(
                lock, 
                execute, 
                con, 
                "INSERT OR REPLACE INTO keystore VALUES(?, ?)", 
                [
                    ("last_update_history_ts", mtime), 
                    ("last_update_life_ts", mtime), 
                ], 
                executemany=True, 
                commit=True, 
            )
    return run_gen_step(gen_step, async_)


@overload
def tinydb_update_event(
    client: str | PathLike | P115Client, 
    con = "", 
    app: str = "android", 
    cooldown: float = 5, 
    history: bool = False, 
    ignore: None | Callable[[dict], bool] = None, 
    lock = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> None:
    ...
@overload
def tinydb_update_event(
    client: str | PathLike | P115Client, 
    con = "", 
    app: str = "android", 
    cooldown: float = 5, 
    history: bool = False, 
    ignore: None | Callable[[dict], bool] = None, 
    lock = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, None]:
    ...
def tinydb_update_event(
    client: str | PathLike | P115Client, 
    con = "", 
    app: str = "android", 
    cooldown: float = 5, 
    history: bool = False, 
    ignore: None | Callable[[dict], bool] = None, 
    lock = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> None | Coroutine[Any, Any, None]:
    """拉取事件，更新数据库

    .. caution::
        有一些情况，不能用事件立即确定

        - 云下载：根本没有事件
        - 回收站还原：根本没有事件
        - 接收文件：事件产生时，可能并未完成
        - 复制文件：事件产生时，可能并未完成
        - 有一些接口执行操作后，压根没有事件

    :param client: 115 客户端或 cookies
    :param con: 数据库链接、游标或路径
    :param app: 使用某个 app （设备）的接口
    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param history: 如果为 False，拉取 life 事件，否则拉取 history 事件
    :param ignore: 调用以判断是否要忽略某些事件
    :param lock: 更新数据库时加锁
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if isinstance(con, (bytes, str, PathLike)):
        con = connect(con or f"p115-tinydb-{client.user_id}.db")
        tinydb_initdb(con)
    data = dict(query(con, "SELECT key, val FROM keystore"))
    seen: set[str] = set()
    seen_add = seen.add
    upserts: list[dict] = []
    add_upsert = upserts.append
    first_event_id = 0
    def add(event: dict, /):
        nonlocal first_event_id
        if not first_event_id:
            first_event_id = int(event["id"])
        fid = event["file_id"]
        if fid in seen:
            return
        seen_add(fid)
        if ignore and not ignore(event):
            add_upsert(event_normalize_attr(event))
    def gen_step():
        table = ("life", "history")[history]
        key_id = "last_%s_id" %table
        key_ts = "last_update_%s_ts" %table
        if history:
            iter_once: Callable = iter_history_once
        else:
            iter_once = iter_life_behavior_once
        mtime = int(time())
        yield foreach(add, iter_once(
            client, 
            from_id=data.get(key_id, 0), 
            from_time=data.get(key_ts) or _init_ts, 
            ignore_types=None, 
            app=app, 
            cooldown=cooldown, 
            async_=async_, 
            **request_kwargs, 
        ))
        if upserts:
            pids: set[int] = {pid for a in upserts if a["is_alive"] and (pid := a["parent_id"])}
            if pids.difference(P115QueryDB(con).iter_existing_id(pids)):
                def add_item(attr, /):
                    attr["sha1"] = ""
                    attr["size"] = 0
                    attr["mtime"] = mtime
                    attr["is_alive"] = True
                    add_upsert(attr)
                yield foreach(add_item, iter_dirs(
                    client, 
                    id_to_dirnode=..., 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                ))
            yield from locked_gen_step(
                lock, 
                wrap_async(upsert_items, async_, threaded=True), 
                con, 
                upserts, 
                commit=True, 
            )
            first_event = upserts[0]
            yield from locked_gen_step(
                lock, 
                execute, 
                con, 
                "INSERT OR REPLACE INTO keystore VALUES(?, ?)", 
                [
                    (key_id, first_event_id), 
                    (key_ts, first_event["mtime"]), 
                ], 
                executemany=True, 
                commit=True, 
            )
        else:
            yield from locked_gen_step(
                lock, 
                execute, 
                con, 
                "INSERT OR REPLACE INTO keystore VALUES(?, ?)", 
                (key_ts, mtime), 
                commit=True, 
            )
    return run_gen_step(gen_step, async_)

