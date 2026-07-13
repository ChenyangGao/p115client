#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "updatedb_initdb", "updatedb", "updatedb_event_iter", 
]
__doc__ = "这个模块提供了一些和更新数据库有关的函数"

from collections.abc import AsyncIterator, Callable, Coroutine, Iterator
from inspect import isawaitable
from os import PathLike
from time import time
from typing import overload, Any, Literal

from asynctools import ensure_async
from iterutils import (
    chunked, foreach, run_gen_step, run_gen_step_iter, 
    with_iter_next, Yield, 
)
from orjson import dumps
from sqlitetools import connect, executescript, execute, find, query, upsert_items

from ..client import P115Client
from .history import iter_history_list
from .iterdir import iterdir, iter_dirs, traverse_tree
from .life import iter_life_behavior_list
from .querydb import P115QueryDB


def wrap_async(
    func: Callable, 
    async_: bool = False, 
    /, 
    threaded: bool = False, 
):
    if async_:
        return ensure_async(func, threaded=threaded)
    else:
        return func


def locked_gen_step(lock, func, /, *args, **kwds):
    try:
        if lock is not None:
            r = lock.acquire()
            if isawaitable(r):
                yield r
        r = func(*args, **kwds)
        if isawaitable(r):
            r = yield r
    finally:
        try:
            if lock is not None:
                lock.release()
        except RuntimeError:
            pass
    return r


def event_normalize_attr(event: dict, /) -> dict:
    return {
        "id": int(event["file_id"]), 
        "parent_id": int(event["parent_id"]), 
        "name": event["file_name"], 
        "sha1": event["sha1"], 
        "size": int(event.get("file_size") or 0), 
        "is_alive": event["type"] != 22, 
        "mtime": int(event["update_time"]), 
    }


def updatedb_initdb(con, /):
    """初始化数据库，然后返回游标
    """
    sql = """\
PRAGMA journal_mode = WAL;
PRAGMA auto_vacuum  = NONE;
PRAGMA foreign_keys = OFF;
PRAGMA synchronous  = NORMAL;

-- data 表，用来保存数据
CREATE TABLE IF NOT EXISTS data (
    id INTEGER NOT NULL PRIMARY KEY,       -- 文件或目录的 id
    parent_id INTEGER NOT NULL DEFAULT 0,  -- 上级目录的 id
    name TEXT NOT NULL DEFAULT '',         -- 名字
    sha1 TEXT NOT NULL DEFAULT '',         -- 文件 sha1 值
    size INTEGER NOT NULL DEFAULT 0,       -- 文件大小
    mtime INTEGER NOT NULL DEFAULT 0,      -- 数据更新时间
    is_dir BOOLEAN AS (sha1 = ''),         -- 是否目录
    is_alive BOOLEAN NOT NULL DEFAULT TRUE -- 是否存活
);

-- life 表，用来保存操作事件
CREATE TABLE IF NOT EXISTS life (
    id INTEGER NOT NULL PRIMARY KEY, -- 文件或目录的 id
    data JSON NOT NULL, -- 数据
    ctime TIMESTAMP DEFAULT (unixepoch('subsec')) -- 创建时间
);

-- history 表，用来保存历史记录
CREATE TABLE IF NOT EXISTS history (
    id INTEGER NOT NULL PRIMARY KEY, -- 文件或目录的 id
    data JSON NOT NULL, -- 数据
    ctime TIMESTAMP DEFAULT (unixepoch('subsec')) -- 创建时间
);

-- fs_event 表，用来保存文件系统变更（由 data 表触发）
CREATE TABLE IF NOT EXISTS fs_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- 事件 id
    event TEXT NOT NULL,                  -- 事件类型：add（增）、remove（删）、rename（改名）、move（移动）
    file_id INTEGER NOT NULL,             -- 文件或目录的 id，此 id 必在 `data` 表中
    pid0 INTEGER NOT NULL DEFAULT -1,     -- 变更前上级目录的 id
    pid1 INTEGER NOT NULL DEFAULT -1,     -- 变更后上级目录的 id
    name0 TEXT NOT NULL DEFAULT '',       -- 变更前的名字
    name1 TEXT NOT NULL DEFAULT '',       -- 变更后的名字
    ctime TIMESTAMP DEFAULT (unixepoch('subsec')) -- 创建时间
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_data_pid_name ON data(parent_id, name);
CREATE INDEX IF NOT EXISTS idx_data_mtime ON data(mtime);
CREATE INDEX IF NOT EXISTS idx_fs_event_ctime ON fs_event(ctime);

-- data 表发生插入
CREATE TRIGGER IF NOT EXISTS trg_data_insert
AFTER INSERT ON data
FOR EACH ROW
BEGIN
    INSERT INTO fs_event(event, file_id, pid1, name1) VALUES (
        'add', NEW.id, NEW.parent_id, NEW.name
    );
END;

-- data 表发生还原
CREATE TRIGGER IF NOT EXISTS trg_data_revoke
AFTER UPDATE ON data
FOR EACH ROW WHEN (NOT OLD.is_alive AND NEW.is_alive)
BEGIN
    INSERT INTO fs_event(event, file_id, pid1, name1) VALUES (
        'add', NEW.id, NEW.parent_id, NEW.name
    );
END;

-- data 表发生移除
CREATE TRIGGER IF NOT EXISTS trg_data_remove
AFTER UPDATE ON data
FOR EACH ROW WHEN (OLD.is_alive AND NOT NEW.is_alive)
BEGIN
    INSERT INTO fs_event(event, file_id, pid0, name0) VALUES (
        'remove', OLD.id, OLD.parent_id, OLD.name
    );
END;

-- data 表发生改名或移动
CREATE TRIGGER IF NOT EXISTS trg_data_change
AFTER UPDATE ON data
FOR EACH ROW WHEN (OLD.is_alive AND NEW.is_alive)
BEGIN
    -- move
    INSERT INTO fs_event(event, file_id, pid0, pid1, name0, name1)
    SELECT
        'move', OLD.id, OLD.parent_id, NEW.parent_id, OLD.name, OLD.name
    WHERE OLD.parent_id != NEW.parent_id;
    -- rename
    INSERT INTO fs_event(event, file_id, pid0, pid1, name0, name1) 
    SELECT * FROM (
        SELECT
            'rename', NEW.id, NEW.parent_id, NEW.parent_id, OLD.name, NEW.name
        WHERE OLD.name != NEW.name
    );
END;"""
    return executescript(con, sql)


@overload
def updatedb_dir(
    client: str | PathLike | P115Client, 
    con = "", 
    cid: int | str = 0, 
    only_alive: bool = False, 
    lock = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def updatedb_dir(
    client: str | PathLike | P115Client, 
    con = "", 
    cid: int | str = 0, 
    only_alive: bool = False, 
    lock = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def updatedb_dir(
    client: str | PathLike | P115Client, 
    con = "", 
    cid: int | str = 0, 
    only_alive: bool = False, 
    lock = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """拉取一个目录

    :param client: 115 客户端或 cookies
    :param con: 数据库链接、游标或路径
    :param cid: 目录的 id 或 pickcode
    :param only_alive: 只更新 ``is_alive=True`` 的条目
    :param lock: 更新数据库时加锁
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if isinstance(con, (bytes, str, PathLike)):
        con = connect(con or f"p115-updatedb-{client.user_id}.db")
        updatedb_initdb(con)
    cid = client.to_id(cid)
    def gen_step():
        if not P115QueryDB(con).is_alive(cid):
            return 0
        upsert = wrap_async(upsert_items, async_, threaded=True)
        ids: set[int] = {t for t, in query(con, "SELECT id FROM data WHERE parent_id=? AND is_alive")}
        try:
            id_to_dirnode: dict[int, tuple[str, int]] = {}
            with with_iter_next(chunked(iterdir(
                client, 
                cid, 
                id_to_dirnode=id_to_dirnode, 
                async_=async_, 
                **request_kwargs
            ), 1000)) as get_next:
                while True:
                    batch = yield get_next()
                    yield from locked_gen_step(
                        lock, 
                        upsert, 
                        con, 
                        batch, 
                        extras=None if only_alive else {"is_alive": True}, 
                        fields=("id", "parent_id", "name", "sha1", "size", "mtime"), 
                        commit=True, 
                    )
                    if ids:
                        ids.difference_update(a["id"] for a in batch)
            if fid := cid:
                ancestors: list[dict] = []
                while fid:
                    name, pid = id_to_dirnode[fid]
                    ancestors.append({"id": fid, "name": name, "parent_id": pid, "is_alive": True})
                    fid = pid
                yield from locked_gen_step(
                    lock, 
                    upsert, 
                    con, 
                    ancestors, 
                    commit=True, 
                )
            if ids:
                yield from locked_gen_step(
                    lock, 
                    execute, 
                    con, 
                    "UPDATE data SET is_alive=FALSE WHERE id IN (%s) AND is_alive" % ",".join(map(str, ids)), 
                    commit=True, 
                )
        except FileNotFoundError:
            yield from locked_gen_step(
                lock, 
                execute, 
                con, 
                "UPDATE data SET is_alive=FALSE WHERE parent_id=? AND is_alive", 
                (cid,), 
                commit=True, 
            )
        return 0
    return run_gen_step(gen_step, async_)


@overload
def updatedb(
    client: str | PathLike | P115Client, 
    con = "", 
    cid: int | str = 0, 
    recursive: bool = True, 
    only_alive: bool = False, 
    lock = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def updatedb(
    client: str | PathLike | P115Client, 
    con = "", 
    cid: int | str = 0, 
    recursive: bool = True, 
    only_alive: bool = False, 
    lock = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def updatedb(
    client: str | PathLike | P115Client, 
    con = "", 
    cid: int | str = 0, 
    recursive: bool = True, 
    only_alive: bool = False, 
    lock = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
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
    if not recursive:
        return updatedb_dir(
            client, 
            con, 
            cid, 
            only_alive=only_alive, 
            lock=lock, 
            async_=async_, 
            **request_kwargs, 
        )
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if isinstance(con, (bytes, str, PathLike)):
        con = connect(con or f"p115-updatedb-{client.user_id}.db")
        updatedb_initdb(con)
    cid = client.to_id(cid)
    def gen_step():
        if not P115QueryDB(con).is_alive(cid):
            return 0
        upsert = wrap_async(upsert_items, async_, threaded=True)
        try:
            mtime = int(time())
            extra = {"mtime": mtime}
            if not only_alive:
                extra["is_alive"] = True
            with with_iter_next(chunked(traverse_tree(
                client, 
                cid, 
                id_to_dirnode=..., 
                async_=async_, 
                **request_kwargs, 
            ), 1000)) as get_next:
                while True:
                    batch = yield get_next()
                    yield from locked_gen_step(
                        lock, 
                        upsert, 
                        con, 
                        batch, 
                        extras=extra, 
                        fields=("id", "parent_id", "name", "sha1", "size"), 
                        commit=True, 
                    )
            sql = """\
UPDATE data SET is_alive=FALSE WHERE id IN (
    WITH ids AS (
        SELECT id, parent_id FROM data WHERE parent_id=:cid AND mtime<:mtime AND is_alive
        UNION ALL
        SELECT data.id, data.parent_id FROM ids JOIN data ON(ids.id=data.parent_id) WHERE mtime<:mtime AND is_alive
    )
    SELECT id FROM ids
)"""
            yield from locked_gen_step(
                lock, 
                wrap_async(execute, async_, threaded=True), 
                con, 
                sql, 
                {"cid": cid, "mtime": mtime}, 
                commit=True, 
            )
            if not cid:
                return mtime
        except FileNotFoundError:
            yield from locked_gen_step(
                lock, 
                execute, 
                con, 
                "UPDATE data SET is_alive=FALSE WHERE parent_id=? AND is_alive", 
                (cid,), 
                commit=True, 
            )
        return 0
    return run_gen_step(gen_step, async_)


@overload
def updatedb_event_iter(
    client: str | PathLike | P115Client, 
    con = "", 
    from_id: int = -1, 
    from_time: float = 0, 
    cooldown: float = 5, 
    app: str = "android", 
    history: bool = False, 
    lock = None, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[list[dict]]:
    ...
@overload
def updatedb_event_iter(
    client: str | PathLike | P115Client, 
    con = "", 
    from_id: int = -1, 
    from_time: float = 0, 
    cooldown: float = 5, 
    app: str = "android", 
    history: bool = False, 
    lock = None, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[list[dict]]:
    ...
def updatedb_event_iter(
    client: str | PathLike | P115Client, 
    con = "", 
    from_id: int = -1, 
    from_time: float = 0, 
    cooldown: float = 5, 
    app: str = "android", 
    history: bool = False, 
    lock = None, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[list[dict]] | AsyncIterator[list[dict]]:
    """持续采集 115 生活日志，以更新 SQLite 数据库

    .. note::
        当 ``from_id < 0`` 时，会从数据库获取最大 id 作为 ``from_id``，获取不到时设为 0。
        当 ``from_id != 0`` 时，如果 from_time 为 0，则自动重设为 -1。

    :param client: 115 网盘客户端对象
    :param con: 数据库文件路径，如果为 None，则自动确定
    :param from_id: 开始的事件 id （不含），若 < 0 则是从数据库获取最大 id
    :param from_time: 开始时间（含），若为 0 则从当前时间开始，若 < 0 则从最早开始
    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param app: 使用指定 app（设备）的接口
    :param history: 如果为 False，拉取 life 事件，否则拉取 history 事件
    :param lock: 更新数据库时加锁
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，每次产生一批事件（从当前到上次截止）

    .. code::

        from time import sleep
        from p115client import P115Client
        from p115client.tool import updatedb_life_iter

        client = P115Client.from_path()

        for event_list in updatedb_life_iter(client):
            if event_list:
                print("采集到操作事件列表:", event_list)
            else:
                sleep(1)
    """
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if isinstance(con, (bytes, str, PathLike)):
        con = connect(con or f"p115-updatedb-{client.user_id}.db")
        updatedb_initdb(con)
    def gen_step():
        nonlocal from_id
        table = ("life", "history")[history]
        if from_id < 0:
            from_id = yield wrap_async(find, async_, threaded=True)(
                con, 
                "SELECT MAX(id) FROM life", 
                default=0, 
            )
        if history:
            iter_list: Callable = iter_history_list
        else:
            iter_list = iter_life_behavior_list
        querydb = P115QueryDB(con)
        with with_iter_next(iter_list(
            client, 
            from_id=from_id, 
            from_time=from_time, 
            ignore_types=None, 
            cooldown=cooldown, 
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )) as get_next:
            while True:
                event_list = yield get_next()
                if event_list:
                    event_list.reverse()
                    attrs = list(map(event_normalize_attr, event_list))
                    add_attr = attrs.append
                    pids: set[int] = {pid for a in attrs if a["is_alive"] and (pid := a["parent_id"])}
                    if pids.difference(querydb.iter_existing_id(pids)):
                        mtime = int(time())
                        def add_item(attr, /):
                            attr["sha1"] = ""
                            attr["size"] = 0
                            attr["mtime"] = mtime
                            attr["is_alive"] = True
                            add_attr(attr)
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
                        attrs, 
                        commit=True, 
                    )
                    yield from locked_gen_step(
                        lock, 
                        wrap_async(execute, async_, threaded=True), 
                        con, 
                        "INSERT OR IGNORE INTO %s(id, data) VALUES (?, ?)" %table, 
                        ((int(event["id"]), dumps(event)) for event in event_list), 
                        executemany=True, 
                        commit=True, 
                    )
                yield Yield(event_list)
    return run_gen_step_iter(gen_step, async_)

