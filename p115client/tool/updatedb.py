#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "updatedb_initdb", "updatedb", "updatedb_life_iter", 
    "updatedb_history_iter", 
]
__doc__ = "这个模块提供了一些和更新数据库有关的函数"

from collections.abc import AsyncIterator, Coroutine, Iterator
from math import inf
from os import PathLike
from sqlite3 import register_adapter, register_converter, Connection, Cursor
from time import time
from typing import overload, Any, Literal
from warnings import warn

from asynctools import ensure_async
from iterutils import (
    chunked, foreach, run_gen_step, run_gen_step_iter, 
    with_iter_next, Yield, 
)
from orjson import dumps, loads
from p115pickcode import to_id
from sqlitetools import connect, execute, find, upsert_items

from ..client import P115Client, P115Warning
from .attr import get_ancestors, normalize_attr_simple
from .history import iter_history_list
from .iterdir import iterdir, iter_nodes_using_event, traverse_tree
from .life import iter_life_behavior_list


register_adapter(list, dumps)
register_adapter(dict, dumps)
register_converter("JSON", loads)


def updatedb_initdb(con: Connection | Cursor, /) -> Cursor:
    """初始化数据库，然后返回游标
    """
    sql = """\
-- 修改日志模式为 WAL (Write Ahead Log)
PRAGMA journal_mode = WAL;

-- data 表，用来保存数据
CREATE TABLE IF NOT EXISTS data (
    id INTEGER NOT NULL PRIMARY KEY,      -- 主键
    parent_id INTEGER NOT NULL DEFAULT 0, -- 上级目录的 id
    name TEXT NOT NULL,                   -- 名字
    sha1 TEXT NOT NULL DEFAULT '',        -- 文件的 sha1 哈希值
    size INTEGER NOT NULL DEFAULT 0,      -- 文件大小
    pickcode TEXT NOT NULL DEFAULT '',    -- 提取码，下载等操作时需要用到
    is_dir INTEGER NOT NULL DEFAULT 1 CHECK(is_dir IN (0, 1)), -- 是否目录
    is_alive INTEGER NOT NULL DEFAULT 1 CHECK(is_alive IN (0, 1)), -- 是否存活（存活即是不是删除状态）
    extra BLOB DEFAULT NULL,              -- 额外的数据
    created_at TIMESTAMP DEFAULT (unixepoch('subsec')), -- 创建时间
    updated_at TIMESTAMP DEFAULT (CAST(STRFTIME('%s', 'now') AS INTEGER))  -- 更新时间
);

-- life 表，用来保存操作事件
CREATE TABLE IF NOT EXISTS life (
    id INTEGER NOT NULL PRIMARY KEY, -- 文件或目录的 id
    data JSON NOT NULL, -- 数据
    created_at TIMESTAMP DEFAULT (unixepoch('subsec')) -- 创建时间
);

-- history 表，用来保存历史记录
CREATE TABLE IF NOT EXISTS history (
    id INTEGER NOT NULL PRIMARY KEY, -- 文件或目录的 id
    data JSON NOT NULL, -- 数据
    created_at TIMESTAMP DEFAULT (unixepoch('subsec')) -- 创建时间
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_data_pid ON data(parent_id);
CREATE INDEX IF NOT EXISTS idx_data_utime ON data(updated_at);

-- data 表的记录发生更新，自动更新它的更新时间
CREATE TRIGGER IF NOT EXISTS trg_data_update
AFTER UPDATE ON data
FOR EACH ROW
BEGIN
    SELECT CASE
        WHEN NEW.updated_at < OLD.updated_at THEN RAISE(IGNORE)
    END;
    UPDATE data SET updated_at = CAST(STRFTIME('%s', 'now') AS INTEGER) WHERE id = NEW.id AND NEW.updated_at = OLD.updated_at;
END;

-- fs_event 表，用来保存文件系统变更（由 data 表触发）
CREATE TABLE IF NOT EXISTS fs_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- 事件 id
    event TEXT NOT NULL,                  -- 事件类型：add（增）、remove（删）、rename（改名）、move（移动）
    file_id INTEGER NOT NULL,             -- 文件或目录的 id，此 id 必在 `data` 表中
    pid0 INTEGER NOT NULL DEFAULT -1,     -- 变更前上级目录的 id
    pid1 INTEGER NOT NULL DEFAULT -1,     -- 变更后上级目录的 id
    name0 TEXT NOT NULL DEFAULT '',       -- 变更前的名字
    name1 TEXT NOT NULL DEFAULT '',       -- 变更后的名字
    created_at TIMESTAMP DEFAULT (unixepoch('subsec')) -- 创建时间
);

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
    INSERT INTO fs_event(event, file_id, pid0, pid1, name0, name1)
    SELECT
        'move', OLD.id, OLD.parent_id, NEW.parent_id, OLD.name, OLD.name
    WHERE OLD.parent_id != NEW.parent_id;

    INSERT INTO fs_event(event, file_id, pid0, pid1, name0, name1) 
    SELECT * FROM (
        SELECT
            'rename', NEW.id, NEW.parent_id, NEW.parent_id, OLD.name, NEW.name
        WHERE OLD.name != NEW.name
    );
END;"""
    return con.executescript(sql)


def wrap_async(func, async_: bool = False, /, threaded: bool = False):
    if async_:
        return ensure_async(func, threaded=threaded)
    else:
        return func


def _init_client(
    client: str | PathLike | P115Client, 
    dbfile: None | str | PathLike | Connection | Cursor = None, 
    init_sql: None | str = None, 
) -> tuple[P115Client, Connection | Cursor]:
    if isinstance(client, (str, PathLike)):
        client = P115Client(client)
    if client.login_app() in ("web", "desktop", "aps"):
        warn(
            f'app within ("web", "desktop", "aps") is not recommended, it will be replaced by "apple_tv" cookies', 
            category=P115Warning, 
        )
        client.login_another_app("apple_tv", replace=True)
    if not dbfile:
        dbfile = f"p115db-{client.user_id}.db"
    if isinstance(dbfile, (Connection, Cursor)):
        con = dbfile
    else:
        con = connect(dbfile, check_same_thread=False, timeout=inf)
        if init_sql is None:
            updatedb_initdb(con)
        elif init_sql:
            con.executescript(init_sql)
    return client, con


def has_id(con: Connection | Cursor, id: int, /) -> int:
    sql = "SELECT 1 FROM data WHERE id = ? AND is_alive"
    return find(con, sql, (id,), default=0)


def event_normalize_attr(event: dict, /) -> dict:
    sha1 = event["sha1"]
    return {
        "id": int(event["file_id"]), 
        "parent_id": int(event["parent_id"]), 
        "name": event["file_name"], 
        "sha1": sha1, 
        "size": int(event.get("file_size") or 0), 
        "pickcode": event["pick_code"], 
        "is_dir": not sha1, 
        "is_alive": event["type"] != 22, 
        "updated_at": int(event["create_time"]), 
    }


@overload
def load_missing_ancestors(
    client: P115Client, 
    con: Connection | Cursor, 
    attrs: list[dict], 
    cooldown: float = 0.2, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> list[dict]:
    ...
@overload
def load_missing_ancestors(
    client: P115Client, 
    con: Connection | Cursor, 
    attrs: list[dict], 
    cooldown: float = 0.2, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, list[dict]]:
    ...
def load_missing_ancestors(
    client: P115Client, 
    con: Connection | Cursor, 
    attrs: list[dict], 
    cooldown: float = 0.2, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> list[dict] | Coroutine[Any, Any, list[dict]]:
    def gen_step():
        seen_ids: set[int] = {a["id"] for a in attrs}
        ancestors: list[dict] = []
        add_to_seen = seen_ids.add
        add_ancestor = ancestors.append
        def add(attr: dict, /):
            add_to_seen(attr["id"])
            add_ancestor(attr)
        while pids := [
            pid for a in attrs 
            if (pid := a["parent_id"]) and not (pid in seen_ids or has_id(con, pid))
        ]:
            yield foreach(
                add, 
                iter_nodes_using_event(
                    client, 
                    pids, 
                    type="doc", 
                    normalize_attr=event_normalize_attr, 
                    id_to_dirnode=..., 
                    cooldown=cooldown, 
                    app=app, 
                    async_=async_, 
                    **request_kwargs, 
                ), 
            )
        return ancestors
    return run_gen_step(gen_step, async_)


@overload
def updatedb(
    client: str | PathLike | P115Client, 
    dbfile: None | str | PathLike | Connection | Cursor = None, 
    cid: int | str = 0, 
    recursive: bool = True, 
    max_workers: None | int = None, 
    max_files: int = 0, 
    max_dirs: int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> int:
    ...
@overload
def updatedb(
    client: str | PathLike | P115Client, 
    dbfile: None | str | PathLike | Connection | Cursor = None, 
    cid: int | str = 0, 
    recursive: bool = True, 
    max_workers: None | int = None, 
    max_files: int = 0, 
    max_dirs: int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> Coroutine[Any, Any, int]:
    ...
def updatedb(
    client: str | PathLike | P115Client, 
    dbfile: None | str | PathLike | Connection | Cursor = None, 
    cid: int | str = 0, 
    recursive: bool = True, 
    max_workers: None | int = None, 
    max_files: int = 0, 
    max_dirs: int = 0, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> int | Coroutine[Any, Any, int]:
    """对某个目录执行一次拉取，以更新 SQLite 数据

    :param client: 115 网盘客户端对象
    :param dbfile: 数据库文件路径，如果为 None，则自动确定
    :param cid: 目录的 id 或 pickcode
    :param recursive: 如果为 True，则拉取所有以之为祖先（先驱）节点的节点信息；否则，拉取所有以之为父（前驱）节点的节点信息
    :param max_workers: 最大并发数，如果为 None 或 < 0 则自动确定，如果为 0 则单工作者惰性执行
    :param max_files: 估计最大存在的文件数，<= 0 时则无限
    :param max_dirs: 估计最大存在的目录数，<= 0 时则无限
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 返回总共影响到数据行数，即所有 DML SQL 执行后，游标的 ``.rowcount`` 累加
    """
    client, con = _init_client(client, dbfile)
    upsert = wrap_async(upsert_items, async_, threaded=True)
    cid = to_id(cid)
    def gen_step():
        total = 0
        if recursive:
            start_t = int(time())
            try:
                if cid and not has_id(con, cid):
                    ancestors = yield get_ancestors(
                        client, 
                        cid, 
                        id_to_dirnode=..., 
                        ensure_file=False, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    if ancestors:
                        if ancestors[0]["id"] == 0:
                            ancestors = ancestors[1:]
                        if ancestors:
                            to_pickcode = client.to_pickcode
                            for a in ancestors:
                                a["pickcode"] = to_pickcode(a["id"], "fa")
                            total += (yield upsert(
                                con, 
                                ancestors, 
                                {"is_alive": 1}, 
                                commit=True, 
                            )).rowcount
                with with_iter_next(chunked(
                    traverse_tree(
                        client, 
                        cid, 
                        id_to_dirnode=..., 
                        max_workers=max_workers, 
                        max_files=max_files, 
                        max_dirs=max_dirs, 
                        app=app, 
                        async_=async_, 
                        **request_kwargs, 
                    ), 
                    1000, 
                )) as get_next:
                    while True:
                        batch = yield get_next()
                        total += (yield upsert(con, batch, {"is_alive": 1}, commit=True)).rowcount
                if cid:
                    clean_sql = f"""\
UPDATE data SET is_alive = 0 WHERE id in (
    WITH ids(id) AS (
        SELECT id FROM data WHERE parent_id = {cid} AND is_alive AND updated_at < :start_t
        UNION ALL
        SELECT data.id FROM ids JOIN data ON (ids.id = data.parent_id) WHERE is_alive AND updated_at < :start_t
    )
    SELECT id FROM ids
);"""
                else:
                    clean_sql = "UPDATE data SET is_alive = 0 WHERE is_alive AND updated_at < :start_t"
                total += (yield wrap_async(execute, async_, threaded=True)(
                    con, 
                    clean_sql, 
                    {"start_t": start_t}, 
                    commit=True, 
                )).rowcount
            except FileNotFoundError:
                if cid:
                    clean_sql = f"""\
UPDATE data SET is_alive = 0 WHERE id in (
    WITH ids(id) AS (
        SELECT id FROM data WHERE parent_id = {cid} AND is_alive
        UNION ALL
        SELECT data.id FROM ids JOIN data ON (ids.id = data.parent_id) WHERE is_alive
    )
    SELECT id FROM ids
);"""
                else:
                    clean_sql = "UPDATE data SET is_alive = 0 WHERE is_alive"
                total = (yield wrap_async(execute, async_, threaded=True)(
                    con, 
                    clean_sql, 
                    commit=True, 
                )).rowcount
        else:
            id_to_dirnode: dict[int, tuple[str, int]] = {}
            seen_ids: set[int] = set()
            try:
                with with_iter_next(chunked(iterdir(
                    client, 
                    cid, 
                    normalize_attr=normalize_attr_simple, 
                    id_to_dirnode=id_to_dirnode, 
                    raise_for_changed_count=True, 
                    app=app, 
                    cooldown=0.5, 
                    max_workers=max_workers, 
                    async_=async_, 
                    **request_kwargs, 
                ), 1000)) as get_next:
                    while True:
                        batch = yield get_next()
                        total += (yield upsert(
                            con, 
                            batch, 
                            extras={"is_alive": 1}, 
                            fields=("id", "parent_id", "name", "sha1", "size", "pickcode", "is_dir", "is_alive"), 
                            commit=True, 
                        )).rowcount
                        seen_ids.update(a["id"] for a in batch)
                if id_to_dirnode:
                    to_pickcode = client.to_pickcode
                    total += (yield upsert(
                        con, 
                        [
                            {"id": id, "name": name, "parent_id": pid, "ancestors": to_pickcode(id, "fa")} 
                            for id, (name, pid) in id_to_dirnode.items()
                            if id not in seen_ids
                        ], 
                        {"is_alive": 1}, 
                        commit=True, 
                    )).rowcount
                clean_sql = "UPDATE data SET is_alive = 0 WHERE is_alive and parent_id = ?"
                if seen_ids:
                    clean_sql += " AND id NOT IN (%s)" % ",".join(map(str, seen_ids))
                total += (yield wrap_async(execute, async_, threaded=True)(
                    con, 
                    clean_sql, 
                    (cid,), 
                    commit=True, 
                )).rowcount
            except FileNotFoundError:
                clean_sql = "UPDATE data SET is_alive = 0 WHERE is_alive and parent_id = ?"
                total = (yield wrap_async(execute, async_, threaded=True)(
                    con, 
                    clean_sql, 
                    (cid,), 
                    commit=True, 
                )).rowcount
        return total
    return run_gen_step(gen_step, async_)


@overload
def updatedb_life_iter(
    client: str | PathLike | P115Client, 
    dbfile: None | str | PathLike | Connection | Cursor = None, 
    from_id: int = -1, 
    from_time: float = 0, 
    cooldown: float = 0.2, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[list[dict]]:
    ...
@overload
def updatedb_life_iter(
    client: str | PathLike | P115Client, 
    dbfile: None | str | PathLike | Connection | Cursor = None, 
    from_id: int = -1, 
    from_time: float = 0, 
    cooldown: float = 0.2, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[list[dict]]:
    ...
def updatedb_life_iter(
    client: str | PathLike | P115Client, 
    dbfile: None | str | PathLike | Connection | Cursor = None, 
    from_id: int = -1, 
    from_time: float = 0, 
    cooldown: float = 0.2, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[list[dict]] | AsyncIterator[list[dict]]:
    """持续采集 115 生活日志，以更新 SQLite 数据库

    .. note::
        当 ``from_id < 0`` 时，会从数据库获取最大 id 作为 ``from_id``，获取不到时设为 0。
        当 ``from_id != 0`` 时，如果 from_time 为 0，则自动重设为 -1。

    :param client: 115 网盘客户端对象
    :param dbfile: 数据库文件路径，如果为 None，则自动确定
    :param from_id: 开始的事件 id （不含），若 < 0 则是从数据库获取最大 id
    :param from_time: 开始时间（含），若为 0 则从当前时间开始，若 < 0 则从最早开始
    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param app: 使用指定 app（设备）的接口
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
    client, con = _init_client(client, dbfile)
    def gen_step():
        nonlocal from_id
        if from_id < 0:
            from_id = yield wrap_async(find, async_, threaded=True)(
                con, 
                "SELECT MAX(id) FROM life", 
                default=0, 
            )
        with with_iter_next(iter_life_behavior_list(
            client, 
            from_id=from_id, 
            from_time=from_time, 
            ignore_types=(10,), 
            cooldown=cooldown,         
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )) as get_next:
            while True:
                event_list = yield get_next()
                event_list.reverse()
                if attrs := list(map(event_normalize_attr, event_list)):
                    if news := [a for a in attrs if a["is_alive"]]:
                        attrs.extend((yield load_missing_ancestors(
                            client, 
                            con, 
                            news, 
                            cooldown=cooldown, 
                            app=app, 
                            async_=async_, 
                            **request_kwargs, 
                        )))
                    yield wrap_async(upsert_items, async_, threaded=True)(
                        con, attrs, commit=True)
                if event_list:
                    yield wrap_async(execute, async_, threaded=True)(
                        con, 
                        "INSERT OR IGNORE INTO life(id, data) VALUES (?, ?)", 
                        [(int(event["id"]), dumps(event)) for event in event_list], 
                        commit=True, 
                    )
                yield Yield(event_list)
    return run_gen_step_iter(gen_step, async_)


@overload
def updatedb_history_iter(
    client: str | PathLike | P115Client, 
    dbfile: None | str | PathLike | Connection | Cursor = None, 
    from_id: int = -1, 
    from_time: float = 0, 
    cooldown: float = 0.2, 
    app: str = "android", 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[list[dict]]:
    ...
@overload
def updatedb_history_iter(
    client: str | PathLike | P115Client, 
    dbfile: None | str | PathLike | Connection | Cursor = None, 
    from_id: int = -1, 
    from_time: float = 0, 
    cooldown: float = 0.2, 
    app: str = "android", 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[list[dict]]:
    ...
def updatedb_history_iter(
    client: str | PathLike | P115Client, 
    dbfile: None | str | PathLike | Connection | Cursor = None, 
    from_id: int = -1, 
    from_time: float = 0, 
    cooldown: float = 0.2, 
    app: str = "android", 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[list[dict]] | AsyncIterator[list[dict]]:
    """持续采集 115 历史记录，以更新 SQLite 数据库

    .. note::
        当 ``from_id < 0`` 时，会从数据库获取最大 id 作为 ``from_id``，获取不到时设为 0。
        当 ``from_id != 0`` 时，如果 from_time 为 0，则自动重设为 -1。

    :param client: 115 网盘客户端对象
    :param dbfile: 数据库文件路径，如果为 None，则自动确定
    :param from_id: 开始的事件 id （不含），若 < 0 则是从数据库获取最大 id
    :param from_time: 开始时间（含），若为 0 则从当前时间开始，若 < 0 则从最早开始
    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param app: 使用指定 app（设备）的接口
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，每次产生一批事件（从当前到上次截止）

    .. code::

        from time import sleep
        from p115client import P115Client
        from p115client.tool import updatedb_history_iter

        client = P115Client.from_path()

        for event_list in updatedb_history_iter(client):
            if event_list:
                print("采集到历史记录列表:", event_list)
            else:
                sleep(1)
    """
    client, con = _init_client(client, dbfile)
    def gen_step():
        nonlocal from_id
        if from_id < 0:
            from_id = yield wrap_async(find, async_, threaded=True)(
                con, 
                "SELECT MAX(id) FROM history", 
                default=0, 
            )
        with with_iter_next(iter_history_list(
            client, 
            from_id=from_id, 
            from_time=from_time, 
            ignore_types=(), 
            cooldown=cooldown,         
            app=app, 
            async_=async_, 
            **request_kwargs, 
        )) as get_next:
            while True:
                event_list = yield get_next()
                event_list.reverse()
                if attrs := list(map(event_normalize_attr, event_list)):
                    if news := [a for a in attrs if a["is_alive"]]:
                        attrs.extend((yield load_missing_ancestors(
                            client, 
                            con, 
                            news, 
                            cooldown=cooldown, 
                            app=app, 
                            async_=async_, 
                            **request_kwargs, 
                        )))
                    yield wrap_async(upsert_items, async_, threaded=True)(
                        con, attrs, commit=True)
                if event_list:
                    yield wrap_async(execute, async_, threaded=True)(
                        con, 
                        "INSERT OR IGNORE INTO history(id, data) VALUES (?, ?)", 
                        [(int(event["id"]), dumps(event)) for event in event_list], 
                        commit=True, 
                    )
                yield Yield(event_list)
    return run_gen_step_iter(gen_step, async_)

