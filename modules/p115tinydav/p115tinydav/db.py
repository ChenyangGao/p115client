#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["init_db", "updatedb_dir", "updatedb_tree", "updatedb_life"]

from asyncio import to_thread
from itertools import batched
from sqlite3 import connect, Connection, Cursor
from time import time

from asynctools import async_batched
from p115client import P115Client
from p115client.tool import (
    iterdir, iter_life_behavior_once, iter_nodes_using_event, 
    traverse_tree, P115QueryDB, 
)
from sqlitetools import execute, query, upsert_items, AutoCloseConnection


_init_ts = int(time())


def get_con(path: str, /):
    return connect(
        path, 
        autocommit=True, 
        check_same_thread=False, 
        factory=AutoCloseConnection, 
        uri=path.startswith("file:"), 
    )


def init_db(
    con: Connection | Cursor, 
    /, 
) -> Cursor:
    """执行一些 SQL 语句以初始化数据库，并返回游标
    """
    if isinstance(con, Connection):
        conn = con
    else:
        conn = con.connection
    return conn.executescript(
        """\
PRAGMA journal_mode = WAL;
PRAGMA cache_size = -67108864;

CREATE TABLE IF NOT EXISTS data (
    id INTEGER NOT NULL PRIMARY KEY,       -- 文件或目录的 id
    parent_id INTEGER NOT NULL DEFAULT 0,  -- 上级目录的 id
    name TEXT NOT NULL DEFAULT '',         -- 名字
    sha1 TEXT NOT NULL DEFAULT '',         -- 文件 sha1 值
    size INTEGER NOT NULL DEFAULT 0,       -- 文件大小
    is_dir BOOLEAN AS (sha1 = ''),         -- 是否目录
    is_alive BOOLEAN NOT NULL DEFAULT TRUE -- 是否存活
);
CREATE TABLE IF NOT EXISTS keystore (
    key TEXT NOT NULL PRIMARY KEY,
    val ANY NOT NULL
);

INSERT OR IGNORE INTO keystore VALUES ('last_update_ts', 0);
INSERT OR IGNORE INTO keystore VALUES ('last_life_id', 0);

CREATE INDEX IF NOT EXISTS idx_data_pid_name ON data(parent_id, name);
""")


async def updatedb_dir(
    client: P115Client, 
    con: Connection | Cursor, 
    cid: int | str = 0, 
):
    try:
        async for batch in async_batched(iterdir(client, cid, id_to_dirnode=..., async_=True), 1000):
            await to_thread(
                upsert_items, 
                con, 
                batch, 
                {"is_alive": True}, 
                fields=("id", "parent_id", "name", "sha1", "size"), 
            )
    except FileNotFoundError:
        pass


async def updatedb_tree(
    client: P115Client, 
    con: Connection | Cursor, 
    top: int | str = 0, 
    recursive: bool = True, 
):
    if not recursive:
        return updatedb_dir(client, con, top)
    try:
        now = int(time())
        async for batch in async_batched(traverse_tree(client, top, id_to_dirnode=..., async_=True), 1000):
            await to_thread(
                upsert_items, 
                con, 
                batch, 
                {"is_alive": True}, 
                fields=("id", "parent_id", "name", "sha1", "size"), 
            )
        if not top:
            execute(con, "INSERT OR REPLACE INTO keystore VALUES(?, ?)", ("last_update_ts", now))
    except FileNotFoundError:
        pass


# TODO: 有一些特殊的情况，不能用事件立即确定
# 云下载：根本没有事件（但可以从历史获取）
# 接收文件："receive_files", 14（因为不是立即完成）
# 复制文件："copy_folder", 18（因为不是立即完成）
async def updatedb_life(
    client: P115Client, 
    con: Connection | Cursor, 
):
    data = dict(query(con, "SELECT key, val FROM keystore"))
    seen: set[str] = set()
    seen_add = seen.add
    upserts: list[dict] = []
    add_upsert = upserts.append
    removes: list[dict] = []
    add_remove = removes.append
    pids: set[int] = set()
    add_pid = pids.add
    first_event: None | dict = None
    def add(event):
        fid = event["file_id"]
        if fid in seen:
            return
        seen_add(fid)
        event_type = event["type"]
        if event_type == 22:
            add_remove({
                "id": int(fid), 
                "parent_id": int(event.get("parent_id", 0)), 
                "name": event["file_name"], 
                "sha1": event.get("sha1", ""), 
                "size": event.get("file_size", 0), 
                "is_alive": 0, 
            })
        else:
            pid = int(event["parent_id"])
            add_upsert({
                "id": int(fid), 
                "parent_id": pid, 
                "name": event["file_name"], 
                "sha1": event.get("sha1", ""), 
                "size": event.get("file_size", 0), 
                "is_alive": 1, 
            })
            if pid:
                add_pid(pid)
    i = 0
    async for event in iter_life_behavior_once(
        client, 
        from_id=data.get("last_life_id", 0), 
        from_time=data.get("last_update_ts") or _init_ts, 
        ignore_types=None, 
        yield_latest=True, 
        first_batch_size=50, 
        app="web", 
        async_=True, 
    ):
        if not first_event:
            first_event = event
        i += 1
        add(event)
    if i == 10_0000:
        async for event in iter_life_behavior_once(
            client, 
            from_id=data.get("last_life_id", 0), 
            from_time=data.get("last_update_ts") or _init_ts, 
            ignore_types=None, 
            first_batch_size=50, 
            offset=10_000, 
            app="android", 
            cooldown=5, 
            async_=True, 
        ):
            add(event)
    querydb = P115QueryDB(con)
    pids -= set(querydb.iter_existing_id(pids))
    while pids:
        for t_pids in batched(tuple(pids), 9000):
            async for attr in iter_nodes_using_event(
                client, 
                t_pids, 
                id_to_dirnode=..., 
                app="web", 
                async_=True, 
            ):
                attr["is_alive"] = True
                add_upsert(attr)
                if pid := attr["parent_id"]:
                    add_pid(pid)
        pids -= set(querydb.iter_existing_id(pids))
    if upserts:
        await to_thread(upsert_items, con, upserts)
    if removes:
        await to_thread(upsert_items, con, removes)
    if first_event:
        execute(
            con, 
            "INSERT OR REPLACE INTO keystore VALUES(?, ?)", 
            [
                ("last_life_id", int(first_event["id"])), 
                ("last_update_ts", int(first_event["update_time"])), 
            ], 
            executemany=True, 
        )


# TODO: 根目录也要能懒惰更新（冷却时间 1s）
# TODO: 用户罗列某个不存在于数据库的目录，则会用 client.fs_dir_getid2 查看是否存在，存在则会触发一次 update_tree
# TODO: 用户罗列某个在数据库中的目录，但是没有子元素项，也就是看起来是空目录，也会触发一次 update_tree
# TODO: 偶尔也会用 fs_info 来检查一下目录里面的文件和目录总数，如果和数据库中的不匹配，则会触发一次 update_tree
# TODO: propfind 某个路径，发现不在数据库，但是用 client 查看发现是存在的，应该如何处理？（路径level < 3，update_dir，>= 3 update_tree）
# TODO: get 某个文件，发现已经删除，数据库里面也要响应删除
# TODO: 用户可以对目录进行改名，如果名字里面带 >，则 update_dir，<，则是 update_tree
