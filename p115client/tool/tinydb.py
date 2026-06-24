#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["tinydb_initdb", "updatedb_dir", "updatedb_tree", "updatedb_life"]
__doc__ = "这个模块提供了一些和更新小型数据库有关的函数"

from asyncio import to_thread
from itertools import batched
from sqlite3 import Connection, Cursor
from time import time

from asynctools import async_batched
from p115client import P115Client
from sqlitetools import execute, query, upsert_items

from .querydb import P115QueryDB
from .iterdir import (
    iterdir, iter_life_behavior_once, iter_nodes_using_event, 
    traverse_tree, 
)


_init_ts = int(time())


def tinydb_initdb(
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

INSERT OR IGNORE INTO keystore VALUES ('last_update_ts', 0);
INSERT OR IGNORE INTO keystore VALUES ('last_life_id', 0);

CREATE INDEX IF NOT EXISTS idx_data_pid_name ON data(parent_id, name);
CREATE INDEX IF NOT EXISTS idx_data_mtime ON data(mtime);
""")


async def tinydb_update_dir(
    client: P115Client, 
    con: Connection | Cursor, 
    cid: int | str = 0, 
):
    cid = client.to_id(cid)
    try:
        mtime = int(time())
        async for batch in async_batched(iterdir(client, cid, id_to_dirnode=..., async_=True), 1000):
            await to_thread(
                upsert_items, 
                con, 
                batch, 
                {"is_alive": True, "mtime": mtime}, 
                fields=("id", "parent_id", "name", "sha1", "size"), 
                commit=True, 
            )
        execute(
            con, 
            "UPDATE data SET is_alive=FALSE WHERE parent_id=? AND mtime<? AND is_alive", 
            (cid, mtime), 
            commit=True, 
        )
    except FileNotFoundError:
        pass


async def tinydb_update_tree(
    client: P115Client, 
    con: Connection | Cursor, 
    cid: int | str = 0, 
    recursive: bool = True, 
):
    if not recursive:
        return tinydb_update_dir(client, con, cid)
    cid = client.to_id(cid)
    try:
        mtime = int(time())
        print(mtime)
        async for batch in async_batched(traverse_tree(client, cid, id_to_dirnode=..., async_=True), 1000):
            await to_thread(
                upsert_items, 
                con, 
                batch, 
                {"is_alive": True, "mtime": mtime}, 
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
        await to_thread(
            execute, 
            con, 
            sql, 
            {"cid": cid, "mtime": mtime}, 
            commit=True, 
        )
        if not cid:
            execute(con, "INSERT OR REPLACE INTO keystore VALUES(?, ?)", ("last_update_ts", mtime), commit=True)
    except FileNotFoundError:
        pass


# TODO: 有一些特殊的情况，不能用事件立即确定
# 云下载：根本没有事件（但可以从历史获取）
# 接收文件："receive_files", 14（因为不是立即完成）
# 复制文件："copy_folder", 18（因为不是立即完成）
async def tinydb_updatedb_life(
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
                "mtime": int(event["update_time"]), 
                "is_alive": False, 
            })
        else:
            pid = int(event["parent_id"])
            add_upsert({
                "id": int(fid), 
                "parent_id": pid, 
                "name": event["file_name"], 
                "sha1": event.get("sha1", ""), 
                "size": event.get("file_size", 0), 
                "mtime": int(event["update_time"]), 
                "is_alive": True, 
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
        await to_thread(upsert_items, con, upserts, commit=True)
    if removes:
        await to_thread(upsert_items, con, removes, commit=True)
    if first_event:
        execute(
            con, 
            "INSERT OR REPLACE INTO keystore VALUES(?, ?)", 
            [
                ("last_life_id", int(first_event["id"])), 
                ("last_update_ts", int(first_event["update_time"])), 
            ], 
            executemany=True, 
            commit=True, 
        )

