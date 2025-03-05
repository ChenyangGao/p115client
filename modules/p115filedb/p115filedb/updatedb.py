#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["updatedb"]

import logging

from collections import deque
from collections.abc import Iterable
from itertools import batched
from math import inf
from sqlite3 import connect, register_adapter, Connection, Cursor
from string import digits
from time import sleep, time
from warnings import warn

from concurrenttools import run_as_thread
from orjson import dumps
from p115client import P115Client, normalize_attr_simple
from p115client.exception import BusyOSError, P115Warning
from p115client.tool import iter_files_with_path, get_id_to_path
from sqlitetools import execute, upsert_items, AutoCloseConnection


logger = logging.Logger("115-updatedb-file", level=logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    "[\x1b[1m%(asctime)s\x1b[0m] (\x1b[1;36m%(levelname)s\x1b[0m) "
    "\x1b[0m\x1b[1;35m%(name)s\x1b[0m \x1b[5;31m➜\x1b[0m %(message)s"
))
logger.addHandler(handler)
register_adapter(list, dumps)
register_adapter(dict, dumps)


def initdb(con: Connection | Cursor, /) -> Cursor:
    sql = """\
PRAGMA journal_mode = WAL;
-- 创建表
CREATE TABLE IF NOT EXISTS data (
    id INTEGER NOT NULL PRIMARY KEY,   -- 文件的 id
    parent_id INTEGER NOT NULL ,       -- 所在目录 id
    name TEXT NOT NULL DEFAULT '',     -- 名字
    sha1 TEXT NOT NULL DEFAULT '',     -- 文件的 sha1 散列值
    size INTEGER NOT NULL DEFAULT 0,   -- 文件大小
    pickcode TEXT NOT NULL DEFAULT '', -- 提取码，下载时需要用到
    ctime INTEGER NOT NULL DEFAULT 0,  -- 创建时间
    mtime INTEGER NOT NULL DEFAULT 0,  -- 更新时间
    type INTEGER NOT NULL DEFAULT 99,  -- 文件类型
    is_collect INTEGER NOT NULL DEFAULT 0, -- 是否已被标记为违规
    is_dir INTEGER NOT NULL DEFAULT 0, -- 是否目录，值总是 0
    path TEXT NOT NULL DEFAULT '',     -- 路径
    ancestors JSON NOT NULL DEFAULT '[]', -- 祖先节点列表
    top_id INTEGER NOT NULL DEFAULT 0, -- 上一次拉取时顶层目录的 id
    extra BLOB DEFAULT NULL -- 其它信息
);
-- 创建索引
CREATE INDEX IF NOT EXISTS idx_data_pc ON data(pickcode);
CREATE INDEX IF NOT EXISTS idx_data_sha1_size ON data(sha1, size);
CREATE INDEX IF NOT EXISTS idx_data_tid ON data(top_id);
CREATE INDEX IF NOT EXISTS idx_data_pid ON data(parent_id);
CREATE INDEX IF NOT EXISTS idx_data_name ON data(name);
CREATE INDEX IF NOT EXISTS idx_data_mtime ON data(mtime);
CREATE INDEX IF NOT EXISTS idx_data_path ON data(path);
"""
    return con.executescript(sql)


def updatedb_all(
    client: P115Client, 
    con: Connection | Cursor, 
    top_id: int = 0, 
    page_size: int = 7_000, 
    max_workers: None | int = None, 
) -> tuple[int, int]:
    def norm_attr(info: dict, /) -> dict:
        attr = normalize_attr_simple(info)
        attr["top_id"] = top_id
        return attr
    if page_size <= 0:
        page_size = 7_000
    future = run_as_thread(lambda: {id for id, in con.execute("SELECT id FROM data WHERE top_id = ?", (top_id,))})
    total = 0
    alive_ids: set[int] = set()
    for batch in batched(iter_files_with_path(
        client, 
        top_id, 
        page_size=page_size, 
        normalize_attr=norm_attr, 
        id_to_dirnode=..., 
        max_workers=max_workers, 
    ), page_size):
        upsert_items(con, batch, commit=True)
        total += len(batch)
        alive_ids.update(a["id"] for a in batch)
    dead_ids = future.result() - alive_ids
    if dead_ids:
        execute(con, f"DELETE FROM data WHERE top_id=%d AND id in (%s)" % (top_id, ",".join(map(str, dead_ids))), commit=True)
    return total, len(dead_ids)


def _init_client(
    client: str | P115Client, 
    dbfile: None | str | Connection | Cursor = None, 
) -> tuple[P115Client, Connection | Cursor]:
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if (app := client.login_app()) in ("web", "desktop", "harmony"):
        warn(f'app within ("web", "desktop", "harmony") is not recommended, as it will retrieve a new "tv" cookies', category=P115Warning)
        client.login_another_app("tv", replace=True)
    if not dbfile:
        dbfile = f"115-file-{client.user_id}.db"
    if isinstance(dbfile, (Connection, Cursor)):
        con = dbfile
    else:
        con = connect(
            dbfile, 
            uri=dbfile.startswith("file:"), 
            check_same_thread=False, 
            factory=AutoCloseConnection, 
            timeout=inf, 
        )
        initdb(con)
    if isinstance(con, Cursor):
        conn = con.connection
    else:
        conn = con
    return client, con


def updatedb(
    client: str | P115Client, 
    dbfile: None | str | Connection | Cursor = None, 
    top_dirs: int | str | Iterable[int | str] = 0, 
    page_size: int = 7_000, 
    interval: int | float = 0.5, 
    max_workers: None | int = None, 
    logger = logger, 
):
    """批量执行一组任务，任务为更新单个目录或者目录树的文件信息

    :param client: 115 网盘客户端对象
    :param dbfile: 数据库文件路径，如果为 None，则自动确定
    :param top_dirs: 要拉取的顶层目录集，可以是目录 id 或路径
    :param page_size: 每次批量拉取的分页大小
    :param interval: 两个任务之间的睡眠时间，如果 <= 0，则不睡眠
    :param max_workers: 全量更新时，最大的并发数
    :param logger: 日志对象，如果为 None，则不输出日志
    """
    if isinstance(top_dirs, (int, str)):
        top_dirs = top_dirs,
    dq = deque(top_dirs)
    get, put = dq.popleft, dq.append
    client, con = _init_client(client, dbfile)
    first_loop = True
    start_time: float = 0
    while dq:
        if start_time and interval > 0 and (diff := start_time + interval - time()) > 0:
            sleep(diff)
        top_dir = get()
        if isinstance(top_dir, int):
            top_id = top_dir
        else:
            if top_dir in ("", "0", ".", "..", "/"):
                top_id = 0
            elif not (top_dir.startswith("0") or top_dir.strip(digits)):
                top_id = int(top_dir)
            else:
                try:
                    top_id = get_id_to_path(
                        client, 
                        top_dir, 
                        ensure_file=False, 
                        app="android", 
                    )
                except FileNotFoundError:
                    if logger is not None:
                        logger.exception("[\x1b[1;31mFAIL\x1b[0m] directory not found: %r", top_dir)
                    continue
        start_time = time()
        if first_loop and interval > 0:
            sleep(interval)
        try:
            upserted, removed = updatedb_all(client, con, top_id, page_size, max_workers=max_workers)
        except FileNotFoundError:
            execute(con, "DELETE FROM data WHERE top_id = ?", top_id, commit=True)
            if logger is not None:
                logger.warning("[\x1b[1;33mSKIP\x1b[0m] not found: %s", top_id)
        except NotADirectoryError:
            if logger is not None:
                logger.warning("[\x1b[1;33mSKIP\x1b[0m] not a directory: %s", top_id)
        except BusyOSError:
            if logger is not None:
                logger.warning("[\x1b[1;35mREDO\x1b[0m] directory is busy updating: %s", top_id)
            put(top_id)
        except:
            if logger is not None:
                logger.exception("[\x1b[1;31mFAIL\x1b[0m] %s", top_id)
            raise
        else:
            if logger is not None:
                logger.info(
                    "[\x1b[1;32mGOOD\x1b[0m] \x1b[1m%s\x1b[0m, upsert: %d, remove: %d, cost: %.6f s", 
                    top_id, 
                    upserted, 
                    removed, 
                    time() - start_time, 
                )

# TODO: 支持增量更新，根据 mtime 逆序排列进行比对

