#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "updatedb_life_iter", "updatedb_life", "updatedb_one", "updatedb_tree", 
    "updatedb", "iter_fs_event", 
]

import logging

from collections.abc import Iterator, Iterable, Mapping
from errno import EBUSY
from functools import partial
from itertools import takewhile
from math import inf, isnan, isinf
from os import PathLike
from posixpath import splitext
from sqlite3 import connect, Connection, Cursor
from string import digits
from time import sleep, time
from typing import cast, Final, NoReturn
from warnings import warn

from concurrenttools import run_as_thread
from iterutils import bfs_gen
from orjson import dumps, loads
from p115client import check_response, normalize_attr_simple, P115Client
from p115client.const import SUFFIX_TO_TYPE
from p115client.exception import BusyOSError, P115Warning
from p115client.tool.download import iter_download_nodes
from p115client.tool.fs_files import iter_fs_files, iter_fs_files_threaded
from p115client.tool.iterdir import (
    get_file_count, get_id_to_path, iter_stared_dirs, iter_selected_nodes, 
    iter_selected_nodes_by_pickcode, iter_selected_nodes_using_star_event, 
    iter_selected_nodes_using_category_get, 
)
from p115client.tool.life import (
    iter_life_behavior, IGNORE_BEHAVIOR_TYPES, BEHAVIOR_TYPE_TO_NAME, 
)
from sqlitetools import execute, find, upsert_items, AutoCloseConnection

from .query import (
    get_dir_count, has_id, iter_descendants_bfs, iter_existing_id, 
    iter_id_to_parent_id, select_mtime_groups,  
)


# NOTE: 需要 mtime 的 115 生活事件类型集
MTIME_BEHAVIOR_TYPES: Final = frozenset((1, 2, 14, 17, 18, 20))
# NOTE: 需要 ctime 的 115 生活事件类型集
CTIME_BEHAVIOR_TYPES: Final = frozenset((1, 2, 14, 17, 18))
# NOTE: 初始化日志对象
logger = logging.Logger("115-updatedb", level=logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    "[\x1b[1m%(asctime)s\x1b[0m] (\x1b[1;36m%(levelname)s\x1b[0m) "
    "\x1b[0m\x1b[1;35m%(name)s\x1b[0m \x1b[5;31m➜\x1b[0m %(message)s"
))
logger.addHandler(handler)


def initdb(con: Connection | Cursor, /, disable_event: bool = False) -> Cursor:
    """初始化数据库，会尝试创建一些表、索引、触发器等，并把表的 "journal_mode" 改为 WAL (write-ahead-log)

    :param con: 数据库连接或游标

    :return: 游标
    """
    sql = """\
-- 修改日志模式为 WAL (write-ahead-log)
PRAGMA journal_mode = WAL;

-- 允许触发器递归触发
PRAGMA recursive_triggers = ON;

-- data 表，用来保存数据
CREATE TABLE IF NOT EXISTS data (
    id INTEGER NOT NULL PRIMARY KEY,   -- 文件或目录的 id
    parent_id INTEGER NOT NULL,        -- 上级目录的 id
    name TEXT NOT NULL,                -- 名字
    sha1 TEXT NOT NULL DEFAULT '',     -- 文件的 sha1 散列值
    size INTEGER NOT NULL DEFAULT 0,   -- 文件大小
    pickcode TEXT NOT NULL DEFAULT '', -- 提取码，下载时需要用到
    type INTEGER NOT NULL DEFAULT 0,   -- 文件类型，目录的 type 总是 0
    ctime INTEGER NOT NULL DEFAULT 0,  -- 创建时间戳，一旦设置就不会更新
    mtime INTEGER NOT NULL DEFAULT 0,  -- 更新时间戳，如果名字、备注被设置（即使值没变），或者（如果自己是目录）进出回收站或增删直接子节点或设置封面，会更新此值，但移动并不更新
    is_dir INTEGER NOT NULL CHECK(is_dir IN (0, 1)), -- 是否目录
    is_collect INTEGER NOT NULL DEFAULT 0, -- 是否已被标记为违规
    is_alive INTEGER NOT NULL DEFAULT 1 CHECK(is_alive IN (0, 1)),   -- 是否存活中（未被移除）
    extra BLOB DEFAULT NULL,           -- 额外的数据
    updated_at DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%f+08:00', 'now', '+8 hours')), -- 最近一次更新时间
    _triggered INTEGER NOT NULL DEFAULT 0 -- 是否执行过触发器
);

-- life 表，用来收集 115 生活事件
CREATE TABLE IF NOT EXISTS life (
    id INTEGER NOT NULL PRIMARY KEY, -- 事件 id
    data JSON NOT NULL,              -- 事件日志数据
    create_time INTEGER NOT NULL     -- 事件时间
);

-- event 表，用于记录 data 表上发生的变更事件
CREATE TABLE IF NOT EXISTS event (
    _id INTEGER PRIMARY KEY AUTOINCREMENT, -- 主键
    id INTEGER NOT NULL,   -- 文件或目录的 id
    old JSON DEFAULT NULL, -- 更新前的值
    diff JSON NOT NULL,    -- 将更新的值
    fs JSON DEFAULT NULL,  -- 发生的文件系统事件：add:新增，remove:移除，revert:还原，move:移动，rename:重名
    created_at DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%f+08:00', 'now', '+8 hours')) -- 创建时间
);

-- dirlen 表，用于记录 data 表中每个目录的节点数
CREATE TABLE IF NOT EXISTS dirlen (
    id INTEGER NOT NULL PRIMARY KEY,            -- 目录 id
    dir_count INTEGER NOT NULL DEFAULT 0,       -- 直属目录数
    file_count INTEGER NOT NULL DEFAULT 0,      -- 直属文件数
    tree_dir_count INTEGER NOT NULL DEFAULT 0,  -- 子目录树目录数
    tree_file_count INTEGER NOT NULL DEFAULT 0, -- 子目录树文件数
    is_alive INTEGER NOT NULL DEFAULT 1 CHECK(is_alive IN (0, 1)) -- 是否存活中（未被移除）
);

-- dirlen 表插入根节点
INSERT OR IGNORE INTO dirlen(id) VALUES (0);

-- 触发器，用来更新 dirlen 表
CREATE TRIGGER IF NOT EXISTS trg_dirlen_update
AFTER UPDATE ON dirlen 
FOR EACH ROW 
WHEN OLD.id AND OLD.is_alive AND (OLD.tree_dir_count != NEW.tree_dir_count OR OLD.tree_file_count != NEW.tree_file_count)
BEGIN
    UPDATE dirlen SET
        tree_dir_count = tree_dir_count + NEW.tree_dir_count - OLD.tree_dir_count, 
        tree_file_count = tree_file_count + NEW.tree_file_count - OLD.tree_file_count
    WHERE
        id = (SELECT parent_id FROM data WHERE id = OLD.id);
END;

-- 触发器，用来丢弃 mtime 较早的更新
CREATE TRIGGER IF NOT EXISTS trg_data_before_update
BEFORE UPDATE ON data
FOR EACH ROW
BEGIN
    SELECT CASE
        WHEN NEW.mtime < OLD.mtime THEN RAISE(IGNORE)
    END;
END;

-- 索引
CREATE INDEX IF NOT EXISTS idx_data_pid ON data(parent_id);
CREATE INDEX IF NOT EXISTS idx_data_pc ON data(pickcode);
CREATE INDEX IF NOT EXISTS idx_data_sha1 ON data(sha1);
CREATE INDEX IF NOT EXISTS idx_data_name ON data(name);
CREATE INDEX IF NOT EXISTS idx_data_utime ON data(updated_at);
CREATE INDEX IF NOT EXISTS idx_life_create ON life(create_time);
CREATE INDEX IF NOT EXISTS idx_event_create ON event(created_at);
"""
    if disable_event:
        sql += """
DROP TRIGGER IF EXISTS trg_data_insert;
CREATE TRIGGER trg_data_insert
AFTER INSERT ON data
FOR EACH ROW
BEGIN
    INSERT OR IGNORE INTO dirlen(id) SELECT NEW.id WHERE NEW.is_dir;
    UPDATE dirlen SET 
        dir_count = dir_count + NEW.is_dir, 
        file_count = file_count + NOT NEW.is_dir, 
        tree_dir_count = tree_dir_count + NEW.is_dir, 
        tree_file_count = tree_file_count + NOT NEW.is_dir
    WHERE id = NEW.parent_id;
END;

DROP TRIGGER IF EXISTS trg_data_update;
CREATE TRIGGER trg_data_update
AFTER UPDATE ON data 
FOR EACH ROW
WHEN NOT NEW._triggered
BEGIN
    -- 更新时间
    UPDATE data SET updated_at = strftime('%Y-%m-%dT%H:%M:%f+08:00', 'now', '+8 hours'), _triggered=1 WHERE id = NEW.id;
    -- 移除文件
    UPDATE dirlen SET
        file_count = file_count - 1, 
        tree_file_count = tree_file_count - 1
    WHERE OLD.is_alive AND NOT OLD.is_dir AND NOT (NEW.is_alive AND OLD.parent_id = NEW.parent_id) AND id = OLD.parent_id;
    -- 移除目录
    UPDATE dirlen SET
        dir_count = dir_count - 1, 
        tree_dir_count = tree_dir_count - 1 - (SELECT tree_dir_count FROM dirlen WHERE id = OLD.id), 
        tree_file_count = tree_file_count - (SELECT tree_file_count FROM dirlen WHERE id = OLD.id)
    WHERE OLD.is_alive AND OLD.is_dir AND NOT (NEW.is_alive AND OLD.parent_id = NEW.parent_id) AND id = OLD.parent_id;
    -- 移入文件
    UPDATE dirlen SET
        file_count = file_count + 1, 
        tree_file_count = tree_file_count + 1
    WHERE NEW.is_alive AND NOT OLD.is_dir AND NOT (OLD.is_alive AND OLD.parent_id = NEW.parent_id) AND id = NEW.parent_id;
    -- 移入目录
    UPDATE dirlen SET
        dir_count = dir_count + 1, 
        tree_dir_count = tree_dir_count + 1 + (SELECT tree_dir_count FROM dirlen WHERE id = OLD.id), 
        tree_file_count = tree_file_count + (SELECT tree_file_count FROM dirlen WHERE id = OLD.id)
    WHERE NEW.is_alive AND OLD.is_dir AND NOT (OLD.is_alive AND OLD.parent_id = NEW.parent_id) AND id = NEW.parent_id;
    -- 更新 is_alive 标记
    UPDATE dirlen SET is_alive = NEW.is_alive WHERE id = NEW.id;
END;"""
    else:
        sql += """
-- 触发器，记录 data 表 'insert'
DROP TRIGGER IF EXISTS trg_data_insert;
CREATE TRIGGER trg_data_insert
AFTER INSERT ON data
FOR EACH ROW
BEGIN
    INSERT OR IGNORE INTO dirlen(id) SELECT NEW.id WHERE NEW.is_dir;
    UPDATE dirlen SET 
        dir_count = dir_count + NEW.is_dir, 
        file_count = file_count + NOT NEW.is_dir, 
        tree_dir_count = tree_dir_count + NEW.is_dir, 
        tree_file_count = tree_file_count + NOT NEW.is_dir
    WHERE id = NEW.parent_id;
    INSERT INTO event(id, diff, fs) VALUES (
        NEW.id, 
        JSON_OBJECT(
            'id', NEW.id, 
            'parent_id', NEW.parent_id, 
            'pickcode', NEW.pickcode, 
            'sha1', NEW.sha1, 
            'name', NEW.name, 
            'size', NEW.size, 
            'is_dir', NEW.is_dir, 
            'type', NEW.type, 
            'ctime', NEW.ctime, 
            'mtime', NEW.mtime, 
            'is_collect', NEW.is_collect, 
            'is_alive', NEW.is_alive
        ), 
        JSON_OBJECT('type', 'insert', 'is_dir', NEW.is_dir, 'src_path', NULL, 'dst_path', (
            WITH ancestors AS (
                SELECT parent_id, '/' || REPLACE(name, '/', '|') AS path FROM data WHERE id=NEW.id
                UNION ALL
                SELECT data.parent_id, '/' || REPLACE(data.name, '/', '|') || ancestors.path FROM ancestors JOIN data ON (ancestors.parent_id = data.id) WHERE ancestors.parent_id
            )
            SELECT path FROM ancestors WHERE parent_id = 0
        ), 'op', JSON_ARRAY('add'))
    );
END;

-- 触发器，记录 data 表 'update'
DROP TRIGGER IF EXISTS trg_data_update;
CREATE TRIGGER trg_data_update
AFTER UPDATE ON data 
FOR EACH ROW
WHEN NOT NEW._triggered
BEGIN
    -- 更新时间
    UPDATE data SET updated_at = strftime('%Y-%m-%dT%H:%M:%f+08:00', 'now', '+8 hours'), _triggered=1 WHERE id = NEW.id;
    -- 移除文件
    UPDATE dirlen SET
        file_count = file_count - 1, 
        tree_file_count = tree_file_count - 1
    WHERE OLD.is_alive AND NOT OLD.is_dir AND NOT (NEW.is_alive AND OLD.parent_id = NEW.parent_id) AND id = OLD.parent_id;
    -- 移除目录
    UPDATE dirlen SET
        dir_count = dir_count - 1, 
        tree_dir_count = tree_dir_count - 1 - (SELECT tree_dir_count FROM dirlen WHERE id = OLD.id), 
        tree_file_count = tree_file_count - (SELECT tree_file_count FROM dirlen WHERE id = OLD.id)
    WHERE OLD.is_alive AND OLD.is_dir AND NOT (NEW.is_alive AND OLD.parent_id = NEW.parent_id) AND id = OLD.parent_id;
    -- 移入文件
    UPDATE dirlen SET
        file_count = file_count + 1, 
        tree_file_count = tree_file_count + 1
    WHERE NEW.is_alive AND NOT OLD.is_dir AND NOT (OLD.is_alive AND OLD.parent_id = NEW.parent_id) AND id = NEW.parent_id;
    -- 移入目录
    UPDATE dirlen SET
        dir_count = dir_count + 1, 
        tree_dir_count = tree_dir_count + 1 + (SELECT tree_dir_count FROM dirlen WHERE id = OLD.id), 
        tree_file_count = tree_file_count + (SELECT tree_file_count FROM dirlen WHERE id = OLD.id)
    WHERE NEW.is_alive AND OLD.is_dir AND NOT (OLD.is_alive AND OLD.parent_id = NEW.parent_id) AND id = NEW.parent_id;
    -- 更新 is_alive 标记
    UPDATE dirlen SET is_alive = NEW.is_alive WHERE id = NEW.id;
    -- 写入事件
    INSERT INTO event(id, old, diff, fs)
    SELECT *, (
        WITH t(event) AS (
            VALUES 
                (CASE WHEN diff->>'is_alive' THEN 'revert' END), 
                (CASE WHEN diff->>'is_alive' = 0 THEN 'remove' END), 
                (CASE WHEN diff->>'name' IS NOT NULL THEN 'rename' END), 
                (CASE WHEN diff->>'parent_id' IS NOT NULL THEN 'move' END)
        ), op(op) AS (
            SELECT JSON_GROUP_ARRAY(event) FROM t WHERE event IS NOT NULL
        )
        SELECT JSON_OBJECT('type', 'update', 'is_dir', NEW.is_dir, 'src_path', (
            CASE 
                WHEN OLD.parent_id = 0 THEN '/' || REPLACE(OLD.name, '/', '|') 
                ELSE (
                    WITH ancestors AS (
                        SELECT parent_id, '/' || REPLACE(name, '/', '|') AS path FROM data WHERE id=OLD.parent_id
                        UNION ALL
                        SELECT data.parent_id, '/' || REPLACE(data.name, '/', '|') || ancestors.path FROM ancestors JOIN data ON (ancestors.parent_id = data.id) WHERE ancestors.parent_id
                    )
                    SELECT path || '/' || REPLACE(OLD.name, '/', '|') FROM ancestors WHERE parent_id = 0
                ) 
            END
        ), 'dst_path', (
            CASE 
                WHEN NEW.parent_id = 0 THEN '/' || REPLACE(NEW.name, '/', '|')
                ELSE (
                    WITH ancestors AS (
                        SELECT parent_id, '/' || REPLACE(name, '/', '|') AS path FROM data WHERE id=NEW.parent_id
                        UNION ALL
                        SELECT data.parent_id, '/' || REPLACE(data.name, '/', '|') || ancestors.path FROM ancestors JOIN data ON (ancestors.parent_id = data.id) WHERE ancestors.parent_id
                    )
                    SELECT path || '/' || REPLACE(NEW.name, '/', '|') FROM ancestors WHERE parent_id = 0
                )
            END
        ), 'op', JSON(op.op)) FROM op WHERE JSON_ARRAY_LENGTH(op.op)
    )
    FROM (
        WITH data(id, old, new) AS (
            SELECT
                NEW.id, 
                JSON_OBJECT(
                    'id', OLD.id, 
                    'parent_id', OLD.parent_id, 
                    'pickcode', OLD.pickcode, 
                    'sha1', OLD.sha1, 
                    'name', OLD.name, 
                    'size', OLD.size, 
                    'is_dir', OLD.is_dir, 
                    'type', OLD.type, 
                    'ctime', OLD.ctime, 
                    'mtime', OLD.mtime, 
                    'is_collect', OLD.is_collect, 
                    'is_alive', OLD.is_alive
                ) AS old, 
                JSON_OBJECT(
                    'id', NEW.id, 
                    'parent_id', NEW.parent_id, 
                    'pickcode', NEW.pickcode, 
                    'sha1', NEW.sha1, 
                    'name', NEW.name, 
                    'size', NEW.size, 
                    'is_dir', NEW.is_dir, 
                    'type', NEW.type, 
                    'ctime', NEW.ctime, 
                    'mtime', NEW.mtime, 
                    'is_collect', NEW.is_collect, 
                    'is_alive', NEW.is_alive
                ) AS new
        ), old(key, value) AS (
            SELECT tbl.key, tbl.value FROM data, JSON_EACH(data.old) AS tbl
        ), new(key, value) AS (
            SELECT tbl.key, tbl.value FROM data, JSON_EACH(data.new) AS tbl
        ), diff(diff) AS (
            SELECT JSON_GROUP_OBJECT(key, new.value)
            FROM old JOIN new USING (key)
            WHERE old.value != new.value
        )
        SELECT data.id, data.old, diff.diff FROM data, diff WHERE data.old != data.new
    );
END;"""
    return con.executescript(sql)


def kill_items(
    con: Connection | Cursor, 
    ids: int | Iterable[int], 
    /, 
    where: str = "", 
    commit: bool = False, 
) -> Cursor:
    """使用 id 去筛选和移除一组数据

    :param con: 数据库连接或游标
    :param ids: 一组 id，会被移除
    :param where: 其它筛选条件
    :param commit: 是否提交

    :return: 游标
    """
    if isinstance(ids, int):
        cond = f"id = {ids:d}"
    else:
        cond = "id IN (%s)" % (",".join(map(str, ids)) or "NULL")
    sql = "UPDATE data SET _triggered=0, is_alive=0 WHERE " + cond
    if where:
        sql += " AND (%s)" % where
    return execute(con, sql, commit=commit)


def sort(
    data: list[dict], 
    /, 
    reverse: bool = False, 
) -> list[dict]:
    """对文件信息数据进行排序，使得如果某个元素是另一个元素的父节点，则后者在前

    :param data: 待排序的文件信息列表
    :param reverse: 是否你需排列

    :return: 原地排序，返回传入的列表本身
    """
    d: dict[int, int] = {a["id"]: a["parent_id"] for a in data}
    depth_d: dict[int, int] = {}
    def depth(id: int, /) -> int:
        try:
            return depth_d[id]
        except KeyError:
            if id in d:
                return 1 + depth(d[id])
            return 0
    data.sort(key=lambda a: depth(a["id"]), reverse=reverse)
    return data


def load_ancestors(
    con: Connection | Cursor, 
    /, 
    client: P115Client, 
    data: list[dict], 
    all_are_files: bool = False, 
    refresh: bool = False, 
    use_star: None | bool = False, 
) -> list[dict]:
    """加载祖先节点列表

    :param con: 数据库连接或游标
    :param client: 115 网盘客户端对象
    :param data: 文件信息列表
    :param all_are_files: 说明所有的列表元素都是文件节点，如此可减少一次判断
    :param refresh: 是否全量更新，如果为 False，则数据库中已经存在的节点不会被拉取
    :param use_star: 使用星标事件

    :return: 返回所传入的文件信息列表所对应的祖先节点列表
    """
    if use_star is None:
        id_to_dirnode: dict = {}
        for _ in iter_selected_nodes_using_category_get(
            client, 
            {a["parent_id"]: a["id"] for a in data}.values(), 
            id_to_dirnode=id_to_dirnode, 
            normalize_attr=normalize_attr, 
        ):
            pass
        ancestors: list[dict] = [
            {"id": fid, "name": name, "parent_id": pid, "is_dir": 1} 
            for fid, (name, pid) in id_to_dirnode.items()
        ]
    else:
        seen = {0}
        if not all_are_files:
            seen.update(a["id"] for a in data if a["is_dir"])
        ancestors = []
        if use_star:
            call = partial(
                iter_selected_nodes_using_star_event, 
                app="android", 
                id_to_dirnode=..., 
                normalize_attr = lambda event: {
                    "id": int(event["file_id"]), 
                    "parent_id": int(event["parent_id"]), 
                    "name": event["file_name"], 
                    "pickcode": event["pick_code"], 
                    "is_dir": 1, 
                }, 
                cooldown=0.5, 
            )
        else:
            call = partial(iter_selected_nodes, id_to_dirnode=..., normalize_attr=normalize_attr)
        while pids := {pid for a in data if (pid := a["parent_id"]) not in seen}:
            seen |= pids
            if not refresh:
                pids.difference_update(iter_existing_id(con, pids, is_alive=False))
            data = list(call(client, pids))
            ancestors.extend(data)
    if ancestors:
        sort(ancestors)
    return ancestors


def update_stared_dirs(
    con: Connection | Cursor, 
    /, 
    client: P115Client, 
    **request_kwargs, 
) -> list[dict]:
    """从网上增量拉取目录数据，并更新到数据库

    :param con: 数据库连接或游标
    :param client: 115 网盘客户端对象
    :param request_kwargs: 其它 http 请求参数，会传给具体的请求函数，默认的是 httpx，可用参数 request 进行设置

    :return: 拉取下来的新增或更新的目录的信息字典列表
    """
    mtime = find(con, "SELECT COALESCE(MAX(mtime), 0) FROM data WHERE is_dir")
    data: list[dict] = []
    if mtime:
        data.extend(takewhile(
            lambda attr: attr["mtime"] > mtime or not has_id(con, attr["id"]), 
            iter_stared_dirs(
                client, 
                order="user_utime", 
                asc=0, 
                first_page_size=64, 
                id_to_dirnode=..., 
                normalize_attr=normalize_attr, 
                app="android", 
                **request_kwargs, 
            ), 
        ))
    else:
        data_add = data.append
        for resp in iter_fs_files_threaded(
            client, 
            {"show_dir": 1, "star": 1, "fc_mix": 1}, 
            app="android", 
            cooldown=0.5, 
            max_workers=20, 
            **request_kwargs, 
        ):
            for attr in map(normalize_attr, resp["data"]):
                if not attr["is_dir"]:
                    break
                data_add(attr)
    if data:
        ancestors = load_ancestors(con, client, data)
        upsert_items(con, ancestors, extras={"_triggered": 0}, commit=True)
        upsert_items(con, sort(data), extras={"_triggered": 0}, commit=True)
    return data


def is_timeouterror(exc: Exception) -> bool:
    "判断一个错误类型是不是超时错误"
    if isinstance(exc, TimeoutError):
        return True
    exctype = type(exc)
    for exctype in exctype.mro():
        if exctype is Exception:
            break
        if "Timeout" in exctype.__name__:
            return True
    return False


def iterdir(
    client: P115Client, 
    cid: int = 0, 
    /, 
    first_page_size: int = 0, 
    page_size: int = 0, 
    count: int = -1, 
    show_dir: bool = True, 
    cooldown: None | int | float = None, 
    **request_kwargs, 
) -> tuple[int, list[dict], set[int], Iterator[dict]]:
    """拉取一个目录中的文件或目录的数据

    :param client: 115 网盘客户端对象
    :param cid: 目录的 id
    :param first_page_size: 首次拉取的分页大小，如果 <= 0，自动确定
    :param page_size: 分页大小，如果 <= 0，自动确定
    :param count: 文件总数
    :param show_dir: 如果为 True，则拉取 cid 所指定目录下直属的文件或目录节点，否则拉取所指定目录下整个子目录树中的所有文件节点（不含目录）
    :param payload: 其它查询参数
    :param request_kwargs: 其它 http 请求参数，会传给具体的请求函数，默认的是 httpx，可用参数 request 进行设置

    :return: 4 元组，分别是

        1. 总数
        2. 祖先节点的简略信息（不含根目录）
        3. 已经拉取的文件或目录的 id 的集合
        4. 迭代器，用来获取数据
    """
    seen: set[int] = set()
    seen_add = seen.add
    ancestors: list[dict] = []
    def iterate():
        nonlocal count
        payload = {"asc": 0, "cid": cid, "show_dir": int(show_dir), "o": "user_utime", "fc_mix": 1}
        if cooldown:
            it = iter_fs_files_threaded(
                client, 
                payload, 
                page_size=page_size, 
                count=count, 
                app="android", 
                raise_for_changed_count=True, 
                cooldown=cooldown, 
                **request_kwargs, 
            )
        else:
            it = iter_fs_files(
                client, 
                payload, 
                first_page_size=first_page_size, 
                page_size=page_size, 
                count=count, 
                app="android", 
                raise_for_changed_count=True, 
                **request_kwargs, 
            )
        for n, resp in enumerate(it):
            ancestors[:] = (
                {"id": int(a["cid"]), "parent_id": int(a["pid"]), "name": a["name"]} 
                for a in resp["path"][1:]
            )
            if not n:
                count = int(resp["count"])
                yield
            for attr in map(normalize_attr, resp["data"]):
                fid = cast(int, attr["id"])
                if fid in seen:
                    raise BusyOSError(
                        EBUSY, 
                        f"duplicate id found, means that some unpulled items have been updated: cid={cid}", 
                    )
                seen_add(fid)
                yield attr
    it = iterate()
    next(it)
    return count, ancestors, seen, it


def diff_dir(
    con: Connection | Cursor, 
    client: P115Client, 
    id: int = 0, 
    /, 
    count: int = -1, 
    refresh: bool = False, 
    tree: bool = False, 
    **request_kwargs, 
) -> tuple[bool, list[dict], list[int]]:
    """拉取数据，确定哪些记录需要移除或更替

    :param con: 数据库连接或游标
    :param client: 115 网盘客户端对象
    :param id: 目录的 id
    :param count: 文件总数
    :param refresh: 执行全量拉取
    :param tree: 如果为 True，则比对目录树，但仅对文件，即叶子节点，如果为 False，则比对所有直接（1 级）子节点，包括文件和目录
    :param request_kwargs: 其它 http 请求参数，会传给具体的请求函数，默认的是 httpx，可用参数 request 进行设置

    :return: 3 元组，1) 是否被全量拉取，2) 待更替的数据列表，3) 待移除的 id 列表
    """
    upsert_list: list[dict] = []
    remove_list: list[int] = []
    if refresh or not ((dirlen := get_dir_count(con, id)) and dirlen["tree_file_count"]):
        future1 = run_as_thread(lambda: set(iter_descendants_bfs(con, id, fields="id")))
        future2 = run_as_thread(lambda: [{"id": int(a["fid"]), "parent_id": int(a["pid"]), "name": a["fn"], "is_dir": 1, "is_alive": 1} 
                                        for a in iter_download_nodes(client, id, files=False, max_workers=None)])
        if tree:
            _, ancestors, _, data_it = iterdir(client, id, count=count, show_dir=False, cooldown=0.5, **request_kwargs)
        else:
            _, ancestors, _, data_it = iterdir(client, id, count=count, cooldown=0.5, **request_kwargs)
        try:
            upsert_list.extend(data_it)
        finally:
            if ancestors:
                upsert_items(con, ancestors, extras={"is_alive": 1, "is_dir": 1, "_triggered": 0}, commit=True)
        upsert_dir_list: list[dict] = future2.result()
        alive_ids = {a["id"] for a in upsert_list}
        alive_ids.update(a["id"] for a in upsert_dir_list)
        alive_ids.update(a["id"] for a in ancestors)
        remove_list.extend(future1.result() - alive_ids)
        sort(upsert_dir_list)
        upsert_items(con, upsert_dir_list, commit=True)
        return True, upsert_list, remove_list
    future = run_as_thread(select_mtime_groups, con, id, tree=tree)
    if tree:
        count, ancestors, seen, data_it = iterdir(client, id, first_page_size=128, count=count, show_dir=False, **request_kwargs)
    else:
        count, ancestors, seen, data_it = iterdir(client, id, first_page_size=16, count=count, **request_kwargs)
    groups = future.result()
    remains = sum(len(g[1]) for g in groups)
    upsert_add = upsert_list.append
    remove_extend = remove_list.extend
    result = not tree, upsert_list, remove_list
    try:
        if remains:
            his_it = iter(groups)
            his_mtime, his_ids = next(his_it)
        for n, attr in enumerate(data_it, 1):
            if remains:
                cur_id = attr["id"]
                cur_mtime = attr["mtime"]
                try:
                    while his_mtime > cur_mtime:
                        remove_extend(his_ids - seen)
                        remains -= len(his_ids)
                        his_mtime, his_ids = next(his_it)
                except StopIteration:
                    continue
                if his_mtime == cur_mtime and cur_id in his_ids:
                    remains -= 1
                    if n + remains == count:
                        return result
                    his_ids.remove(cur_id)
                    continue
            upsert_add(attr)
        if remains:
            remove_extend(his_ids - seen)
            for _, his_ids in his_it:
                remove_extend(his_ids - seen)
        return result
    finally:
        if ancestors:
            upsert_items(con, ancestors, extras={"is_alive": 1, "is_dir": 1, "_triggered": 0}, commit=True)


def normalize_attr(info: Mapping, /) -> dict:
    """筛选和规范化数据的名字，以便插入 `data` 表

    :param info: 原始数据

    :return: 经过规范化后的数据
    """
    attr = normalize_attr_simple(info)
    attr["is_alive"] = 1
    return attr


def _init_client(
    client: str | P115Client, 
    dbfile: None | str | Connection | Cursor = None, 
    disable_event: bool = False, 
) -> tuple[P115Client, Connection | Cursor]:
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    if (app := client.login_app()) in ("web", "desktop", "harmony"):
        warn(f'app within ("web", "desktop", "harmony") is not recommended, as it will retrieve a new "tv" cookies', category=P115Warning)
        client.login_another_app("tv", replace=True)
    if not dbfile:
        dbfile = f"115-{client.user_id}.db"
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
        initdb(con, disable_event=disable_event)
    return client, con


def updatedb_life_iter(
    client: str | P115Client, 
    dbfile: None | str | Connection | Cursor = None, 
    from_time: int | float = 0, 
    from_id: int = 0, 
    cooldown: int | float = 0, 
    interval: int | float = 0, 
    app: str = "android", 
    **request_kwargs, 
) -> Iterator[dict]:
    """持续采集 115 生活日志，以更新数据库

    :param client: 115 网盘客户端对象
    :param dbfile: 数据库文件路径，如果为 None，则自动确定
    :param from_time: 开始时间（含），若为 0 则从当前时间开始，若小于 0 则从最早开始
    :param from_id: 开始的事件 id （不含）
    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param interval: 两个批量拉取之间的睡眠时间间隔，如果小于等于 0，则不睡眠
    :param app: 使用此设备的接口
    :param request_kwargs: 其它 http 请求参数，会传给具体的请求函数，默认的是 httpx，可用参数 request 进行设置

    :return: 迭代器，每当一个事件成功入数据库，就产出它
    """
    client, con = _init_client(client, dbfile)
    for event in iter_life_behavior(
        client, 
        from_time=from_time, 
        from_id=from_id, 
        cooldown=cooldown, 
        interval=interval, 
        ignore_types=(), 
        app=app, 
    ):
        type = event["type"]
        event["event_name"] = BEHAVIOR_TYPE_TO_NAME.get(type, "")
        create_time = int(event["create_time"])
        if type not in IGNORE_BEHAVIOR_TYPES:
            sha1 = event["sha1"]
            is_dir = not sha1
            id = int(event["file_id"])
            parent_id = int(event["parent_id"])
            attr = {
                "id": id, 
                "parent_id": parent_id, 
                "pickcode": event["pick_code"], 
                "sha1": sha1, 
                "name": event["file_name"], 
                "size": int(event.get("file_size") or 0), 
                "is_dir": is_dir, 
                "is_alive": 1, 
            }
            if type == 22:
                attr["is_alive"] = 0
            if type in MTIME_BEHAVIOR_TYPES:
                attr["mtime"] = create_time
            if type in CTIME_BEHAVIOR_TYPES:
                attr["ctime"] = create_time
            if is_dir:
                attr["type"] = 0
            elif event.get("is_v"):
                attr["type"] = 4
            elif "muc" in event:
                attr["type"] = 3
            elif event.get("thumb", "").startswith("?"):
                attr["type"] = 2
            else:
                attr["type"] = SUFFIX_TO_TYPE.get(splitext(attr["name"])[-1].lower(), 99)
            if not has_id(con, parent_id, is_alive=False):
                ancestors: list[dict] = []
                try:
                    if parent_id == 0:
                        pass
                    elif is_dir:
                        resp = check_response(client.fs_files_app({"cid": id, "hide_data": 1}, **request_kwargs))
                        if int(resp["path"][-1]["cid"]) == id:
                            ancestors.extend(
                                {"id": int(a["cid"]), "parent_id": int(a["pid"]), "name": a["name"]} 
                                for a in resp["path"][1:]
                            )
                    else:
                        resp = client.fs_category_get_app(id, **request_kwargs)
                        if resp:
                            check_response(resp)
                            pid = 0
                            for a in resp["paths"][1:]:
                                fid = int(a["file_id"])
                                ancestors.append({"id": fid, "parent_id": pid, "name": a["file_name"]})
                                pid = fid
                except FileNotFoundError:
                    pass
                if ancestors:
                    upsert_items(con, ancestors, extras={"is_alive": 1, "is_dir": 1, "_triggered": 0}, commit=True)
            upsert_items(con, attr, extras={"_triggered": 0}, commit=True)
        execute(
            con, 
            "INSERT OR IGNORE INTO life(id, data, create_time) VALUES (?,?,?)", 
            (int(event["id"]), dumps(event), create_time), 
            commit=True, 
        )
        yield event


def updatedb_life(
    client: str | P115Client, 
    dbfile: None | str | Connection | Cursor = None, 
    from_time: int | float = 0, 
    from_id: int = 0, 
    cooldown: int | float = 0, 
    interval: int | float = 0, 
    logger = logger, 
    app: str = "android", 
    **request_kwargs, 
) -> NoReturn:
    """持续采集 115 生活日志，以更新数据库

    :param client: 115 网盘客户端对象
    :param dbfile: 数据库文件路径，如果为 None，则自动确定
    :param from_time: 开始时间（含），若为 0 则从当前时间开始，若小于 0 则从最早开始
    :param from_id: 开始的事件 id （不含）
    :param cooldown: 冷却时间，大于 0 时，两次接口调用之间至少间隔这么多秒
    :param interval: 两个批量拉取之间的睡眠时间间隔，如果小于等于 0，则不睡眠
    :param app: 使用此设备的接口
    :param request_kwargs: 其它 http 请求参数，会传给具体的请求函数，默认的是 httpx，可用参数 request 进行设置
    """
    it = updatedb_life_iter(
        client, 
        dbfile, 
        from_time=from_time, 
        from_id=from_id, 
        cooldown=cooldown, 
        interval=interval, 
        app=app, 
        **request_kwargs, 
    )
    if logger is None:
        for _ in it: pass
    else:
        log = logger.info
        for event in it:
            log("event occurred: %r", event)
    raise


def updatedb_one(
    client: str | P115Client, 
    dbfile: None | str | Connection | Cursor = None, 
    id: int = 0, 
    /, 
    count: int = -1, 
    refresh: bool = False, 
    **request_kwargs, 
) -> tuple[int, int]:
    """更新一个目录

    :param client: 115 网盘客户端对象
    :param dbfile: 数据库文件路径，如果为 None，则自动确定
    :param id: 要拉取的目录 id
    :param count: 文件总数
    :param refresh: 是否全量更新
    :param request_kwargs: 其它 http 请求参数，会传给具体的请求函数，默认的是 httpx，可用参数 request 进行设置

    :return: 2 元组，1) 已更替的数据列表，2) 已移除的 id 列表
    """
    client, con = _init_client(client, dbfile)
    _, to_upsert, to_remove = diff_dir(con, client, id, refresh=refresh, count=count, **request_kwargs)
    upsert_items(con, to_upsert, extras={"_triggered": 0}, commit=True)
    kill_items(con, to_remove, commit=True)
    return len(to_upsert), len(to_remove)


def updatedb_tree(
    client: str | P115Client, 
    dbfile: None | str | Connection | Cursor = None, 
    id: int = 0, 
    /, 
    count: int = -1, 
    no_dir_moved: bool = True, 
    refresh: bool = False, 
    **request_kwargs, 
) -> tuple[int, int]:
    """更新一个目录树

    :param client: 115 网盘客户端对象
    :param dbfile: 数据库文件路径，如果为 None，则自动确定
    :param id: 要拉取的顶层目录 id
    :param count: 文件总数
    :param no_dir_moved: 是否无目录被移动或改名，如果为 True，则拉取会快一些
    :param refresh: 是否全量更新
    :param request_kwargs: 其它 http 请求参数，会传给具体的请求函数，默认的是 httpx，可用参数 request 进行设置

    :return: 2 元组，1) 已更替的数据列表，2) 已移除的 id 列表
    """
    client, con = _init_client(client, dbfile)
    refresh, to_upsert, to_remove = diff_dir(con, client, id, count=count, refresh=refresh, tree=True, **request_kwargs)
    to_recall: list[dict] = []
    if not refresh and to_remove and not no_dir_moved:
        pairs = dict(iter_id_to_parent_id(con, to_remove))
        to_remove = []
        add_to_recall = to_recall.append
        for attr in iter_selected_nodes_by_pickcode(
            client, 
            tuple(pairs.keys()), 
            normalize_attr = lambda info: {
                "id": int(info["file_id"]), 
                "parent_id": int(info["parent_id"]), 
                "name": info["file_name"], 
                "pickcode": info["pick_code"], 
                "is_dir": not info["file_sha1"], 
                "is_collect": int(info["is_collect"]), 
            }, 
            id_to_dirnode=..., 
            **request_kwargs, 
        ):
            add_to_recall(attr)
            del pairs[attr["id"]]
        if pairs:
            to_remove.extend(pairs)
    if not refresh:
        sql = f"SELECT id, parent_id, mtime FROM data WHERE id IN ({','.join(map(str, (a['id'] for a in to_upsert))) or 'NULL'})"
        triplets = set(con.execute(sql))
        to_upsert = [a for a in to_upsert if (a["id"], a["parent_id"], a["mtime"]) not in triplets]
    upserted = len(to_upsert) + len(to_recall)
    if upserted:
        if not refresh:
            ancestors = load_ancestors(
                con, 
                client, 
                to_upsert+to_recall, 
                all_are_files=True, 
                refresh=not no_dir_moved, 
                use_star=True, 
            )
            upsert_items(con, ancestors, extras={"_triggered": 0}, commit=True)
            upserted += len(ancestors)
        upsert_items(con, to_upsert, extras={"_triggered": 0}, commit=True)
        if to_recall:
            upsert_items(con, to_recall, extras={"_triggered": 0}, commit=True)
    if to_remove:
        kill_items(con, to_remove, commit=True)
    return upserted, len(to_remove)


def updatedb(
    client: str | P115Client, 
    dbfile: None | str | Connection | Cursor = None, 
    top_dirs: int | str | Iterable[int | str] = 0, 
    auto_splitting_threshold: int = 30_000, 
    auto_splitting_statistics_timeout: None | float = 5, 
    no_dir_moved: bool = True, 
    refresh: bool = False, 
    recursive: bool = True, 
    interval: int | float = 0.5, 
    logger = logger, 
    disable_event: bool = False, 
    **request_kwargs, 
):
    """批量执行一组任务，任务为更新单个目录或者目录树的文件信息

    :param client: 115 网盘客户端对象
    :param dbfile: 数据库文件路径，如果为 None，则自动确定
    :param top_dirs: 要拉取的顶层目录集，可以是目录 id 或路径
    :param auto_splitting_threshold: 自动拆分任务时，仅当目录里面的总的文件和目录数大于此值才拆分任务，当 recursive 为 True 时生效
    :param auto_splitting_statistics_timeout: 自动拆分任务统计超时，当 recursive 为 True 时生效。如果超过此时间还不能确定目录里面的总的文件和目录数，则视为无穷大
    :param no_dir_moved: 是否无目录被移动或改名，如果为 True，则拉取会快一些
    :param refresh: 是否全量更新
    :param recursive: 是否递归拉取，如果为 True 则拉取目录树，否则只拉取一级目录
    :param interval: 两个批处理任务至少需要间隔的时间（以启动前那一刻作为计算依据）
    :param logger: 日志对象，如果为 None，则不输出日志
    :param disable_event: 是否关闭 event 表的数据收集
    :param request_kwargs: 其它 http 请求参数，会传给具体的请求函数，默认的是 httpx，可用参数 request 进行设置
    """
    client, con = _init_client(client, dbfile, disable_event=disable_event)
    id_to_dirnode: dict = {}
    def parse_top_iter(top: int | str | Iterable[int | str], /) -> Iterator[int]:
        if isinstance(top, int):
            yield top
        elif isinstance(top, str):
            if top in ("", "0", ".", "..", "/"):
                yield 0
            elif not (top.startswith("0") or top.strip(digits)):
                yield int(top)
            else:
                try:
                    yield get_id_to_path(
                        client, 
                        top, 
                        ensure_file=False, 
                        app="android", 
                        id_to_dirnode=id_to_dirnode, 
                    )
                except FileNotFoundError:
                    if logger is not None:
                        logger.exception("[\x1b[1;31mFAIL\x1b[0m] directory not found: %r", top)
        else:
            for top_ in top:
                yield from parse_top_iter(top_)
    if not (top_ids := set(parse_top_iter(top_dirs))):
        return
    if (auto_splitting_statistics_timeout is None or 
        isnan(auto_splitting_statistics_timeout) or 
        isinf(auto_splitting_statistics_timeout) or 
        auto_splitting_statistics_timeout <= 0
    ):
        auto_splitting_statistics_timeout = None
    seen: set[int] = set()
    seen_add = seen.add
    need_calc_size = recursive and auto_splitting_threshold > 0
    if need_calc_size:
        kwargs = {**request_kwargs, "timeout": auto_splitting_statistics_timeout}
        def get_file_count_in_tree(cid: int = 0, /) -> int | float:
            try:
                return get_file_count(client, cid, **kwargs)
            except Exception as e:
                if is_timeouterror(e):
                    if logger is not None:
                        logger.info("[\x1b[1;37;43mSTAT\x1b[0m] \x1b[1m%d\x1b[0m, too big, since statistics timeout, consider the size as \x1b[1;3minf\x1b[0m", id)
                    return float("inf")
                raise
    gen = bfs_gen(iter(top_ids), unpack_iterator=True) # type: ignore
    send = gen.send
    start_time: float = 0
    for id in gen:
        if start_time and interval > 0 and (diff := start_time + interval - time()) > 0:
            sleep(diff)
        if id in seen:
            if logger is not None:
                logger.warning("[\x1b[1;33mSKIP\x1b[0m] already processed: %s", id)
            continue
        count: int | float = -1
        if auto_splitting_threshold == 0:
            need_to_split_tasks = True
        elif auto_splitting_threshold < 0:
            need_to_split_tasks = False
        elif recursive:
            count = get_file_count_in_tree(id)
            if not count:
                seen_add(id)
                continue
            need_to_split_tasks = count > auto_splitting_threshold
            if logger is not None:
                if need_to_split_tasks:
                    logger.info(f"[\x1b[1;37;41mTELL\x1b[0m] \x1b[1m{id}\x1b[0m, \x1b[1;31mbig\x1b[0m ({count:,.0f} > {auto_splitting_threshold:,d}), will be pulled in \x1b[1;4;5;31mmulti batches\x1b[0m")
                else:
                    logger.info(f"[\x1b[1;37;42mTELL\x1b[0m] \x1b[1m{id}\x1b[0m, \x1b[1;32mfit\x1b[0m ({count:,.0f} <= {auto_splitting_threshold:,d}), will be pulled in \x1b[1;4;5;32mone batch\x1b[0m")
        else:
            need_to_split_tasks = True
        start_time = time()
        try:
            logger.info(f"[\x1b[1;37;43mTELL\x1b[0m] \x1b[1m{id}\x1b[0m is running ...")
            if need_to_split_tasks or not recursive:
                upserted, removed = updatedb_one(client, con, id, refresh=refresh, **request_kwargs)
            else:
                if id and count < 0:
                    resp = client.fs_file(id)
                    check_response(resp)
                    if int(resp["data"][0]["aid"]) != 1:
                        raise FileNotFoundError
                upserted, removed = updatedb_tree(client, con, id, refresh=refresh, no_dir_moved=no_dir_moved, **request_kwargs)
        except FileNotFoundError:
            kill_items(con, id, commit=True)
            if logger is not None:
                logger.warning("[\x1b[1;33mSKIP\x1b[0m] not found: %s", id)
        except NotADirectoryError:
            kill_items(con, id, where="is_dir", commit=True)
            if logger is not None:
                logger.warning("[\x1b[1;33mSKIP\x1b[0m] not a directory: %s", id)
        except BusyOSError:
            if logger is not None:
                logger.warning("[\x1b[1;35mREDO\x1b[0m] directory is busy updating: %s", id)
            send(id)
        except:
            if logger is not None:
                logger.exception("[\x1b[1;31mFAIL\x1b[0m] %s", id)
            raise
        else:
            if logger is not None:
                logger.info(
                    "[\x1b[1;32mGOOD\x1b[0m] \x1b[1m%s\x1b[0m, upsert: %d, remove: %d, cost: %.6f s", 
                    id, 
                    upserted, 
                    removed, 
                    time() - start_time, 
                )
            seen_add(id)
            if recursive and need_to_split_tasks:
                for cid in iter_descendants_bfs(con, id, fields="id", ensure_file=False, max_depth=1):
                    send(cid)


def iter_fs_event(
    dbfile: bytes | str | PathLike, 
    from_id: int = -1, 
    sleep_interval: float = 0.1, 
) -> Iterator[dict]:
    """从数据库拉取文件系统事件

    :param dbfile: 数据库文件路径
    :param from_id: 从大于此 id 的数据开始拉取，如果小于 0，则从最新开始
    :param sleep_interval: 当一次拉取未拉到任何数据，将会休眠的时间

    :return: 迭代器，产生文件系统事件
    """
    with connect(dbfile) as con:
        if from_id < 0:
            from_id, = con.execute("SELECT seq FROM sqlite_sequence WHERE name = 'event'").fetchone()
        cur_from_id = from_id
        while True:
            if sleep_interval > 0:
                start_t = time()
            for cur_from_id, file_id, event in con.execute(
                "SELECT ROWID, id, fs FROM event WHERE ROWID > ?", 
                (from_id,), 
            ):
                if event:
                    event = loads(event)
                    event["id"] = cur_from_id
                    event["file_id"] = file_id
                    yield event
            if from_id == cur_from_id:
                if sleep_interval > 0 and (diff := start_t + sleep_interval - time()) > 0:
                    sleep(diff)
            else:
                from_id = cur_from_id

# TODO: 为 115 生活单独做一个命令行命令
# TODO: 重新实现为异步，这样便可随时取消
# TODO: 允许在初始化数据库时，传入一些参数
