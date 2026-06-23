#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "init_db", "iter_id_to_path", "id_to_path", "get_parent_id", "get_id", 
    "get_pickcode", "get_sha1", "get_path", "get_ancestors", "get_children", 
    "get_file_list", "share_is_loaded", "share_get_parent_id", "share_get_id", 
    "share_get_sha1", "share_get_path", "share_get_ancestors", "share_get_children", 
    "share_get_file_list", "get_updated_at", 
]

from asyncio import to_thread
from collections.abc import Callable, Coroutine, Iterator, Sequence
from errno import ENOENT
from functools import update_wrapper
from sqlite3 import Connection, Cursor, register_adapter, register_converter
from typing import overload, Any, Literal

from dictattr import AttrDict
from orjson import dumps, loads
from posixpatht import dirname, escape, path_is_dir_form, splits
from sqlitetools import find, query


register_adapter(list, dumps)
register_adapter(dict, dumps)
register_converter("JSON", loads)


def can_async[**Args, T](func: Callable[Args, T], /):
    @overload
    def wrapper(
        *args: Args.args, 
        async_: Literal[False] = False, 
        **kwds: Args.kwargs, 
    ) -> T:
        ...
    @overload
    def wrapper(
        *args: Args.args, 
        async_: Literal[True], 
        **kwds: Args.kwargs, 
    ) -> Coroutine[Any, Any, T]:
        ...
    def wrapper(
        *args: Args.args, 
        async_: Literal[False, True] = False, 
        **kwds: Args.kwargs, 
    ) -> T | Coroutine[Any, Any, T]:
        if async_:
            return to_thread(func, *args, **kwds)
        return func(*args, **kwds)
    update_wrapper(wrapper, func)
    return wrapper


@can_async
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
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn.executescript("""\
CREATE TABLE IF NOT EXISTS data ( -- 用于缓存数据
    id INTEGER NOT NULL PRIMARY KEY,   -- 文件或目录的 id
    parent_id INTEGER,                 -- 上级目录的 id
    pickcode TEXT NOT NULL DEFAULT '', -- 提取码，下载时需要用到
    sha1 TEXT NOT NULL DEFAULT '',     -- 文件的 sha1 散列值
    name TEXT NOT NULL DEFAULT '',     -- 名字
    is_dir BOOLEAN NOT NULL DEFAULT TRUE  -- 是否目录
);
CREATE TABLE IF NOT EXISTS share_data ( -- 用于缓存分享链接数据
    share_code TEXT NOT NULL DEFAULT '',  -- 分享码
    id INTEGER NOT NULL,                  -- 文件或目录的 id
    parent_id INTEGER,                    -- 上级目录的 id
    sha1 TEXT NOT NULL DEFAULT '',        -- 文件的 sha1 散列值
    name TEXT NOT NULL DEFAULT '',        -- 名字
    path TEXT NOT NULL DEFAULT '',        -- 路径
    is_dir BOOLEAN NOT NULL DEFAULT TRUE  -- 是否目录
);
CREATE TABLE IF NOT EXISTS list ( -- 用于缓存文件列表数据
    id INTEGER NOT NULL PRIMARY KEY,   -- 目录的 id
    data JSON NOT NULL,                -- 二进制数据
    updated_at DATETIME DEFAULT (strftime('%s', 'now')) -- 最近一次更新时间
);
CREATE TABLE IF NOT EXISTS share_list ( -- 用于缓存分享链接的文件列表数据
    share_code TEXT NOT NULL DEFAULT '', -- 分享码
    id INTEGER NOT NULL,                 -- 目录的 id
    data JSON NOT NULL,                  -- 二进制数据
    updated_at DATETIME DEFAULT (strftime('%s', 'now')) -- 最近一次更新时间
);
CREATE TABLE IF NOT EXISTS share_list_loaded ( -- 用于标记分享链接的文件列表是否已经加载完
    share_code TEXT NOT NULL PRIMARY KEY, -- 分享码
    loaded BOOLEAN NOT NULL DEFAULT TRUE  -- 分享链接的文件列表是否已经加载完
);

CREATE INDEX IF NOT EXISTS idx_data_pid ON data(parent_id);
CREATE INDEX IF NOT EXISTS idx_data_pc ON data(pickcode);
CREATE INDEX IF NOT EXISTS idx_data_sha1 ON data(sha1);
CREATE INDEX IF NOT EXISTS idx_data_name ON data(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sdata_code_id ON share_data(share_code, id);
CREATE INDEX IF NOT EXISTS idx_sdata_pid ON share_data(parent_id);
CREATE INDEX IF NOT EXISTS idx_sdata_sha1 ON share_data(sha1);
CREATE INDEX IF NOT EXISTS idx_sdata_name ON share_data(name);
CREATE INDEX IF NOT EXISTS idx_sdata_path ON share_data(path);
CREATE UNIQUE INDEX IF NOT EXISTS idx_slist_code_id ON share_list(share_code, id);

CREATE TRIGGER IF NOT EXISTS trg_list_insert AFTER INSERT ON list
FOR EACH ROW
BEGIN
    DELETE FROM data WHERE parent_id=NEW.id;
    INSERT OR IGNORE INTO data
    SELECT * FROM (
        WITH flist(data) AS (
            SELECT data FROM list WHERE id=NEW.id
        )
        SELECT
            json_each.value->>'id', 
            json_each.value->>'parent_id', 
            json_each.value->>'pickcode', 
            json_each.value->>'sha1', 
            json_each.value->>'name', 
            json_each.value->>'is_dir'
        FROM flist, json_each(flist.data)
    );
END;
                           
CREATE TRIGGER IF NOT EXISTS trg_list_update AFTER UPDATE ON list
FOR EACH ROW
BEGIN
    UPDATE list SET updated_at=strftime('%s', 'now') WHERE id=NEW.id;
    DELETE FROM data WHERE parent_id=NEW.id;
    INSERT OR IGNORE INTO data
    SELECT * FROM (
        WITH flist(data) AS (
            SELECT data FROM list WHERE id=NEW.id
        )
        SELECT
            json_each.value->>'id', 
            json_each.value->>'parent_id', 
            json_each.value->>'pickcode', 
            json_each.value->>'sha1', 
            json_each.value->>'name', 
            json_each.value->>'is_dir'
        FROM flist, json_each(flist.data)
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_list_delete AFTER DELETE ON list
FOR EACH ROW
BEGIN
    DELETE FROM data WHERE parent_id=OLD.id;
END;                              

CREATE TRIGGER IF NOT EXISTS trg_slist_insert AFTER INSERT ON share_list
FOR EACH ROW
BEGIN
    DELETE FROM share_data WHERE share_code=NEW.share_code AND parent_id=NEW.id;
    INSERT OR IGNORE INTO share_data
    SELECT * FROM (
        WITH flist(data) AS (
            SELECT data->'children' FROM share_list 
            WHERE share_code=NEW.share_code AND id=NEW.id
        )
        SELECT
            NEW.share_code, 
            json_each.value->>'id', 
            json_each.value->>'parent_id', 
            json_each.value->>'sha1', 
            json_each.value->>'name', 
            json_each.value->>'path', 
            json_each.value->>'is_dir'
        FROM flist, json_each(flist.data)
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_slist_update AFTER UPDATE ON share_list
FOR EACH ROW
BEGIN
    UPDATE share_list SET updated_at=strftime('%s', 'now') WHERE share_code=NEW.share_code AND id=NEW.id;
    DELETE FROM share_data WHERE share_code=NEW.share_code AND parent_id=NEW.id;
    INSERT OR IGNORE INTO share_data
    SELECT * FROM (
        WITH flist(data) AS (
            SELECT data->'children' FROM share_list 
            WHERE share_code=NEW.share_code AND id=NEW.id
        )
        SELECT
            NEW.share_code, 
            json_each.value->>'id', 
            json_each.value->>'parent_id', 
            json_each.value->>'sha1', 
            json_each.value->>'name', 
            json_each.value->>'path', 
            json_each.value->>'is_dir'
        FROM flist, json_each(flist.data)
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_slist_delete AFTER DELETE ON share_list
FOR EACH ROW
BEGIN
    DELETE FROM share_data WHERE share_code=NEW.share_code AND parent_id=OLD.id;
END;
""")


def iter_id_to_path(
    con: Connection | Cursor, 
    /, 
    path: str | Sequence[str] = "", 
    ensure_file: None | bool = None, 
    parent_id: int = 0, 
) -> Iterator[int]:
    """查询匹配某个路径的文件或目录的信息字典

    .. note::
        同一个路径可以有多条对应的数据

    :param con: 数据库连接或游标
    :param path: 路径
    :param ensure_file: 是否文件

        - 如果为 True，必须是文件
        - 如果为 False，必须是目录
        - 如果为 None，可以是文件或目录

    :param parent_id: 顶层目录的 id

    :return: 迭代器，产生一组匹配指定路径的（文件或目录）节点的 id
    """
    patht: Sequence[str]
    if isinstance(path, str):
        if ensure_file is None and path_is_dir_form(path):
            ensure_file = False
        patht, _ = splits("/" + path)
    else:
        patht = ("", *filter(None, path))
    if not parent_id and len(patht) == 1:
        return iter((0,))
    if len(patht) > 2:
        sql = "SELECT id FROM data WHERE parent_id=? AND name=? AND is_dir LIMIT 1"
        for name in patht[1:-1]:
            parent_id = find(con, sql, (parent_id, name), default=-1)
            if parent_id < 0:
                return iter(())
    sql = "SELECT id FROM data WHERE parent_id=? AND name=?"
    if ensure_file is None:
        sql += " ORDER BY is_dir DESC"
    elif ensure_file:
        sql += " AND NOT is_dir"
    else:
        sql += " AND is_dir LIMIT 1"
    return query(con, sql, (parent_id, patht[-1]), row_factory="one")


@can_async
def id_to_path(
    con: Connection | Cursor, 
    /, 
    path: str | Sequence[str] = "", 
    ensure_file: None | bool = None, 
    parent_id: int = 0, 
) -> None | int:
    """查询匹配某个路径的文件或目录的信息字典，只返回找到的第 1 个

    :param con: 数据库连接或游标
    :param path: 路径
    :param ensure_file: 是否文件

        - 如果为 True，必须是文件
        - 如果为 False，必须是目录
        - 如果为 None，可以是文件或目录

    :param parent_id: 顶层目录的 id

    :return: 找到的第 1 个匹配的节点 id
    """
    return next(iter_id_to_path(con, path, ensure_file, parent_id), None)


@can_async
def get_parent_id(
    con: Connection | Cursor, 
    /, 
    id: int = -1, 
    pickcode: str = "", 
    sha1: str = "", 
    path: str = "", 
) -> None | int:
    if pickcode:
        return find(
            con, 
            "SELECT parent_id FROM data WHERE pickcode=? LIMIT 1", 
            pickcode, 
        )
    elif id >= 0:
        if not id:
            return 0
        return find(
            con, 
            "SELECT parent_id FROM data WHERE id=? LIMIT 1", 
            id, 
        )
    elif sha1:
        return find(
            con, 
            "SELECT parent_id FROM data WHERE sha1=? LIMIT 1", 
            sha1, 
        )
    elif path:
        return get_id(con, path=dirname(path))
    return 0


@can_async
def get_id(
    con: Connection | Cursor, 
    /, 
    pickcode: str = "", 
    sha1: str = "", 
    path: str = "", 
) -> None | int:
    """查询匹配某个字段的文件或目录的 id

    :param con: 数据库连接或游标
    :param pickcode: 当前节点的提取码，优先级高于 sha1
    :param sha1: 当前节点的 sha1，优先级高于 path
    :param path: 当前节点的路径

    :return: 当前节点的 id
    """
    if pickcode:
        return find(
            con, 
            "SELECT id FROM data WHERE pickcode=? LIMIT 1", 
            pickcode, 
        )
    elif sha1:
        return find(
            con, 
            "SELECT id FROM data WHERE sha1=? LIMIT 1", 
            sha1, 
        )
    elif path and path != "/":
        return id_to_path(con, path)
    return 0


@can_async
def get_pickcode(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
    sha1: str = "", 
    path: str = "", 
) -> str:
    """查询匹配某个字段的文件或目录的提取码

    :param con: 数据库连接或游标
    :param id: 当前节点的 id，优先级高于 sha1
    :param sha1: 当前节点的 sha1，优先级高于 path
    :param path: 当前节点的路径

    :return: 当前节点的提取码
    """
    if id:
        return find(
            con, 
            "SELECT pickcode FROM data WHERE id=? LIMIT 1", 
            id, 
            default="", 
        )
    elif sha1:
        return find(
            con, 
            "SELECT pickcode FROM data WHERE sha1=? LIMIT 1", 
            sha1, 
            default="", 
        )
    elif path and path != "/":
        if id := id_to_path(con, path):
            return get_pickcode(con, id)
    return ""


@can_async
def get_sha1(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
    pickcode: str = "", 
    path: str = "", 
) -> None | str:
    """查询匹配某个字段的文件的 sha1

    :param con: 数据库连接或游标
    :param id: 当前节点的 id，优先级高于 pickcode
    :param pickcode: 当前节点的提取码，优先级高于 path
    :param path: 当前节点的路径

    :return: 当前节点的 sha1
    """
    if id:
        return find(
            con, 
            "SELECT sha1 FROM data WHERE id=? LIMIT 1", 
            id, 
        )
    elif pickcode:
        return find(
            con, 
            "SELECT sha1 FROM data WHERE pickcode=? LIMIT 1", 
            pickcode, 
        )
    elif path and path != "/":
        if id := id_to_path(con, path):
            return get_sha1(con, id)
    return ""


@can_async
def get_path(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
) -> str:
    """获取某个文件或目录的路径

    :param con: 数据库连接或游标
    :param id: 当前节点的 id

    :return: 当前节点的路径
    """
    if not id:
        return "/"
    ancestors = get_ancestors(con, id)
    return "/".join(escape(a["name"]) for a in ancestors)


@can_async
def get_ancestors(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
) -> list[dict]:
    """获取某个文件或目录的祖先节点信息，包括 id、parent_id 和 name

    :param con: 数据库连接或游标
    :param id: 当前节点的 id

    :return: 当前节点的祖先节点列表，从根目录开始（id 为 0）直到当前节点
    """
    ancestors = [{"id": 0, "parent_id": 0, "name": ""}]
    if not id:
        return ancestors
    ls = list(query(con, """\
WITH t AS (
    SELECT id, parent_id, name FROM data WHERE id = ?
    UNION ALL
    SELECT data.id, data.parent_id, data.name FROM t JOIN data ON (t.parent_id = data.id)
)
SELECT id, parent_id, name FROM t""", id))
    if not ls:
        raise FileNotFoundError(ENOENT, id)
    if ls[-1][1]:
        raise ValueError(f"dangling id: {id}")
    ancestors.extend(dict(zip(("id", "parent_id", "name"), record)) for record in reversed(ls))
    return ancestors


@can_async
def get_children(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
) -> None | list[dict]:
    """获取某个目录 id 的所有子节点信息列表

    :param con: 数据库连接或游标
    :param id: 当前节点的 id

    :return: 当前节点的子节点信息列表
    """
    children = find(
        con, 
        "SELECT data FROM list WHERE id=? LIMIT 1", 
        id, 
    )
    if children:
        for i, attr in enumerate(children):
            children[i] = AttrDict(attr)
    return children


@can_async
def get_file_list(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
) -> None | dict:
    """获取当前节点的祖先节点列表和子节点列表构成的字典

    :param con: 数据库连接或游标
    :param id: 当前节点的 id

    :return: 当前节点的祖先节点列表和子节点列表构成的字典，形式为

        .. code: python

            {
                "ancestors": list[dict], # 祖先节点列表
                "children": list[dict],  # 子节点列表
            }
    """
    children = get_children(con, id)
    if children is None:
        return None
    return {"ancestors": get_ancestors(con, id), "children": children}


@can_async
def share_is_loaded(
    con: Connection | Cursor, 
    /, 
    share_code: str, 
) -> bool:
    """判断某个分享链接的文件树数据是否完全加载

    :param con: 数据库连接或游标
    :param share_code: 分享码

    :return: 分享的文件树数据是否完全加载到数据库
    """
    return bool(find(
        con, 
        "SELECT loaded FROM share_list_loaded WHERE share_code=?", 
        share_code, 
    ))


@can_async
def share_get_parent_id(
    con: Connection | Cursor, 
    /, 
    share_code, 
    id: int = -1, 
    sha1: str = "", 
    path: str = "", 
) -> None | int:
    """分享链接中，文件树中某个节点的父节点 id

    :param con: 数据库连接或游标
    :param share_code: 分享码
    :param id: 当前节点的 id，优先级高于 sha1
    :param sha1: 当前节点的 sha1，优先级高于 path
    :param path: 当前节点的路径

    :return: 当前节点的父节点 id
    """
    if not id:
        return 0
    pid: None | int = None
    if id:
        pid = find(
            con, 
            "SELECT parent_id FROM share_data WHERE share_code=? AND id=? LIMIT 1", 
            (share_code, id), 
        )
    elif sha1:
        pid = find(
            con, 
            "SELECT parent_id FROM share_data WHERE share_code=? AND sha1=? LIMIT 1", 
            (share_code, sha1), 
        )
    elif path:
        pid = find(
            con, 
            "SELECT parent_id FROM share_data WHERE share_code=? AND path=? LIMIT 1", 
            (share_code, path), 
        )
    else:
        pid = 0
    if pid is None and share_is_loaded(con, share_code):
        raise FileNotFoundError(
            ENOENT, 
            {"share_code": share_code, "id": id, "sha1": sha1, "path": path}, 
        )
    return pid


@can_async
def share_get_id(
    con: Connection | Cursor, 
    /, 
    share_code: str, 
    sha1: str = "", 
    path: str = "", 
) -> None | int:
    """分享链接中，文件树中某个节点的 id

    :param con: 数据库连接或游标
    :param share_code: 分享码
    :param sha1: 当前节点的 sha1，优先级高于 path
    :param path: 当前节点的路径

    :return: 当前节点的 id
    """
    id: None | int = None
    if sha1:
        id = find(
            con, 
            "SELECT id FROM share_data WHERE share_code=? AND sha1=? LIMIT 1", 
            (share_code, sha1), 
        )
    elif path:
        id = find(
            con, 
            "SELECT id FROM share_data WHERE share_code=? AND path=? LIMIT 1", 
            (share_code, path), 
        )
    else:
        id = 0
    if id is None and share_is_loaded(con, share_code):
        raise FileNotFoundError(
            ENOENT, 
            {"share_code": share_code, "sha1": sha1, "path": path}, 
        )
    return id


@can_async
def share_get_sha1(
    con: Connection | Cursor, 
    /, 
    share_code: str, 
    id: int = 0, 
    path: str = "", 
) -> None | str:
    """分享链接中，文件树中某个节点的 sha1

    :param con: 数据库连接或游标
    :param share_code: 分享码
    :param id: 当前节点的 id，优先级高于 path
    :param path: 当前节点的路径

    :return: 当前节点的 sha1
    """
    sha1: None | str = None
    if id:
        sha1 = find(
            con, 
            "SELECT sha1 FROM share_data WHERE share_code=? AND id=? LIMIT 1", 
            (share_code, id), 
        )
    elif path:
        sha1 = find(
            con, 
            "SELECT sha1 FROM share_data WHERE share_code=? AND path=? LIMIT 1", 
            (share_code, path), 
        )
    else:
        sha1 = ""
    if sha1 is None and share_is_loaded(con, share_code):
        raise FileNotFoundError(
            ENOENT, 
            {"share_code": share_code, "id": id, "path": path}, 
        )
    return sha1


@can_async
def share_get_path(
    con: Connection | Cursor, 
    /, 
    share_code: str, 
    id: int = -1, 
    sha1: str = "", 
) -> str:
    """分享链接中，文件树中某个节点的路径

    :param con: 数据库连接或游标
    :param share_code: 分享码
    :param id: 当前节点的 id，优先级高于 sha1
    :param sha1: 当前节点的 sha1

    :return: 当前节点的路径
    """
    if not id:
        return "/"
    path: str = ""
    if id > 0:
        path = find(
            con, 
            "SELECT path FROM share_data WHERE share_code=? AND id=? LIMIT 1", 
            (share_code, id), 
            default="", 
        )
    elif sha1:
        path = find(
            con, 
            "SELECT path FROM share_data WHERE share_code=? AND sha1=? LIMIT 1", 
            (share_code, sha1), 
            default="", 
        )
    else:
        path = "/"
    if not path and share_is_loaded(con, share_code):
        raise FileNotFoundError(
            ENOENT, 
            {"share_code": share_code, "id": id, "sha1": sha1}, 
        )
    return path


@can_async
def share_get_ancestors(
    con: Connection | Cursor, 
    /, 
    share_code: str, 
    id: int = 0, 
) -> list[dict]:
    """分享链接中，文件树中某个节点的祖先节点列表

    :param con: 数据库连接或游标
    :param share_code: 分享码
    :param id: 当前节点的 id

    :return: 当前节点的祖先节点列表
    """
    if not id:
        return [{"id": "0", "parent_id": "0", "name": ""}]
    ancestors = find(con, """\
SELECT data->'ancestors' AS "ancestors [JSON]" 
FROM share_list 
WHERE share_code=? AND id=? 
LIMIT 1""", (share_code, id))
    if ancestors is None and share_is_loaded(con, share_code):
        raise FileNotFoundError(ENOENT, {"share_code": share_code, "id": id})
    return ancestors


@can_async
def share_get_children(
    con: Connection | Cursor, 
    /, 
    share_code: str, 
    id: int = 0, 
) -> None | list[dict]:
    """分享链接中，文件树中某个节点的子节点信息列表

    :param con: 数据库连接或游标
    :param share_code: 分享码
    :param id: 当前节点的 id

    :return: 当前节点的子节点信息列表
    """
    children = find(con, """\
SELECT data->>'children' AS "children [JSON]" 
FROM share_list 
WHERE share_code=? AND id=? 
LIMIT 1""", (share_code, id))
    if children is None and share_is_loaded(con, share_code):
        raise FileNotFoundError(ENOENT, {"share_code": share_code, "id": id})
    if children:
        for i, attr in enumerate(children):
            children[i] = AttrDict(attr)
    return children


@can_async
def share_get_file_list(
    con: Connection | Cursor, 
    /, 
    share_code: str, 
    id: int = 0, 
) -> None | dict:
    """分享链接中，文件树中某个节点的祖先节点列表和子节点列表构成的字典

    :param con: 数据库连接或游标
    :param share_code: 分享码
    :param id: 当前节点的 id

    :return: 当前节点的祖先节点列表和子节点列表构成的字典，形式为

        .. code: python

            {
                "ancestors": list[dict], # 祖先节点列表
                "children": list[dict],  # 子节点列表
            }
    """
    file_list = find(con, """\
SELECT data
FROM share_list 
WHERE share_code=? AND id=? 
LIMIT 1""", (share_code, id))
    if file_list is None and share_is_loaded(con, share_code):
        raise FileNotFoundError(ENOENT, {"share_code": share_code, "id": id})
    if file_list and (children := file_list["children"]):
        for i, attr in enumerate(children):
            children[i] = AttrDict(attr)
    return file_list


@can_async
def get_updated_at(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
    share_code: str = "", 
) -> int:
    """从数据库中获取某个节点的子文件信息列表的更新时间

    :param con: 数据库连接或游标
    :param id: 当前节点的 id
    :param share_code: 分享码，如果提供 `share_code`，则是分享链接，否则则是自己网盘

    :return: 当前节点的子文件信息列表的更新时间，如果从未拉取过，则返回 0
    """
    if share_code:
        return find(
            con, 
            "SELECT updated_at FROM share_list WHERE share_code=? AND id=? LIMIT 1", 
            (share_code, id), 
            default=0, 
        )
    else:
        return find(
            con, 
            "SELECT updated_at FROM list WHERE id=? LIMIT 1", 
            id, 
            default=0, 
        )

# TODO: 有些数据被更新或者拉取后，更新了 data 表，但不更新 list 表
# TODO: 允许拉取非自己所分享的分享链接的文件列表
