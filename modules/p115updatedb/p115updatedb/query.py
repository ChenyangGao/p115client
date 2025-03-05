#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "get_dir_count", "has_id", "iter_existing_id", "get_parent_id", "iter_parent_id", 
    "iter_id_to_parent_id", "iter_id_to_path", "id_to_path", "get_id", "get_pickcode", 
    "get_sha1", "get_path", "get_ancestors", "get_attr", "iter_children", 
    "iter_descendants", "iter_descendants_bfs", "iter_files_with_path_url", 
    "iter_dup_files", "iter_dangling_parent_ids", "iter_dangling_ids", "select_na_ids", 
    "select_mtime_groups", "dump_to_alist", "dump_efu", 
]

from collections.abc import Callable, Iterable, Iterator, Sequence
from csv import writer
from datetime import datetime
from errno import ENOENT, ENOTDIR
from itertools import batched
from ntpath import normpath
from os.path import expanduser
from pathlib import Path
from sqlite3 import register_converter, Connection, Cursor, OperationalError
from posixpath import join
from typing import cast, overload, Any, Final, Literal
from urllib.parse import quote

from iterutils import bfs_gen, group_collect
from orjson import dumps, loads
from posixpatht import escape, path_is_dir_form, splits
from sqlitetools import find, query, transact


FIELDS: Final = (
    "id", "parent_id", "pickcode", "sha1", "name", "size", "is_dir", "type", 
    "ctime", "mtime", "is_collect", "is_alive", "updated_at", 
)
EXTENDED_FIELDS: Final = (*FIELDS, "depth", "path", "posixpath", "ancestors")

register_converter("DATETIME", lambda dt: datetime.fromisoformat(str(dt, "utf-8")))
register_converter("JSON", loads)


def get_dir_count(
    con: Connection | Cursor, 
    id: int = 0, 
    /, 
    is_alive: bool = True, 
) -> None | dict:
    """获取某个目录里的文件数和目录数统计
    """
    sql = "SELECT dir_count, file_count, tree_dir_count, tree_file_count FROM dirlen WHERE id=?"
    if is_alive:
        sql += " AND is_alive"
    return find(con, sql, id, row_factory="dict")


def has_id(
    con: Connection | Cursor, 
    id: int, 
    /, 
    is_alive: bool = True, 
) -> int:
    if id == 0:
        return 1
    elif id < 0:
        return 0
    sql = "SELECT 1 FROM data WHERE id=?"
    if is_alive:
        sql += " AND is_alive"
    return find(con, sql, id, 0)


def iter_existing_id(
    con: Connection | Cursor, 
    ids: Iterable[int], 
    /, 
    is_alive: bool = True, 
) -> Iterator[int]:
    sql = "SELECT id FROM data WHERE id IN (%s)" % (",".join(map("%d".__mod__, ids)) or "NULL")
    if is_alive:
        sql += " AND is_alive"
    return query(con, sql, row_factory="one")


def get_parent_id(
    con: Connection | Cursor, 
    id: int = 0, 
    /, 
    default: None | int = None, 
) -> int:
    if id == 0:
        return 0
    sql = "SELECT parent_id FROM data WHERE id=?"
    return find(con, sql, id, FileNotFoundError(ENOENT, id) if default is None else default)


def iter_parent_id(
    con: Connection | Cursor, 
    ids: Iterable[int], 
    /, 
) -> Iterator[int]:
    sql = "SELECT parent_id FROM data WHERE id IN (%s)" % (",".join(map("%d".__mod__, ids)) or "NULL")
    return query(con, sql, row_factory="one")


def iter_id_to_parent_id(
    con: Connection | Cursor, 
    ids: Iterable[int], 
    /, 
    recursive: bool = False, 
) -> Iterator[tuple[int, int]]:
    s_ids = "(%s)" % (",".join(map(str, ids)) or "NULL")
    if recursive:
        sql = """\
WITH pairs AS (
    SELECT id, parent_id FROM data WHERE id IN %s
    UNION ALL
    SELECT data.id, data.parent_id FROM pairs JOIN data ON (pairs.parent_id = data.id)
) SELECT * FROM pairs""" % s_ids
    else:
        sql = "SELECT id, parent_id FROM data WHERE id IN %s" % s_ids
    return query(con, sql)


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
        sql = "SELECT id FROM data WHERE parent_id=? AND name=? AND is_alive AND is_dir LIMIT 1"
        for name in patht[1:-1]:
            parent_id = find(con, sql, (parent_id, name), default=-1)
            if parent_id < 0:
                return iter(())
    sql = "SELECT id FROM data WHERE parent_id=? AND name=? AND is_alive"
    if ensure_file is None:
        sql += " ORDER BY is_dir DESC"
    elif ensure_file:
        sql += " AND NOT is_dir"
    else:
        sql += " AND is_dir LIMIT 1"
    return query(con, sql, (parent_id, patht[-1]), row_factory="one")


def id_to_path(
    con: Connection | Cursor, 
    /, 
    path: str | Sequence[str] = "", 
    ensure_file: None | bool = None, 
    parent_id: int = 0, 
) -> int:
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
    try:
        return next(iter_id_to_path(con, path, ensure_file, parent_id))
    except StopIteration:
        raise FileNotFoundError(ENOENT, path) from None


def get_id(
    con: Connection | Cursor, 
    /, 
    pickcode: str = "", 
    sha1: str = "", 
    path: str = "", 
    is_alive: bool = True, 
) -> int:
    """查询匹配某个字段的文件或目录的 id

    :param con: 数据库连接或游标
    :param pickcode: 当前节点的提取码，优先级高于 sha1
    :param sha1: 当前节点的 sha1 校验散列值，优先级高于 path
    :param path: 当前节点的路径

    :return: 当前节点的 id
    """
    insertion = " AND is_alive" if is_alive else ""
    if pickcode:
        return find(
            con, 
            f"SELECT id FROM data WHERE pickcode=?{insertion} LIMIT 1", 
            pickcode, 
            default=FileNotFoundError(pickcode), 
        )
    elif sha1:
        return find(
            con, 
            f"SELECT id FROM data WHERE sha1=?{insertion} LIMIT 1", 
            sha1, 
            default=FileNotFoundError(sha1), 
        )
    elif path:
        return id_to_path(con, path)
    return 0


def get_pickcode(
    con: Connection | Cursor, 
    /, 
    id: int = -1, 
    sha1: str = "", 
    path: str = "", 
    is_alive: bool = True, 
) -> str:
    """查询匹配某个字段的文件或目录的提取码

    :param con: 数据库连接或游标
    :param id: 当前节点的 id，优先级高于 sha1
    :param sha1: 当前节点的 sha1 校验散列值，优先级高于 path
    :param path: 当前节点的路径

    :return: 当前节点的提取码
    """
    insertion = " AND is_alive" if is_alive else ""
    if id >= 0:
        if not id:
            return ""
        return find(
            con, 
            f"SELECT pickcode FROM data WHERE id=?{insertion} LIMIT 1;", 
            id, 
            default=FileNotFoundError(id), 
        )
    elif sha1:
        return find(
            con, 
            f"SELECT pickcode FROM data WHERE sha1=?{insertion} LIMIT 1;", 
            sha1, 
            default=FileNotFoundError(sha1), 
        )
    else:
        if path in ("", "/"):
            return ""
        return get_pickcode(con, id_to_path(con, path))


def get_sha1(
    con: Connection | Cursor, 
    /, 
    id: int = -1, 
    pickcode: str = "", 
    path: str = "", 
    is_alive: bool = True, 
) -> str:
    """查询匹配某个字段的文件的 sha1

    :param con: 数据库连接或游标
    :param id: 当前节点的 id，优先级高于 pickcode
    :param pickcode: 当前节点的提取码，优先级高于 path
    :param path: 当前节点的路径

    :return: 当前节点的 sha1 校验散列值
    """
    insertion = " AND is_alive" if is_alive else ""
    if id >= 0:
        if not id:
            return ""
        return find(
            con, 
            f"SELECT sha1 FROM data WHERE id=?{insertion} LIMIT 1;", 
            id, 
            default=FileNotFoundError(id), 
        )
    elif pickcode:
        return find(
            con, 
            f"SELECT sha1 FROM data WHERE pickcode=?{insertion} LIMIT 1;", 
            pickcode, 
            default=FileNotFoundError(pickcode), 
        )
    else:
        if path in ("", "/"):
            return ""
        return get_sha1(con, id_to_path(con, path))


def get_path(
    con: Connection | Cursor, 
    id: int = 0, 
    /, 
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


def get_ancestors(
    con: Connection | Cursor, 
    id: int = 0, 
    /, 
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
SELECT id, parent_id, name FROM t;""", id))
    if not ls:
        raise FileNotFoundError(ENOENT, id)
    if ls[-1][1]:
        raise ValueError(f"dangling id: {id}")
    ancestors.extend(dict(zip(("id", "parent_id", "name"), record)) for record in reversed(ls))
    return ancestors


def get_attr(
    con: Connection | Cursor, 
    id: int = 0, 
    /, 
) -> dict:
    """获取某个文件或目录的信息

    :param con: 数据库连接或游标
    :param id: 当前节点的 id

    :return: 当前节点的信息字典
    """
    if not id:
        return {
            "id": 0, "parent_id": 0, "pickcode": "", "sha1": "", "name": "", "size": 0, 
            "is_dir": 1, "type": 0, "ctime": 0, "mtime": 0, "is_collect": 0, 
            "is_alive": 1, "updated_at": datetime.fromtimestamp(0), 
        }
    return find(
        con, 
        f"SELECT {','.join(FIELDS)} FROM data WHERE id=? LIMIT 1", 
        id, 
        FileNotFoundError(ENOENT, id), 
        row_factory="dict", 
    )


def iter_children(
    con: Connection | Cursor, 
    parent_id: int | dict = 0, 
    /, 
    ensure_file: None | bool = None, 
) -> Iterator[dict]:
    """获取某个目录之下的文件或目录的信息

    :param con: 数据库连接或游标
    :param parent_id: 父目录的 id
    :param ensure_file: 是否仅输出文件

        - 如果为 True，仅输出文件
        - 如果为 False，仅输出目录
        - 如果为 None，全部输出

    :return: 迭代器，产生一组信息的字典
    """
    if isinstance(parent_id, int):
        attr = get_attr(con, parent_id)
    else:
        attr = parent_id
    if not attr["is_dir"]:
        raise NotADirectoryError(ENOTDIR, attr)
    sql = f"SELECT {','.join(FIELDS)} FROM data WHERE parent_id=? AND is_alive"
    if ensure_file is not None:
        if ensure_file:
            sql += " AND NOT is_dir"
        else:
            sql += " AND is_dir"
    return query(con, sql, attr["id"], row_factory="dict")


def iter_descendants(
    con: Connection | Cursor, 
    parent_id: int | dict = 0, 
    /, 
    min_depth: int = 1, 
    max_depth: int = -1, 
    ensure_file: None | bool = None, 
    use_relpath: None | bool = False, 
    with_root: bool = False, 
    topdown: None | bool = True, 
) -> Iterator[dict]:
    """遍历获取某个目录之下的所有文件或目录的信息

    :param con: 数据库连接或游标
    :param parent_id: 顶层目录的 id
    :param min_depth: 最小深度
    :param max_depth: 最大深度。如果小于 0，则无限深度
    :param ensure_file: 是否仅输出文件

        - 如果为 True，仅输出文件
        - 如果为 False，仅输出目录
        - 如果为 None，全部输出

    :param use_relpath: 是否仅输出相对路径。如果为 False，则输出完整路径（从 / 开始）；如果为 None，则不输出 "ancestors", "path", "posixpath"
    :param with_root: 仅当 `use_relpath=True` 时生效。如果为 True，则相对路径包含 `parent_id` 对应的节点
    :param topdown: 是否自顶向下深度优先遍历

        - 如果为 True，则自顶向下深度优先遍历
        - 如果为 False，则自底向上深度优先遍历
        - 如果为 None，则自顶向下宽度优先遍历

    :return: 迭代器，产生一组信息的字典，包含如下字段：

        .. code:: python

            (
                "id", "parent_id", "pickcode", "sha1", "name", "size", "is_dir", 
                "type", "ctime", "mtime", "is_collect", "is_alive", "updated_at", 
                "depth", "ancestors", "path", "posixpath", 
            )
    """
    with_path = use_relpath is not None
    if isinstance(parent_id, int):
        if 0 <= max_depth < min_depth:
            return
        depth = 1
        if with_path:
            if not parent_id:
                ancestors: list[dict] = [{"id": 0, "parent_id": 0, "name": ""}]
                dir_ = posixdir = "/"
            elif use_relpath:
                if with_root:
                    attr = parent_id = get_attr(con, parent_id)
                    name = attr["name"]
                    ancestors = [{"id": attr["id"], "parent_id": attr["parent_id"], "name": name}]
                    dir_ = escape(name) + "/"
                    posixdir = name.replace("/", "|") + "/"
                else:
                    ancestors = []
                    dir_ = posixdir = ""
            else:
                ancestors = get_ancestors(con, parent_id)
                dir_ = "/".join(escape(a["name"]) for a in ancestors) + "/"
                posixdir = "/".join(a["name"].replace("/", "|") for a in ancestors) + "/"
    else:
        attr = parent_id
        depth = attr["depth"] + 1
        if with_path:
            ancestors = attr["ancestors"]
            dir_ = attr["path"]
            posixdir = attr["posixpath"]
            if dir_ != "/":
                dir_ += "/"
                posixdir += "/"
    if topdown is None:
        if with_path:
            gen = bfs_gen((parent_id, 0, ancestors, dir_, posixdir))
        else:
            gen = bfs_gen((parent_id, 0)) # type: ignore
        send: Callable = gen.send
        p: list
        for parent_id, depth, *p in gen:
            depth += 1
            will_step_in = max_depth < 0 or depth < max_depth
            will_yield = min_depth <= depth and (max_depth < 0 or depth <= max_depth)
            if with_path:
                ancestors, dir_, posixdir = p
            for attr in iter_children(con, parent_id, False if ensure_file is False else None):
                attr["depth"] = depth
                is_dir = attr["is_dir"]
                if with_path:
                    attr["ancestors"] = [
                        *ancestors, 
                        {k: attr[k] for k in ("id", "parent_id", "name")}, 
                    ]
                    attr["path"] = dir_ + escape(attr["name"])
                    attr["posixpath"] = posixdir + attr["name"].replace("/", "|")
                if is_dir and will_step_in:
                    if with_path:
                        send((attr, depth, attr["ancestors"], attr["path"] + "/", attr["posixpath"] + "/"))
                    else:
                        send((attr, depth))
                if will_yield:
                    if ensure_file is None:
                        yield attr
                    elif is_dir:
                        if not ensure_file:
                            yield attr
                    elif ensure_file:
                        yield attr
    else:
        will_step_in = max_depth < 0 or depth < max_depth
        will_yield = min_depth <= depth and (max_depth < 0 or depth <= max_depth)
        for attr in iter_children(con, parent_id, False if ensure_file is False else None):
            is_dir = attr["is_dir"]
            attr["depth"] = depth
            if with_path:
                attr["ancestors"] = [
                    *ancestors, 
                    {k: attr[k] for k in ("id", "parent_id", "name")}, 
                ]
                attr["path"] = dir_ + escape(attr["name"])
                attr["posixpath"] = posixdir + attr["name"].replace("/", "|")
            if will_yield and topdown:
                if ensure_file is None:
                    yield attr
                elif is_dir:
                    if not ensure_file:
                        yield attr
                elif ensure_file:
                    yield attr
            if is_dir and will_step_in:
                yield from iter_descendants(
                    con, 
                    attr, 
                    min_depth=min_depth, 
                    max_depth=max_depth, 
                    ensure_file=ensure_file, 
                    use_relpath=use_relpath, 
                    with_root=with_root, 
                    topdown=topdown, 
                )
            if will_yield and not topdown:
                if ensure_file is None:
                    yield attr
                elif is_dir:
                    if not ensure_file:
                        yield attr
                elif ensure_file:
                    yield attr


@overload
def iter_descendants_bfs(
    con: Connection | Cursor, 
    parent_id: int = 0, 
    /, 
    min_depth: int = 1, 
    max_depth: int = -1, 
    ensure_file: None | bool = None, 
    use_relpath: bool = False, 
    with_root: bool = False, 
    *, 
    fields: str, 
) -> Iterator[Any]:
    ...
@overload
def iter_descendants_bfs(
    con: Connection | Cursor, 
    parent_id: int = 0, 
    /, 
    min_depth: int = 1, 
    max_depth: int = -1, 
    ensure_file: None | bool = None, 
    use_relpath: bool = False, 
    with_root: bool = False, 
    *, 
    fields: tuple[str, ...] = EXTENDED_FIELDS, 
    to_dict: Literal[False], 
) -> Iterator[tuple[Any, ...]]:
    ...
@overload
def iter_descendants_bfs(
    con: Connection | Cursor, 
    parent_id: int = 0, 
    /, 
    min_depth: int = 1, 
    max_depth: int = -1, 
    ensure_file: None | bool = None, 
    use_relpath: bool = False, 
    with_root: bool = False, 
    *, 
    fields: tuple[str, ...] = EXTENDED_FIELDS, 
    to_dict: Literal[True] = True, 
) -> Iterator[dict[str, Any]]:
    ...
def iter_descendants_bfs(
    con: Connection | Cursor, 
    parent_id: int = 0, 
    /, 
    min_depth: int = 1, 
    max_depth: int = -1, 
    ensure_file: None | bool = None, 
    use_relpath: bool = False, 
    with_root: bool = False, 
    *, 
    fields: str | tuple[str, ...] = EXTENDED_FIELDS, 
    to_dict: bool = True, 
) -> Iterator:
    """获取某个目录之下的所有目录节点的 id 或者信息字典（宽度优先遍历）

    :param con: 数据库连接或游标
    :param parent_id: 顶层目录的 id
    :param min_depth: 最小深度
    :param max_depth: 最大深度。如果小于 0，则无限深度
    :param ensure_file: 是否仅输出文件

        - 如果为 True，仅输出文件
        - 如果为 False，仅输出目录
        - 如果为 None，全部输出

    :param use_relpath: 仅输出相对路径，否则输出完整路径（从 / 开始）
    :param with_root: 仅当 `use_relpath=True` 时生效。如果为 True，则相对路径包含 `parent_id` 对应的节点
    :param fields: 需要获取的字段，接受如下这些：

        .. code:: python

            (
                "id", "parent_id", "pickcode", "sha1", "name", "size", "is_dir", 
                "type", "ctime", "mtime", "is_collect", "is_alive", "updated_at", 
                "depth", "ancestors", "path", "posixpath", 
            )

        - 如果为 str，则获取指定的字段的值
        - 如果为 tuple，则拉取这一组字段的值（但会过滤掉不可用的）

    :param to_dict: 是否产生字典，如果为 True 且 fields 不为 str，则产生字典

    :return: 迭代器，产生一组数据
    """
    one_value = False
    parse: None | Callable = None
    if isinstance(fields, str):
        one_value = True
        field = fields
        if field not in EXTENDED_FIELDS:
            raise ValueError(f"invalid field {field!r}, must be in {EXTENDED_FIELDS!r}")
        with_id = "id" == field
        with_depth = max_depth > 1 or "depth" == field
        with_ancestors = "ancestors" == field
        with_path = "path" == field
        with_posixpath = "posixpath" == field
        fields = field,
    else:
        fields = tuple(filter(set(EXTENDED_FIELDS).__contains__, fields))
        with_id = "id" in fields
        with_depth = max_depth > 1 or min_depth > 1 or "depth" in fields
        with_ancestors = "ancestors" in fields
        with_path = "path" in fields
        with_posixpath = "posixpath" in fields
    select_fields1 = ["id"]
    select_fields1.extend(set(fields) & set(FIELDS[1:]))
    select_fields2 = ["data." + f for f in select_fields1]
    where1, where2 = "", ""
    if with_depth:
        select_fields1.append("1 AS depth")
        select_fields2.append("t.depth + 1")
    if with_path or with_posixpath or with_ancestors:
        if not parent_id:
            ancestors: list[dict] = [{"id": 0, "parent_id": 0, "name": ""}]
            path = posixpath = "/"
        elif use_relpath:
            if with_root:
                attr = get_attr(con, parent_id)
                name = attr["name"]
                ancestors = [{"id": attr["id"], "parent_id": attr["parent_id"], "name": name}]
                path = escape(name) + "/"
                posixpath = name.replace("/", "|") + "/"
            else:
                ancestors = []
                path = posixpath = ""
        else:
            ancestors = get_ancestors(con, parent_id)
            if with_path:
                path = "/".join(escape(a["name"]) for a in ancestors) + "/"
            if with_posixpath:
                posixpath = "/".join(a["name"].replace("/", "|") for a in ancestors) + "/"
        if with_ancestors:
            if ancestors:
                parse_ancestors = lambda val: [*ancestors, *loads("[%s]" % val)]
            else:
                parse_ancestors = lambda val: loads("[%s]" % val)
            parse = parse_ancestors
            select_fields1.append("json_object('id', id, 'parent_id', parent_id, 'name', name) AS ancestors")
            select_fields2.append("concat(t.ancestors, ',', json_object('id', data.id, 'parent_id', data.parent_id, 'name', data.name))")
        if with_path:
            def parse_path(val: str, /) -> str:
                return path + val
            parse = parse_path
            if isinstance(con, Cursor):
                conn = con.connection
            else:
                conn = con
            conn.create_function("escape_name", 1, escape, deterministic=True)
            select_fields1.append("escape_name(name) AS path")
            select_fields2.append("concat(t.path, '/', escape_name(data.name))")
        if with_posixpath:
            def parse_posixpath(val: str, /) -> str:
                return posixpath + val
            parse = parse_posixpath
            select_fields1.append("replace(name, '/', '|') AS posixpath")
            select_fields2.append("concat(t.posixpath, '/', replace(data.name, '/', '|'))")
    if min_depth <= 1 and max_depth in (0, 1) or 0 <= max_depth < min_depth:
        if 0 <= max_depth < min_depth:
            where1 = " AND FALSE"
        elif ensure_file:
            where1 = " AND NOT is_dir"
        elif ensure_file is False:
            where1 = " AND is_dir"
        sql = f"""\
WITH t AS (
    SELECT {",".join(select_fields1)} FROM data WHERE parent_id={parent_id:d} AND is_alive{where1}
) SELECT {",".join(fields)} FROM t"""
    else:
        if max_depth > 1:
            where2 = f" AND depth < {max_depth:d}"
        if ensure_file:
            if "is_dir" not in fields:
                select_fields1.append("is_dir")
                select_fields2.append("data.is_dir")
        elif ensure_file is False:
            where1 += " AND is_dir"
            where2 += " AND data.is_dir"
        sql = f"""\
WITH t AS (
    SELECT {",".join(select_fields1)} FROM data WHERE parent_id={parent_id:d} AND is_alive{where1}
    UNION ALL
    SELECT {",".join(select_fields2)} FROM t JOIN data ON(t.id = data.parent_id) WHERE data.is_alive{where2}
) SELECT {",".join(fields)} FROM t WHERE True"""
        if ensure_file:
            sql += " AND NOT is_dir"
        if min_depth > 1:
            sql += f" AND depth >= {min_depth:d}"
    if one_value:
        if parse is None:
            row_factory = lambda _, r: r[0]
        else:
            row_factory = lambda _, r: parse(r[0])
    elif to_dict:
        def row_factory(_, r):
            d = dict(zip(fields, r))
            if with_ancestors:
                d["ancestors"] = parse_ancestors(d["ancestors"])
            if with_path:
                d["path"] = parse_path(d["path"])
            if with_posixpath:
                d["posixpath"] = parse_posixpath(d["posixpath"])
            return d
    else:
        with_route = with_ancestors or with_path or with_posixpath
        def parse(f, v):
            match f:
                case "ancestors":
                    return parse_ancestors(v)
                case "path":
                    return parse_path(v)
                case "posixpath":
                    return parse_posixpath(v)
                case _:
                    return v
        def row_factory(_, r):
            if with_route:
                return tuple(parse(f, v) for f, v in zip(fields, r))
            return r
    return query(con, sql, row_factory=row_factory)


def iter_files_with_path_url(
    con: Connection | Cursor, 
    parent_id: int | str = 0, 
    /, 
    base_url: str = "http://localhost:8000", 
) -> Iterator[tuple[str, str]]:
    """迭代获取所有文件的路径和下载链接

    :param con: 数据库连接或游标
    :param parent_id: 根目录 id 或者路径
    :param base_url: 115 的 302 服务后端地址

    :return: 迭代器，返回每个文件的 路径 和 下载链接 的 2 元组
    """
    if isinstance(parent_id, str):
        parent_id = get_id(con, path=parent_id)
    code = compile('f"%s/{quote(name, '"''"')}?{id=}&{pickcode=!s}&{sha1=!s}&{size=}&file=true"' % base_url.translate({ord(c): c*2 for c in "{}"}), "-", "eval")
    for attr in iter_descendants_bfs(
        con, 
        parent_id, 
        fields=("id", "sha1", "pickcode", "size", "name", "posixpath"), 
        ensure_file=True, 
    ):
        yield attr["posixpath"], eval(code, None, attr)


def iter_dup_files(
    con: Connection | Cursor, 
    /, 
) -> Iterator[dict]:
    """罗列所有重复文件

    :param con: 数据库连接或游标

    :return: 迭代器，一组文件的信息
    """
    sql = f"""\
WITH stats AS (
    SELECT
        COUNT(1) OVER w AS total, 
        ROW_NUMBER() OVER w AS nth, 
        {",".join(FIELDS)}
    FROM data
    WHERE NOT is_dir AND is_alive
    WINDOW w AS (PARTITION BY sha1, size)
)
SELECT * FROM stats WHERE total > 1"""
    return query(con, sql, row_factory="dict")


def iter_dangling_parent_ids(
    con: Connection | Cursor, 
    /, 
) -> Iterator[int]:
    """罗列所有悬空的 parent_id

    .. note::
        悬空的 parent_id，即所有的 parent_id 中，，不为 0 且不在 `data` 表中的部分

    :param con: 数据库连接或游标

    :return: 迭代器，一组目录的 id
    """
    sql = """\
SELECT
    DISTINCT d1.parent_id
FROM
    data AS d1 LEFT JOIN data AS d2 ON (d1.parent_id = d2.id)
WHERE
    d1.parent_id AND d2.id IS NULL"""
    return query(con, sql, row_factory="one")


def iter_dangling_ids(
    con: Connection | Cursor, 
    /, 
) -> Iterator[int]:
    """罗列所有悬空的文件或目录的 id

    .. note::
        悬空的 id，即祖先节点中，存在一个节点，它的 parent_id 是悬空的

    :param con: 数据库连接或游标

    :return: 迭代器，一组目录的 id
    """
    sql = """\
WITH dangling_ids(id) AS (
    SELECT d1.id
    FROM data AS d1 LEFT JOIN data AS d2 ON (d1.parent_id = d2.id)
    WHERE d1.parent_id AND d2.id IS NULL
    UNION ALL
    SELECT data.id FROM dangling_ids JOIN data ON (dangling_ids.id = data.parent_id)
)
SELECT id FROM dangling_ids"""
    return query(con, sql, row_factory="one")


def select_na_ids(
    con: Connection | Cursor, 
    /, 
) -> set[int]:
    """找出所有的失效节点和悬空节点的 id

    .. note::
        悬空节点，就是此节点有一个祖先节点的 parant_id，不为 0 且不在 `data` 表中

    :param con: 数据库连接或游标

    :return: 一组悬空节点的 id 的集合
    """
    ok_ids: set[int] = set(query(con, "SELECT id FROM data WHERE NOT is_alive", row_factory="one"))
    na_ids: set[int] = set()
    d = dict(query(con, "SELECT id, parent_id FROM data WHERE is_alive"))
    temp: list[int] = []
    push = temp.append
    clear = temp.clear
    update_ok = ok_ids.update
    update_na = na_ids.update
    for k, v in d.items():
        try:
            push(k)
            while k := d[k]:
                if k in ok_ids:
                    update_ok(temp)
                    break
                elif k in na_ids:
                    update_na(temp)
                    break
                push(k)
            else:
                update_ok(temp)
        except KeyError:
            update_na(temp)
        finally:
            clear()
    return na_ids


def select_mtime_groups(
    con: Connection | Cursor, 
    parent_id: int = 0, 
    /, 
    tree: bool = False, 
) -> list[tuple[int, set[int]]]:
    """获取某个目录之下的节点（不含此节点本身），按 mtime 进行分组，相同 mtime 的 id 归入同一组

    :param con: 数据库连接或游标
    :param parent_id: 父目录的 id
    :param tree: 是否拉取目录树，如果为 True，则拉取全部后代的文件节点（不含目录节点），如果为 False，则只拉取子节点（含目录节点）

    :return: 元组的列表（逆序排列），每个元组第 1 个元素是 mtime，第 2 个元素是相同 mtime 的 id 的集合
    """
    if tree:
        it = iter_descendants_bfs(con, parent_id, fields=("mtime", "id"), ensure_file=True, to_dict=False)
    else:
        it = iter_descendants_bfs(con, parent_id, fields=("mtime", "id"), max_depth=1, to_dict=False)
    d: dict[int, set[int]] = group_collect(it, factory=set)
    return sorted(d.items(), reverse=True)


def dump_to_alist(
    con: Connection | Cursor, 
    /, 
    alist_db: str | Path | Connection | Cursor = expanduser("~/alist.d/data/data.db"), 
    parent_id: int | str = 0, 
    dirname: str = "/115", 
    clean: bool = True, 
) -> int:
    """把 p115updatedb 导出的数据，导入到 alist 的搜索索引

    :param con: 数据库连接或游标
    :param alist_db: alist 数据库文件路径或连接
    :param parent_id: 在 p115updatedb 所导出数据库中的顶层目录 id 或路径
    :param dirname: 在 alist 中所对应的的顶层目录路径
    :param clean: 在插入前先清除 alist 的数据库中 `dirname` 目录下的所有数据

    :return: 总共导入的数量
    """
    if isinstance(parent_id, str):
        parent_id = get_id(con, path=parent_id)
    sql = """\
WITH t AS (
    SELECT 
        :dirname AS parent, 
        name, 
        is_dir, 
        size, 
        id, 
        CASE WHEN is_dir THEN CONCAT(:dirname, '/', REPLACE(name, '/', '|')) END AS dirname 
    FROM data WHERE parent_id=:parent_id AND is_alive
    UNION ALL
    SELECT 
        t.dirname AS parent, 
        data.name, 
        data.is_dir, 
        data.size, 
        data.id, 
        CASE WHEN data.is_dir THEN CONCAT(t.dirname, '/', REPLACE(data.name, '/', '|')) END AS dirname
    FROM t JOIN data ON(t.id = data.parent_id) WHERE data.is_alive
)
SELECT parent, name, is_dir, size FROM t"""
    dirname = "/" + dirname.strip("/")
    with transact(alist_db) as cur:
        if clean:
            cur.execute("DELETE FROM x_search_nodes WHERE parent=? OR parent LIKE ? || '/%';", (dirname, dirname))
        count = 0
        executemany = cur.executemany
        for items in batched(query(con, sql, locals()), 10_000):
            executemany("INSERT INTO x_search_nodes(parent, name, is_dir, size) VALUES (?, ?, ?, ?)", items)
            count += len(items)
        return count


def dump_efu(
    con: Connection | Cursor, 
    /, 
    efu_file: str | Path = "export.efu", 
    parent_id: int | str = 0, 
    dirname: str = "", 
    use_relpath: bool = False, 
) -> int:
    """把 p115updatedb 导出的数据，导出为 efu 文件，可供 everything 软件使用

    :param con: 数据库连接或游标
    :param efu_file: 要导出的文件路径
    :param parent_id: 在 p115updatedb 所导出数据库中的顶层目录 id 或路径
    :param dirname: 给每个导出路径添加的目录前缀

    :return: 总共导出的数量
    """
    def unix_to_filetime(unix_time: float, /) -> int:
        return int(unix_time * 10 ** 7) + 11644473600 * 10 ** 7
    if dirname:
        dirname = normpath(dirname)
        if not dirname.endswith("\\"):
            dirname += "\\"
    if isinstance(parent_id, str):
        parent_id = get_id(con, path=parent_id)
    n = 0
    with open(efu_file, "w", newline="", encoding="utf-8") as file:
        csvfile = writer(file)
        writerow = csvfile.writerow
        writerow(("Filename", "Size", "Date Modified", "Date Created", "Attributes"))
        for n, (size, ctime, mtime, is_dir, path) in enumerate(iter_descendants_bfs(
            con, 
            parent_id, 
            use_relpath=use_relpath, 
            fields=("size", "ctime", "mtime", "is_dir", "posixpath"), 
            to_dict=False, 
        ), 1):
            if use_relpath:
                path = normpath(path)
            else:
                path = normpath(path[1:])
            writerow((dirname + path, size, unix_to_filetime(mtime), unix_to_filetime(ctime), 16 if is_dir else 0))
    return n

