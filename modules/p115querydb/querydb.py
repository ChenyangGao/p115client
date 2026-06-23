#!/usr/bin/env python3
# encoding: utf-8

__all__ = [
    "get_ancestors", "get_attr", "get_id", "get_parent_id", 
    "get_path", "get_patht", "get_pickcode", "get_sha1", 
    "has_id", "iter_children", "iter_count_dir", "iter_count_tree", 
    "iter_dangling_ids", "iter_dangling_parent_ids", "iter_descendants", 
    "iter_descendants_bfs", "iter_dup_files", "iter_existing_id", 
    "iter_id_to_parent_id", "iter_id_to_path", "iter_parent_id", 
    "path_to_id", "select_mtime_groups", "select_na_ids", 
    "dump_to_efu", 
]
__doc__ = "这个模块提供了一些和查询 sqlite 数据库有关的函数"

from collections.abc import Callable, Collection, Iterable, Iterator, Sequence
from ntpath import normpath
from os import PathLike
from sqlite3 import Connection, Cursor
from typing import cast, overload, Any

from errno2 import errno
from iter_collect import grouped_mapping
from iterutils import bfs_gen, group_collect
from posixpatht import path_is_dir_form, escape, splits
from sqlitetools import find, query

from p115client.util import posix_escape_name


# TODO: 进行一些优化，以适应其它数据库，例如 MySQL
# TODO: 以后还将支持文档数据库 MongoDB、key-value 数据库等

def get_ancestors(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
) -> list[dict]:
    """获取某个文件或目录的祖先节点信息，包括 "id"、"parent_id" 和 "name" 字段

    :param con: sqlite 数据库连接或游标
    :param id: 节点的 id

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
        raise FileNotFoundError(errno.ENOENT, id)
    if ls[-1][1]:
        raise ValueError(f"dangling id: {id}")
    ancestors.extend(dict(zip(("id", "parent_id", "name"), record)) for record in reversed(ls))
    return ancestors


def get_attr(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
) -> dict:
    """获取某个文件或目录的信息

    :param con: sqlite 数据库连接或游标
    :param id: 节点的 id

    :return: 当前节点的信息字典
    """
    if not id:
        return {
            "id": 0, "parent_id": 0, "pickcode": "", "name": "", "sha1": "", "size": 0, 
            "is_dir": 1, "is_alive": 1, 
        }
    return find(
        con, 
        f"SELECT * FROM data WHERE id=? LIMIT 1", 
        id, 
        FileNotFoundError(errno.ENOENT, id), 
        row_factory="dict", 
    )


def get_id(
    con: Connection | Cursor, 
    /, 
    pickcode: str = "", 
    sha1: str = "", 
    path: str | Sequence[str] = "", 
    parent_id:  int = 0, 
    is_alive: bool = True, 
) -> int:
    """查询匹配某个字段的文件或目录的 id

    :param con: sqlite 数据库连接或游标
    :param pickcode: 当前节点的提取码，优先级高于 sha1
    :param sha1: 当前节点的 sha1 校验哈希值，优先级高于 path
    :param path: 当前节点的路径
    :param parent_id: 仅用于 `path` 参数，用来限定搜索的顶层路径
    :param is_alive: 是否存活

    :return: 节点的 id
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
        return path_to_id(
            con, 
            path, 
            parent_id=parent_id, 
            is_alive=is_alive, 
        )
    return 0


def get_parent_id(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
    default: None | int = None, 
) -> int:
    """获取某个节点 id 对应的父 id

    :param con: sqlite 数据库连接或游标
    :param id: 节点的 id
    :param default: 未找到时返回的默认值，如果为 None，则抛出 ``FileNotFoundError``

    :return: 当前节点的父 id，未找到则返回 ``default``
    """
    if id == 0:
        return 0
    sql = "SELECT parent_id FROM data WHERE id=?"
    return find(
        con, sql, id, 
        FileNotFoundError(errno.ENOENT, id) if default is None else default
    )


def get_path(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
    escape: None | Callable[[str, str]] = escape, 
) -> str:
    """获取某个文件或目录的路径

    :param con: sqlite 数据库连接或游标
    :param id: 节点的 id
    :param escape: 对文件名进行转义，如果为 None，则保持原样

    :return: 当前节点的路径
    """
    if not id:
        return "/"
    ancestors = get_ancestors(con, id)
    if escape is None:
        return "/".join(a["name"] for a in ancestors)
    else:
        return "/".join(escape(a["name"]) for a in ancestors)


def get_patht(
    con: Connection | Cursor, 
    /, 
    id: int = 0, 
) -> list[str]:
    """获取某个文件或目录的路径节点元组

    :param con: sqlite 数据库连接或游标
    :param id: 节点的 id

    :return: 当前节点的路径节点元组
    """
    if not id:
        return [""]
    ancestors = get_ancestors(con, id)
    return [a["name"] for a in ancestors]


def get_pickcode(
    con: Connection | Cursor, 
    /, 
    id: int = -1, 
    sha1: str = "", 
    path: str | Sequence[str] = "", 
    parent_id: int = 0, 
    is_alive: bool = True, 
) -> str:
    """查询匹配某个字段的文件或目录的提取码

    :param con: sqlite 数据库连接或游标
    :param id: 节点的 id，优先级高于 sha1
    :param sha1: 当前节点的 sha1 校验哈希值，优先级高于 path
    :param path: 当前节点的路径
    :param parent_id: 仅用于 `path` 参数，用来限定搜索的顶层路径
    :param is_alive: 是否存活

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
        id = path_to_id(con, path, parent_id=parent_id, is_alive=is_alive)
        return get_pickcode(con, id)


def get_sha1(
    con: Connection | Cursor, 
    /, 
    id: int = -1, 
    pickcode: str = "", 
    path: str | Sequence[str] = "", 
    parent_id: int = 0, 
    is_alive: bool = True, 
) -> str:
    """查询匹配某个字段的文件的 sha1

    :param con: sqlite 数据库连接或游标
    :param id: 节点的 id，优先级高于 pickcode
    :param pickcode: 当前节点的提取码，优先级高于 path
    :param path: 当前节点的路径
    :param parent_id: 仅用于 `path` 参数，用来限定搜索的顶层路径
    :param is_alive: 是否存活

    :return: 当前节点的 sha1 校验哈希值
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
        id = path_to_id(con, path, parent_id=parent_id, is_alive=is_alive)
        return get_sha1(con, id)


def has_id(
    con: Connection | Cursor, 
    /, 
    id: int, 
    is_alive: bool = True, 
) -> bool:
    """检查是否存在某个 id

    :param con: sqlite 数据库连接或游标
    :param id: 节点的 id
    :param is_alive: 是否存活

    :return: 是否存在某个 id
    """
    if id == 0:
        return True
    elif id < 0:
        return False
    sql = "SELECT 1 FROM data WHERE id=?"
    if is_alive:
        sql += " AND is_alive"
    return bool(find(con, sql, id, 0))


def iter_children(
    con: Connection | Cursor, 
    /, 
    parent_id: int = 0, 
    fields: Collection[str] = (), 
    ensure_file: None | bool = None, 
) -> Iterator[dict]:
    """获取某个目录之下的文件或目录的信息

    .. caution::
        当 ``fields`` 为空时，获取全部字段

    :param con: sqlite 数据库连接或游标
    :param parent_id: 父目录的 id
    :param fields: 需要获取的字段
    :param ensure_file: 是否仅输出文件

        - 如果为 True，仅输出文件
        - 如果为 False，仅输出目录
        - 如果为 None，全部输出

    :return: 迭代器，产生一组信息的字典，大概包含如下字段：

        .. code:: python

            (
                "id", "parent_id", "name", "sha1", "size", "pickcode", 
                "is_dir", "is_alive", 
            )
    """
    if fields:
        sql = f"SELECT {','.join(fields)} FROM data WHERE parent_id=? AND is_alive"
    else:
        sql = "SELECT * FROM data WHERE parent_id=? AND is_alive"
    if ensure_file is not None:
        if ensure_file:
            sql += " AND NOT is_dir"
        else:
            sql += " AND is_dir"
    return query(con, sql, parent_id, row_factory="dict")


def iter_count_dir(
    con: Connection | Cursor, 
    /, 
    parent_id: int = 0, 
) -> Iterator[dict]:
    """迭代获取所有指定 id 下所有目录节点（包括自己）直属的文件数和目录数

    :param con: sqlite 数据库连接或游标
    :param parent_id: 顶层目录的 id

    :return: 迭代器，返回字典

        .. code::

            {
                "id": int, 
                "parent_id": int, 
                "dir_count": int, 
                "file_count": int, 
            }
    """
    sql = """\
WITH t AS (
    SELECT id, parent_id, is_dir FROM data WHERE parent_id = ? AND is_alive
    UNION ALL
    SELECT data.id, data.parent_id, data.is_dir FROM t JOIN data ON (t.id = data.parent_id) WHERE is_alive
), count AS (
    SELECT parent_id AS id, SUM(is_dir) AS dir_count, SUM(NOT is_dir) AS file_count 
    FROM t 
    GROUP BY parent_id
)
SELECT data.parent_id, count.* FROM count JOIN data USING (id)"""
    return query(con, sql, parent_id, row_factory="dict")


def iter_count_tree(
    con: Connection | Cursor, 
    /, 
    parent_id: int = 0, 
) -> Iterator[dict]:
    """迭代获取所有指定 id 下所有目录节点（包括自己）直属的文件数和目录数，以及子树下的文件数合计和目录数合计

    :param con: sqlite 数据库连接或游标
    :param parent_id: 顶层目录的 id

    :return: 迭代器，返回字典

        .. code::

            {
                "id": int, 
                "parent_id": int, 
                "dir_count": int, 
                "file_count": int, 
                "tree_dir_count": int, 
                "tree_file_count": int, 
            }
    """
    data = {a["id"]: a for a in iter_count_dir(con, parent_id)}
    id_to_children = grouped_mapping((a["parent_id"], id) for id, a in data.items())
    def calc(attr: dict, /) -> dict:
        if children := id_to_children.get(attr["id"]):
            for cid in children:
                cattr = data[cid]
                if "tree_dir_count" not in cattr:
                    calc(cattr)
                attr["tree_dir_count"] = attr.get("tree_dir_count", 0) + 1 + cattr["tree_dir_count"]
                attr["tree_file_count"] = attr.get("tree_file_count", attr["file_count"]) + cattr["tree_file_count"]
        elif "tree_dir_count" not in attr:
            attr["tree_dir_count"] = attr["dir_count"]
            attr["tree_file_count"] = attr["file_count"]
        return attr
    return map(calc, data.values())


def iter_dangling_ids(
    con: Connection | Cursor, 
    /, 
) -> Iterator[int]:
    """罗列所有悬空的文件或目录的 id

    .. note::
        悬空的 id，即祖先节点中，存在一个节点，它的 parent_id 是悬空的

    :param con: sqlite 数据库连接或游标

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


def iter_dangling_parent_ids(
    con: Connection | Cursor, 
    /, 
) -> Iterator[int]:
    """罗列所有悬空的 parent_id

    .. note::
        悬空的 parent_id，即所有的 parent_id 中，既不为 0 又不在表中的那一部分

    :param con: sqlite 数据库连接或游标

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


# TODO: 输出 ancestors 和 path，但却是相对的，但可以用一个参数要求是绝对的
@overload
def iter_descendants(
    con: Connection | Cursor, 
    /, 
    parent_id: int = 0, 
    min_depth: int = 1, 
    max_depth: int = -1, 
    *, 
    fields: str, 
    escape: None | bool | Callable[[str], str] = True, 
    ensure_file: None | bool = None, 
    topdown: None | bool = True, 
) -> Iterator[Any]:
    ...
@overload
def iter_descendants(
    con: Connection | Cursor, 
    /, 
    parent_id: int = 0, 
    min_depth: int = 1, 
    max_depth: int = -1, 
    *, 
    fields: Collection[str] | bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    ensure_file: None | bool = None, 
    topdown: None | bool = True, 
) -> Iterator[dict]:
    ...
def iter_descendants(
    con: Connection | Cursor, 
    /, 
    parent_id: int = 0, 
    min_depth: int = 1, 
    max_depth: int = -1, 
    *, 
    fields: str | Collection[str] | bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
    ensure_file: None | bool = None, 
    topdown: None | bool = True, 
) -> Iterator:
    """获取某个目录之下的所有节点信息

    .. caution::
        当 ``fields`` 为空时，获取全部字段

    :param con: sqlite 数据库连接或游标
    :param parent_id: 顶层目录的 id
    :param min_depth: 最小深度
    :param max_depth: 最大深度。如果小于 0，则无限深度
    :param fields: 需要获取的字段

        - 如果为 str，直接获取这个字段的值（不返回字典）
        - 如果为 True，获取所有字段，且包括（"ancestors", "path", "relpath", "depth"），返回字典
        - 如果为 False，获取所有字段，但除了（"ancestors", "path", "relpath", "depth"），返回字典
        - 否则，获取所指定的这组字段，返回字典

    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :param ensure_file: 是否仅输出文件

        - 如果为 True，仅输出文件
        - 如果为 False，仅输出目录
        - 如果为 None，全部输出

    :param topdown: 是否自顶向下深度优先遍历

        - 如果为 True，则自顶向下深度优先遍历
        - 如果为 False，则自底向上深度优先遍历
        - 如果为 None，则自顶向下宽度优先遍历

    :return: 迭代器，产生一组信息的字典，大概包含如下字段：

        .. code:: python

            (
                # NOTE: 大概包含如下字段
                "id", "parent_id", "name", "sha1", "size", "pickcode", 
                "is_dir", "is_alive", 
                # NOTE: 以及这些可选字段
                "ancestors", "path", "relpath", "depth", 
            )
    """
    if 0 <= max_depth < min_depth:
        return
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    field: str = ""
    if isinstance(fields, bool) or not fields:
        with_ancestors = with_path = with_relpath = with_depth = fields if isinstance(fields, bool) else True
        children_fields = set()
    else:
        if isinstance(fields, str):
            field = fields
            fields = {field}
        else:
            fields = set(fields)
        with_ancestors = "ancestors" in fields
        with_path = "path" in fields
        with_relpath = "relpath" in fields
        with_depth = "depth" in fields
        children_fields = fields - frozenset(("ancestors", "path", "relpath", "depth")) | {"id", "is_dir"}
        if with_ancestors or with_path or with_relpath:
            children_fields |= frozenset(("name", "parent_id"))
    ancestors: list[dict] = []
    dir_: str = ""
    reldir: str = ""
    if parent_id:
        if with_ancestors or with_path:
            ancestors = get_ancestors(con, parent_id)
            if with_path:
                if escape is None:
                    dir_ = "".join(a["name"] + "/" for a in ancestors)
                else:
                    dir_ = "".join(escape(a["name"]) + "/" for a in ancestors)
    else:
        if with_ancestors:
            ancestors = [{"id": 0, "parent_id": 0, "name": ""}]
        if with_path:
            dir_ = "/"
    def may_yield(attr: dict, /):
        if ensure_file is None or (attr["is_dir"] ^ ensure_file):
            if field:
                yield attr[field]
            else:
                yield attr
    children_ensure_file = False if ensure_file is False else None
    if topdown is None:
        gen = bfs_gen((parent_id, 0, ancestors, dir_, reldir))
        send: Callable = gen.send
        for parent_id, depth, ancestors, dir_, reldir in gen:
            depth += 1
            will_step_in = max_depth < 0 or depth < max_depth
            will_yield = min_depth <= depth and (max_depth < 0 or depth <= max_depth)
            for attr in iter_children(
                con, 
                parent_id, 
                fields=children_fields, 
                ensure_file=children_ensure_file, 
            ):
                if with_depth:
                    attr["depth"] = depth
                if with_ancestors:
                    attr["ancestors"] = [
                        *ancestors, 
                        {k: attr[k] for k in ("id", "parent_id", "name")}, 
                    ]
                if with_path or with_relpath:
                    name = attr["name"]
                    if escape is not None:
                        name = escape(name)
                    if with_path:
                        attr["path"] = dir_ + name
                    if with_relpath:
                        attr["relpath"] = reldir + name
                if will_step_in and attr["is_dir"]:
                    send((
                        attr["id"], 
                        depth, 
                        attr["ancestors"] if with_ancestors else None, 
                        attr["path"] + "/" if with_path else "", 
                        attr["relpath"] + "/" if with_relpath else "", 
                    ))
                if will_yield:
                    yield from may_yield(attr)
    else:
        cache: dict[Iterator, dict] = {}
        stack: list[tuple[Iterator[dict], list[dict], str, str]] = [(
            iter(tuple(iter_children(
                con, 
                parent_id, 
                fields=children_fields, 
                ensure_file=children_ensure_file, 
            ))), ancestors, dir_, reldir)]
        depth = 0
        while depth >= 0:
            attrs, ancestors, dir_, reldir = stack[depth]
            depth += 1
            will_step_in = max_depth < 0 or depth < max_depth
            will_yield = min_depth <= depth and (max_depth < 0 or depth <= max_depth)
            for attr in attrs:
                if with_depth:
                    attr["depth"] = depth
                if with_ancestors:
                    attr["ancestors"] = [
                        *ancestors, 
                        {k: attr[k] for k in ("id", "parent_id", "name")}, 
                    ]
                if with_path or with_relpath:
                    name = attr["name"]
                    if escape is not None:
                        name = escape(name)
                    if with_path:
                        attr["path"] = dir_ + name
                    if with_relpath:
                        attr["relpath"] = reldir + name
                if will_yield and topdown:
                    yield from may_yield(attr)
                if will_step_in and attr["is_dir"]:
                    attrs = iter(tuple(iter_children(
                        con, 
                        attr["id"], 
                        fields=children_fields, 
                        ensure_file=children_ensure_file, 
                    )))
                    quadruple = (
                        attrs, 
                        attr["ancestors"] if with_ancestors else ancestors, 
                        attr["path"] + "/" if with_path else "", 
                        attr["relpath"] + "/" if with_relpath else "", 
                    )
                    try:
                        stack[depth] = quadruple
                    except IndexError:
                        stack.append(quadruple)
                    if will_yield and not topdown:
                        cache[attrs] = attr
                    break
                if will_yield and not topdown:
                    yield from may_yield(attr)
            else:
                if cache and attrs in cache:
                    yield from may_yield(cache.pop(attrs))
                depth -= 2


# TODO: 输出 ancestors 和 path，但却是相对的，但可以用一个参数要求是绝对的
@overload
def iter_descendants_bfs(
    con: Connection | Cursor, 
    /, 
    parent_id: int = 0, 
    *, 
    fields: str, 
    escape: None | bool | Callable[[str], str] = True, 
) -> Iterator[Any]:
    ...
@overload
def iter_descendants_bfs(
    con: Connection | Cursor, 
    /, 
    parent_id: int = 0, 
    *, 
    fields: Collection[str] | bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
) -> Iterator[dict]:
    ...
def iter_descendants_bfs(
    con: Connection | Cursor, 
    /, 
    parent_id: int = 0, 
    *, 
    fields: str | Collection[str] | bool = True, 
    escape: None | bool | Callable[[str], str] = True, 
) -> Iterator:
    """获取某个目录之下的所有节点信息

    .. caution::
        当 ``fields`` 为空时，获取全部字段        

    :param con: sqlite 数据库连接或游标
    :param parent_id: 顶层目录的 id
    :param fields: 需要获取的字段

        - 如果为 str，直接获取这个字段的值（不返回字典）
        - 如果为 True，获取所有字段，且包括（"ancestors", "path", "relpath", "depth"），返回字典
        - 如果为 False，获取所有字段，但除了（"ancestors", "path", "relpath", "depth"），返回字典
        - 否则，获取所指定的这组字段，返回字典

    :param escape: 对文件名进行转义

        - 如果为 None，则不处理；否则，这个函数用来对文件名中某些符号进行转义，例如 "/" 等
        - 如果为 True，则使用 `posixpatht.escape`，会对文件名中 "/"，或单独出现的 "." 和 ".." 用 "\\" 进行转义
        - 如果为 False，则使用 `posix_escape_name` 函数对名字进行转义，会把文件名中的 "/" 转换为 "|"
        - 如果为 Callable，则用你所提供的调用，以或者转义后的名字

    :return: 迭代器，产生一组信息的字典，大概包含如下字段：

        .. code:: python

            (
                # NOTE: 大概包含如下字段
                "id", "parent_id", "name", "sha1", "size", "pickcode", 
                "is_dir", "is_alive", 
                # NOTE: 以及这些可选字段
                "ancestors", "path", "relpath", "depth", 
            )
    """
    if isinstance(escape, bool):
        if escape:
            from posixpatht import escape
        else:
            escape = posix_escape_name
    escape = cast(None | Callable[[str], str], escape)
    field: str = ""
    if isinstance(fields, bool) or not fields:
        with_depth = with_ancestors = with_path = with_relpath = fields if isinstance(fields, bool) else True
        fields = "*"
        fields1 = "*"
        fields2 = "data.*"
    else:
        if isinstance(fields, str):
            field = fields
            fields = {field}
        else:
            fields = set(fields)
        fields.add("id")
        with_depth = "depth" in fields
        with_ancestors = "ancestors" in fields
        with_path = "path" in fields
        with_relpath = "relpath" in fields
        if with_depth or with_ancestors or with_path or with_relpath:
            fields.add("parent_id")
            fields.add("name")
        fields -= frozenset(("depth", "ancestors", "path", "relpath"))
        fields1 = ",".join(fields)
        fields2 = ",".join("data." + f for f in fields)
    sql = f"""\
WITH t AS (
SELECT {fields1} FROM data WHERE parent_id={parent_id:d} AND is_alive
UNION ALL
SELECT {fields2} FROM t JOIN data ON(t.id = data.parent_id) WHERE data.is_alive
) SELECT * FROM t"""
    row_factory: str | Callable = "any"
    if with_depth or with_ancestors or with_path or with_relpath:
        if with_depth:
            d_depth = {parent_id: 0}
        if with_ancestors or with_path:
            if parent_id:
                ancestors = get_ancestors(con, parent_id)
                if with_ancestors:
                    d_ancestors = {parent_id: ancestors}
                if with_path:
                    if escape is None:
                        d_path = {parent_id: "".join(a["name"] + "/" for a in ancestors)}
                    else:
                        d_path = {parent_id: "".join(escape(a["name"]) + "/" for a in ancestors)}
            else:
                if with_ancestors:
                    d_ancestors = {0: [{"id": 0, "parent_id": 0, "name": ""}]}
                if with_path:
                    d_path = {0: "/"}
        if with_relpath:
            d_relpath = {parent_id: ""}
        cursor_fields: None | tuple[str, ...] = None
        def row_factory(cursor, record, /):
            nonlocal cursor_fields
            if cursor_fields is None:
                cursor_fields = tuple(f[0] for f in cursor.description)
            attr = dict(zip(cursor_fields, record))
            id, pid, name = attr["id"], attr["parent_id"], attr["name"]
            if with_depth:
                d_depth[id] = attr["depth"] = d_depth[pid] + 1
            if with_ancestors:
                attr["ancestors"] = [*d_ancestors[pid], {"id": id, "parent_id": pid, "name": name}]
            if escape is not None and (with_path or with_relpath):
                name = escape(name)
            if with_path:
                attr["path"] = d_path[pid] + name
            if with_relpath:
                attr["relpath"] = d_relpath[pid] + name
            if attr.get("is_dir", True):
                if with_ancestors:
                    d_ancestors[id] = attr["ancestors"]
                if with_path:
                    d_path[id] = attr["path"] + "/"
                if with_relpath:
                    d_relpath[id] = attr["relpath"] + "/"
            if field:
                return attr[field]
            return attr
    elif field:
        row_factory = "one"
    else:
        row_factory = "dict"
    return query(con, sql, row_factory=row_factory)


def iter_dup_files(
    con: Connection | Cursor, 
    /, 
) -> Iterator[dict]:
    """罗列所有重复文件

    .. note::
        直接用数据库查询做的查重，性能较差，实际应该使用下面这种

       .. code:: python

            from operator import itemgetter
            from iter_collect import iter_keyed_dups
 
            sql = "SELECT * FROM data WHERE NOT is_dir AND is_alive"
            # NOTE: 得到一个迭代器，可以输出所有 ("sha1", "size") 重复的节点
            it = iter_keyed_dups(
                query(con, sql, row_factory="dict"), 
                key=itemgetter("sha1", "size"), 
            )

    :param con: sqlite 数据库连接或游标

    :return: 迭代器，一组文件的信息
    """
    sql = f"""\
WITH stats AS (
    SELECT
        COUNT(1) OVER w AS total, 
        ROW_NUMBER() OVER w AS nth, 
        *
    FROM data
    WHERE NOT is_dir AND is_alive
    WINDOW w AS (PARTITION BY sha1, size)
)
SELECT * FROM stats WHERE total > 1"""
    return query(con, sql, row_factory="dict")


def iter_existing_id(
    con: Connection | Cursor, 
    /, 
    ids: Iterable[int], 
    is_alive: bool = True, 
) -> Iterator[int]:
    """从一组 id 中筛选出也存在于数据库中的

    :param con: sqlite 数据库连接或游标
    :param ids: 一组节点 id
    :param is_alive: 是否存活

    :return: 迭代器，实际是一个游标
    """
    sql = "SELECT id FROM data WHERE id IN (%s)" % (",".join(map("%d".__mod__, ids)) or "NULL")
    if is_alive:
        sql += " AND is_alive"
    return query(con, sql, row_factory="one")


def iter_id_to_parent_id(
    con: Connection | Cursor, 
    /, 
    ids: Iterable[int], 
    recursive: bool = False, 
) -> Iterator[tuple[int, int]]:
    """找出一系列 id 所对应的父 id，返回 ``(id, parent_id)`` 的 2 元组

    :param con: sqlite 数据库连接或游标
    :param ids: 一组节点 id
    :param recursive: 是否递归，如果为 True，则还会处理它们的祖先节点

    :return: 迭代器，产生 ``(id, parent_id)`` 的 2 元组，实际是一个游标
    """
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
    is_alive: bool = True, 
) -> Iterator[int]:
    """查询匹配某个路径的文件或目录的信息字典

    .. note::
        同一个路径可以有多条对应的数据

    :param con: sqlite 数据库连接或游标
    :param path: 路径
    :param ensure_file: 是否文件

        - 如果为 True，必须是文件
        - 如果为 False，必须是目录
        - 如果为 None，可以是文件或目录

    :param parent_id: 顶层目录的 id
    :param is_alive: 是否存活

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
    insertion = " AND is_alive" if is_alive else ""
    if len(patht) > 2:
        sql = f"SELECT id FROM data WHERE parent_id=? AND name=?{insertion} AND is_dir LIMIT 1"
        for name in patht[1:-1]:
            parent_id = find(con, sql, (parent_id, name), default=-1)
            if parent_id < 0:
                return iter(())
    sql = f"SELECT id FROM data WHERE parent_id=? AND name=?{insertion}"
    if ensure_file is None:
        sql += " ORDER BY is_dir DESC"
    elif ensure_file:
        sql += " AND NOT is_dir"
    else:
        sql += " AND is_dir LIMIT 1"
    return query(con, sql, (parent_id, patht[-1]), row_factory="one")


def iter_parent_id(
    con: Connection | Cursor, 
    /, 
    ids: Iterable[int], 
) -> Iterator[int]:
    """找出一组节点 id 所对应的父 id

    :param con: sqlite 数据库连接或游标
    :param ids: 一组节点 id

    :return: 迭代器，实际是一个游标
    """
    sql = "SELECT parent_id FROM data WHERE id IN (%s)" % (",".join(map("%d".__mod__, ids)) or "NULL")
    return query(con, sql, row_factory="one")


def path_to_id(
    con: Connection | Cursor, 
    /, 
    path: str | Sequence[str] = "", 
    ensure_file: None | bool = None, 
    parent_id: int = 0, 
    is_alive: bool = True, 
) -> int:
    """查询匹配某个路径的文件或目录的信息字典，只返回找到的第 1 个

    :param con: sqlite 数据库连接或游标
    :param path: 路径
    :param ensure_file: 是否文件

        - 如果为 True，必须是文件
        - 如果为 False，必须是目录
        - 如果为 None，可以是文件或目录

    :param parent_id: 顶层目录的 id
    :param is_alive: 是否存活

    :return: 找到的第 1 个匹配的节点 id
    """
    try:
        return next(iter_id_to_path(
            con, 
            path=path, 
            ensure_file=ensure_file, 
            parent_id=parent_id, 
            is_alive=is_alive, 
        ))
    except StopIteration:
        raise FileNotFoundError(errno.ENOENT, path) from None


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


def select_na_ids(
    con: Connection | Cursor, 
    /, 
) -> set[int]:
    """找出所有的失效节点和悬空节点的 id

    .. note::
        悬空节点，就是此节点有一个祖先节点的 parant_id，不为 0 且不在表中

    :param con: sqlite 数据库连接或游标

    :return: 一组悬空节点的 id 的集合
    """
    ok_ids: set[int] = set(query(
        con, 
        "SELECT id FROM data WHERE NOT is_alive", 
        row_factory="one", 
    ))
    na_ids: set[int] = set()
    d = dict(query(con, "SELECT id, parent_id FROM data WHERE is_alive"))
    temp: list[int] = []
    push = temp.append
    clear = temp.clear
    update_ok = ok_ids.update
    update_na = na_ids.update
    for k in d:
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


def dump_to_efu(
    con: Connection | Cursor, 
    /, 
    efu_file: str | PathLike = "export.efu", 
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
    from csv import writer
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
            writerow((
                dirname + path, 
                size, 
                unix_to_filetime(mtime), 
                unix_to_filetime(ctime), 
                16 if is_dir else 0, 
            ))
    return n


# TODO: 对数据的处理通过 row_factory 的自定义函数实现
def traverse_tree(
    con: Connection | Cursor, 
    /, 
    top_id: int = 0, 
    fields: str | Collection[str] | bool = True, 
) -> Iterable[dict]:
    """遍历目录树

    :param con: 数据库连接或游标
    :param top_id: 顶层目录 id

    :return: 文件信息的迭代器，其实是一个游标
    """
    sql = """\
WITH t AS (
    SELECT * FROM data WHERE parent_id=? AND is_alive
    UNION ALL
    SELECT data.* FROM t JOIN data ON(t.id = data.parent_id) WHERE data.is_alive
)
SELECT * FROM t"""
    return query(con, sql, (top_id,), row_factory="dict")

