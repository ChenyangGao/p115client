#!/usr/bin/env python3
# encoding: utf-8

from collections.abc import Callable, Iterable, Iterator, Sequence
from csv import writer
from datetime import datetime
from errno import ENOENT, ENOTDIR
from itertools import batched
from ntpath import normpath
from os.path import expanduser
from pathlib import Path
from sqlite3 import register_converter, Connection, Cursor
from typing import overload, Any, Final, Literal

from iterutils import bfs_gen, group_collect
from orjson import loads
from posixpatht import escape, path_is_dir_form, splits
from sqlitetools import find, query, transact


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



