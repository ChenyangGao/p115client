#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"

from pkgutil import get_data
from sqlite3 import Connection, Cursor

from p115client import P115Client
from p115client.tool import traverse_tree


INIT_SQL = get_data("p115incdb", "init.sql").decode("utf-8")


def initdb(con: Connection | Cursor, /) -> Cursor:
    return con.executescript(INIT_SQL)


def sort(
    data: list[dict], 
    /, 
    reverse: bool = False, 
) -> list[dict]:
    """对文件信息数据进行排序，使得如果某个元素是另一个元素的父节点，则后者在前

    :param data: 待排序的文件信息列表
    :param reverse: 是否逆序排列

    :return: 原地排序，返回传入的列表本身
    """
    d: dict[int, int] = {a["id"]: a["parent_id"] for a in data}
    depth_d: dict[int, int] = {}
    def depth(id: int, /) -> int:
        try:
            return depth_d[id]
        except KeyError:
            if id in d:
                return depth(d[id]) + 1
            return 0
    data.sort(key=lambda a: depth(a["id"]), reverse=reverse)
    return data


# TODO: 检查一下，如果 cid 不为 0 时不在数据库，则进行补充，用多种接口获取 paths
async def load_tree(
    client: P115Client, 
    cid: int = 0, 
):
    files = [a async for a in traverse_tree(client, cid, async_=True)]



