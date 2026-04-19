#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "attr_to_path", "get_id_from_db", "get_pickcode_from_db", "get_sha1_from_db", 
    "get_path_from_db", "get_ancestors_from_db", "get_attr_from_db", "get_children_from_db", 
]

from collections.abc import Mapping, Iterable, Sequence
from sqlite3 import Connection, Cursor
from typing import Any

from dictattr import AttrDict
from encode_uri import encode_uri_component_loose
from p115client.tool import P115QueryDB


def normattr(m: Mapping | Iterable[tuple[str, Any]], /) -> AttrDict:
    attr: AttrDict = AttrDict(m)
    attr["id"] = str(attr["id"])
    attr["parent_id"] = str(attr["parent_id"])
    name = encode_uri_component_loose(attr["name"])
    if attr["is_dir"]:
        attr["url"] = f"/{name}?file=false&id={attr['id']}"
        attr["ico"] = "folder"
    else:
        attr["url"] = f"/{name}?file=true&pickcode={attr['pickcode']}"
        if attr.get("is_collect", False) and attr["size"] < 1024 * 1024 * 115:
            attr["url"] += "&web=true"
        attr["ico"] = attr["name"].rpartition(".")[-1].lower()
    if "ctime" not in attr:
        attr["ctime"] = attr.get("created_at", 0)
    if "mtime" not in attr:
        attr["mtime"] = attr.get("updated_at", 0)
    return attr


def attr_to_path(
    con: Connection | Cursor, 
    /, 
    path: str | Sequence[str] = "", 
    ensure_file: None | bool = None, 
    parent_id: int = 0, 
) -> AttrDict:
    id = P115QueryDB(con).id_to_path(path, ensure_file=ensure_file, parent_id=parent_id)
    return get_attr_from_db(con, id)


def get_id_from_db(
    con: Connection | Cursor, 
    /, 
    pickcode: str = "", 
    sha1: str = "", 
    path: str = "", 
) -> int:
    return P115QueryDB(con).get_id(pickcode, sha1, path)


def get_pickcode_from_db(
    con: Connection | Cursor, 
    /, 
    id: int = -1, 
    sha1: str = "", 
    path: str = "", 
) -> str:
    return P115QueryDB(con).get_pickcode(id, sha1, path)


def get_sha1_from_db(
    con: Connection | Cursor, 
    /, 
    id: int = -1, 
    pickcode: str = "", 
    path: str = "", 
) -> str:
    return P115QueryDB(con).get_sha1(id, pickcode, path)


def get_path_from_db(
    con: Connection | Cursor, 
    id: int = 0, 
    /, 
) -> str:
    return P115QueryDB(con).get_path(id)


def get_ancestors_from_db(
    con: Connection | Cursor, 
    id: int = 0, 
    /, 
) -> list[dict]:
    ancestors = P115QueryDB(con).get_ancestors(id)
    for a in ancestors:
        a["id"] = str(a["id"])
        a["parent_id"] = str(a["parent_id"])
    return ancestors


def get_attr_from_db(
    con: Connection | Cursor, 
    id: int = 0, 
    /, 
) -> AttrDict:
    return normattr(P115QueryDB(con).get_attr(id))


def get_children_from_db(
    con: Connection | Cursor, 
    id: int = 0, 
    /, 
) -> list[AttrDict]:
    ls = list(map(normattr, P115QueryDB(con).iter_children(id)))
    ls.sort(key=lambda a: (1 - a["is_dir"], a["name"]))
    return ls

