#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["iter_115_to_115", "iter_115_to_115_resume"]
__doc__ = "这个模块提供了一些和上传有关的函数"

from collections.abc import AsyncIterator, Iterator
from itertools import dropwhile
from typing import overload, Any, Literal

from asynctools import to_list
from concurrenttools import threadpool_map, taskgroup_map, Return
from iterutils import as_gen_step, run_gen_step_iter, with_iter_next, YieldFrom
from p115client import check_response, normalize_attr_simple, P115Client

from .download import iter_download_files
from .iterdir import iterdir, iter_files_with_path, unescape_115_charref


@overload
def iter_115_to_115(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int = 0, 
    to_pid: int = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    use_iter_files: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_115_to_115(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int = 0, 
    to_pid: int = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    use_iter_files: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_115_to_115(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int = 0, 
    to_pid: int = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    use_iter_files: bool = False, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """从 115 传到 115

    :param from_client: 来源 115 客户端对象
    :param to_client: 去向 115 客户端对象
    :param from_cid: 来源 115 的目录 id
    :param to_pid: 去向 115 的父目录 id
    :param max_workers: 最大并发数
    :param with_root: 是否保留 `from_cid` 对应的目录名（如果为 False，则会少 1 级目录）
    :param use_iter_files: 如果为 True，则调用 iter_files_with_path，否则调用 iter_download_files
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生转移结果，有 3 种类型："good"、"fail" 和 "skip"
    """
    @as_gen_step(async_=async_)
    def upload(attr: dict, pid: int, /):
        @as_gen_step(async_=async_)
        def read_range_bytes_or_hash(sign_check: str, /):
            if attr["is_collect"]:
                url = yield from_client.download_url(
                    attr["pickcode"], 
                    use_web_api=True, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                url = yield from_client.download_url(
                    attr["pickcode"], 
                    app="android", 
                    async_=async_, 
                    **request_kwargs, 
                )
            return from_client.request(
                url, 
                headers=dict(url["headers"], Range="bytes="+sign_check), 
                parse=False, 
                async_=async_, 
                **request_kwargs, 
            )
        try:
            if not use_iter_files:
                resp = yield from_client.fs_supervision(
                    attr["pickcode"], 
                    async_=async_, 
                    **request_kwargs, 
                )
                check_response(resp)
                info = resp["data"]
                attr.update(
                    id=int(info["file_id"]), 
                    name=info["file_name"], 
                    sha1=info["file_sha1"], 
                    size=int(info["file_size"]), 
                    is_collect=int(info["is_collect"]), 
                    file_type=int(info["file_type"]), 
                )
                if attr["is_collect"] and attr["size"] >= 1024 * 1024 * 115:
                    return {"type": "skip", "attr": attr, "resp": None}
            resp = yield to_client.upload_file_init(
                filename=attr["name"], 
                filesize=attr["size"], 
                filesha1=attr["sha1"], 
                pid=pid, 
                read_range_bytes_or_hash=read_range_bytes_or_hash, 
                base_url=True, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            if resp.get("statuscode"):
                return {"type": "fail", "attr": attr, "resp": resp}
            else:
                return {"type": "good", "attr": attr, "resp": resp}
        except BaseException as e:
            if isinstance(e, OSError) and len(e.args) == 2 and isinstance(e.args[1], dict):
                return {"type": "fail", "attr": attr, "resp": e.args[1], "exc": e}
            else:
                return {"type": "fail", "attr": attr, "resp": None, "exc": e}
    key_of_id = "id" if with_root else "parent_id"
    @as_gen_step(async_=async_)
    def get_pid(attr: dict, /):
        if use_iter_files:
            if attr["is_collect"] and attr["size"] >= 1024 * 1024 * 115:
                return Return({"type": "skip", "attr": attr, "resp": None})
            if from_cid:
                dir_ = "/".join(a["name"] for a in dropwhile(
                    lambda a: a[key_of_id] != from_cid, 
                    attr["ancestors"][1:-1], 
                ))
            else:
                dir_ = "/".join(a["name"] for a in attr["ancestors"][1:-1])
        else:
            if from_cid:
                dir_ = "/".join(a["name"] for a in dropwhile(
                    lambda a: a[key_of_id] != from_cid, 
                    attr["dir_ancestors"][1:], 
                ))
            else:
                dir_ = attr["dirname"][1:]
        if dir_ in dir_to_cid:
            return dir_to_cid[dir_]
        else:
            resp = yield to_client.fs_makedirs_app(
                dir_, 
                to_pid, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            pid = dir_to_cid[dir_] = resp["cid"]
            return pid
    dir_to_cid = {"": 0}
    if use_iter_files:
        it = iter_files_with_path(
            from_client, 
            from_cid, 
            normalize_attr=normalize_attr_simple, 
            async_=async_, 
            **request_kwargs, 
        )
    else:
        it = iter_download_files(
            from_client, 
            from_cid, 
            async_=async_, 
            **request_kwargs, 
        )
    if async_:
        return taskgroup_map(upload, it, arg_func=get_pid, max_workers=max_workers)
    else:
        return threadpool_map(upload, it, arg_func=get_pid, max_workers=max_workers)


# TODO: 支持一次性把所有文件找完，也支持慢慢处理（可能会风控）
@overload
def iter_115_to_115_resume(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int = 0, 
    to_pid: int = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> Iterator[dict]:
    ...
@overload
def iter_115_to_115_resume(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int = 0, 
    to_pid: int = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> AsyncIterator[dict]:
    ...
def iter_115_to_115_resume(
    from_client: P115Client, 
    to_client: P115Client, 
    from_cid: int = 0, 
    to_pid: int = 0, 
    max_workers: int = 8, 
    with_root: bool = True, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> Iterator[dict] | AsyncIterator[dict]:
    """从 115 传到 115（可以跳过已经存在的文件）

    :param from_client: 来源 115 客户端对象
    :param to_client: 去向 115 客户端对象
    :param from_cid: 来源 115 的目录 id（文件数最好控制在 100 万以内，太多的话，里面多个子文件夹分别传即可）
    :param to_pid: 去向 115 的父目录 id
    :param max_workers: 最大并发数
    :param with_root: 是否保留 `from_cid` 对应的目录名（如果为 False，则会少 1 级目录）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 迭代器，产生转移结果，有 3 种类型："good"、"fail" 和 "skip"
    """
    @as_gen_step(async_=async_)
    def upload(attr: dict, pid: int, /):
        @as_gen_step(async_=async_)
        def read_range_bytes_or_hash(sign_check: str, /):
            if attr["is_collect"]:
                url = yield from_client.download_url(
                    attr["pickcode"], 
                    use_web_api=True, 
                    async_=async_, 
                    **request_kwargs, 
                )
            else:
                url = yield from_client.download_url(
                    attr["pickcode"], 
                    app="android", 
                    async_=async_, 
                    **request_kwargs, 
                )
            return from_client.request(
                url, 
                headers=dict(url["headers"], Range="bytes="+sign_check), 
                parse=False, 
                async_=async_, 
                **request_kwargs, 
            )
        try:
            resp = yield to_client.upload_file_init(
                filename=attr["name"], 
                filesize=attr["size"], 
                filesha1=attr["sha1"], 
                pid=pid, 
                read_range_bytes_or_hash=read_range_bytes_or_hash, 
                base_url=True, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            if resp.get("statuscode"):
                return {"type": "fail", "attr": attr, "resp": resp}
            else:
                return {"type": "good", "attr": attr, "resp": resp}
        except BaseException as e:
            if isinstance(e, OSError) and len(e.args) == 2 and isinstance(e.args[1], dict):
                return {"type": "fail", "attr": attr, "resp": e.args[1], "exc": e}
            else:
                return {"type": "fail", "attr": attr, "resp": None, "exc": e}
    dirt_to_cid: dict[tuple[str, ...], int] = {}
    key_of_id = "id" if with_root else "parent_id"
    @as_gen_step(async_=async_)
    def get_pid(attr: dict, /):
        if attr["is_collect"] and attr["size"] >= 1024 * 1024 * 115:
            return Return({"type": "skip", "attr": attr, "resp": None})
        dirt = tuple(a["name"] for a in dropwhile(
            lambda a: a[key_of_id] != from_cid, 
            attr["ancestors"][1:-1], 
        ))
        try:
            return dirt_to_cid[dirt]
        except KeyError:
            pid = dirt_to_cid[()]
            for i, name in enumerate(dirt, 1):
                p_dirt = dirt[:i]
                if p_dirt in dirt_to_cid:
                    pid = dirt_to_cid[p_dirt]
                else:
                    resp = yield to_client.fs_mkdir(
                        name, 
                        pid, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    check_response(resp)
                    pid = dirt_to_cid[p_dirt] = int(resp["cid"])
            return pid
    def gen_step():
        from_files: Any = iter_files_with_path(
            from_client, 
            from_cid, 
            normalize_attr=normalize_attr_simple, 
            async_=async_, 
            **request_kwargs, 
        )
        if from_cid:
            resp = yield from_client.fs_file_skim(
                from_cid, 
                async_=async_, 
                **request_kwargs, 
            )
            check_response(resp)
            name = unescape_115_charref(resp["data"][0]["file_name"])
            resp = yield to_client.fs_mkdir(
                name, 
                to_pid, 
                async_=async_, 
                **request_kwargs, 
            )
            if resp.get("errno") == 20004:
                if "/" in name:
                    with with_iter_next(iterdir(
                        to_client, 
                        to_pid, 
                        normalize_attr=normalize_attr_simple, 
                        ensure_file=False, 
                        async_=async_, 
                        **request_kwargs, 
                    )) as get_next:
                        while True:
                            attr = yield get_next()
                            if attr["name"] == name:
                                to_cid = attr["id"]
                                break
                else:
                    resp = yield to_client.fs_makedirs_app(
                        name, 
                        to_pid, 
                        async_=async_, 
                        **request_kwargs, 
                    )
                    check_response(resp)
                    to_cid = int(resp["cid"])
                dirt_to_cid[()] = to_cid
                id_to_dirnode: dict[int, tuple[str, int]] = {}
                to_files: Any = iter_files_with_path(
                    to_client, 
                    to_cid, 
                    id_to_dirnode=id_to_dirnode, 
                    normalize_attr=normalize_attr_simple, 
                    async_=async_, 
                    **request_kwargs, 
                )
                if async_:
                    from_files, to_files = yield to_list(
                        taskgroup_map(to_list, (from_files, to_files), max_workers=2))
                else:
                    from_files, to_files = threadpool_map(list, (from_files, to_files), max_workers=2)
                while to_cid:
                    _, to_cid = id_to_dirnode.pop(to_cid)
                cid_to_dirt: dict[int, tuple[str, ...]] = {}
                def get_dirt(cid: int, /) -> tuple[str, ...]:
                    if cid not in id_to_dirnode:
                        return ()
                    name, pid = id_to_dirnode[cid]
                    if pid in cid_to_dirt:
                        p_dirt = cid_to_dirt[pid]
                    else:
                        p_dirt = get_dirt(pid)
                    dirt = (*p_dirt, name)
                    dirt_to_cid[dirt] = cid
                    cid_to_dirt[cid] = dirt
                    return dirt
                for cid, (name, pid) in id_to_dirnode.items():
                    if cid not in cid_to_dirt:
                        get_dirt(cid)
                del cid_to_dirt, id_to_dirnode
                to_cid = dirt_to_cid[()]
                seen = {
                    tuple(a["name"] for a in dropwhile(
                        lambda a: a["parent_id"] != to_cid, 
                        attr["ancestors"][1:], 
                    )) for attr in to_files
                }
                from_files = [
                    attr for attr in from_files
                    if tuple(a["name"] for a in dropwhile(
                        lambda a: a["parent_id"] != from_cid, 
                        attr["ancestors"][1:], 
                    )) not in seen
                ]
                del to_files, seen
            else:
                check_response(resp)
                dirt_to_cid[()] = int(resp["cid"])
        else:
            dirt_to_cid[()] = 0
        if async_:
            return YieldFrom(taskgroup_map(
                upload, 
                from_files, 
                arg_func=get_pid, 
                max_workers=max_workers, 
            ))
        else:
            return YieldFrom(threadpool_map(
                upload, 
                from_files, 
                arg_func=get_pid, 
                max_workers=max_workers, 
            ))
    return run_gen_step_iter(gen_step, may_call=False, async_=async_)

