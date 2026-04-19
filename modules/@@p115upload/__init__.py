#!/usr/bin/env python3
# coding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 1)
__all__ = ["main"]

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from os import fspath, remove, removedirs, scandir, PathLike
from os.path import dirname, normpath
from pathlib import Path
from textwrap import indent
from threading import Lock
from traceback import format_exc
from typing import cast, ContextManager, NamedTuple, TypedDict

from concurrenttools import thread_batch
from hashtools import file_digest
from http_response import get_status_code
from p115client import P115Client, check_response
from p115client.tool import get_attr, get_path, get_id_to_path, iterdir
from posixpatht import normpath as pnormpath, split as psplit, path_is_dir_form
from rich.progress import (
    Progress, DownloadColumn, FileSizeColumn, MofNCompleteColumn, SpinnerColumn, 
    TimeElapsedColumn, TransferSpeedColumn, 
)
from texttools import rotate_text


@dataclass
class Task:
    src_attr: Mapping
    dst_pid: int
    dst_attr: None | str | Mapping = None
    times: int = 0
    reasons: list[BaseException] = field(default_factory=list)


class Tasks(TypedDict):
    success: dict[str, Task]
    failed: dict[str, Task]
    unfinished: dict[str, Task]


class Result(NamedTuple):
    stats: dict
    tasks: Tasks


# TODO: 写一个函数，支持多线程和协程，会有各种的统计信息
# TODO: 写一个函数，支持在命令行展示进度
# TODO: 写一个函数，支持在网页中展示进度
def main(
    client: str | PathLike | P115Client = Path("~/115-cookies.txt").expanduser(), 
    src_path: str = ".", 
    dst_path: int | str = 0, 
    part_size: int = 10485760, 
    max_workers: None | int = 1, 
    max_retries: int = 1, 
    resume: bool = False, 
    remove_done: bool = False, 
    with_root: bool = False, 
) -> Result:
    if max_workers <= 0:
        max_workers = None
    count_lock: None | ContextManager = None
    if max_workers > 1:
        count_lock = Lock()

    @contextmanager
    def ensure_cm(cm):
        if isinstance(cm, ContextManager):
            with cm as val:
                yield val
        else:
            yield cm

    stats: dict = {
        # 开始时间
        "start_time": datetime.now(), 
        # 总耗时
        "elapsed": "", 
        # 源路径
        "src_path": "",  
        # 目标路径
        "dst_path": "", 
        # 任务总数
        "tasks": {"total": 0, "files": 0, "dirs": 0, "size": 0}, 
        # 成功任务数
        "success": {"total": 0, "files": 0, "dirs": 0, "size": 0}, 
        # 失败任务数（发生错误但已抛弃）
        "failed": {"total": 0, "files": 0, "dirs": 0, "size": 0}, 
        # 重试任务数（发生错误但可重试），一个任务可以重试多次
        "retry": {"total": 0, "files": 0, "dirs": 0}, 
        # 未完成任务数：未运行、重试中或运行中
        "unfinished": {"total": 0, "files": 0, "dirs": 0, "size": 0}, 
        # 各种错误数量和分类汇总
        "errors": {"total": 0, "files": 0, "dirs": 0, "reasons": {}}, 
        # 是否执行完成：如果是 False，说明是被人为终止
        "is_completed": False, 
    }
    # 任务总数
    tasks: dict[str, int] = stats["tasks"]
    # 成功任务数
    success: dict[str, int] = stats["success"]
    # 失败任务数（发生错误但已抛弃）
    failed: dict[str, int] = stats["failed"]
    # 重试任务数（发生错误但可重试），一个任务可以重试多次
    retry: dict[str, int] = stats["retry"]
    # 未完成任务数：未运行、重试中或运行中
    unfinished: dict[str, int] = stats["unfinished"]
    # 各种错误数量和分类汇总
    errors: dict = stats["errors"]
    # 各种错误的分类汇总
    reasons: dict[str, int] = errors["reasons"]
    # 开始时间
    start_time = stats["start_time"]

    def get_path_attr(path) -> dict:
        if isinstance(path, str):
            path = Path(path)
        attr = {
            "path": fspath(path), 
            "name": path.name, 
            "is_dir": path.is_dir(), 
        }
        attr.update(zip(("mode", "inode", "dev", "nlink", "uid", "gid", "size", "atime", "mtime", "ctime"), path.stat()))
        return attr

    def update_tasks(total=1, files=0, size=0):
        dirs = total - files
        with ensure_cm(count_lock):
            tasks["total"] += total
            unfinished["total"] += total
            if dirs:
                tasks["dirs"] += dirs
                unfinished["dirs"] += dirs
            if files:
                tasks["files"] += files
                tasks["size"] += size
                unfinished["files"] += files
                unfinished["size"] += size

    def update_success(total=1, files=0, size=0):
        dirs = total - files
        with ensure_cm(count_lock):
            success["total"] += total
            unfinished["total"] -= total
            if dirs:
                success["dirs"] += dirs
                unfinished["dirs"] -= dirs
            if files:
                success["files"] += files
                success["size"] += size
                unfinished["files"] -= files
                unfinished["size"] -= size

    def update_failed(total=1, files=0, size=0):
        dirs = total - files
        with ensure_cm(count_lock):
            failed["total"] += total
            unfinished["total"] -= total
            if dirs:
                failed["dirs"] += dirs
                unfinished["dirs"] -= dirs
            if files:
                failed["files"] += files
                failed["size"] += size
                unfinished["files"] -= files
                unfinished["size"] -= size

    def update_retry(total=1, files=0):
        dirs = total - files
        with ensure_cm(count_lock):
            retry["total"] += total
            if dirs:
                retry["dirs"] += dirs
            if files:
                retry["files"] += files

    def update_errors(e, is_dir=False):
        exctype = type(e).__module__ + "." + type(e).__qualname__
        with ensure_cm(count_lock):
            errors["total"] += 1
            if is_dir:
                errors["dirs"] += 1
            else:
                errors["files"] += 1
            try:
                reasons[exctype] += 1
            except KeyError:
                reasons[exctype] = 1

    def hash_report(attr):
        update_desc = rotate_text(attr["name"], 22, interval=0.1).__next__
        task = progress.add_task("[bold blink red on yellow]DIGESTING[/bold blink red on yellow] " + update_desc(), total=attr["size"])
        def hash_progress(step):
            progress.update(task, description="[bold blink red on yellow]DIGESTING[/bold blink red on yellow] " + update_desc(), advance=step)
            progress.update(statistics_bar, description=get_stat_str())
        try:
            return file_digest(
                open(attr["path"], "rb"), 
                "sha1", 
                callback=hash_progress, 
            )
        finally:
            progress.remove_task(task)

    def add_report(_, attr):
        update_desc = rotate_text(attr["name"], 32, interval=0.1).__next__
        task = progress.add_task(update_desc(), total=attr["size"])
        try:
            while not closed:
                step = yield
                progress.update(task, description=update_desc(), advance=step)
                progress.update(statistics_bar, description=get_stat_str(), advance=step, total=tasks["size"])
        finally:
            progress.remove_task(task)

    def work(task: Task, submit):
        src_attr, dst_pid, dst_attr = task.src_attr, task.dst_pid, task.dst_attr
        src_path = src_attr["path"]
        if dst_attr is None:
            name: None | str = None
        elif isinstance(dst_attr, str):
            name = dst_attr
        else:
            name = cast(str, dst_attr["name"])
        try:
            task.times += 1
            if src_attr["is_dir"]:
                if not name:
                    dst_id = dst_pid
                else:
                    if isinstance(dst_attr, str):
                        name = dst_attr
                        resp = check_response(client.fs_makedirs_app(name, dst_pid))
                        dst_id = int(resp["cid"])
                        task.dst_attr = {"id": dst_id, "parent_id": dst_pid, "name": name, "is_dir": True}
                        console_print(f"[bold green][GOOD][/bold green] 📂 创建目录: [blue underline]{src_path!r}[/blue underline] ➜ [blue underline]{name!r}[/blue underline] in {dst_pid}")
                    else:
                        dst_id = cast(Mapping, dst_attr)["id"]
                # TODO: 这个接口调用过快，会 405，需要优化
                subdattrs = {
                    (attr["name"], attr["is_dir"]): attr 
                    for attr in iterdir(client, dst_id)
                }
                subattrs = [
                    a for a in map(get_path_attr, scandir(src_path))
                    if a["name"] not in (".DS_Store", "Thumbs.db") and not a["name"].startswith("._")
                ]
                update_tasks(
                    total=len(subattrs), 
                    files=sum(not a["is_dir"] for a in subattrs), 
                    size=sum(a["size"] for a in subattrs if not a["is_dir"]), 
                )
                progress.update(statistics_bar, description=get_stat_str(), total=tasks["size"])
                pending_to_remove: list[int] = []
                for subattr in subattrs:
                    subname = subattr["name"]
                    subpath = subattr["path"]
                    is_dir = subattr["is_dir"]
                    key = subname, is_dir
                    if key in subdattrs:
                        subdattr = subdattrs[key]
                        subdpath = subdattr["path"]
                        if is_dir:
                            console_print(f"[bold yellow][SKIP][/bold yellow] 📂 目录已建: [blue underline]{subpath!r}[/blue underline] ➜ [blue underline]{subdpath!r}[/blue underline]")
                            subtask = Task(subattr, dst_id, subdattr)
                        elif resume and subattr["size"] == subdattr["size"] and subattr["mtime"] <= subdattr["ctime"]:
                            console_print(f"[bold yellow][SKIP][/bold yellow] 📝 跳过文件: [blue underline]{subpath!r}[/blue underline] ➜ [blue underline]{subdpath!r}[/blue underline]")
                            update_success(1, 1, subattr["size"])
                            progress.update(statistics_bar, description=get_stat_str())
                            continue
                        else:
                            subtask = Task(subattr, dst_id, subname)
                            pending_to_remove.append(subdattr["id"])
                    else:
                        subtask = Task(subattr, dst_id, subname)
                    unfinished_tasks[subpath] = subtask
                    submit(subtask)
                if not subattrs and remove_done:
                    try:
                        removedirs(src_path)
                    except OSError:
                        pass
                if pending_to_remove:
                    for i in range(0, len(pending_to_remove), 1_000):
                        part_ids = pending_to_remove[i:i+1_000]
                        try:
                            resp = check_response(client.fs_delete_app(part_ids))
                            console_print(f"""\
[bold green][DELETE][/bold green] 📝 删除文件列表
    ├ ids({len(part_ids)}) = {part_ids}
    ├ response = {resp}""")
                        except BaseException as e:
                            console_print(f"""[bold yellow][SKIP][/bold yellow] 📝 删除文件列表失败
    ├ ids({len(part_ids)}) = {part_ids}
    ├ reason = [red]{type(e).__module__}.{type(e).__qualname__}[/red]: {e}""")
                update_success(1)
            else:
                if not name:
                    name = src_attr["name"]

                filesize, filehash = hash_report(src_attr)
                console_print(f"[bold green][HASH][/bold green] 🧠 计算哈希: sha1([blue underline]{src_path!r}[/blue underline]) = {filehash.hexdigest()!r}")
                kwargs: dict = {
                    "filename": name, 
                    "filesha1": filehash.hexdigest(), 
                    "filesize": filesize, 
                    "pid": dst_pid, 
                    "partsize": part_size, 
                }
                # TODO: 这里应该可以多次重试
                #data = upload_init(client, src_path)
                resp = client.upload_file(
                    src_path, 
                    make_reporthook=partial(add_report, attr=src_attr), 
                    **kwargs, 
                )
                check_response(resp)
                if resp.get("status") == 2 and resp.get("statuscode") == 0:
                    prompt = "秒传文件"
                else:
                    prompt = "上传文件"
                console_print(f"""\
[bold green][GOOD][/bold green] 📝 {prompt}: [blue underline]{src_path!r}[/blue underline] ➜ [blue underline]{name!r}[/blue underline] in {dst_pid}
    ├ response = {resp}""")
                update_success(1, 1, src_attr["size"])
                if remove_done:
                    try:
                        remove(src_path)
                    except OSError:
                        pass
                    try:
                        removedirs(dirname(src_path))
                    except OSError:
                        pass
            progress.update(statistics_bar, description=get_stat_str())
            success_tasks[src_path] = unfinished_tasks.pop(src_path)
        except BaseException as e:
            task.reasons.append(e)
            update_errors(e, src_attr["is_dir"])
            if max_retries < 0:
                status_code = get_status_code(e)
                if status_code:
                    retryable = status_code >= 500
                else:
                    # TODO: 需要更具体
                    retryable = False
            else:
                retryable = task.times <= max_retries
            if retryable:
                console_print(f"""\
[bold red][FAIL][/bold red] ♻️ 发生错误（将重试）: [blue underline]{src_path!r}[/blue underline] ➜ [blue underline]{name!r}[/blue underline] in {dst_pid}
    ├ [red]{type(e).__module__}.{type(e).__qualname__}[/red]: {e}""")
                update_retry(1, not src_attr["is_dir"])
                submit(task)
            else:
                console_print(f"""\
[bold red][FAIL][/bold red] 💀 发生错误（将抛弃）: [blue underline]{src_path!r}[/blue underline] ➜ [blue underline]{name!r}[/blue underline] in {dst_pid}
{indent(format_exc().strip(), "    ├ ")}""")
                progress.update(statistics_bar, description=get_stat_str())
                update_failed(1, not src_attr["is_dir"], src_attr.get("size"))
                failed_tasks[src_path] = unfinished_tasks.pop(src_path)
                if len(task.reasons) == 1:
                    raise
                else:
                    raise BaseExceptionGroup("max retries exceed", task.reasons)
    src_attr = get_path_attr(normpath(src_path))
    dst_attr: None | dict = None
    name: str = src_attr["name"]
    is_dir = src_attr["is_dir"]
    with Progress(
        SpinnerColumn(), 
        *Progress.get_default_columns(), 
        TimeElapsedColumn(), 
        MofNCompleteColumn(), 
        DownloadColumn(), 
        FileSizeColumn(), 
        TransferSpeedColumn(), 
    ) as progress:
        console_print = lambda msg: progress.console.print(f"[bold][[cyan]{datetime.now()}[/cyan]][/bold]", msg)
        if isinstance(dst_path, str):
            if dst_path == "0" or pnormpath(dst_path) in ("", "/"):
                dst_pid = 0
                dst_path = "/" + name
            elif not dst_path.startswith("0") and dst_path.isascii() and dst_path.isdecimal():
                dst_pid = int(dst_path)
            elif is_dir:
                resp = check_response(client.fs_makedirs_app(dst_path, 0))
                dst_pid = int(resp["cid"])
            elif with_root or path_is_dir_form(dst_path):
                resp = check_response(client.fs_makedirs_app(dst_path, 0))
                dst_pid = int(resp["cid"])
                dst_path = get_path(dst_pid) + "/" + name
            else:
                dst_path = pnormpath("/" + dst_path)
                dst_dir, dst_name = psplit(dst_path)
                try:
                    from p115client.type import P115ID
                    dst_pid = get_id_to_path(client, dst_path)
                    if isinstance(dst_pid, P115ID):
                        dst_attr = dst_pid.__dict__
                    else:
                        dst_attr = get_attr(client, dst_pid, skim=True)
                        dst_attr["is_dir"] = True
                except FileNotFoundError:
                    resp = check_response(client.fs_makedirs_app(dst_dir, 0))
                    dst_pid = int(resp["cid"])
                    name = dst_name
                else:
                    if dst_attr["is_dir"]:
                        dst_pid = dst_attr["id"]
                        dst_path += "/" + name
                    else:
                        dst_pid = dst_attr["parent_id"]
                        name = dst_name
        else:
            dst_pid = dst_path
        if is_dir:
            if with_root and name:
                resp = check_response(client.fs_makedirs_app(name, dst_pid))
                dst_pid = int(resp["cid"])
            elif not dst_attr:
                dst_attr = get_attr(client, dst_pid)
                if not dst_attr["is_dir"]:
                    raise NotADirectoryError(20, dst_path)
            dst_path = get_path(client, dst_pid)
        elif dst_pid and not dst_attr:
            dst_attr = get_attr(client, dst_pid)
            if dst_attr["is_dir"]:
                dst_path = get_path(client, dst_attr["id"]) + "/" + name
            else:
                dst_pid = dst_attr["parent_id"]
                dst_path = get_path(client, dst_attr["id"])
        task = Task(src_attr, dst_pid, None if is_dir else name)
        unfinished_tasks: dict[str, Task] = {src_attr["path"]: task}
        success_tasks: dict[str, Task] = {}
        failed_tasks: dict[str, Task] = {}
        all_tasks: Tasks = {
            "success": success_tasks, 
            "failed": failed_tasks, 
            "unfinished": unfinished_tasks, 
        }
        stats["src_path"] = src_attr["path"]
        stats["dst_path"] = dst_path
        update_tasks(1, not src_attr["is_dir"], src_attr.get("size"))
        get_stat_str = lambda: f"📊 [cyan bold]statistics[/cyan bold] 🧮 {tasks['total']} = 💯 {success['total']} + ⛔ {failed['total']} + ⏳ {unfinished['total']}"
        statistics_bar = progress.add_task(get_stat_str(), total=tasks["size"])
        closed = False
        try:
            thread_batch(work, unfinished_tasks.values(), max_workers=max_workers)
            stats["is_completed"] = True
        finally:
            closed = True
            progress.remove_task(statistics_bar)
            stats["elapsed"] = str(datetime.now() - start_time)
            console_print(f"📊 [cyan bold]statistics:[/cyan bold] {stats}")
    return Result(stats, all_tasks)


# TODO: 实现网页版进度窗口
# TODO: statistics 行要有更详细的信息，如果一行不够，就再加一行
# TODO: 以后要支持断点续传，可用 分块上传 和 本地保存进度
# TODO: 支持在上传的时候，改变文件的名字，特别是改变了扩展名

# 1. 通过名字和大小来唯一确定文件
# 2. 对于非法符号的某种特别处理（可能导致两个文件夹合并）
# 3. 对于文件的上传有分步的处理机制
# 4. 什么时候该重试、跳过或停止
# 5. 有某个临时的任务文件，可以保留上传尚未处理的文件
# 6. 可以通过某种机制跳过一些文件
# 7. 支持多线程或异步，使用尽量少的内存
# 8. 允许从迭代器中获取文件列表

# # TODO: 是否要保留 drive 记号
# from iterdir import iterdir
# from os import sep
# from posixpath import relpath

# if sep == "/":
#     normpath = lambda path, /: path
# else:
#     from os import path as ospath
#     def normpath(path: str, /) -> str:
#         if ospath.isabs(path):
#             _, path = ospath.splitdrive(path)
#         return path.replace(sep, "/")

# for entry in iterdir("Multimedia"):
#     "判断是否要保留"
#     if entry.is_dir():
#         "创建目录"
#     else:
#         "创建文件"

# 本地路径
# 远程路径

# get_path(client, 3327397098554392215, ensure_file=False)

# try:
#     get_id_to_path(client, '/Multimedia')
# except FileNotFoundError:

# stat = entry.stat()
# stat.st_mtime
# stat.st_size
# entry.name # 文件名
# entry.path # 减掉 common_path，得到相对路径

# 对于要上传的文件
# 1. 确定远程有没有这个文件（通过更新时间对比）
# 2. 如果远程的文件更旧，那就把远程文件删除，上传此文件
# 3. 计算 sha1 和 size
# 4. 尝试秒传
# 5. 秒传失败，则进行分块上传
# 6. 上传成功

# from p115client import *
# from p115client.tool import *
# upload_init(client, file, pid, filename, filesha1, filesize)

# TODO: 对于超过 115 GB 的文件直接跳过，错误提示是文件太大
# TODO: 如果文件大于特定大小，就不能秒传，需要直接报错（而不需要进行尝试）1. 非vip是5G，2.vip是115G
