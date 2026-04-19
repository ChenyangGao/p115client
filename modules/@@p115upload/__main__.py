#!/usr/bin/env python3
# coding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__doc__ = "115 网盘批量上传"

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

if __name__ == "__main__":
    from sys import path

    path[0] = str(Path(__file__).parents[2])
    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import NamedTuple, TypedDict


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


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parser.parse_args(argv)

    import errno

    from collections.abc import Callable
    from contextlib import contextmanager
    from datetime import datetime
    from functools import partial
    from os import fspath, remove, removedirs, scandir, stat
    from os.path import dirname, normpath
    from textwrap import indent
    from threading import Lock
    from traceback import format_exc
    from typing import cast, ContextManager
    from urllib.error import URLError

    from concurrenttools import thread_batch
    from hashtools import file_digest
    from http_response import get_status_code
    from p115client import P115Client, check_response
    from p115client.tool import upload_init
    from posixpatht import normpath as pnormpath, split as psplit, path_is_dir_form
    from rich.progress import (
        Progress, DownloadColumn, FileSizeColumn, MofNCompleteColumn, SpinnerColumn, 
        TimeElapsedColumn, TransferSpeedColumn, 
    )
    from texttools import rotate_text

    if not (cookies := args.cookies):
        if cookies_path := args.cookies_path:
            cookies = Path(cookies_path)
        else:
            cookies = Path("115-cookies.txt")
    client = P115Client(cookies, check_for_relogin=True, ensure_cookies=True, app="qandroid")

    src_path = args.src_path
    dst_path = args.dst_path
    part_size = args.part_size
    max_workers = args.max_workers
    max_retries = args.max_retries
    resume = args.resume
    remove_done = args.remove_done
    with_root = args.with_root

    if max_workers <= 0:
        max_workers = 1
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
            "is_directory": path.is_dir(), 
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

    def update_errors(e, is_directory=False):
        exctype = type(e).__module__ + "." + type(e).__qualname__
        with ensure_cm(count_lock):
            errors["total"] += 1
            if is_directory:
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
            if src_attr["is_directory"]:
                subdattrs: None | dict = None
                if not name:
                    dst_id = dst_pid
                else:
                    try:
                        if isinstance(dst_attr, str):
                            resp = check_response(client.fs_mkdir_app(name, dst_pid))
                            name = cast(str, resp["file_name"])
                            dst_id = int(resp["file_id"])
                            task.dst_attr = {"id": dst_id, "parent_id": dst_pid, "name": name, "is_directory": True}
                            subdattrs = {}
                            console_print(f"[bold green][GOOD][/bold green] 📂 创建目录: [blue underline]{src_path!r}[/blue underline] ➜ [blue underline]{name!r}[/blue underline] in {dst_pid}")
                        else:
                            dst_id = cast(Mapping, dst_attr)["id"]
                    except FileExistsError:
                        dst_attr = task.dst_attr = fs.attr([name], pid=dst_pid, ensure_dir=True)
                        dst_id = dst_attr["id"]
                if subdattrs is None:
                    subdattrs = {
                        (attr["name"], attr["is_directory"]): attr 
                        for attr in fs.listdir_attr(dst_id)
                    }
                subattrs = [
                    a for a in map(get_path_attr, scandir(src_path))
                    if a["name"] not in (".DS_Store", "Thumbs.db") and not a["name"].startswith("._")
                ]
                update_tasks(
                    total=len(subattrs), 
                    files=sum(not a["is_directory"] for a in subattrs), 
                    size=sum(a["size"] for a in subattrs if not a["is_directory"]), 
                )
                progress.update(statistics_bar, description=get_stat_str(), total=tasks["size"])
                pending_to_remove: list[int] = []
                for subattr in subattrs:
                    subname = subattr["name"]
                    subpath = subattr["path"]
                    is_directory = subattr["is_directory"]
                    key = subname, is_directory
                    if key in subdattrs:
                        subdattr = subdattrs[key]
                        subdpath = subdattr["path"]
                        if is_directory:
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
                            resp = fs.fs_delete(part_ids)
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
                for i in range(5):
                    data = upload_init(client, src_path)
                    if i:
                        console_print(f"""\
[bold yellow][RETRY][/bold yellow] 📝 重试上传: [blue underline]{src_path!r}[/blue underline] ➜ [blue underline]{name!r}[/blue underline] in {dst_pid}
    ├ ticket = {ticket}""")
                    try:
                        resp = client.upload_file(
                            src_path, 
                            name, 
                            pid=dst_pid, 
                            make_reporthook=partial(add_report, attr=src_attr), 
                            **kwargs, 
                        )
                        break
                    except MultipartUploadAbort as e:
                        exc = e
                        ticket = kwargs["multipart_resume_data"] = e.ticket
                else:
                    raise exc
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
            update_errors(e, src_attr["is_directory"])
            if max_retries < 0:
                status_code = get_status_code(e)
                if status_code:
                    retryable = status_code >= 500
                else:
                    retryable = isinstance(e, (RequestError, URLError, TimeoutError))
            else:
                retryable = task.times <= max_retries
            if retryable:
                console_print(f"""\
[bold red][FAIL][/bold red] ♻️ 发生错误（将重试）: [blue underline]{src_path!r}[/blue underline] ➜ [blue underline]{name!r}[/blue underline] in {dst_pid}
    ├ [red]{type(e).__module__}.{type(e).__qualname__}[/red]: {e}""")
                update_retry(1, not src_attr["is_directory"])
                submit(task)
            else:
                console_print(f"""\
[bold red][FAIL][/bold red] 💀 发生错误（将抛弃）: [blue underline]{src_path!r}[/blue underline] ➜ [blue underline]{name!r}[/blue underline] in {dst_pid}
{indent(format_exc().strip(), "    ├ ")}""")
                progress.update(statistics_bar, description=get_stat_str())
                update_failed(1, not src_attr["is_directory"], src_attr.get("size"))
                failed_tasks[src_path] = unfinished_tasks.pop(src_path)
                if len(task.reasons) == 1:
                    raise
                else:
                    raise BaseExceptionGroup("max retries exceed", task.reasons)
    src_attr = get_path_attr(normpath(src_path))
    dst_attr: None | dict = None
    name: str = src_attr["name"]
    is_directory = src_attr["is_directory"]
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
            elif is_directory:
                dst_attr = fs.makedirs(dst_path, pid=0, exist_ok=True)
                dst_pid = dst_attr["id"]
            elif with_root or path_is_dir_form(dst_path):
                dst_attr = fs.makedirs(dst_path, pid=0, exist_ok=True)
                dst_pid = dst_attr["id"]
                dst_path = dst_attr["path"] + "/" + name
            else:
                dst_path = pnormpath("/" + dst_path)
                dst_dir, dst_name = psplit(dst_path)
                try:
                    dst_attr = fs.attr(dst_path)
                except FileNotFoundError:
                    dst_attr = fs.makedirs(dst_dir, pid=0, exist_ok=True)
                    dst_pid = dst_attr["id"]
                    name = dst_name
                else:
                    if dst_attr["is_directory"]:
                        dst_pid = dst_attr["id"]
                        dst_path += "/" + name
                    else:
                        dst_pid = dst_attr["parent_id"]
                        name = dst_name
        else:
            dst_pid = dst_path
        if is_directory:
            if with_root and name:
                dst_attr = fs.makedirs(name, pid=dst_pid, exist_ok=True)
                dst_pid = dst_attr["id"]
            elif not dst_attr:
                dst_attr = fs.attr(dst_pid)
                if not dst_attr["is_directory"]:
                    raise NotADirectoryError(errno.ENOTDIR, dst_path)
            dst_path = dst_attr["path"]
        elif dst_pid and not dst_attr:
            dst_attr = fs.attr(dst_pid)
            if dst_attr["is_directory"]:
                dst_path = dst_attr["path"] + "/" + name
            else:
                dst_pid = dst_attr["parent_id"]
                dst_path = dst_attr["path"]
        task = Task(src_attr, dst_pid, None if is_directory else name)
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
        update_tasks(1, not src_attr["is_directory"], src_attr.get("size"))
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


parser.epilog = """\
-------------------------

🛣️ 路径解析说明：
如果指定的网盘路径以斜杠 "/" 结尾，则视为目录

目录的合并上传，是指把本地目录不包括自身上传到网盘目录中，属于自己的一级目录，就会是属于网盘目录的一级目录。而普通的上传，是指在网盘目录下，创建一个和本地目录同名的目录，然后把本地目录合并上传到这个目录中

如果本地路径是一个文件
    1. 如果 with_root 为 False（默认）
        - 如果网盘路径不存在，则上传文件到此路径
        - 如果网盘路径或 id 是一个文件，则上传到此文件相同路径下
        - 如果网盘路径或 id 是一个目录，则上传到此文件到此目录下
    2. 如果 with_root 为 True，或者网盘路径以斜杠 "/" 结尾
        - 如果网盘路径不存在，则上传文件到此目录下
        - 如果网盘路径或 id 是一个文件，则上传到此文件相同路径下
        - 如果网盘路径或 id 是一个目录，则上传到此文件到此目录下
如果本地路径是一个目录
    1. 如果 with_root 为 False（默认）
        - 如果网盘路径不存在，则把本地目录合并上传到此目录下
        - 如果网盘路径或 id 是一个文件，则报错 NotADirectoryError
        - 如果网盘路径或 id 是一个目录，则把本地目录合并上传到此目录下
    2. 如果 with_root 为 True
        - 如果网盘路径不存在，则把本地目录上传到此目录下
        - 如果网盘路径或 id 是一个文件，则报错 NotADirectoryError
        - 如果网盘路径或 id 是一个目录，则把本地目录上传到此目录下
"""
parser.add_argument("-c", "--cookies", help="115 登录 cookies，优先级高于 -cp/--cookies-path")
parser.add_argument("-cp", "--cookies-path", help="cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt")
parser.add_argument("-p", "--src-path", default=".", help="本地的路径，默认是当前工作目录")
parser.add_argument("-t", "--dst-path", default="/", help="""115 网盘中的文件或目录的 id 或路径，默认值："/"
如果想要把本地文件上传到网盘目录中，且指定了路径而不是 id，则最好在路径尾部加一个斜杠 "/" """)
parser.add_argument("-ps", "--part-size", default=1024*1024*100, type=int, help="分块上传时的分块大小，单位是 Byte，默认为 104857600，即 100 MB")

parser.add_argument("-m", "--max-workers", default=1, type=int, help="并发线程数，默认值 1")
parser.add_argument("-mr", "--max-retries", default=-1, type=int, 
                    help="""最大重试次数。
    - 如果小于 0（默认），则会对一些超时、网络请求错误进行无限重试，其它错误进行抛出
    - 如果等于 0，则发生错误就抛出
    - 如果大于 0（实际执行 1+n 次，第一次不叫重试），则对所有错误等类齐观，只要次数到达此数值就抛出""")
parser.add_argument("-wr", "--with-root", action="store_true", help="上传时，把 -t/--dst-path 视为要上传到的父目录，而不是默认为根目录")
parser.add_argument("-r", "--resume", action="store_true", help="断点续传")
parser.add_argument("-rm", "--remove-done", action="store_true", help="上传成功后，删除本地文件")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")
parser.set_defaults(func=main)


if __name__ == "__main__":
    main()




# # TODO: statistics 行要有更详细的信息，如果一行不够，就再加一行
# # TODO: 以后要支持断点续传，可用 分块上传 和 本地保存进度
# # TODO: 支持在上传的时候，改变文件的名字，特别是改变了扩展名
# # TODO: 如果文件大于特定大小，就不能秒传，需要直接报错（而不需要进行尝试）
# # TODO: 支持把一个目录上传到另一个目录（如果扩展名没改，就直接复制，然后改名，否则就秒传）
# # TODO: 支持直接从一个115网盘直接上传到另一个115网盘


# # TODO: 实现一个 115 网盘的上传器、转存器和下载器
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

# 确定要上传的目标目录（目录 id 或路径）


# from p115client import *
# from p115client.tool import *

# client = P115Client.from_path()

# upload_init(client, file, pid, filename, filesha1, filesize)

# # TODO: 超过 115 GB 的直接跳过

