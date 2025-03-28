#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__doc__ = "遍历 115 网盘的目录，仅导出文件信息导出到数据库"

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

parser = ArgumentParser(
    formatter_class=RawTextHelpFormatter, 
    description=__doc__, 
)
parser.add_argument("top_dirs", metavar="dir", nargs="*", help="""\
115 目录，可以传入多个，如果不传默认为 0
允许 3 种类型的目录
    1. 整数，视为目录的 id
    2. 形如 "/名字/名字/..." 的路径，最前面的 "/" 可以省略，本程序会尝试获取对应的 id
    3. 形如 "根目录 > 名字 > 名字 > ..." 的路径，来自点击文件的【显示属性】，在【位置】这部分看到的路径，本程序会尝试获取对应的 id
""")
parser.add_argument("-cp", "--cookies-path", default="", help="cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt")
parser.add_argument("-f", "--dbfile", default="", help="sqlite 数据库文件路径，默认为在当前工作目录下的 f'115-file-{user_id}.db'")
parser.add_argument("-i", "--interval", type=float, default=0, help="两个任务之间的睡眠时间，如果 <= 0，则不睡眠")
parser.add_argument("-m", "--max-workers", type=int, help="拉取分页时的最大并发数，默认会自动确定")
parser.add_argument("-p", "--page-size", type=int, default=7_000, help="每次批量拉取的分页大小，默认值：7,000")
parser.add_argument("-cl", "--check-for-relogin", action="store_true", help="当风控时，自动重新扫码登录")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")
parser.add_argument("-l", "--license", action="store_true", help="输出开源协议")


def parse_args(argv: None | list[str] = None, /) -> Namespace:
    args = parser.parse_args(argv)
    if args.version:
        from p115filedb import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115filedb import __license__
        print(__license__)
        raise SystemExit(0)
    return args


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parse_args(argv)

    from p115client import P115Client
    from p115filedb import updatedb

    if cookies_path := args.cookies_path:
        cookies = Path(cookies_path)
    else:
        cookies = Path("115-cookies.txt")
    client = P115Client(cookies, check_for_relogin=args.check_for_relogin, ensure_cookies=True, app="alipaymini")
    updatedb(
        client, 
        dbfile=args.dbfile, 
        top_dirs=args.top_dirs or 0, 
        page_size=args.page_size, 
        interval=args.interval, 
        max_workers=args.max_workers, 
    )


if __name__ == "__main__":
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

