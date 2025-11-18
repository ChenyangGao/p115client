#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__doc__ = "遍历 115 网盘的目录，并把信息导出到数据库"

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
parser.add_argument("-f", "--dbfile", default="", help="sqlite 数据库文件路径，默认为在当前工作目录下的 f'115-{user_id}.db'")
parser.add_argument("-i", "--interval", type=float, default=0.5, help="两个批处理任务至少需要间隔的时间（以启动前那一刻作为计算依据），默认值: 0.5")
parser.add_argument("-st", "--auto-splitting-threshold", type=int, default=300_000, help="自动拆分的文件数阈值，大于此值时，自动进行拆分，如果 = 0，则总是拆分，如果 < 0，则总是不拆分，默认值 300,000（30 万）")
parser.add_argument("-sst", "--auto-splitting-statistics-timeout", type=float, default=5.0, help="自动拆分前的执行文件数统计的超时时间（秒），大于此值时，视为文件数无穷大，如果 <= 0，视为永不超时，默认值 5.0")
parser.add_argument("-nm", "--no-dir-moved", action="store_true", help="声明没有目录被移动或改名（但可以有目录被新增或删除），这可以加快批量拉取时的速度")
parser.add_argument("-r", "--refresh", action="store_true", help="是否强制刷新")
parser.add_argument("-nr", "--not-recursive", action="store_true", help="不遍历目录树：只拉取顶层目录，不递归子目录")
parser.add_argument("-de", "--disable-event", action="store_true", help="关闭 event 表的数据收集")
parser.add_argument("-cl", "--check-for-relogin", action="store_true", help="当风控时，自动重新扫码登录")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")
parser.add_argument("-l", "--license", action="store_true", help="输出开源协议")


def parse_args(argv: None | list[str] = None, /) -> Namespace:
    args = parser.parse_args(argv)
    if args.version:
        from p115updatedb import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115updatedb import __license__
        print(__license__)
        raise SystemExit(0)
    return args


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parse_args(argv)

    from p115client import P115Client
    from p115updatedb import updatedb

    if cookies_path := args.cookies_path:
        cookies = Path(cookies_path)
    else:
        cookies = Path("115-cookies.txt")
    client = P115Client(cookies, check_for_relogin=args.check_for_relogin, ensure_cookies=True, app="alipaymini")
    updatedb(
        client, 
        dbfile=args.dbfile, 
        top_dirs=args.top_dirs or 0, 
        auto_splitting_threshold=args.auto_splitting_threshold, 
        auto_splitting_statistics_timeout=args.auto_splitting_statistics_timeout, 
        no_dir_moved=args.no_dir_moved, 
        refresh=args.refresh, 
        recursive=not args.not_recursive, 
        interval=args.interval, 
        disable_event=args.disable_event, 
    )


if __name__ == "__main__":
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

