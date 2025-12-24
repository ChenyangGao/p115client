#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter

parser = ArgumentParser(description="115 图床", formatter_class=RawTextHelpFormatter)
parser.add_argument("files", nargs="*", metavar="file", help="图片路径")
parser.add_argument("-c", "--cookies", default="", help="cookies 字符串，优先级高于 -cp/--cookies-path")
parser.add_argument("-cp", "--cookies-path", default="", help="cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")
parser.add_argument("-l", "--license", action="store_true", help="输出授权信息")


def parse_args(argv: None | list[str] = None, /) -> Namespace:
    args = parser.parse_args(argv)
    if not args.files:
        parser.parse_args(["-h"])
    elif args.version:
        from p115imghost import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115imghost import __license__
        print(__license__)
        raise SystemExit(0)
    return args


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parse_args(argv)

    from p115client.tool import upload_host_image

    if not (cookies := args.cookies.strip()):
        from pathlib import Path
        cookies = Path(args.cookies_path or "115-cookies.txt")

    for file in args.files:
        print(upload_host_image(cookies, file))


if __name__ == "__main__":
    from pathlib import Path
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

