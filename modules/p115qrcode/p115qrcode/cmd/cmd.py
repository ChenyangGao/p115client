#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["parser", "main"]
__doc__ = "115 网盘扫码登录（命令行版）"

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

if __name__ == "__main__":
    from sys import path

    path[0] = str(Path(__file__).parents[2])
    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
else:
    from .init import subparsers

    parser = subparsers.add_parser("cmd", description=__doc__, formatter_class=RawTextHelpFormatter)


def parse_args(argv: None | list[str] = None, /) -> Namespace:
    args = parser.parse_args(argv)
    if args.version:
        from p115qrcode import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115qrcode import __license__
        print(__license__)
        raise SystemExit(0)
    return args


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parse_args(argv)

    from string import hexdigits
    from typing import cast, TextIO

    from p115qrcode import qrcode_result, qrcode_scan, qrcode_scan_confirm, qrcode_token, scan_qrcode

    app: str = args.app
    cookies: str = args.cookies.strip()
    if not cookies:
        cookies_path = args.cookies_path
        if not cookies_path:
            cookies_path = Path("~/115-cookies.txt").expanduser()
        try:
            cookies = open(cookies_path, "r", encoding="utf-8").read().strip()
        except OSError:
            pass
    resp: None | dict = None
    try:
        if cookies:
            if len(cookies) == 40 and not cookies.strip(hexdigits):
                uid = cookies
            elif all(k in cookies for k in ("UID=", "CID=", "SEID=")):
                uid = qrcode_token()["uid"]
                qrcode_scan(uid, cookies)
                qrcode_scan_confirm(uid, cookies)
            else:
                raise OSError
            resp = qrcode_result(uid, app)
    except OSError:
        pass
    if not resp:
        future = scan_qrcode(app, console_qrcode=not args.open_qrcode, show_message=True)
        uid = future.uid
        resp = cast(dict, future.result())
    cookies = "; ".join(f"{k}={v}" for k, v in resp["cookie"].items())
    cookies += f"; uid={uid}"
    if outfile := args.output_file:
        try:
            file: TextIO = open(outfile, "w", encoding="utf-8")
        except OSError as e:
            print(f"error occured: {e!r}")
            from sys import stdout as file
    else:
        from sys import stdout as file
    print(cookies, file=file)


parser.add_argument(
    "app", nargs="?", default="alipaymini", 
    choices=("web", "ios", "115ios", "android", "115android", "115ipad", "tv", "qandroid", "wechatmini", "alipaymini", "harmony"), 
    help="选择一个 app 进行登录，默认值 'alipaymini'", 
)
parser.add_argument("-o", "--output-file", help="保存到文件，未指定时输出到 stdout")
parser.add_argument("-oq", "--open-qrcode", action="store_true", help="在浏览器中打开二维码，而不是在命令行输出")
parser.add_argument("-c", "--cookies", default="", help="115 登录 cookies 或二维码的 uid，使用后可以自动扫码，优先级高于 -cp/--cookies-path")
parser.add_argument("-cp", "--cookies-path", help="cookies 文件保存路径，使用后可以自动扫码")
parser.add_argument("-l", "--license", action="store_true", help="输出授权信息")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")
parser.set_defaults(func=main)


if __name__ == "__main__":
    main()

