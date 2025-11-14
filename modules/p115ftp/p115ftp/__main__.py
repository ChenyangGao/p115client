#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
# NOTE: https://patorjk.com/software/taag/#p=display&f=Univers&t=p115ftp
__doc__ = """
    🕸️ Python 115 FTP Server 🕷️

             88      88  8888888888      ad88                        
           ,d88    ,d88  88             d8"      ,d                  
         888888  888888  88  ____       88       88                  
8b,dPPYba,   88      88  88a8PPPP8b,  MM88MMM  MM88MMM  8b,dPPYba,   
88P'    "8a  88      88  PP"     `8b    88       88     88P'    "8a  
88       d8  88      88           d8    88       88     88       d8  
88b,   ,a8"  88      88  Y8a     a8P    88       88,    88b,   ,a8"  
88`YbbdP"'   88      88   "Y88888P"     88       "Y888  88`YbbdP"'   
88                                                      88           
88                                                      88           

"""

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

parser = ArgumentParser(formatter_class=RawTextHelpFormatter, description=__doc__)
parser.add_argument("-H", "--host", help="ip 或 hostname，默认值：'0.0.0.0'")
parser.add_argument("-P", "--port", type=int, help="端口号，默认值：7115")
parser.add_argument("-cp", "--cookies-path", help="""\
cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
如果你需要直接传入一个 cookies 字符串，需要这样写

.. code:: shell

    COOKIES='UID=...; CID=..., SEID=...'
    p115dav --cookies-path <(echo "$COOKIES")

""")
parser.add_argument("-cl", "--check-for-relogin", action="store_true", help="当风控时，自动重新扫码登录")
parser.add_argument("-ut", "--use-thumbs", action="store_true", help="为请求图片链接提供缩略图 CDN 链接")
parser.add_argument("-ll", "--log-level", default="ERROR", help=f"指定日志级别，可以是数字或名称，不传此参数则不输出日志，默认值: 'ERROR'")
parser.add_argument("-l", "--license", action="store_true", help="输出授权信息")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")


def parse_args(argv: None | list[str] = None, /) -> Namespace:
    args = parser.parse_args(argv)
    if args.version:
        from p115ftp import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115ftp import __license__
        print(__license__)
        raise SystemExit(0)
    return args


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parse_args(argv)

    import logging

    from p115client import P115Client
    from p115ftp import P115FS, logger

    if log_level := args.log_level:
        if log_level.isascii() and log_level.isdecimal():
            log_level = int(log_level)
        else:
            log_level = getattr(logging, log_level.upper(), 0)
        if log_level:
            logger.setLevel(log_level)

    host = args.host or "0.0.0.0"
    port = args.port or 7115
    cookies_path = Path(args.cookies_path or "115-cookies.txt")
    client = P115Client(cookies_path, check_for_relogin=args.check_for_relogin)
    P115FS.run_forever(client, host, port, use_thumbs=args.use_thumbs)


if __name__ == "__main__":
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

