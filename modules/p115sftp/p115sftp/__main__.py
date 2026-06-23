#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
# NOTE: https://patorjk.com/software/taag/#p=display&f=Sweet&t=p115sftp
__doc__ = r"""    🕸️ Python 115 SFTP Server 🕷️

                                                .-.      ___                
                                               /    \   (   )               
   .-..    .--.   .--.  ,-----.       .--.     | .`. ;   | |_        .-..   
  /    \  (_  |  (_  |  |   ___)    /  _  \    | |(___) (   __)     /    \  
 ' .-,  ;   | |    | |  |  |       . .' `. ;   | |_      | |       ' .-,  ; 
 | |  . |   | |    | |  |  '-.     | '   | |  (   __)    | | ___   | |  . | 
 | |  | |   | |    | |  '---.  .   _\_`.(___)  | |       | |(   )  | |  | | 
 | |  | |   | |    | |   ___ `  \ (   ). '.    | |       | | | |   | |  | | 
 | |  ' |   | |    | |  (   ) | |  | |  `\ |   | |       | ' | |   | |  ' | 
 | `-'  '   | |    | |   ; `-'  /  ; '._,' '   | |       ' `-' ;   | `-'  ' 
 | \__.'   (___)  (___)   '.__.'    '.___.'   (___)       `.__.    | \__.'  
 | |                                                               | |      
(___)                                                             (___)     
"""

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

parser = ArgumentParser(formatter_class=RawTextHelpFormatter, description=__doc__)
parser.add_argument("-H", "--host", default="0.0.0.0", help="ip 或 hostname，默认值：'0.0.0.0'")
parser.add_argument("-P", "--port", type=int, default=6115, help="端口号，默认值：6115")
parser.add_argument("-cp", "--cookies-path", help="""\
cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
如果你需要直接传入一个 cookies 字符串，需要这样写

.. code:: shell

    COOKIES='UID=...; CID=..., SEID=...'
    p115dav --cookies-path <(echo "$COOKIES")

""")
parser.add_argument("-ll", "--log-level", default="INFO", help=f"指定日志级别，可以是数字或名称，不传此参数则不输出日志，默认值: 'INFO'")
parser.add_argument("-k", "--key-file", help="服务器私钥文件，如果不提供则随机生成")
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
    from p115sftp import logger, P115RequestHandler

    if log_level := args.log_level:
        if log_level.isascii() and log_level.isdecimal():
            log_level = int(log_level)
        else:
            log_level = getattr(logging, log_level.upper(), 0)
        if log_level:
            logger.setLevel(log_level)

    logging.basicConfig(level=log_level)
    if server_key := args.key_file:
        from paramiko import RSAKey
        server_key = RSAKey.from_private_key_file(server_key)

    cookies_path = Path(args.cookies_path or "115-cookies.txt")
    client = P115Client(cookies_path)
    P115RequestHandler.serve_forever(
        host=args.host, 
        port=args.port, 
        client=client, 
        server_key=server_key, 
    )


if __name__ == "__main__":
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

