#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
# NOTE: https://patorjk.com/software/taag/#p=display&f=Electronic&t=p115fuse
__doc__ = """
    🕸️ Python 115 FUSE mount 🕷️

 ▄▄▄▄▄▄▄▄▄▄▄    ▄▄▄▄         ▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌ ▄█░░░░▌      ▄█░░░░▌    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀█░▌▐░░▌▐░░▌     ▐░░▌▐░░▌    ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌       ▐░▌ ▀▀ ▐░░▌      ▀▀ ▐░░▌    ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌          ▐░▌       ▐░▌▐░▌          ▐░▌          
▐░█▄▄▄▄▄▄▄█░▌    ▐░░▌         ▐░░▌    ▐░░░░░░░░░░░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌    ▐░░▌         ▐░░▌     ▀▀▀▀▀▀▀▀▀█░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀     ▐░░▌         ▐░░▌              ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌ ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌              ▐░░▌         ▐░░▌              ▐░▌▐░▌          ▐░▌       ▐░▌          ▐░▌▐░▌          
▐░▌          ▄▄▄▄█░░█▄▄▄  ▄▄▄▄█░░█▄▄▄  ▄▄▄▄▄▄▄▄▄█░▌▐░▌          ▐░█▄▄▄▄▄▄▄█░▌ ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ 
▐░▌         ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌          ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
 ▀           ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀            ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 

"""

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

parser = ArgumentParser(formatter_class=RawTextHelpFormatter, description=__doc__)
parser.add_argument("mountpoint", nargs="?", help="挂载路径")
parser.add_argument("-cp", "--cookies-path", help="""\
cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
如果你需要直接传入一个 cookies 字符串，需要这样写

.. code:: shell

    COOKIES='UID=...; CID=..., SEID=...'
    p115dav --cookies-path <(echo "$COOKIES")

""")
parser.add_argument(
    "-fo", "--fuse-option", dest="fuse_options", metavar="option", nargs="+", 
    help="""fuse 挂载选项，支持如下几种格式：
    - name         设置 name 选项
    - name=        取消 name 选项
    - name=value   设置 name 选项，值为 value
参考资料：
    - https://man7.org/linux/man-pages/man8/mount.fuse3.8.html
    - https://code.google.com/archive/p/macfuse/wikis/OPTIONS.wiki
""")
parser.add_argument("-ll", "--log-level", default="ERROR", help=f"指定日志级别，可以是数字或名称，不传此参数则不输出日志，默认值: 'ERROR'")
parser.add_argument("-l", "--license", action="store_true", help="输出授权信息")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")


def parse_args(argv: None | list[str] = None, /) -> Namespace:
    args = parser.parse_args(argv)
    if args.version:
        from p115fuse import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115fuse import __license__
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
    from p115fuse import P115FuseOperations, logger

    if log_level := args.log_level:
        if log_level.isascii() and log_level.isdecimal():
            log_level = int(log_level)
        else:
            log_level = getattr(logging, log_level.upper(), 0)
        if log_level:
            logger.setLevel(log_level)

    options = {
        "mountpoint": args.mountpoint, 
        "foreground": True, 
        "max_readahead": 0, 
        "noauto_cache": True, 
    }
    if fuse_options := args.fuse_options:
        for option in fuse_options:
            if "=" in option:
                name, value = option.split("=", 1)
                if value:
                    options[name] = value
                else:
                    options.pop(name, None)
            else:
                options[option] = True
    P115FuseOperations(P115Client(Path(args.cookies_path or "115-cookies.txt"))).run_forever(**options)


if __name__ == "__main__":
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

