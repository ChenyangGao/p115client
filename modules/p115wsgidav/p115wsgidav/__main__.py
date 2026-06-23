#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
# NOTE: https://patorjk.com/software/taag/#p=display&f=ANSI+Shadow&t=p115webdav
__doc__ = """
    🕸️ Python 115 WsgiDAV 🕷️

██████╗  ██╗ ██╗███████╗██╗    ██╗███████╗██████╗ ██████╗  █████╗ ██╗   ██╗
██╔══██╗███║███║██╔════╝██║    ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██║   ██║
██████╔╝╚██║╚██║███████╗██║ █╗ ██║█████╗  ██████╔╝██║  ██║███████║██║   ██║
██╔═══╝  ██║ ██║╚════██║██║███╗██║██╔══╝  ██╔══██╗██║  ██║██╔══██║╚██╗ ██╔╝
██║      ██║ ██║███████║╚███╔███╔╝███████╗██████╔╝██████╔╝██║  ██║ ╚████╔╝ 
╚═╝      ╚═╝ ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  

"""

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

parser = ArgumentParser(formatter_class=RawTextHelpFormatter, description=__doc__)
parser.add_argument("-H", "--host", help="ip 或 hostname，默认值：'0.0.0.0'")
parser.add_argument("-P", "--port", type=int, help="端口号，默认值：8115")
parser.add_argument("-cp", "--cookies-path", help="""\
cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
如果你需要直接传入一个 cookies 字符串，需要这样写

.. code:: shell

    COOKIES='UID=...; CID=..., SEID=...'
    p115dav --cookies-path <(echo "$COOKIES")

""")
parser.add_argument("-nt", "--no-thumbs", action="store_true", help="不要为请求图片链接提供缩略图")
parser.add_argument("-o", "--origin-302", help="设置 302 请求转发。如果为空，则由此模块提供；特别的，如果缺省此参数，则视为缓存链接；如果为空字符串 ''，则不缓存")
parser.add_argument("-wc", "--wsgidav-config-path", help="""WsgiDAV 启动时的配置文件路径，支持 JSON、YAML 或 TOML 格式，会根据扩展名确定，不能确定时视为 JSON
如需样板文件，请阅读：

    https://wsgidav.readthedocs.io/en/latest/user_guide_configure.html#sample-wsgidav-yaml

""")
parser.add_argument("-l", "--license", action="store_true", help="输出授权信息")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")


def parse_args(argv: None | list[str] = None, /) -> Namespace:
    args = parser.parse_args(argv)
    if args.version:
        from p115wsgidav import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115wsgidav import __license__
        print(__license__)
        raise SystemExit(0)
    return args


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parse_args(argv)

    from p115client import P115Client
    from p115wsgidav import P115FileSystemProvider

    wsgidav_config_path = args.wsgidav_config_path
    if wsgidav_config_path:
        file = open(wsgidav_config_path, "rb")
        match Path(wsgidav_config_path).suffix.lower():
            case ".yml" | ".yaml":
                from yaml import load as yaml_load, Loader
                run_config = yaml_load(file, Loader=Loader)
            case ".toml":
                from tomllib import load as toml_load
                run_config = toml_load(file)
            case _:
                from json import load
                run_config = load(file)
    else:
        run_config = {}
    if host := args.host:
        run_config["host"] = host
    else:
        run_config.setdefault("host", "0.0.0.0")
    if port := args.port:
        run_config["port"] = port
    else:
        run_config.setdefault(port, 8115)
    cookies_path = Path(args.cookies_path or "115-cookies.txt")
    origin_302 = args.origin_302
    if not origin_302:
        origin_302 = origin_302 is None
    provider = P115FileSystemProvider(
        P115Client(cookies_path), 
        origin_302=origin_302, 
        use_thumbs=not args.no_thumbs, 
    )
    provider.run_forever(run_config)


if __name__ == "__main__":
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

