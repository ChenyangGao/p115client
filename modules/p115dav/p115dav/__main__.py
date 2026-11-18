#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
# http://patorjk.com/software/taag/#p=display&f=ANSI%20Shadow&t=p115%20web
__doc__ = """
    🕸️ 115 网盘 WebDAV 和 302 直链程序 🕷️

██████╗  ██╗ ██╗███████╗██████╗  █████╗ ██╗   ██╗
██╔══██╗███║███║██╔════╝██╔══██╗██╔══██╗██║   ██║
██████╔╝╚██║╚██║███████╗██║  ██║███████║██║   ██║
██╔═══╝  ██║ ██║╚════██║██║  ██║██╔══██║╚██╗ ██╔╝
██║      ██║ ██║███████║██████╔╝██║  ██║ ╚████╔╝ 
╚═╝      ╚═╝ ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝  ╚═══╝  

"""

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter
from pathlib import Path

parser = ArgumentParser(
    formatter_class=RawTextHelpFormatter, 
    description=__doc__, 
    epilog="""
---------- 使用说明 ----------

你可以打开浏览器进行直接访问。

1. 如果想要访问某个路径，可以通过查询接口

    GET /{path}
    GET /<share/{path}

或者

    GET ?path={path}

也可以通过 pickcode 查询（对于分享无效）

    GET ?pickcode={pickcode}

也可以通过 id 查询

    GET ?id={id}

也可以通过 sha1 查询（必是文件）（对于分享无效）

    GET ?sha1={sha1}

2. 查询文件或文件夹的信息，返回 json

    GET /<attr
    GET /<share/<attr

3. 查询文件夹内所有文件和文件夹的信息，返回 json

    GET /<list
    GET /<share/<list

4. 获取文件的下载链接

    GET /<url
    GET /<share/<url

5. 说明是否文件（如果不传此参数，则需要额外做一个检测）

💡 是文件

    GET ?file=true

💡 是目录

    GET ?file=false

6. 支持的查询参数

        参数         |  类型   | 必填 | 说明
-------------------- | ------- | ---- | ----------
?pickcode={pickcode} | string  | 否   | 文件或文件夹的 pickcode，优先级高于 id
?id={id}             | integer | 否   | 文件或文件夹的 id，优先级高于 sha1
?sha1={sha1}         | string  | 否   | 文件或文件夹的 id，优先级高于 path
?path={path}         | string  | 否   | 文件或文件夹的路径，优先级高于 url 中的路径部分
/{path}              | string  | 否   | 文件或文件夹的路径，位于 url 中的路径部分

💡 如果是分享 （路由路径以 /<share 开始），则支持的参数会少一些

    参数     | 类型    | 必填 | 说明
------------ | ------- | ---- | ----------
?id={id}     | integer | 否   | 文件或文件夹的 id，优先级高于 sha1
?sha1={sha1} | string  | 否   | 文件或文件夹的 id，优先级高于 path
?path={path} | string  | 否   | 文件或文件夹的路径，优先级高于 url 中的路径部分
/{path}      | string  | 否   | 文件或文件夹的路径，位于 url 中的路径部分

当文件被下载时，可以有其它查询参数

 参数      |  类型   | 必填 | 说明
---------  | ------- | ---- | ----------
image      | boolean | 否   | 文件是图片，可获取 CDN 链接
web        | boolean | 否   | 使用 web 接口获取下载链接（文件由服务器代理转发，不走 302）

7. 支持 webdav

在浏览器或 webdav 挂载软件 中输入

    http://localhost:8000/<dav

默认没有用户名和密码，支持 302

8. 支持分享列表

在浏览器中输入

    http://localhost:8000/<share

在浏览器或 webdav 挂载软件 中输入

    http://localhost:8000/<dav/<share
""")

parser.add_argument("dbfile", nargs="?", default="", help="sqlite 数据库文件路径或 URI，如果不传，则自动创建临时文件")
parser.add_argument("-cp", "--cookies-path", default="", help="""\
cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
如果你需要直接传入一个 cookies 字符串，需要这样写

.. code:: shell

    COOKIES='UID=...; CID=..., SEID=...'
    p115dav --cookies-path <(echo "$COOKIES")

""")
parser.add_argument("-a", "--app-id", type=int, help="开放平台应用的 AppID")
parser.add_argument("-o", "--strm-origin", help="[WEBDAV] origin 或者说 base_url，用来拼接路径，获取完整链接，默认行为是自行确定")
parser.add_argument("-t", "--ttl", default=0, type=float, help="""缓存存活时间
    - 如果等于 0（默认值），则总是更新
    - 如果为 nan、inf 或者小于 0，则永远存活
    - 如果大于 0，则存活这么久时间
""")
parser.add_argument("-p1", "--predicate", help="[WEBDAV] 断言，当断言的结果为 True 时，文件或目录会被显示")
parser.add_argument(
    "-t1", "--predicate-type", default="ignore", 
    choices=("ignore", "ignore-file", "expr", "lambda", "stmt", "module", "file", "re"), 
    help="""[webdav] 断言类型，默认值为 'ignore'
    - ignore       （默认值）gitignore 配置文本（有多个时用空格隔开），在文件路径上执行模式匹配，匹配成功则断言为 False
                   NOTE: https://git-scm.com/docs/gitignore#_pattern_format
    - ignore-file  接受一个文件路径，包含 gitignore 的配置文本（一行一个），在文件路径上执行模式匹配，匹配成功则断言为 False
                   NOTE: https://git-scm.com/docs/gitignore#_pattern_format
    - expr         表达式，会注入一个名为 path 的类 pathlib.Path 对象
    - lambda       lambda 函数，接受一个类 pathlib.Path 对象作为参数
    - stmt         语句，当且仅当不抛出异常，则视为 True，会注入一个名为 path 的类 pathlib.Path 对象
    - module       模块，运行后需要在它的全局命名空间中生成一个 check 或 predicate 函数用于断言，接受一个类 pathlib.Path 对象作为参数
    - file         文件路径，运行后需要在它的全局命名空间中生成一个 check 或 predicate 函数用于断言，接受一个类 pathlib.Path 对象作为参数
    - re           正则表达式，模式匹配，如果文件的名字匹配此模式，则断言为 True
""")
parser.add_argument("-p2", "--strm-predicate", help="[webdav] strm 断言（优先级高于 -p1/--predicate），当断言的结果为 True 时，文件会被显示为带有 .strm 后缀的文本文件，打开后是链接")
parser.add_argument(
    "-t2", "--strm-predicate-type", default="filter", 
    choices=("filter", "filter-file", "expr", "lambda", "stmt", "module", "file", "re"), 
    help="""[webdav] 断言类型，默认值为 'filter'
    - filter       （默认值）gitignore 配置文本（有多个时用空格隔开），在文件路径上执行模式匹配，匹配成功则断言为 True
                   请参考：https://git-scm.com/docs/gitignore#_pattern_format
    - filter-file  接受一个文件路径，包含 gitignore 的配置文本（一行一个），在文件路径上执行模式匹配，匹配成功则断言为 True
                   请参考：https://git-scm.com/docs/gitignore#_pattern_format
    - expr         表达式，会注入一个名为 path 的类 pathlib.Path 对象
    - lambda       lambda 函数，接受一个类 pathlib.Path 对象作为参数
    - stmt         语句，当且仅当不抛出异常，则视为 True，会注入一个名为 path 的类 pathlib.Path 对象
    - module       模块，运行后需要在它的全局命名空间中生成一个 check 或 predicate 函数用于断言，接受一个类 pathlib.Path 对象作为参数
    - file         文件路径，运行后需要在它的全局命名空间中生成一个 check 或 predicate 函数用于断言，接受一个类 pathlib.Path 对象作为参数
    - re           正则表达式，模式匹配，如果文件的名字匹配此模式，则断言为 True
""")
parser.add_argument("-fs", "--fast-strm", action="store_true", help="""快速实现 媒体筛选 和 虚拟 strm，此命令优先级较高，相当于命令行指定

    --strm-predicate-type expr \\
    --strm-predicate '(
        path["type"] in (3, 4) or
        path.media_type.startswith(("video/", "audio/")) and
        path.suffix.lower() != ".ass" or
        path.suffix.lower() in (".divx", ".iso", ".m2ts", ".swf", ".xvid")
    )' \\
    --predicate-type expr \\
    --predicate '(
        path.is_dir() or
        path.media_type.startswith("image/") or
        path.suffix.lower() in (".nfo", ".ass", ".ssa", ".srt", ".idx", ".sub", ".txt", ".vtt", ".smi")
    )'

""")
parser.add_argument("-H", "--host", default="", help="ip 或 hostname，默认值：'0.0.0.0'")
parser.add_argument("-P", "--port", default=8000, type=int, help="端口号，默认值：8000，如果为 0 则自动确定")
parser.add_argument("-cu", "--cache-url", action="store_true", help="缓存下载链接")
parser.add_argument("-d", "--debug", action="store_true", help="启用 debug 模式，输出详细的错误信息")
parser.add_argument("-ow", "--only-webdav", action="store_true", help="禁用网页版，只有 webdav 可用")
parser.add_argument("-uc", "--uvicorn-run-config-path", help="uvicorn 启动时的配置文件路径，会作为关键字参数传给 `uvicorn.run`，支持 JSON、YAML 或 TOML 格式，会根据扩展名确定，不能确定时视为 JSON")
parser.add_argument("-wc", "--wsgidav-config-path", help="""WsgiDAV 启动时的配置文件路径，支持 JSON、YAML 或 TOML 格式，会根据扩展名确定，不能确定时视为 JSON
如需样板文件，请阅读：

    https://wsgidav.readthedocs.io/en/latest/user_guide_configure.html#sample-wsgidav-yaml

""")
parser.add_argument("-wu", "--wsgidav-username-password", nargs="*", help="可传入多组用户名和密码，格式为 username:password，中间用逗号分隔，如果不传则无或者任意用户名和密码都可通过")
parser.add_argument("-l", "--license", action="store_true", help="输出授权信息")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")


def parse_args(argv: None | list[str] = None, /) -> Namespace:
    args = parser.parse_args(argv)
    if args.version:
        from p115dav import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115dav import __license__
        print(__license__)
        raise SystemExit(0)
    return args


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parse_args(argv)

    import uvicorn

    from orjson import loads as json_loads
    from tomllib import load as toml_load
    from p115dav import make_application
    from path_predicate import make_predicate
    from yaml import load as yaml_load, Loader

    if args.fast_strm:
        predicate = make_predicate("""(
    path.is_dir() or
    path.media_type.startswith("image/") or
    path.suffix.lower() in (".nfo", ".ass", ".ssa", ".srt", ".idx", ".sub", ".txt", ".vtt", ".smi")
)""", type="expr")
    elif predicate := args.predicate or None:
        predicate = make_predicate(predicate, {"re": __import__("re")}, type=args.predicate_type)
    if args.fast_strm:
        strm_predicate = make_predicate("""(
    path["type"] in (3, 4) or
    path.media_type.startswith(("video/", "audio/")) and
    path.suffix.lower() != ".ass" or
    path.suffix.lower() in (".divx", ".iso", ".m2ts", ".swf", ".xvid")
)""", type="expr")
    elif strm_predicate := args.strm_predicate or None:
        strm_predicate = make_predicate(strm_predicate, {"re": __import__("re")}, type=args.strm_predicate_type)

    if wsgidav_config_path := args.wsgidav_config_path:
        file = open(wsgidav_config_path, "rb")
        match suffix := Path(wsgidav_config_path).suffix.lower():
            case ".yml" | ".yaml":
                wsgidav_config = yaml_load(file, Loader=Loader)
            case ".toml":
                wsgidav_config = toml_load(file)
            case _:
                wsgidav_config = json_loads(file.read())
    else:
        wsgidav_config = {}
    if list_username_password := args.wsgidav_username_password:
        if user_mapping := {
            "user_mapping": {
                "*": {
                    user: {"password": pswd}
                    for user, _, pswd in (
                        user_pswd.partition(":") for user_pswd in list_username_password
                    ) if user
                }
            }
        }:
            wsgidav_config["simple_dc"] = user_mapping

    uvicorn_run_config_path = args.uvicorn_run_config_path
    if uvicorn_run_config_path:
        file = open(uvicorn_run_config_path, "rb")
        match suffix := Path(uvicorn_run_config_path).suffix.lower():
            case ".yml" | ".yaml":
                run_config = yaml_load(file, Loader=Loader)
            case ".toml":
                run_config = toml_load(file)
            case _:
                run_config = json_loads(file.read())
    else:
        run_config = {}

    if args.host:
        run_config["host"] = args.host
    else:
        run_config.setdefault("host", "0.0.0.0")
    if args.port:
        run_config["port"] = args.port
    elif not run_config.get("port"):
        from socket import create_connection

        def get_available_ip(start: int = 1024, stop: int = 65536) -> int:
            for port in range(start, stop):
                try:
                    with create_connection(("127.0.0.1", port), timeout=1):
                        pass
                except OSError:
                    return port
            raise RuntimeError("no available ports")

        run_config["port"] = get_available_ip()

    run_config.setdefault("proxy_headers", True)
    run_config.setdefault("server_header", False)
    run_config.setdefault("forwarded_allow_ips", "*")
    run_config.setdefault("timeout_graceful_shutdown", 1)
    run_config.setdefault("access_log", False)

    app = make_application(
        dbfile=args.dbfile, 
        cookies_path=args.cookies_path, 
        ttl=args.ttl, 
        strm_origin=args.strm_origin, 
        predicate=predicate, 
        strm_predicate=strm_predicate, 
        app_id=args.app_id, 
        cache_url=args.cache_url, 
        debug=args.debug, 
        wsgidav_config=wsgidav_config, 
        only_webdav=args.only_webdav, 
    )
    uvicorn.run(app, **run_config)


if __name__ == "__main__":
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

