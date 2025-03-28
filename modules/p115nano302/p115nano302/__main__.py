#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__doc__ = """\
    ╭───────────────────────── \x1b[31mWelcome to \x1b[1m115 nano 302\x1b[0m ────────────────────────────╮
    │                                                                              │
    │  \x1b[1;35mmaintained by\x1b[0m \x1b[3;5;31m❤\x1b[0m     \x1b[32mChenyangGao \x1b[4;34mhttps://chenyanggao.github.io\x1b[0m               │
    │                                                                              │
    │                      \x1b[32mGithub      \x1b[4;34mhttps://github.com/ChenyangGao/p115client/\x1b[0m  │
    │                                                                              │
    │                      \x1b[32mlicense     \x1b[4;34mhttps://www.gnu.org/licenses/gpl-3.0.txt\x1b[0m    │
    │                                                                              │
    │                      \x1b[32mversion     \x1b[1;36m0.1.1\x1b[0m                                       │
    │                                                                              │
    ╰──────────────────────────────────────────────────────────────────────────────╯

> 网盘文件支持用 \x1b[3;36mpickcode\x1b[0m、\x1b[3;36mid\x1b[0m、\x1b[3;36msha1\x1b[0m、\x1b[3;36mname\x1b[0m 或 \x1b[3;36mpath\x1b[0m 查询
> 指定 \x1b[3;36mis_path=1\x1b[0m 或 \x1b[3;36mis_path=true\x1b[0m 即可启用 \x1b[3;36mpath\x1b[0m 查询，会以 \x1b[1m\\\x1b[0m 作为路径分隔符
> 分享文件支持用 \x1b[3;36mid\x1b[0m 或 \x1b[3;36mname\x1b[0m 查询

< 支持参数 \x1b[3;36muser_id\x1b[0m，以指定用户 id，并在实际执行时使用此用户的 cookies 和网盘数据（\x1b[1;31m未指定时，使用所传入的第 1 个 cookies\x1b[0m）
< 支持参数 \x1b[3;36mrefresh\x1b[0m，指定 bool 值，用于搜索名字时忽略缓存（\x1b[1;31m强制刷新\x1b[0m）
< 支持参数 \x1b[3;36mis_path\x1b[0m，指定 bool 值，要求搜索路径而不是名字（\x1b[1;31m仅限你自己的网盘文件，对于分享链接无效\x1b[0m）
< 支持参数 \x1b[3;36mapp\x1b[0m，用于指定从此设备的接口获取下载链接（\x1b[1;31m可以不管\x1b[0m）

⏰ 此版本不依赖于 \x1b[31mp115client\x1b[0m 和 \x1b[31mpycryptodome\x1b[0m，至少要求 \x1b[31mpython \x1b[1m3.12\x1b[0m

🌰 携带 sign

通过命令行参数 -t/--token 指定令牌后，你就必须在请求时携带签名，即 \x1b[3;36msign\x1b[0m 参数
计算方式为

    \x1b[3;34mhashlib\x1b[0m.\x1b[3;31msha1\x1b[0m(\x1b[3;31mbytes\x1b[0m(f\x1b[32m"302@115-{\x1b[1;3;36mtoken\x1b[0m\x1b[32m}-{\x1b[1;3;36mt\x1b[0m\x1b[32m}-{\x1b[1;3;36mvalue\x1b[0m\x1b[32m}"\x1b[0m, \x1b[32m"utf-8"\x1b[0m)).\x1b[3;31mhexdigest\x1b[0m()

其中
- \x1b[3;36mtoken\x1b[0m 就是命令行所传入的令牌
- \x1b[3;36mt\x1b[0m 为过期时间点（默认值为 0，即永不过期）
- \x1b[3;36mvalue\x1b[0m 就是值，像这样的链接，优先级顺序为 \x1b[3;36mpickcode\x1b[0m > \x1b[3;36mid\x1b[0m > \x1b[3;36msha1\x1b[0m > \x1b[3;36mname\x1b[0m > \x1b[3;36mname2\x1b[0m

    \x1b[4;34mhttp://localhost:8000/{\x1b[1;3;36mname2\x1b[0m\x1b[4;34m}?id={\x1b[1;3;36mid\x1b[0m\x1b[4;34m}&name={\x1b[1;3;36mname\x1b[0m\x1b[4;34m}&sha1={\x1b[1;3;36msha1\x1b[0m\x1b[4;34m}&pickcode={\x1b[1;3;36mpickcode\x1b[0m\x1b[4;34m}\x1b[0m

🌰 更新 cookies

通过命令行参数 -p/--password 指定密码后，你就可以一次性更新很多个 cookies，使用接口（请求时需携带和命令行传入的相同的密码）

    \x1b[1mPOST\x1b[0m \x1b[4;34mhttp://localhost:8000/<cookies?password={\x1b[1;3;36mpassword\x1b[0m\x1b[4;34m}\x1b[0m

请求体为 json 数据

    \x1b[3;35m{"cookies": "一行写一个 cookies"}\x1b[0m

如果要查询目前所有的 cookies，使用接口（请求时需携带和命令行传入的相同的密码）

    \x1b[1mGET\x1b[0m \x1b[4;34mhttp://localhost:8000/<cookies?password={\x1b[1;3;36mpassword\x1b[0m\x1b[4;34m}\x1b[0m

🌰 查询示例：

    0. 查询 \x1b[3;36mpickcode\x1b[0m
        \x1b[4;34mhttp://localhost:8000?ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000/ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000?pickcode=ecjq9ichcb40lzlvx\x1b[0m
    1. 带（任意）名字查询 \x1b[3;36mpickcode\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?pickcode=ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000/ecjq9ichcb40lzlvx/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    2. 查询 \x1b[3;36mid\x1b[0m
        \x1b[4;34mhttp://localhost:8000?2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000/2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000?id=2691590992858971545\x1b[0m
    3. 带（任意）名字查询 \x1b[3;36mid\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?id=2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000/2691590992858971545/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    4. 查询 \x1b[3;36msha1\x1b[0m
        \x1b[4;34mhttp://localhost:8000?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
    5. 带（任意）名字查询 \x1b[3;36msha1\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    6. 查询 \x1b[3;36mname\x1b[0m（直接以路径作为 \x1b[3;36mname\x1b[0m，且不要有 \x1b[3;36mpickcode\x1b[0m、\x1b[3;36mid\x1b[0m、\x1b[3;36msha1\x1b[0m 或 \x1b[3;36mname\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
        \x1b[4;34mhttp://localhost:8000?Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
        \x1b[4;34mhttp://localhost:8000?name=Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    7. 查询分享文件（如果是你自己的分享，则无须提供密码 \x1b[3;36mreceive_code\x1b[0m）
        \x1b[4;34mhttp://localhost:8000?share_code=sw68md23w8m&receive_code=q353&id=2580033742990999218\x1b[0m
        \x1b[4;34mhttp://localhost:8000?share_code=sw68md23w8m&id=2580033742990999218\x1b[0m
    8. 带（任意）名字查询分享文件（如果是你自己的分享，则无须提供密码 \x1b[3;36mreceive_code\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353&id=2580033742990999218\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&id=2580033742990999218\x1b[0m
    9. 用 \x1b[3;36mname\x1b[0m 查询分享文件（直接以路径作为 \x1b[3;36mname\x1b[0m，且不要有 \x1b[3;36mid\x1b[0m 查询参数。如果是你自己的分享，则无须提供密码 \x1b[3;36mreceive_code\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m\x1b[0m
        \x1b[4;34mhttp://localhost:8000?name=Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m&receive_code=q353\x1b[0m
        \x1b[4;34mhttp://localhost:8000?name=Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m\x1b[0m
   10. 用 \x1b[3;36mpath\x1b[0m 查询网盘中的文件（限制同第 6 条，但需要指定 \x1b[3;36mis_path\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/a/b/c/movie.mkv?is_path=1\x1b[0m
        \x1b[4;34mhttp://localhost:8000?/a/b/c/movie.mkv&is_path=1\x1b[0m
        \x1b[4;34mhttp://localhost:8000?name=/a/b/c/movie.mkv&is_path=1\x1b[0m

再推荐一个命令行使用，用于执行 HTTP 请求的工具，类似 \x1b[1;3mwget\x1b[0m

    \x1b[4m\x1b[34mhttps://pypi.org/project/httpie/\x1b[0m
"""

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter

parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
parser.add_argument("-c", "--cookies", default="", help="cookies 字符串，优先级高于 -cp/--cookies-path，如果有多个则一行写一个")
parser.add_argument("-cp", "--cookies-path", default="", help="cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt，如果有多个则一行写一个")
parser.add_argument("-p", "--password", default="", help="执行后台信息操作请求所需密码，仅当提供时，才会启用一组后台信息操作接口")
parser.add_argument("-t", "--token", default="", help="签名所用的 token，如果提供，则请求必须携带签名，即 sign 查询参数")
parser.add_argument("-H", "--host", default="0.0.0.0", help="ip 或 hostname，默认值：'0.0.0.0'")
parser.add_argument("-P", "--port", default=8000, type=int, help="端口号，默认值：8000，如果为 0 则自动确定")
parser.add_argument("-cu", "--cache-url", action="store_true", help="缓存下载链接")
parser.add_argument("-d", "--debug", action="store_true", help="启用调试，会输出更详细信息")
parser.add_argument("-uc", "--uvicorn-run-config-path", help="uvicorn 启动时的配置文件路径，会作为关键字参数传给 `uvicorn.run`，支持 JSON、YAML 或 TOML 格式，会根据扩展名确定，不能确定时视为 JSON")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")
parser.add_argument("-l", "--license", action="store_true", help="输出授权信息")


def parse_args(argv: None | list[str] = None, /) -> Namespace:
    args = parser.parse_args(argv)
    if args.version:
        from p115nano302 import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115nano302 import __license__
        print(__license__)
        raise SystemExit(0)
    return args


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parse_args(argv)

    cookies = args.cookies.strip()
    if not cookies:
        cookies_path = args.cookies_path.strip() or "115-cookies.txt"
        cookies = open(cookies_path, encoding="latin-1").read().strip()

    uvicorn_run_config_path = args.uvicorn_run_config_path
    if uvicorn_run_config_path:
        file = open(uvicorn_run_config_path, "rb")
        match suffix := Path(uvicorn_run_config_path).suffix.lower():
            case ".yml" | ".yaml":
                from yaml import load as yaml_load, Loader
                run_config = yaml_load(file, Loader=Loader)
            case ".toml":
                from tomllib import load as toml_load
                run_config = toml_load(file)
            case _:
                from orjson import loads as json_loads
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

    from p115nano302 import make_application
    from uvicorn import run

    print(__doc__)
    app = make_application(
        cookies, 
        debug=args.debug, 
        password=args.password, 
        token=args.token, 
        cache_url=args.cache_url, 
    )
    run(app, **run_config)

if __name__ == "__main__":
    from pathlib import Path
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

