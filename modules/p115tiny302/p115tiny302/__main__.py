#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__doc__ = """\
    ╭───────────────────────── \x1b[31mWelcome to \x1b[1m115 tiny 302\x1b[0m ────────────────────────────╮
    │                                                                              │
    │  \x1b[1;35mmaintained by\x1b[0m \x1b[3;5;31m❤\x1b[0m     \x1b[32mChenyangGao \x1b[4;34mhttps://chenyanggao.github.io\x1b[0m               │
    │                                                                              │
    │                      \x1b[32mGithub      \x1b[4;34mhttps://github.com/ChenyangGao/p115client/\x1b[0m  │
    │                                                                              │
    │                      \x1b[32mlicense     \x1b[4;34mhttps://www.gnu.org/licenses/gpl-3.0.txt\x1b[0m    │
    │                                                                              │
    │                      \x1b[32mversion     \x1b[1;36m0.2.1\x1b[0m                                       │
    │                                                                              │
    ╰──────────────────────────────────────────────────────────────────────────────╯

> 网盘文件支持用 \x1b[3;36mid\x1b[0m、\x1b[3;36mpickcode\x1b[0m、\x1b[3;36msha1\x1b[0m、\x1b[3;36mname\x1b[0m 或 \x1b[3;36mpath\x1b[0m 查询（\x1b[1;3;31m此顺序即优先级从高到低\x1b[0m）
> 分享文件支持用 \x1b[3;36mid\x1b[0m、\x1b[3;36mname\x1b[0m 或 \x1b[3;36mpath\x1b[0m 查询（\x1b[1;3;31m此顺序即优先级从高到低\x1b[0m）
> 支持参数 \x1b[3;36mrefresh\x1b[0m，用于搜索 \x1b[3;36msha1\x1b[0m、\x1b[3;36mname\x1b[0m 或 \x1b[3;36mpath\x1b[0m 时忽略缓存（\x1b[1;3;31m强制刷新\x1b[0m）
> 支持参数 \x1b[3;36msize\x1b[0m，用于搜索 \x1b[3;36msha1\x1b[0m 或 \x1b[3;36mname\x1b[0m 时，要求文件大小等于此值
> 支持参数 \x1b[3;36mapp\x1b[0m，用于指定从此设备的接口获取下载链接

🌰 携带 sign

通过命令行参数 -t/--token 指定令牌后，你就必须在请求时携带签名，即 \x1b[3;36msign\x1b[0m 参数
计算方式为

    \x1b[3;34mhashlib\x1b[0m.\x1b[3;31msha1\x1b[0m(\x1b[3;31mbytes\x1b[0m(f\x1b[32m"302@115-{\x1b[1;3;36mtoken\x1b[0m\x1b[32m}-{\x1b[1;3;36mt\x1b[0m\x1b[32m}-{\x1b[1;3;36mvalue\x1b[0m\x1b[32m}"\x1b[0m, \x1b[32m"utf-8"\x1b[0m)).\x1b[3;31mhexdigest\x1b[0m()

其中：

    1. \x1b[3;36mtoken\x1b[0m 就是命令行所传入的令牌
    2. \x1b[3;36mt\x1b[0m 为过期时间点（\x1b[1;3;31m默认值为 0，即永不过期\x1b[0m）
    3. \x1b[3;36mvalue\x1b[0m 就是值，像这样的链接，优先级顺序为 \x1b[3;36mid\x1b[0m > \x1b[3;36mpickcode\x1b[0m > \x1b[3;36msha1\x1b[0m > \x1b[3;36mname\x1b[0m > \x1b[3;36mpath\x1b[0m > \x1b[3;36mname2\x1b[0m

        \x1b[4;34mhttp://localhost:8000/{\x1b[1;3;36mname2\x1b[0m\x1b[4;34m}?id={\x1b[1;3;36mid\x1b[0m\x1b[4;34m}&pickcode={\x1b[1;3;36mpickcode\x1b[0m\x1b[4;34m}&sha1={\x1b[1;3;36msha1\x1b[0m\x1b[4;34m}&name={\x1b[1;3;36mname\x1b[0m\x1b[4;34m}&path={\x1b[1;3;36mpath\x1b[0m\x1b[4;34m}\x1b[0m

    4. 但如果你传入了查询参数 \x1b[3;36mvalue\x1b[0m，且不是空字符串，那么就强制用这个值来计算签名，优先级高于上一条规则

🌰 查询示例：

    1. 查询 \x1b[3;36mid\x1b[0m
        \x1b[4;34mhttp://localhost:8000?2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000/2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000?id=2691590992858971545\x1b[0m
    2. 带（任意）名字查询 \x1b[3;36mid\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?id=2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000/2691590992858971545/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    3. 查询 \x1b[3;36mpickcode\x1b[0m
        \x1b[4;34mhttp://localhost:8000?ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000/ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000?pickcode=ecjq9ichcb40lzlvx\x1b[0m
    4. 带（任意）名字查询 \x1b[3;36mpickcode\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?pickcode=ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000/ecjq9ichcb40lzlvx/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    5. 查询 \x1b[3;36msha1\x1b[0m
        \x1b[4;34mhttp://localhost:8000?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
    6. 带（任意）名字查询 \x1b[3;36msha1\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    7. 查询 \x1b[3;36mname\x1b[0m（如果直接以路径作为 \x1b[3;36mname\x1b[0m，则不要有 \x1b[3;36mpickcode\x1b[0m、\x1b[3;36mid\x1b[0m、\x1b[3;36msha1\x1b[0m、\x1b[3;36mname\x1b[0m 或 \x1b[3;36mpath\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
        \x1b[4;34mhttp://localhost:8000?Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
        \x1b[4;34mhttp://localhost:8000?name=Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    8. 查询 \x1b[3;36mpath\x1b[0m（如果直接以路径作为 \x1b[3;36mpath\x1b[0m，则不要有 \x1b[3;36mpickcode\x1b[0m、\x1b[3;36mid\x1b[0m、\x1b[3;36msha1\x1b[0m、\x1b[3;36mname\x1b[0m 或 \x1b[3;36mpath\x1b[0m，在根目录下要以 \x1b[1m>\x1b[0m 或 \x1b[1m/\x1b[0m 开头，如果整个路径中不含 \x1b[1m>\x1b[0m 或 \x1b[1m/\x1b[0m，则会视为 \x1b[3;36mname\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/电影/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
        \x1b[4;34mhttp://localhost:8000//电影/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
        \x1b[4;34mhttp://localhost:8000?/电影/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
        \x1b[4;34mhttp://localhost:8000?path=/电影/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    9. 查询分享文件（必须有 \x1b[3;36mshare_code\x1b[0m，如果是你自己的分享，则可省略 \x1b[3;36mreceive_code\x1b[0m）
        \x1b[4;34mhttp://localhost:8000?share_code=sw68md23w8m&receive_code=q353&id=2580033742990999218\x1b[0m
        \x1b[4;34mhttp://localhost:8000?share_code=sw68md23w8m&id=2580033742990999218\x1b[0m
    10. 带（任意）名字查询分享文件（必须有 \x1b[3;36mshare_code\x1b[0m，如果是你自己的分享，则可省略 \x1b[3;36mreceive_code\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353&id=2580033742990999218\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&id=2580033742990999218\x1b[0m
    11. 用 \x1b[3;36mname\x1b[0m 查询分享文件（直接以路径作为 \x1b[3;36mname\x1b[0m，且不要有 \x1b[3;36mid\x1b[0m 查询参数。必须有 \x1b[3;36mshare_code\x1b[0m，如果是你自己的分享，则可省略 \x1b[3;36mreceive_code\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m\x1b[0m
        \x1b[4;34mhttp://localhost:8000?name=Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m&receive_code=q353\x1b[0m
        \x1b[4;34mhttp://localhost:8000?name=Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m\x1b[0m
    12. 用 \x1b[3;36mpath\x1b[0m 查询分享文件（直接以路径作为 \x1b[3;36mpath\x1b[0m，且不要有 \x1b[3;36mid\x1b[0m 查询参数，在根目录下要以 \x1b[1m>\x1b[0m 或 \x1b[1m/\x1b[0m 开头，如果整个路径中不含 \x1b[1m>\x1b[0m 或 \x1b[1m/\x1b[0m，则会视为 \x1b[3;36mname\x1b[0m。必须有 \x1b[3;36mshare_code\x1b[0m，如果是你自己的分享，则可省略 \x1b[3;36mreceive_code\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/盗火纪录片/06286 [国家地理] 宇宙时空之旅：未知世界 ／ Cosmos Possible Worlds/Cosmos.Possible.Worlds.S01.1080p.AMZN.WEBRip.DDP5.1.x264-iKA[rartv]/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353\x1b[0m
        \x1b[4;34mhttp://localhost:8000/盗火纪录片/06286 [国家地理] 宇宙时空之旅：未知世界 ／ Cosmos Possible Worlds/Cosmos.Possible.Worlds.S01.1080p.AMZN.WEBRip.DDP5.1.x264-iKA[rartv]/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m\x1b[0m
        \x1b[4;34mhttp://localhost:8000?path=/盗火纪录片/06286 [国家地理] 宇宙时空之旅：未知世界 ／ Cosmos Possible Worlds/Cosmos.Possible.Worlds.S01.1080p.AMZN.WEBRip.DDP5.1.x264-iKA[rartv]/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m&receive_code=q353\x1b[0m
        \x1b[4;34mhttp://localhost:8000?path=/盗火纪录片/06286 [国家地理] 宇宙时空之旅：未知世界 ／ Cosmos Possible Worlds/Cosmos.Possible.Worlds.S01.1080p.AMZN.WEBRip.DDP5.1.x264-iKA[rartv]/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m\x1b[0m

🌰 视频相关操作：

当你提供 \x1b[3;36mmethod\x1b[0m 参数时，通常就意味着你需要操作的目标是视频，此参数的值分别如下：

    1. \x1b[1m"subs"\x1b[0m、\x1b[1m"subtitle"\x1b[0m 或 \x1b[1m"subtitles"\x1b[0m，获取目标文件的内嵌字幕和与它同一目录下的字幕，返回这些字幕的信息和下载链接，结果是一个 JSON
    2. \x1b[1m"tran"\x1b[0m 或 \x1b[1m"transcode"\x1b[0m，获取目标文件的转码信息和在线播放地址，结果是一个 JSON
    3. \x1b[1m"m3u8"\x1b[0m，获取在线播放地址，会执行 302 重定向，另外接受参数：
        1. \x1b[3;36maudio_track\x1b[0m，接受 1 个整数，以切换不同音轨，这个数字是数组下标（从 \x1b[1;36m0\x1b[0m 开始），请先查询 \x1b[1m"tran"\x1b[0m 或 \x1b[1m"transcode"\x1b[0m 方法，然后看 key 为 \x1b[1m"multitrack_list"\x1b[0m 的数组
        2. \x1b[3;36mdefinition\x1b[0m，接受 1 个整数，以切换不同画质：\x1b[1;36m1\x1b[0m:标清 \x1b[1;36m2\x1b[0m:高清 \x1b[1;36m3\x1b[0m:超清 \x1b[1;36m4\x1b[0m:1080P \x1b[1;36m5\x1b[0m:4k \x1b[1;36m100\x1b[0m:原画
    4. \x1b[1m"hist"\x1b[0m 或 \x1b[1m"history"\x1b[0m，获取或设置视频播放进度。当你没有 \x1b[3;36mtime\x1b[0m 和 \x1b[3;36mwatch_end\x1b[0m 查询参数时，会获取视频播放进度，否则会进行设置。结果是一个 JSON
        - \x1b[3;36mtime\x1b[0m，接受 1 个整数，视频播放进度时长，单位是：秒
        - \x1b[3;36mwatch_end\x1b[0m，接受 \x1b[1;36m0\x1b[0m 或者 \x1b[1;36m1\x1b[0m，视频是否播放播放完毕，默认为 \x1b[1;36m0\x1b[0m，\x1b[1;36m1\x1b[0m 表示播放完毕
    5. \x1b[1m"info"\x1b[0m，获取文件信息，结果是一个 JSON
"""

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter

parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
parser.add_argument("-c", "--cookies", default="", help="cookies 字符串，优先级高于 -cp/--cookies-path")
parser.add_argument("-cp", "--cookies-path", default="", help="cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt")
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
        from p115tiny302 import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115tiny302 import __license__
        print(__license__)
        raise SystemExit(0)
    return args


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parse_args(argv)

    from p115client import P115Client

    if cookies := args.cookies.strip():
        client = P115Client(cookies, check_for_relogin=True)
    else:
        from pathlib import Path
        client = P115Client(Path(args.cookies_path or "115-cookies.txt"), check_for_relogin=True)

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

    from p115tiny302.app import make_application
    from uvicorn import run

    print(__doc__)
    app = make_application(
        client, 
        debug=args.debug, 
        token=args.token, 
        cache_url=args.cache_url, 
    )
    run(app, **run_config)


if __name__ == "__main__":
    from pathlib import Path
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

