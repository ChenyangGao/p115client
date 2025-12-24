#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter

parser = ArgumentParser(description="115 图床", formatter_class=RawTextHelpFormatter)
parser.add_argument("files", nargs="*", metavar="file", help="图片路径或链接")
parser.add_argument("-b", "--base-url", required=False, help="""\
图片的基地址
- 如果不传，则把图片上传到头像，获取一次性的图片链接，有效时间 1 小时
- 如果传 ""，则把图片上传到 U_3_-15，获取一次性的图片链接，有效时间 1 小时（但可以得到 user_id、id 和 pickcode）
- 其它（传了一个字符串，例如 "http://localhost:8000?image=1"），则把图片上传到 U_3_-15，并把此参数视为 302 代理，会把 user_id、id 和 pickcode 作为查询参数拼接到其后
""")
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

    from urllib.request import urlopen
    from p115client.tool import upload_host_image

    if not (cookies := args.cookies.strip()):
        from pathlib import Path
        cookies = Path(args.cookies_path or "115-cookies.txt")

    base_url = args.base_url
    if not base_url:
        base_url = base_url is not None

    for file in args.files:
        try:
            if file.startswith(("http://", "https://")):
                file = urlopen(file)
            print(upload_host_image(cookies, file, base_url=base_url))
        except BaseException as e:
            raise IOError(file) from e


if __name__ == "__main__":
    from pathlib import Path
    from sys import path

    path[0] = str(Path(__file__).parents[1])
    main()

