# 115 nano 302 backend

## 安装

你可以通过 [pypi](https://pypi.org/project/p115nano302/) 安装

```console
pip install -U p115nano302
```

## 用法

### 作为模块

```python
from p115nano302 import make_application
from uvicorn import run

cookies = "UID=...; CID=...; SEID=...; KID=..."
run(
    make_application(cookies, debug=True), 
    host="0.0.0.0", 
    port=8000, 
    proxy_headers=True, 
    server_header=False, 
    forwarded_allow_ips="*", 
    timeout_graceful_shutdown=1, 
)
```

### 作为命令

```console
$ p115nano302 -h
usage:  [-h] [-c COOKIES] [-cp COOKIES_PATH] [-p PASSWORD] [-t TOKEN] [-H HOST]
        [-P PORT] [-cu] [-d] [-uc UVICORN_RUN_CONFIG_PATH] [-v] [-l]

    ╭───────────────────────── Welcome to 115 nano 302 ────────────────────────────╮
    │                                                                              │
    │  maintained by ❤     ChenyangGao https://chenyanggao.github.io               │
    │                                                                              │
    │                      Github      https://github.com/ChenyangGao/p115client/  │
    │                                                                              │
    │                      license     https://www.gnu.org/licenses/gpl-3.0.txt    │
    │                                                                              │
    │                      version     0.1.2                                       │
    │                                                                              │
    ╰──────────────────────────────────────────────────────────────────────────────╯

> 网盘文件支持用 id、pickcode、sha1 或 name 查询（照此优先级），但不支持 path 
> 分享文件支持用 id 或 name 查询
> 用 sha1 或 name 查询时，可以指定参数 cid，作为查询目标的顶层目录

< 支持参数 user_id，以指定用户 id，并在实际执行时使用此用户的 cookies 和网盘数据（未指定时，使用所传入的第 1 个 cookies）
< 支持参数 refresh，指定 bool 值，用于搜索名字时忽略缓存（强制刷新）
< 支持参数 app，用于指定从此设备的接口获取下载链接（可以不管）

⏰ 此版本不依赖于 p115client 和 pycryptodome，至少要求 python 3.12

🌰 携带 sign

通过命令行参数 -t/--token 指定令牌后，你就必须在请求时携带签名，即 sign 参数
计算方式为

    hashlib.sha1(bytes(f"302@115-{token}-{t}-{value}", "utf-8")).hexdigest()

其中：

    1. token 就是命令行所传入的令牌
    2. t 为过期时间点（默认值为 0，即永不过期）
    3. value 就是值，像这样的链接，优先级顺序为 id > pickcode > sha1 > name > path > name2

        http://localhost:8000/{name2}?id={id}&pickcode={pickcode}&sha1={sha1}&name={name}&path={path}

🌰 更新 cookies

通过命令行参数 -p/--password 指定密码后，你就可以一次性更新很多个 cookies，使用接口（请求时需携带和命令行传入的相同的密码）

    POST http://localhost:8000/<cookies?password={password}

请求体为 json 数据，支持 4 种格式

    1. {"cookies": "字符串，一行写一个 cookies，用 \n 分隔"}
    2. {"cookies": ["cookies 列表"]}
    3. "字符串，一行写一个 cookies，用 \n 分隔"}
    4. ["cookies 列表"]

如果要查询目前所有的 cookies，使用接口（请求时需携带和命令行传入的相同的密码）

    GET http://localhost:8000/<cookies?password={password}

🌰 查询示例：

    1. 查询 id
        http://localhost:8000?2691590992858971545
        http://localhost:8000/2691590992858971545
        http://localhost:8000?id=2691590992858971545
    2. 带（任意）名字查询 id
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?2691590992858971545
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?id=2691590992858971545
        http://localhost:8000/2691590992858971545/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    3. 查询 pickcode
        http://localhost:8000?ecjq9ichcb40lzlvx
        http://localhost:8000/ecjq9ichcb40lzlvx
        http://localhost:8000?pickcode=ecjq9ichcb40lzlvx
    4. 带（任意）名字查询 pickcode
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?ecjq9ichcb40lzlvx
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?pickcode=ecjq9ichcb40lzlvx
        http://localhost:8000/ecjq9ichcb40lzlvx/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    5. 查询 sha1
        http://localhost:8000?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
    6. 带（任意）名字查询 sha1
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    7. 查询 name（直接以路径作为 name，且不要有 pickcode、id、sha1 或 name）
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
        http://localhost:8000?Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
        http://localhost:8000?name=Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    8. 用 id 查询分享文件（如果是你自己的分享，则无须提供密码 receive_code）
        http://localhost:8000?share_code=sw68md23w8m&receive_code=q353&id=2580033742990999218
        http://localhost:8000?share_code=sw68md23w8m&id=2580033742990999218
    9. 用 id 带（任意）名字查询分享文件（如果是你自己的分享，则无须提供密码 receive_code）
        http://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353&id=2580033742990999218
        http://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&id=2580033742990999218
    10. 用 name 查询分享文件（直接以路径作为 name，且不要有 id 查询参数。如果是你自己的分享，则无须提供密码 receive_code）
        http://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353
        http://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m
        http://localhost:8000?name=Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m&receive_code=q353
        http://localhost:8000?name=Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m

options:
  -h, --help            show this help message and exit
  -c COOKIES, --cookies COOKIES
                        cookies 字符串，优先级高于 -cp/--cookies-path，如果有多个则一行写一个
  -cp COOKIES_PATH, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt，如果有多个则一行写一个
  -p PASSWORD, --password PASSWORD
                        执行后台信息操作请求所需密码，仅当提供时，才会启用一组后台信息操作接口
  -t TOKEN, --token TOKEN
                        签名所用的 token，如果提供，则请求必须携带签名，即 sign 查询参数
  -H HOST, --host HOST  ip 或 hostname，默认值：'0.0.0.0'
  -P PORT, --port PORT  端口号，默认值：8000，如果为 0 则自动确定
  -cu, --cache-url      缓存下载链接
  -d, --debug           启用调试，会输出更详细信息
  -uc UVICORN_RUN_CONFIG_PATH, --uvicorn-run-config-path UVICORN_RUN_CONFIG_PATH
                        uvicorn 启动时的配置文件路径，会作为关键字参数传给 `uvicorn.run`，支持 JSON、YAML 或 TOML 格式，会根据扩展名确定，不能确定时视为 JSON
  -v, --version         输出版本号
  -l, --license         输出授权信息
```
