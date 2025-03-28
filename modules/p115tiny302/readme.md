# 115 tiny 302 backend

## 安装

你可以通过 [pypi](https://pypi.org/project/p115tiny302/) 安装

```console
pip install -U p115tiny302
```

## 用法

### 作为模块

```python
from p115client import P115Client
from p115tiny302 import make_application
from uvicorn import run

cookies = "UID=...; CID=...; SEID=...; KID=..."
client = P115Client(cookies, ensure_cookies=True, check_for_relogin=True)
run(
    make_application(client, debug=True), 
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
$ p115tiny302 -h
usage: p115tiny302 [-h] [-c COOKIES] [-cp COOKIES_PATH] [-t TOKEN] [-H HOST] [-P PORT] [-cu] [-d] [-uc UVICORN_RUN_CONFIG_PATH] [-v] [-l]

    ╭───────────────────────── Welcome to 115 tiny 302 ────────────────────────────╮
    │                                                                              │
    │  maintained by ❤     ChenyangGao https://chenyanggao.github.io               │
    │                                                                              │
    │                      Github      https://github.com/ChenyangGao/p115client/  │
    │                                                                              │
    │                      license     https://www.gnu.org/licenses/gpl-3.0.txt    │
    │                                                                              │
    │                      version     0.1.0                                       │
    │                                                                              │
    ╰──────────────────────────────────────────────────────────────────────────────╯

> 网盘文件支持用 pickcode、id、sha1 或 name 查询
> 分享文件支持用 id 或 name 查询
> 支持参数 refresh，用于搜索名字时忽略缓存（强制刷新）
> 支持参数 app，用于指定从此设备的接口获取下载链接

🌰 携带 sign

通过命令行参数 -t/--token 指定令牌后，你就必须在请求时携带签名，即 sign 参数
计算方式为

    hashlib.sha1(bytes(f"302@115-{token}-{t}-{value}", "utf-8")).hexdigest()

其中
- token 就是命令行所传入的令牌
- t 为过期时间点（默认值为 0，即永不过期）
- value 就是值，像这样的链接，优先级顺序为 pickcode > id > sha1 > name > name2

    http://localhost:8000/{name2}?id={id}&name={name}&sha1={sha1}&pickcode={pickcode}

🌰 查询示例：

    0. 查询 pickcode
        http://localhost:8000?ecjq9ichcb40lzlvx
        http://localhost:8000/ecjq9ichcb40lzlvx
        http://localhost:8000?pickcode=ecjq9ichcb40lzlvx
    1. 带（任意）名字查询 pickcode
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?ecjq9ichcb40lzlvx
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?pickcode=ecjq9ichcb40lzlvx
        http://localhost:8000/ecjq9ichcb40lzlvx/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    2. 查询 id
        http://localhost:8000?2691590992858971545
        http://localhost:8000/2691590992858971545
        http://localhost:8000?id=2691590992858971545
    3. 带（任意）名字查询 id
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?2691590992858971545
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?id=2691590992858971545
        http://localhost:8000/2691590992858971545/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    4. 查询 sha1
        http://localhost:8000?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
    5. 带（任意）名字查询 sha1
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    6. 查询 name（直接以路径作为 name，且不要有 pickcode、id、sha1 或 name）
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
        http://localhost:8000?Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
        http://localhost:8000?name=Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    7. 查询分享文件（如果是你自己的分享，则无须提供密码 receive_code）
        http://localhost:8000?share_code=sw68md23w8m&receive_code=q353&id=2580033742990999218
        http://localhost:8000?share_code=sw68md23w8m&id=2580033742990999218
    8. 带（任意）名字查询分享文件（如果是你自己的分享，则无须提供密码 receive_code）
        http://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353&id=2580033742990999218
        http://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&id=2580033742990999218
    9. 用 name 查询分享文件（直接以路径作为 name，且不要有 id 查询参数。如果是你自己的分享，则无须提供密码 receive_code）
        http://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353
        http://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m
        http://localhost:8000?name=Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m&receive_code=q353
        http://localhost:8000?name=Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m

再推荐一个命令行使用，用于执行 HTTP 请求的工具，类似 wget

    https://pypi.org/project/httpie/

options:
  -h, --help            show this help message and exit
  -c COOKIES, --cookies COOKIES
                        cookies 字符串，优先级高于 -cp/--cookies-path
  -cp COOKIES_PATH, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
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
