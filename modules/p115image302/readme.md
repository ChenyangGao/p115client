# 115 image 302 backend

## 安装

你可以通过 [pypi](https://pypi.org/project/p115image302/) 安装

```console
pip install -U p115image302
```

## 用法

### 作为模块

```python
from p115client import P115Client
from p115image302 import make_application
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
$ p115image302 -h
usage: p115image302 [-h] [-c COOKIES] [-cp COOKIES_PATH] [-H HOST] [-P PORT] [-d] [-uc UVICORN_RUN_CONFIG_PATH] [-v] [-l] [dbfile]

    ╭───────────────────────── Welcome to 115 image 302 ───────────────────────────╮
    │                                                                              │
    │  maintained by ❤     ChenyangGao https://chenyanggao.github.io               │
    │                                                                              │
    │                      Github      https://github.com/ChenyangGao/p115client/  │
    │                                                                              │
    │                      license     https://www.gnu.org/licenses/gpl-3.0.txt    │
    │                                                                              │
    │                      version     0.0.2                                       │
    │                                                                              │
    ╰──────────────────────────────────────────────────────────────────────────────╯

⚽️ 支持下载：用 key 查询，可以是 sha1、oss、id 或者 pickcode，其中 oss 是阿里云 OSS 对象存储的存储桶和对象 id 的组合，格式形如 f"{bucket}_{object}"，例如 "fhnimg_6991ce15fa60d3515b1eb7866a73b6b59a6b9598_0_0"。支持查询参数 permanent=1，以指定获取永久链接

    GET http://localhost:8000/{key}
    GET http://localhost:8000/{key}/name

🏀 支持上传：用 PUT 方法上传，请求体即是文件内容

    PUT http://localhost:8000

⚾️ 无论上传还是下载，文件大小不得超过 50 MB
🥎 如果用 sha1 或 oss 下载图片（或者任何不大于 50 MB 的文件），则对应文件不必在你网盘中

positional arguments:
  dbfile                缓存的数据库路径，默认为当前工作目录下的 'p115image302.db'

options:
  -h, --help            show this help message and exit
  -c, --cookies COOKIES
                        cookies 字符串，优先级高于 -cp/--cookies-path
  -cp, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
  -H, --host HOST       ip 或 hostname，默认值：'0.0.0.0'
  -P, --port PORT       端口号，默认值：8000，如果为 0 则自动确定
  -d, --debug           启用调试，会输出更详细信息
  -uc, --uvicorn-run-config-path UVICORN_RUN_CONFIG_PATH
                        uvicorn 启动时的配置文件路径，会作为关键字参数传给 `uvicorn.run`，支持 JSON、YAML 或 TOML 格式，会根据扩展名确定，不能确定时视为 JSON
  -v, --version         输出版本号
  -l, --license         输出授权信息
```
