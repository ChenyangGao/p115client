# 115 tiny WebDAV.

## 安装

你可以通过 [pypi](https://pypi.org/project/p115tinydav/) 安装

```console
pip install -U p115tinydav
```

## 用法

### 作为模块

```python
from p115tinydav import make_application
from uvicorn import run

run(
    make_application(debug=True), 
    host="0.0.0.0", 
    port=8000, 
    proxy_headers=True, 
    server_header=False, 
    forwarded_allow_ips="*", 
    timeout_graceful_shutdown=1, 
    access_log=False, 
)
```

### 作为命令

```console
$ p115tinydav -h
usage: p115tinydav [-h] [-c COOKIES] [-cp COOKIES_PATH] [-H HOST] [-P PORT] [-cu] [-d]
                   [-uc UVICORN_RUN_CONFIG_PATH] [-v] [-l]

    ╭───────────────────────── Welcome to 115 tiny dav ────────────────────────────╮
    │                                                                              │
    │  maintained by ❤     ChenyangGao https://chenyanggao.github.io               │
    │                                                                              │
    │                      Github      https://github.com/ChenyangGao/p115client/  │
    │                                                                              │
    │                      license     https://www.gnu.org/licenses/gpl-3.0.txt    │
    │                                                                              │
    │                      version     0.0.1                                       │
    │                                                                              │
    ╰──────────────────────────────────────────────────────────────────────────────╯

options:
  -h, --help            show this help message and exit
  -c, --cookies COOKIES
                        cookies 字符串，优先级高于 -cp/--cookies-path
  -cp, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
  -H, --host HOST       ip 或 hostname，默认值：'0.0.0.0'
  -P, --port PORT       端口号，默认值：8000，如果为 0 则自动确定
  -cu, --cache-url      缓存下载链接
  -d, --debug           启用调试，会输出更详细信息
  -uc, --uvicorn-run-config-path UVICORN_RUN_CONFIG_PATH
                        uvicorn 启动时的配置文件路径，会作为关键字参数传给 `uvicorn.run`，支持 JSON、YAML 或 TOML 格式，会根据扩展名确定，不能确定时视为 JSON
  -v, --version         输出版本号
  -l, --license         输出授权信息
```
