# Python 115 WsgiDAV.

## 安装

你可以通过 [pypi](https://pypi.org/project/p115wsgidav/) 安装

```console
pip install -U p115wsgidav
```

## 用法

### 模块

```python
from p115wsgidav import P115FileSystemProvider

P115FileSystemProvider().run_forever()
```

### 命令行

```console
$ p115wsgidav -h
usage: p115wsgidav [-h] [-H HOST] [-P PORT] [-cp COOKIES_PATH] [-cl] [-nt] [-o ORIGIN_302] [-wc WSGIDAV_CONFIG_PATH] [-l] [-v]

    🕸️ Python 115 WsgiDAV 🕷️

██████╗  ██╗ ██╗███████╗██╗    ██╗███████╗██████╗ ██████╗  █████╗ ██╗   ██╗
██╔══██╗███║███║██╔════╝██║    ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██║   ██║
██████╔╝╚██║╚██║███████╗██║ █╗ ██║█████╗  ██████╔╝██║  ██║███████║██║   ██║
██╔═══╝  ██║ ██║╚════██║██║███╗██║██╔══╝  ██╔══██╗██║  ██║██╔══██║╚██╗ ██╔╝
██║      ██║ ██║███████║╚███╔███╔╝███████╗██████╔╝██████╔╝██║  ██║ ╚████╔╝ 
╚═╝      ╚═╝ ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  

options:
  -h, --help            show this help message and exit
  -H, --host HOST       ip 或 hostname，默认值：'0.0.0.0'
  -P, --port PORT       端口号，默认值：8115
  -cp, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
                        如果你需要直接传入一个 cookies 字符串，需要这样写
                        
                        .. code:: shell
                        
                            COOKIES='UID=...; CID=..., SEID=...'
                            p115dav --cookies-path <(echo "$COOKIES")
                        
  -cl, --check-for-relogin
                        当风控时，自动重新扫码登录
  -nt, --no-thumbs      不要为请求图片链接提供缩略图
  -o, --origin-302 ORIGIN_302
                        设置 302 请求转发。如果为空，则由此模块提供；特别的，如果缺省此参数，则视为缓存链接；如果为空字符串 ''，则不缓存
  -wc, --wsgidav-config-path WSGIDAV_CONFIG_PATH
                        WsgiDAV 启动时的配置文件路径，支持 JSON、YAML 或 TOML 格式，会根据扩展名确定，不能确定时视为 JSON
                        如需样板文件，请阅读：
                        
                            https://wsgidav.readthedocs.io/en/latest/user_guide_configure.html#sample-wsgidav-yaml
                        
  -l, --license         输出授权信息
  -v, --version         输出版本号
```
