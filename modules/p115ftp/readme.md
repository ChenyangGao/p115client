# Python 115 FTP Server.

## 安装

你可以通过 [pypi](https://pypi.org/project/p115ftp/) 安装

```console
pip install -U p115ftp
```

## 用法

### 模块

```python
from p115ftp import P115FS

P115FS.run_forever()
```

### 命令行

```console
$ p115ftp -h
usage: [-h] [-H HOST] [-P PORT] [-cp COOKIES_PATH] [-cl] [-nt] [-l] [-v]

    🕸️ Python 115 FTP Server 🕷️

             88      88  8888888888      ad88                        
           ,d88    ,d88  88             d8"      ,d                  
         888888  888888  88  ____       88       88                  
8b,dPPYba,   88      88  88a8PPPP8b,  MM88MMM  MM88MMM  8b,dPPYba,   
88P'    "8a  88      88  PP"     `8b    88       88     88P'    "8a  
88       d8  88      88           d8    88       88     88       d8  
88b,   ,a8"  88      88  Y8a     a8P    88       88,    88b,   ,a8"  
88`YbbdP"'   88      88   "Y88888P"     88       "Y888  88`YbbdP"'   
88                                                      88           
88                                                      88           

options:
  -h, --help            show this help message and exit
  -H, --host HOST       ip 或 hostname，默认值：'0.0.0.0'
  -P, --port PORT       端口号，默认值：7115
  -cp, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
                        如果你需要直接传入一个 cookies 字符串，需要这样写
                        
                        .. code:: shell
                        
                            COOKIES='UID=...; CID=..., SEID=...'
                            p115dav --cookies-path <(echo "$COOKIES")
                        
  -cl, --check-for-relogin
                        当风控时，自动重新扫码登录
  -nt, --no-thumbs      不要为请求图片链接提供缩略图
  -l, --license         输出授权信息
  -v, --version         输出版本号
```
