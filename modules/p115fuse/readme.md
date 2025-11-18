# Python 115 FUSE mount.

## 安装

你可以通过 [pypi](https://pypi.org/project/p115fuse/) 安装

```console
pip install -U p115fuse
```

## 用法

### 模块

```python
from p115fuse import P115FuseOperations

  P115FuseOperations().run_forever(
      "p115fuse", 
      foreground=True, 
      max_readahead=0, 
      noauto_cache=True, 
  )
```

### 命令行

```console
$ p115fuse -h
usage: p115fuse [-h] [-cp COOKIES_PATH] [-cl] [-fo option [option ...]] [-ll LOG_LEVEL] [-l] [-v] [mount_point]

    🕸️ Python 115 FUSE mount 🕷️

 ▄▄▄▄▄▄▄▄▄▄▄    ▄▄▄▄         ▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌ ▄█░░░░▌      ▄█░░░░▌    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀█░▌▐░░▌▐░░▌     ▐░░▌▐░░▌    ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌       ▐░▌ ▀▀ ▐░░▌      ▀▀ ▐░░▌    ▐░█▄▄▄▄▄▄▄▄▄ ▐░▌          ▐░▌       ▐░▌▐░▌          ▐░▌          
▐░█▄▄▄▄▄▄▄█░▌    ▐░░▌         ▐░░▌    ▐░░░░░░░░░░░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ 
▐░░░░░░░░░░░▌    ▐░░▌         ▐░░▌     ▀▀▀▀▀▀▀▀▀█░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░█▀▀▀▀▀▀▀▀▀     ▐░░▌         ▐░░▌              ▐░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌ ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌              ▐░░▌         ▐░░▌              ▐░▌▐░▌          ▐░▌       ▐░▌          ▐░▌▐░▌          
▐░▌          ▄▄▄▄█░░█▄▄▄  ▄▄▄▄█░░█▄▄▄  ▄▄▄▄▄▄▄▄▄█░▌▐░▌          ▐░█▄▄▄▄▄▄▄█░▌ ▄▄▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄▄▄ 
▐░▌         ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌          ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
 ▀           ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀            ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 

positional arguments:
  mount_point           挂载路径

options:
  -h, --help            show this help message and exit
  -cp, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
                        如果你需要直接传入一个 cookies 字符串，需要这样写
                        
                        .. code:: shell
                        
                            COOKIES='UID=...; CID=..., SEID=...'
                            p115dav --cookies-path <(echo "$COOKIES")
                        
  -cl, --check-for-relogin
                        当风控时，自动重新扫码登录
  -fo, --fuse-option option [option ...]
                        fuse 挂载选项，支持如下几种格式：
                            - name         设置 name 选项
                            - name=        取消 name 选项
                            - name=value   设置 name 选项，值为 value
                        参考资料：
                            - https://man7.org/linux/man-pages/man8/mount.fuse3.8.html
                            - https://code.google.com/archive/p/macfuse/wikis/OPTIONS.wiki
  -ll, --log-level LOG_LEVEL
                        指定日志级别，可以是数字或名称，不传此参数则不输出日志，默认值: 'ERROR'
  -l, --license         输出授权信息
  -v, --version         输出版本号
```
