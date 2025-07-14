# 把 115 网盘的文件列表导出到数据库（仅文件）

## 安装

你可以通过 [pypi](https://pypi.org/project/p115filedb/) 安装

```console
pip install -U p115filedb
```

## 用法

### 模块

```python
from p115filedb import updatedb
```

### 命令行

```console
$ p115filedb -h
usage: p115filedb [-h] [-cp COOKIES_PATH] [-f DBFILE] [-i INTERVAL] [-m MAX_WORKERS] [-p PAGE_SIZE] [-cl] [-v] [-l] [dir ...]

遍历 115 网盘的目录，仅导出文件信息导出到数据库

positional arguments:
  dir                   115 目录，可以传入多个，如果不传默认为 0
                        允许 3 种类型的目录
                            1. 整数，视为目录的 id
                            2. 形如 "/名字/名字/..." 的路径，最前面的 "/" 可以省略，本程序会尝试获取对应的 id
                            3. 形如 "根目录 > 名字 > 名字 > ..." 的路径，来自点击文件的【显示属性】，在【位置】这部分看到的路径，本程序会尝试获取对应的 id

options:
  -h, --help            show this help message and exit
  -cp COOKIES_PATH, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
  -f DBFILE, --dbfile DBFILE
                        sqlite 数据库文件路径，默认为在当前工作目录下的 f'115-file-{user_id}.db'
  -i INTERVAL, --interval INTERVAL
                        两个任务之间的睡眠时间，如果 <= 0，则不睡眠
  -m MAX_WORKERS, --max-workers MAX_WORKERS
                        拉取分页时的最大并发数，默认会自动确定
  -p PAGE_SIZE, --page-size PAGE_SIZE
                        每次批量拉取的分页大小，默认值：8,000
  -cl, --check-for-relogin
                        当风控时，自动重新扫码登录
  -v, --version         输出版本号
  -l, --license         输出开源协议
```
