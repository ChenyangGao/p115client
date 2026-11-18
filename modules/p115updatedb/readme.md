# 把 115 网盘的文件列表导出到数据库

## 安装

你可以通过 [pypi](https://pypi.org/project/p115updatedb/) 安装

```console
pip install -U p115updatedb
```

## 用法

### 模块

```python
from p115updatedb import updatedb_life_iter, updatedb_life, updatedb, updatedb_one, updatedb_tree
```

另外也提供了一些工具函数，封装了一些数据库查询

```python
from p115updatedb.query import *
```

### 命令行

```console
$ p115updatedb -h
usage: p115updatedb [-h] [-cp COOKIES_PATH] [-f DBFILE] [-i INTERVAL]
                    [-st AUTO_SPLITTING_THRESHOLD]
                    [-sst AUTO_SPLITTING_STATISTICS_TIMEOUT] [-nm] [-nr] [-de]
                    [-v] [-l]
                    [dir ...]

遍历 115 网盘的目录，并把信息导出到数据库

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
                        sqlite 数据库文件路径，默认为在当前工作目录下的 f'115-{user_id}.db'
  -i INTERVAL, --interval INTERVAL
                        两个任务之间的睡眠时间，如果 <= 0，则不睡眠
  -st AUTO_SPLITTING_THRESHOLD, --auto-splitting-threshold AUTO_SPLITTING_THRESHOLD
                        自动拆分的文件数阈值，大于此值时，自动进行拆分，如果 = 0，则总是拆分，如果 < 0，则总是不拆分，默认值 100,000（10 万）
  -sst AUTO_SPLITTING_STATISTICS_TIMEOUT, --auto-splitting-statistics-timeout AUTO_SPLITTING_STATISTICS_TIMEOUT
                        自动拆分前的执行文件数统计的超时时间（秒），大于此值时，视为文件数无穷大，如果 <= 0，视为永不超时，默认值 3
  -nm, --no-dir-moved   声明没有目录被移动或改名（但可以有目录被新增或删除），这可以加快批量拉取时的速度
  -nr, --not-recursive  不遍历目录树：只拉取顶层目录，不递归子目录
  -de, --disable-event  关闭 event 表的数据收集
  -v, --version         输出版本号
  -l, --license         输出开源协议
```
