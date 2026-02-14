# Using 115 for hosting image.

## Installation

You can install from [pypi](https://pypi.org/project/p115imghost/)

```console
pip install -U p115imghost
```

## Usage

```console
$ p115imghost -h
usage: p115imghost [-h] [-b BASE_URL] [-c COOKIES] [-cp COOKIES_PATH] [-v] [-l] [file ...]

115 图床（每张图片不大于 50 MB）

positional arguments:
  file                  图片路径或链接

options:
  -h, --help            show this help message and exit
  -b, --base-url BASE_URL
                        图片的基地址
                        - 如果不传，上传到 U_4_-1，获取永久的图片链接
                        - 如果传 ""，上传到 U_4_-1，获取一次性的图片链接，有效时间 1 小时
                        - 其它（例如 "http://localhost:8000?image=1"），上传到 U_12_0，视为 302 代理，会把 user_id、id、pickcode、sha1 和 size 作为查询参数拼接到其后
  -c, --cookies COOKIES
                        cookies 字符串，优先级高于 -cp/--cookies-path
  -cp, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
  -v, --version         输出版本号
  -l, --license         输出授权信
```
