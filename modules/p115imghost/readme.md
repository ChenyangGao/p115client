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

115 图床

positional arguments:
  file                  图片路径或链接

options:
  -h, --help            show this help message and exit
  -b, --base-url BASE_URL
                        图片的基地址
                        - 如果不传，则把图片上传到头像，获取一次性的图片链接，有效时间 1 小时
                        - 如果传 ""，则把图片上传到 U_3_-15，获取一次性的图片链接，有效时间 1 小时（但可以得到 user_id、id 和 pickcode）
                        - 其它（传了一个字符串，例如 "http://localhost:8000?image=1"），则把图片上传到 U_3_-15，并把此参数视为 302 代理，会把 user_id、id 和 pickcode 作为查询参数拼接到其后
  -c, --cookies COOKIES
                        cookies 字符串，优先级高于 -cp/--cookies-path
  -cp, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
  -v, --version         输出版本号
  -l, --license         输出授权信息
```
