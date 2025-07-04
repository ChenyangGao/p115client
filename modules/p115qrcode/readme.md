# 115 网盘二维码扫码登录.

## 安装

你可以通过 [pypi](https://pypi.org/project/p115qrcode/) 安装

```console
pip install -U p115qrcode
```

## 使用

### 作为模块

详情请查看具体函数的文档

```python
import p115qrcode
```

### 作为命令行

```console
$ p115qrcode -h
usage: p115qrcode [-h] [-l] [-v] {cmd,web} ...

115 网盘扫码登录

positional arguments:
  {cmd,web}

options:
  -h, --help     show this help message and exit
  -l, --license  输出授权信息
  -v, --version  输出版本号

$ p115qrcode cmd -h
usage: p115qrcode cmd [-h] [-o OUTPUT_FILE] [-oq] [-c COOKIES] [-cp COOKIES_PATH] [-l] [-v]
                      [{web,ios,115ios,android,115android,115ipad,tv,qandroid,wechatmini,alipaymini,harmony}]

115 网盘扫码登录（命令行版）

positional arguments:
  {web,ios,115ios,android,115android,115ipad,tv,qandroid,wechatmini,alipaymini,harmony}
                        选择一个 app 进行登录，默认值 'alipaymini'

options:
  -h, --help            show this help message and exit
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        保存到文件，未指定时输出到 stdout
  -oq, --open-qrcode    在浏览器中打开二维码，而不是在命令行输出
  -c COOKIES, --cookies COOKIES
                        115 登录 cookies 或二维码的 uid，使用后可以自动扫码，优先级高于 -cp/--cookies-path
  -cp COOKIES_PATH, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，使用后可以自动扫码
  -l, --license         输出授权信息
  -v, --version         输出版本号

$ p115qrcode web -h
usage: p115qrcode web [-h] [-H HOST] [-P PORT] [-c] [-d] [-l] [-v]

115 网盘扫码登录（网页版）

options:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  ip 或 hostname，默认值：'localhost'
  -P PORT, --port PORT  端口号，默认值：8000
  -c, --cors            标识浏览器已经使用 CORS 插件，因此不需要后台代理接口的调用
  -d, --debug           启用 debug 模式
  -l, --license         输出授权信息
  -v, --version         输出版本号
```
