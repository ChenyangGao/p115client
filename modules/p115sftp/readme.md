# Python 115 SFTP Server.

## 安装

你可以通过 [pypi](https://pypi.org/project/p115sftp/) 安装

```console
pip install -U p115sftp
```

## 用法

### 模块

```python
from p115sftp import P115RequestHandler

P115RequestHandler.run_forever()
```

### 命令行

```console
$ p115sftp -h
usage: p115sftp [-h] [-H HOST] [-P PORT] [-cp COOKIES_PATH] [-cl] [-ll LOG_LEVEL] [-k KEY_FILE] [-l] [-v]

    🕸️ Python 115 SFTP Server 🕷️

                                                .-.      ___                
                                               /    \   (   )               
   .-..    .--.   .--.  ,-----.       .--.     | .`. ;   | |_        .-..   
  /    \  (_  |  (_  |  |   ___)    /  _  \    | |(___) (   __)     /    \  
 ' .-,  ;   | |    | |  |  |       . .' `. ;   | |_      | |       ' .-,  ; 
 | |  . |   | |    | |  |  '-.     | '   | |  (   __)    | | ___   | |  . | 
 | |  | |   | |    | |  '---.  .   _\_`.(___)  | |       | |(   )  | |  | | 
 | |  | |   | |    | |   ___ `  \ (   ). '.    | |       | | | |   | |  | | 
 | |  ' |   | |    | |  (   ) | |  | |  `\ |   | |       | ' | |   | |  ' | 
 | `-'  '   | |    | |   ; `-'  /  ; '._,' '   | |       ' `-' ;   | `-'  ' 
 | \__.'   (___)  (___)   '.__.'    '.___.'   (___)       `.__.    | \__.'  
 | |                                                               | |      
(___)                                                             (___)     

options:
  -h, --help            show this help message and exit
  -H, --host HOST       ip 或 hostname，默认值：'0.0.0.0'
  -P, --port PORT       端口号，默认值：6115
  -cp, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
                        如果你需要直接传入一个 cookies 字符串，需要这样写
                        
                        .. code:: shell
                        
                            COOKIES='UID=...; CID=..., SEID=...'
                            p115dav --cookies-path <(echo "$COOKIES")
                        
  -cl, --check-for-relogin
                        当风控时，自动重新扫码登录
  -ll, --log-level LOG_LEVEL
                        指定日志级别，可以是数字或名称，不传此参数则不输出日志，默认值: 'INFO'
  -k, --key-file KEY_FILE
                        服务器私钥文件，如果不提供则随机生成
  -l, --license         输出授权信息
  -v, --version         输出版本号
```
