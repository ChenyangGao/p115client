![license](https://img.shields.io/github/license/ChenyangGao/p115client)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/p115client)
![PyPI - Version](https://img.shields.io/pypi/v/p115client)
![PyPI - Downloads](https://img.shields.io/pypi/dm/p115client)
![PyPI - Format](https://img.shields.io/pypi/format/p115client)
![PyPI - Status](https://img.shields.io/pypi/status/p115client)

# p115client

[p115client](https://github.com/ChenyangGao/p115client) 是一个 [115 网盘](https://115.com) 的 [Python](https://python.org) 客户端模块，不过仅提供最直接的接口包装。

支持同步和异步操作，全面封装了各种 **web**、**app** 和 **[open](https://www.yuque.com/115yun/open/)** 接口。

## 推荐工具

[p115tinydav](https://pypi.org/project/p115tinydav/)

```console
pip install -U p115tinydav
```

这个工具提供了一个 WebDAV 服务，采取了目前最激进的更新数据策略，思路沿袭自我之前写的 updatedb

1. 首次全量：首次创建数据库时，会把整个网盘的目录树全部拉取下来
2. 逐次增量：以后全靠事件来判断增量
3. 懒惰更新：在被访问后，会去尝试拉取增量事件，长久不访问的情况下，仅有 1 小时/次 的例行检查

这个工具在【首次全量】阶段，对机器的性能要求较高，如果机器不够给力，不要部署（或者拿一台性能较好的电脑把全量数据库跑完，然后把数据库复制过去）

<video controls width="70%" poster="https://life.115.com/imgload?h=fhnimg_6a391f2f112a52ae4410cb6bd7291562d8ced960_0_0&i=1&t=0&ss=4466d6b48cd9f611c3f13c676f6967856423a623&tt=1782128432" loop preload="auto">
  <source src="https://life.115.com/imgload?h=fhnimg_6a391dab80660f7b480d54cea335d1c91b99eb39_0_0&i=1&t=0&ss=81ca66e055dfde68d0f8bb0dd2e3c205298ae21e&tt=1782128051" type="video/mp4">
</video>

## 原创玄幻小说《叶不凡修仙记》

- GitHub: [https://github.com/chenyangGao/adventures-of-super-ye](https://github.com/chenyangGao/adventures-of-super-ye)
- 博客：[https://open.forem.com/super-ye](https://open.forem.com/super-ye)

## 安装

你可以从 [pypi](https://pypi.org/project/p115client/) 安装最新版本

```console
pip install -U p115client
```

或者从 [github](https://github.com/ChenyangGao/p115client) 安装最新版本

```console
pip install -U git+https://github.com/ChenyangGao/p115client@main
```

## 入门介绍

### 1. 导入模块

导入模块

```python
from p115client import P115Client
```

### 2. 创建实例

#### 1. 用 cookies 创建实例

创建客户端对象，需要传入 <kbd>[cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies)</kbd>，如果不传，则需要扫码登录

```python
cookies = "UID=...; CID=...; SEID=...; KID=..."
client = P115Client(cookies)
```

如果你的 <kbd>cookies</kbd> 保存在 `~/115-cookies.txt`

```python
from pathlib import Path

client = P115Client(Path("~/115-cookies.txt").expanduser())

# 或者简便写法
client = P115Client.from_path()
```

如果想要调用接口返回时自动捕获 [405](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/405) HTTP 响应码，然后进行自动的扫码登录，并把更新后的 <kbd>cookies</kbd> 写回文件，然后重试接口调用

```python
client = P115Client(Path("~/115-cookies.txt").expanduser())
```

所以综上，推荐的初始化代码为

```python
from p115client import P115Client
from pathlib import Path

client = P115Client(Path("~/115-cookies.txt").expanduser())
```

#### 2. 用 AppID 创建实例

如果你有一个申请通过的开放接口的应用，则可以创建开放接口的客户端实例

你可以直接从一个 `P115Client` 实例拿到授权（自动扫码登录并授权）

```python
app_id = <开放接口应用的 AppID>
# 可以不传 app_id，因为有一个默认值
client_open = client.login_another_open(app_id)
```

你也可以直接在 `P115Client` 实例上使用开放接口，此时会使用 `P115OpenClient` 的对应方法，但名字多一个 "_open" 后缀

```python
# 此时 client.fs_files_open 相当于 client_open.fs_files
client.login_another_open(app_id, replace=True)
```

也可以用一个已经授权得到的 `refresh_token` (一次性使用)

```python
from p115client import P115OpenClient

client_open = P115OpenClient(refresh_token)
```

或者手动扫码登录

```python
client_open = P115OpenClient(app_id)
```

所以综上，推荐的初始化代码为

```python
from p115client import P115Client, P115OpenClient
from pathlib import Path

client = P115Client(Path("~/115-cookies.txt").expanduser())
client_open = client.login_another_open()
```

### 3. 接口调用

> 我推荐你选择 [`ipython`](https://ipython.readthedocs.io/en/latest/) 作为执行环境，可以交互式地执行代码和分析结果

所有需要直接或间接执行 HTTP 请求的接口，都有同步和异步的调用方式

```python
# 同步调用
client.method(payload)
client.method(payload, async_=False)

# 异步调用
await client.method(payload, async_=True)
```

它们都能接受一个参数 `request`，具体要求可以查看 [`P115Client.request`](https://p115client.readthedocs.io/en/latest/reference/module/client.html#p115client.client.P115Client.request) 的文档。我也封装了一些模块, 它们都能提供一个符合要求的 `request` 函数。更一般的实现，可以参考 [`python-http_request`](https://pypi.org/project/python-http_request/)。

1. [aiohttp_client_request](https://pypi.org/project/aiohttp_client_request/)
1. [aiosonic_request](https://pypi.org/project/aiosonic_request/)
1. [asks_request](https://pypi.org/project/asks_request/)
1. [blacksheep_client_request](https://pypi.org/project/blacksheep_client_request/)
1. [curl_cffi_request](https://pypi.org/project/curl_cffi_request/)
1. [http_client_request](https://pypi.org/project/http_client_request/)
1. [httpcore_request](https://pypi.org/project/httpcore_request/)
1. [httpx_request](https://pypi.org/project/httpx_request/)
1. [niquests_request](https://pypi.org/project/niquests_request/)
1. [pycurl_request](https://pypi.org/project/pycurl_request/)
1. [python-urlopen](https://pypi.org/project/python-urlopen/)
1. [requests_request](https://pypi.org/project/requests_request/)
1. [tornado_client_request](https://pypi.org/project/tornado_client_request/)
1. [urllib3_request](https://pypi.org/project/urllib3_request/)
1. [urllib3_future_request](https://pypi.org/project/urllib3_future_request/)

**注意**：从根本上讲，所有接口的封装，最终都会调用 `P115Client.request`

```python
url = "https://webapi.115.com/files"
response = client.request(url=url, params={"cid": 0, "show_dir": 1})
```

当你需要构建自己的扩展模块，以增加一些新的 115 web 接口时，就需要用到此方法了

```python
from collections.abc import Coroutine
from typing import overload, Any, Literal

from p115client import P115Client

class MyCustom115Client(P115Client):

    @overload
    def foo(
        self, 
        payload: dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def foo(
        self, 
        payload: dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def foo(
        self, 
        payload: dict, 
        /, 
        async_: bool = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        api = "https://webapi.115.com/foo"
        return self.request(
            api, 
            method="GET", 
            params=payload, 
            async_=async_, 
            **request_kwargs, 
        )

    @overload
    def bar(
        self, 
        payload: dict, 
        /, 
        async_: Literal[False] = False, 
        **request_kwargs, 
    ) -> dict:
        ...
    @overload
    def bar(
        self, 
        payload: dict, 
        /, 
        async_: Literal[True], 
        **request_kwargs, 
    ) -> Coroutine[Any, Any, dict]:
        ...
    def bar(
        self, 
        payload: dict, 
        /, 
        async_: bool = False, 
        **request_kwargs, 
    ) -> dict | Coroutine[Any, Any, dict]:
        api = "https://webapi.115.com/bar"
        return self.request(
            api, 
            method="POST", 
            data=payload, 
            async_=async_, 
            **request_kwargs, 
        )
```

### 4. 检查响应

接口被调用后，如果返回的是 [dict](https://docs.python.org/3/library/stdtypes.html#mapping-types-dict) 类型的数据（说明原本是 [JSON](https://www.json.org)），则可以用 `p115client.check_response` 执行检查。首先会查看其中名为 "state" 的键的对应值，如果为  True、1 或不存在，则原样返回被检查的数据；否则，"state" 的对应值大概是 False 或 0，说明有问题出现，会根据实际情况抛出一个异常，但都是 `p115client.P115OSError` 的实例。

```python
from p115client import check_response

# 检查同步调用
data = check_response(client.method(payload))

# 检查异步调用
data = check_response(await client.method(payload, async_=True))
# 或者
data = await check_response(client.method(payload, async_=True))
```

### 5. 辅助工具

一些简单的封装工具可能是必要的，特别是那种实现起来代码量比较少，可以封装成单个函数的。我把平常使用过程中，积累的一些经验具体化为一组工具函数。这些工具函数分别有着不同的功能，如果组合起来使用，或许能解决很多问题。

```python
from p115client import tool
```

### 6. 实用案例

我写了几篇文章，介绍了 <kbd>p115client</kbd> 的一些实践案例。有一些文章打开是空的，说明还未上传。

https://p115client.readthedocs.io/en/latest/example/index.html

## 其它资源

- 如果你需要更详细的文档，特别是关于各种接口的信息，可以阅读

    [https://p115client.readthedocs.io/en/latest/](https://p115client.readthedocs.io/en/latest/)

- 如果你想要一组更高级的封装，特别是一组文件系统的操作集合，可以使用（⚠️ 暂不可用）

    [https://pypi.org/project/python-115/](https://pypi.org/project/python-115/)

- 如果你想要获得此项目的衍生模块，可以访问

    [p115client/modules](https://github.com/ChenyangGao/p115client/tree/main/modules)
