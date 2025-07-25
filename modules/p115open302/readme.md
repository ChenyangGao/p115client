# 115 open 302 backend

## 安装

你可以通过 [pypi](https://pypi.org/project/p115open302/) 安装

```console
pip install -U p115open302
```

## 用法

### 作为模块

```python
from p115client import P115Client
from p115open302 import make_application
from uvicorn import run

# 授权登录
cookies = "UID=...; CID=...; SEID=...; KID=..."
app_id = 100195123
client = P115Client(cookies, ensure_cookies=True, check_for_relogin=True)
client.login_another_open(replace=True)
# 或者直接用 refresh_token
refresh_token = "..."
client = P115Client("", heck_for_relogin=True)
client.refresh_token = refresh_token
client.refresh_access_token()

run(
    make_application(client, debug=True), 
    host="0.0.0.0", 
    port=8000, 
    proxy_headers=True, 
    server_header=False, 
    forwarded_allow_ips="*", 
    timeout_graceful_shutdown=1, 
)
```

### 作为命令

```console
$ p115open302 -h
usage: p115open302 [-h] [-c COOKIES] [-cp COOKIES_PATH] [-a APP_ID]
                   [-rt REFRESH_TOKEN] [-t TOKEN] [-H HOST] [-P PORT] [-cu] [-d]
                   [-uc UVICORN_RUN_CONFIG_PATH] [-v] [-l]

    ╭───────────────────────── Welcome to 115 open 302 ────────────────────────────╮
    │                                                                              │
    │  maintained by ❤     ChenyangGao https://chenyanggao.github.io               │
    │                                                                              │
    │                      Github      https://github.com/ChenyangGao/p115client/  │
    │                                                                              │
    │                      license     https://www.gnu.org/licenses/gpl-3.0.txt    │
    │                                                                              │
    │                      version     0.0.5                                       │
    │                                                                              │
    ╰──────────────────────────────────────────────────────────────────────────────╯

> 网盘文件支持用 id、pickcode、sha1、name 或 path 查询（此顺序即优先级从高到低）
> 支持参数 refresh，用于搜索 sha1、name 或 path 时忽略缓存（强制刷新）
> 支持参数 size，用于搜索 sha1 或 name 时，要求文件大小等于此值

🌰 携带 sign

通过命令行参数 -t/--token 指定令牌后，你就必须在请求时携带签名，即 sign 参数
计算方式为

    hashlib.sha1(bytes(f"302@115-{token}-{t}-{value}", "utf-8")).hexdigest()

其中：

    1. token 就是命令行所传入的令牌
    2. t 为过期时间点（默认值为 0，即永不过期）
    3. value 就是值，像这样的链接，优先级顺序为 id > pickcode > sha1 > name > path > name2

        http://localhost:8000/{name2}?id={id}&pickcode={pickcode}&sha1={sha1}&name={name}&path={path}

    4. 但如果你传入了查询参数 value，且不是空字符串，那么就强制用这个值来计算签名，优先级高于上一条规则

🌰 查询示例：

    1. 查询 id
        http://localhost:8000?2691590992858971545
        http://localhost:8000/2691590992858971545
        http://localhost:8000?id=2691590992858971545
    2. 带（任意）名字查询 id
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?2691590992858971545
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?id=2691590992858971545
        http://localhost:8000/2691590992858971545/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    3. 查询 pickcode
        http://localhost:8000?ecjq9ichcb40lzlvx
        http://localhost:8000/ecjq9ichcb40lzlvx
        http://localhost:8000?pickcode=ecjq9ichcb40lzlvx
    4. 带（任意）名字查询 pickcode
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?ecjq9ichcb40lzlvx
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?pickcode=ecjq9ichcb40lzlvx
        http://localhost:8000/ecjq9ichcb40lzlvx/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    5. 查询 sha1
        http://localhost:8000?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
    6. 带（任意）名字查询 sha1
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691
        http://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    7. 查询 name（如果直接以路径作为 name，则不要有 pickcode、id、sha1、name 或 path）
        http://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
        http://localhost:8000?Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
        http://localhost:8000?name=Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
    8. 查询 path（如果直接以路径作为 path，则不要有 pickcode、id、sha1、name 或 path，在根目录下要以 > 或 / 开头，如果整个路径中不含 > 或 /，则会视为 name）
        http://localhost:8000/电影/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
        http://localhost:8000//电影/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
        http://localhost:8000?/电影/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv
        http://localhost:8000?path=/电影/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv

🌰 视频相关操作：

当你提供 method 参数时，通常就意味着你需要操作的目标是视频，此参数的值分别如下：

    1. "subs"、"subtitle" 或 "subtitles"，获取目标文件的内嵌字幕和与它同一目录下的字幕，返回这些字幕的信息和下载链接，结果是一个 JSON
    2. "tran" 或 "transcode"，获取目标文件的转码信息和在线播放地址，结果是一个 JSON
    3. "m3u8"，获取在线播放地址，会执行 302 重定向，另外接受参数：
        1. audio_track，接受 1 个整数，以切换不同音轨，这个数字是数组下标（从 0 开始），请先查询 "tran" 或 "transcode" 方法，然后看 key 为 "multitrack_list" 的数组
        2. definition，接受 1 个整数，以切换不同画质：1:标清 2:高清 3:超清 4:1080P 5:4k 100:原画
    4. "push"，提交视频转码请求，结果是一个 JSON
    5. "hist" 或 "history"，获取或设置视频播放进度。当你没有 time 和 watch_end 查询参数时，会获取视频播放进度，否则会进行设置。结果是一个 JSON
        - time，接受 1 个整数，视频播放进度时长，单位是：秒
        - watch_end，接受 0 或者 1，视频是否播放播放完毕，默认为 0，1 表示播放完毕
    6. "info"，获取文件信息，结果是一个 JSON

options:
  -h, --help            show this help message and exit
  -c COOKIES, --cookies COOKIES
                        cookies 字符串，优先级高于 -cp/--cookies-path
  -cp COOKIES_PATH, --cookies-path COOKIES_PATH
                        cookies 文件保存路径，默认为当前工作目录下的 115-cookies.txt
  -a APP_ID, --app-id APP_ID
                        115 开放接口的 AppID，默认为：100195123
  -rt REFRESH_TOKEN, --refresh-token REFRESH_TOKEN
                        刷新令牌，如果传入此值，则可以不传 --cookies/--cookies-path/--app-id
  -t TOKEN, --token TOKEN
                        签名所用的 token，如果提供，则请求必须携带签名，即 sign 查询参数
  -H HOST, --host HOST  ip 或 hostname，默认值：'0.0.0.0'
  -P PORT, --port PORT  端口号，默认值：8000，如果为 0 则自动确定
  -cu, --cache-url      缓存下载链接
  -d, --debug           启用调试，会输出更详细信息
  -uc UVICORN_RUN_CONFIG_PATH, --uvicorn-run-config-path UVICORN_RUN_CONFIG_PATH
                        uvicorn 启动时的配置文件路径，会作为关键字参数传给 `uvicorn.run`，支持 JSON、YAML 或 TOML 格式，会根据扩展名确定，不能确定时视为 JSON
  -v, --version         输出版本号
  -l, --license         输出授权信息
```
