#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["parser", "main"]
__doc__ = "115 网盘扫码登录（网页版）"

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter

if __name__ == "__main__":
    from pathlib import Path  
    from sys import path

    path[0] = str(Path(__file__).parents[2])
    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
else:
    from .init import subparsers

    parser = subparsers.add_parser("web", description=__doc__, formatter_class=RawTextHelpFormatter)


def parse_args(argv: None | list[str] = None, /) -> Namespace:
    args = parser.parse_args(argv)
    if args.version:
        from p115qrcode import __version__
        print(".".join(map(str, __version__)))
        raise SystemExit(0)
    elif args.license:
        from p115qrcode import __license__
        print(__license__)
        raise SystemExit(0)
    return args


def main(argv: None | list[str] | Namespace = None, /):
    if isinstance(argv, Namespace):
        args = argv
    else:
        args = parse_args(argv)

    from time import sleep
    from _thread import start_new_thread
    from webbrowser import open as open_browser

    def open_url(url: str, /):
        sleep(1)
        open_browser(url)

    app = make_application(cors=args.cors)
    start_new_thread(open_url, (f"http://localhost:{args.port}",))
    app.run(host=args.host, port=args.port, debug=args.debug)


def make_application(
    import_name="p115qrcode", 
    cors: bool = False, 
    **init_kwargs, 
):
    from flask import request, Flask
    from p115qrcode import qrcode_result, qrcode_status, qrcode_token

    app = Flask(import_name, **init_kwargs)

    @app.get("/")
    def index():
        return """\
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>p115qrcode</title>
  <style>
    body {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100vh;
      background-color: #f0f0f0;
      margin: 0;
      padding: 0;
      font-family: Arial, sans-serif;
    }

    .top-container {
      display: flex;
      flex: 1;
      height: 700px;
      margin-top: 50px;
    }

    .top-item {
      flex: 1;
      justify-content: center;
      align-items: center;
      border: 1px solid #000;
      width: 300px;
    }

    .bottom-container {
      display: flex;
      flex: 1;
      justify-content: center;
      align-items: center;
      width: 560px;
    }

    .bottom-item {
      display: flex;
      flex: 1;
      justify-content: center;
      align-items: center;
    }

    .qrcode {
      text-align: center;
      padding: 20px;
      background-color: #ffffff;
      border-radius: 10px;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
      width: 200px;
      height: 310px;
    }

    .qrcode img {
      width: 200px;
      height: 200px;
      display: block;
    }

    .qrcode h2 {
      margin-bottom: 20px;
      color: #333;
    }

    select {
      width: 200px;
      padding: 10px;
      border: 1px solid #ccc;
      border-radius: 5px;
      background-color: #fff;
      background-size: 16px 16px;
      cursor: pointer;
      font-size: 16px;
      color: #333;
    }

    select:focus {
      border-color: #007BFF;
      outline: none;
      box-shadow: 0 0 5px rgba(0, 123, 255, 0.5);
    }

    .banner {
      width: 100%;
      background-color: #3498db;
      color: white;
      padding: 10px 0;
      text-align: center;
      font-size: 18px;
      font-weight: bold;
      position: fixed;
      top: 0;
      left: 0;
      z-index: 1000;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }

    .banner p {
      margin: 0;
      height: 20px
    }

    .code-container {
      position: relative;
    }

    .output-box {
      flex-grow: 1;
      border: 1px solid #ddd;
      border-radius: 4px;
      overflow-x: auto;
      word-wrap: break-word;
      width: 500px;
    }

    .copy-button {
      position: absolute;
      top: 0;
      right: 0;
      padding: 5px 5px;
      color: white;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      opacity: 0.7;
    }

    .copy-button:hover {
      opacity: 1;
      background-color: rgba(128, 128, 128, 0.5);
    }

    pre {
      overflow: scroll;
    }

    .json-container {
      height: 350px;
      min-width: 300px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
      border-radius: 8px;
      margin-left: 20px;
      overflow: scroll;
    }
  </style>
</head>
<body>
  <div class="banner">
    <p id="status"></p>
  </div>
  <div class="top-container">
    <div class="top-item qrcode">
      <h2>请扫码登录</h2>
      <img id="qrcode" src="" />
      <select id="app">
        <option value="web">web</option>
        <option value="ios">ios</option>
        <option value="115ios">115ios</option>
        <option value="android">android</option>
        <option value="115android">115android</option>
        <option value="115ipad">115ipad</option>
        <option value="tv">tv</option>
        <option value="qandroid">qandroid</option>
        <option value="wechatmini">wechatmini</option>
        <option value="alipaymini" selected>alipaymini</option>
        <option value="harmony">harmony</option>
      </select>
    </div>
    <div class="top-item code-container json-container">
      <pre><code class="language-json" id="result"><p style="font-size: 20px; display: flex; align-items: center; justify-content: center; height: 300px">这里将会输出响应</p></code></pre>
    </div>
  </div>
  <div class="bottom-container">
    <div class="bottom-item">
      <div class="code-container output-box">
        <pre><code class="language-config" id="cookie"><p style="font-size: 20px; display: flex; align-items: center; justify-content: center">这里将会输出 cookies</p></code></pre>
      </div>
    </div>
  </div>
  <script>
  var cors = """ + ("true" if cors else "false") +""";
  async function request(url, options={}) {
    const response = await fetch(url, options);
    if (!response.ok)
      throw new Error(`Request failed with status: ${response.status}, message: ${response.statusText}`);
    let data = await response.json();
    if (cors) {
        if (!data.state)
            throw new Error(`Request failed with message: ${JSON.stringify(data)}`);
        data = data.data;
    }
    return data;
  }

  async function loadQrcode() {
    const url = cors ? "https://qrcodeapi.115.com/api/1.0/web/1.0/token/" : "/api/token";
    const { sign, time, uid } = await request(url);
    document.getElementById("qrcode").src = `https://qrcodeapi.115.com/api/1.0/web/1.0/qrcode?uid=${uid}`;
    document.getElementById("status").textContent = "[status=0] qrcode: waiting";
    let status;
    while (true) {
      try {
        status = await loadStatus(sign, time, uid);
      } catch (e) {
        console.error(e);
        continue;
      }
      if (status == 2) {
        await loadResult(uid);
        return true;
      } else if ( status != 0 && status != 1 )
        return false;
    }
  }

  async function loadStatus(sign, time, uid) {
    const url = cors ? `https://qrcodeapi.115.com/get/status/?sign=${sign}&time=${time}&uid=${uid}` : `/api/status?sign=${sign}&time=${time}&uid=${uid}`;
    const { status } = await request(url);
    const statusElement = document.getElementById("status");
    switch (status) {
      case 0:
        statusElement.textContent = "[status=0] qrcode: waiting";
        break;
      case 1:
        statusElement.textContent = "[status=1] qrcode: scanned";
        break;
      case 2:
        statusElement.textContent = "[status=2] qrcode: signed in";
        break;
      case -1:
        statusElement.textContent = "[status=-1] qrcode: expired";
        break;
      case -2:
        statusElement.textContent = "[status=-2] qrcode: canceled";
        break;
      default:
        statusElement.textContent = `[status=${status}] qrcode: abort`;
    }
    return status
  }

  async function loadResult(uid) {
    const app = document.getElementById("app").value;
    let json;
    if (cors)
        json = await request(`https://qrcodeapi.115.com/app/1.0/${app}/1.0/login/qrcode/`, {
            method: "POST", 
            body: `account=${uid}`, 
            headers: {"Content-Type": "application/x-www-form-urlencoded"}, 
        });
    else
        json = await request(`/api/result?app=${app}&uid=${uid}`);
    document.getElementById("result").textContent = JSON.stringify(json, null, 2);
    document.getElementById("cookie").textContent = Object.entries(json.cookie).map(([k, v]) => `${k}=${v}`).join("; ");
    document.querySelectorAll('pre').forEach((block) => {
      // Create copy button
      let button = document.createElement('button');
      button.className = 'copy-button';
      button.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="icon icon-tabler icon-tabler-copy" width="25" height="25" viewBox="0 0 24 24" stroke-width="1.5" stroke="#000000" fill="none" stroke-linecap="round" stroke-linejoin="round">
  <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
  <rect x="8" y="8" width="12" height="12" rx="2" />
  <path d="M16 8v-2a2 2 0 0 0 -2 -2h-8a2 2 0 0 0 -2 2v8a2 2 0 0 0 2 2h2" />
</svg>`;
      block.parentElement.appendChild(button);

      button.addEventListener('click', () => {
        // Copy to clipboard
        navigator.clipboard.writeText(block.innerText).then(() => {
          button.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="icon icon-tabler icon-tabler-check" width="25" height="25" viewBox="0 0 24 24" stroke-width="2" stroke="#22863a" fill="none" stroke-linecap="round" stroke-linejoin="round">
  <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
  <path d="M5 12l5 5l10 -10" />
</svg>`;
          setTimeout(() => {
            button.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="icon icon-tabler icon-tabler-copy" width="25" height="25" viewBox="0 0 24 24" stroke-width="1.5" stroke="#000000" fill="none" stroke-linecap="round" stroke-linejoin="round">
  <path stroke="none" d="M0 0h24v24H0z" fill="none"/>
  <rect x="8" y="8" width="12" height="12" rx="2" />
  <path d="M16 8v-2a2 2 0 0 0 -2 -2h-8a2 2 0 0 0 -2 2v8a2 2 0 0 0 2 2h2" />
</svg>`;
          }, 2000);
        }).catch(err => {
          console.error('Failed to copy:', err);
        });
      });
    });
  }

  async function waitingForScan() {
    while (true) {
      try {
        if (await loadQrcode())
          break
      } catch (e) {
        console.error(e)
      }
    }
  }

  document.addEventListener('DOMContentLoaded', (event) => {
    waitingForScan();
  });
  </script>
</body>
</html>"""

    @app.get("/api/token")
    def get_token():
        return qrcode_token()

    @app.get("/api/status")
    def get_status():
        return qrcode_status(request.args)

    @app.get("/api/result")
    def get_result():
        return qrcode_result(request.args["uid"], request.args["app"])

    return app


parser.add_argument("-H", "--host", default="localhost", help="ip 或 hostname，默认值：'localhost'")
parser.add_argument("-P", "--port", default=8000, type=int, help="端口号，默认值：8000")
parser.add_argument("-c", "--cors", action="store_true", help="标识浏览器已经使用 CORS 插件，因此不需要后台代理接口的调用")
parser.add_argument("-d", "--debug", action="store_true", help="启用 debug 模式")
parser.add_argument("-l", "--license", action="store_true", help="输出授权信息")
parser.add_argument("-v", "--version", action="store_true", help="输出版本号")
parser.set_defaults(func=main)


if __name__ == "__main__":
    main()

