#!/usr/bin/env node

const { readFileSync } = require("fs");
const { createServer, request, STATUS_CODES } = require("http");
const { networkInterfaces } = require("os");
const { extname } = require("path");
const { parse, URL, URLSearchParams } = require("url");

const AUTHOR = "ChenyangGao <https://chenyanggao.github.io>"
const LICENSE = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"
const VERSION = "0.0.7"
const DOC = `usage: web_115_nano_302.js [-h] [-c COOKIES] [-cp COOKIES_PATH] [-H HOST] [-P PORT] [-l] [-v]

    ╭────────────────────── \x1b[31mWelcome to \x1b[1mweb_115_nano_302.js\x1b[0m ────────────────────────╮
    │                                                                              │
    │  \x1b[35mmaintained by\x1b[0m \x1b[3;5;31m❤\x1b[0m     \x1b[32mChenyangGao \x1b[4;34mhttps://chenyanggao.github.io\x1b[0m               │
    │                                                                              │
    │                      \x1b[32mGithub      \x1b[4;34mhttps://github.com/ChenyangGao/p115client/\x1b[0m  │
    │                                                                              │
    │                      \x1b[32mlicense     \x1b[4;34mhttps://www.gnu.org/licenses/gpl-3.0.txt\x1b[0m    │
    │                                                                              │
    │                      \x1b[32mversion     \x1b[1;36m${VERSION}\x1b[0m                                       │
    │                                                                              │
    ╰──────────────────────────────────────────────────────────────────────────────╯

> 网盘文件支持用 \x1b[3;36mpickcode\x1b[0m、\x1b[3;36mid\x1b[0m、\x1b[3;36msha1\x1b[0m 或 \x1b[3;36mname\x1b[0m 查询
> 分享文件支持用 \x1b[3;36mid\x1b[0m 或 \x1b[3;36mname\x1b[0m 查询
> 支持参数 \x1b[3;36mrefresh\x1b[0m，用于搜索名字时忽略缓存（强制刷新）

🌰 查询示例：

    0. 查询 \x1b[3;36mpickcode\x1b[0m
        \x1b[4;34mhttp://localhost:8000?ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000/ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000?pickcode=ecjq9ichcb40lzlvx\x1b[0m
    1. 带（任意）名字查询 \x1b[3;36mpickcode\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?pickcode=ecjq9ichcb40lzlvx\x1b[0m
        \x1b[4;34mhttp://localhost:8000/ecjq9ichcb40lzlvx/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    2. 查询 \x1b[3;36mid\x1b[0m
        \x1b[4;34mhttp://localhost:8000?2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000/2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000?id=2691590992858971545\x1b[0m
    3. 带（任意）名字查询 \x1b[3;36mid\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?id=2691590992858971545\x1b[0m
        \x1b[4;34mhttp://localhost:8000/2691590992858971545/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    4. 查询 \x1b[3;36msha1\x1b[0m
        \x1b[4;34mhttp://localhost:8000?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
    5. 带（任意）名字查询 \x1b[3;36msha1\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv?sha1=E7FAA0BE343AF2DA8915F2B694295C8E4C91E691\x1b[0m
        \x1b[4;34mhttp://localhost:8000/E7FAA0BE343AF2DA8915F2B694295C8E4C91E691/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    6. 查询 \x1b[3;36mname\x1b[0m（直接以路径作为 \x1b[3;36mname\x1b[0m，且不要有 \x1b[3;36mpickcode\x1b[0m、\x1b[3;36mid\x1b[0m、\x1b[3;36msha1\x1b[0m 或 \x1b[3;36mname\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
        \x1b[4;34mhttp://localhost:8000?Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
        \x1b[4;34mhttp://localhost:8000?name=Novembre.2022.FRENCH.2160p.BluRay.DV.HEVC.DTS-HD.MA.5.1.mkv\x1b[0m
    7. 查询分享文件（如果是你自己的分享，则无须提供密码 \x1b[3;36mreceive_code\x1b[0m）
        \x1b[4;34mhttp://localhost:8000?share_code=sw68md23w8m&receive_code=q353&id=2580033742990999218\x1b[0m
        \x1b[4;34mhttp://localhost:8000?share_code=sw68md23w8m&id=2580033742990999218\x1b[0m
    8. 带（任意）名字查询分享文件（如果是你自己的分享，则无须提供密码 \x1b[3;36mreceive_code\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353&id=2580033742990999218\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&id=2580033742990999218\x1b[0m
    9. 用 \x1b[3;36mname\x1b[0m 查询分享文件（直接以路径作为 \x1b[3;36mname\x1b[0m，且不要有 \x1b[3;36mid\x1b[0m 查询参数。如果是你自己的分享，则无须提供密码 \x1b[3;36mreceive_code\x1b[0m）
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m&receive_code=q353\x1b[0m
        \x1b[4;34mhttp://localhost:8000/Cosmos.S01E01.1080p.AMZN.WEB-DL.DD+5.1.H.264-iKA.mkv?share_code=sw68md23w8m\x1b[0m
        \x1b[4;34mhttp://localhost:8000?name=Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m&receive_code=q353\x1b[0m
        \x1b[4;34mhttp://localhost:8000?name=Cosmos.S01E01.1080p.AMZN.WEB-DL.DD%2B5.1.H.264-iKA.mkv&share_code=sw68md23w8m\x1b[0m

options:
  -h, --help            show this help message and exit
  -c \x1b[1mCOOKIES\x1b[0m, --cookies \x1b[1mCOOKIES\x1b[0m
                        \x1b[3;36mcookies\x1b[0m 字符串
  -cp \x1b[1mCOOKIES_PATH\x1b[0m, --cookies-path \x1b[1mCOOKIES_PATH\x1b[0m
                        \x1b[3;36mcookies\x1b[0m 文件保存路径，默认为当前工作目录下的 \x1b[1;4;34m115-cookies.txt\x1b[0m
  -H \x1b[1mHOST\x1b[0m, --host \x1b[1mHOST\x1b[0m  \x1b[3;36mip\x1b[0m 或 \x1b[3;36mhostname\x1b[0m，默认值：\x1b[1;2m'0.0.0.0'\x1b[0m
  -P \x1b[1mPORT\x1b[0m, --port \x1b[1mPORT\x1b[0m  端口号，默认值：\x1b[1;36m8000\x1b[0m
  -l, --license         输出开源协议
  -v, --version         输出版本号`

const G_kts = new Uint8Array([
    0xf0, 0xe5, 0x69, 0xae, 0xbf, 0xdc, 0xbf, 0x8a, 
    0x1a, 0x45, 0xe8, 0xbe, 0x7d, 0xa6, 0x73, 0xb8, 
    0xde, 0x8f, 0xe7, 0xc4, 0x45, 0xda, 0x86, 0xc4, 
    0x9b, 0x64, 0x8b, 0x14, 0x6a, 0xb4, 0xf1, 0xaa, 
    0x38, 0x01, 0x35, 0x9e, 0x26, 0x69, 0x2c, 0x86, 
    0x00, 0x6b, 0x4f, 0xa5, 0x36, 0x34, 0x62, 0xa6, 
    0x2a, 0x96, 0x68, 0x18, 0xf2, 0x4a, 0xfd, 0xbd, 
    0x6b, 0x97, 0x8f, 0x4d, 0x8f, 0x89, 0x13, 0xb7, 
    0x6c, 0x8e, 0x93, 0xed, 0x0e, 0x0d, 0x48, 0x3e, 
    0xd7, 0x2f, 0x88, 0xd8, 0xfe, 0xfe, 0x7e, 0x86, 
    0x50, 0x95, 0x4f, 0xd1, 0xeb, 0x83, 0x26, 0x34, 
    0xdb, 0x66, 0x7b, 0x9c, 0x7e, 0x9d, 0x7a, 0x81, 
    0x32, 0xea, 0xb6, 0x33, 0xde, 0x3a, 0xa9, 0x59, 
    0x34, 0x66, 0x3b, 0xaa, 0xba, 0x81, 0x60, 0x48, 
    0xb9, 0xd5, 0x81, 0x9c, 0xf8, 0x6c, 0x84, 0x77, 
    0xff, 0x54, 0x78, 0x26, 0x5f, 0xbe, 0xe8, 0x1e, 
    0x36, 0x9f, 0x34, 0x80, 0x5c, 0x45, 0x2c, 0x9b, 
    0x76, 0xd5, 0x1b, 0x8f, 0xcc, 0xc3, 0xb8, 0xf5, 
]);
const RSA_e = 0x8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683n;
const RSA_n = 0x10001n;
const ID_TO_PICKCODE = new Map();
const SHA1_TO_PICKCODE = new Map();
const NAME_TO_PICKCODE = new Map();
const SHARE_NAME_TO_ID = new Map();
const RECEIVE_CODE_MAP = new Map();

function toBytes(value, length) {
    if (length == undefined)
        length = Math.ceil(value.toString(16).length / 2);
    const buffer = new Uint8Array(length);
    for (let i = length - 1; i >= 0; i--) {
        buffer[i] = Number(value & 0xffn);
        value >>= 8n;
    }
    return buffer;
}

function fromBytes(bytes) {
    let intVal = 0n;
    for (const b of bytes)
        intVal = (intVal << 8n) | BigInt(b);
    return intVal;
}

function* accStep(start, stop, step = 1) {
    for (let i = start + step; i < stop; i += step) {
        yield [start, i, step];
        start = i;
    }
    if (start !== stop)
        yield [start, stop, stop - start];
}

function bytesXor(v1, v2) {
    const result = new Uint8Array(v1.length);
    for (let i = 0; i < v1.length; i++)
        result[i] = v1[i] ^ v2[i];
    return result;
}

function genKey(randKey, skLen) {
    const xorKey = new Uint8Array(skLen);
    let length = skLen * (skLen - 1);
    let index = 0;
    for (let i = 0; i < skLen; i++) {
        const x = (randKey[i] + G_kts[index]) & 0xff;
        xorKey[i] = G_kts[length] ^ x;
        length -= skLen;
        index += skLen;
    }
    return xorKey;
}

function padPkcs1V1_5(message) {
    const msg_len = message.length
    const buffer = new Uint8Array(128);
    buffer.fill(0x02, 1, 127 - msg_len);
    buffer.set(message, 128 - msg_len);
    return buffer;
}

function xor(src, key) {
    const buffer = new Uint8Array(src.length);
    const i = src.length & 0b11;
    if (i)
        buffer.set(bytesXor(src.subarray(0, i), key.subarray(0, i)));
    for (const [j, k] of accStep(i, src.length, key.length))
        buffer.set(bytesXor(src.subarray(j, k), key), j);
    return buffer;
}

function pow(base, exponent, modulus) {
    if (modulus == undefined)
        return base ** exponent
    else if (modulus == 1n)
        return 0n;
    let result = 1n;
    base %= modulus;
    while (exponent) {
        if (exponent & 1n)
            result = (result * base) % modulus;
        exponent = exponent >> 1n;
        base = (base * base) % modulus;
    }
    return result;
}

function encrypt(data) {
    if (typeof data === "string" || data instanceof String)
        data = (new TextEncoder()).encode(data);
    const xorText = new Uint8Array(16 + data.length);
    xorText.set(xor(
        xor(data, new Uint8Array([0x8d, 0xa5, 0xa5, 0x8d])).reverse(), 
        new Uint8Array([0x78, 0x06, 0xad, 0x4c, 0x33, 0x86, 0x5d, 0x18, 0x4c, 0x01, 0x3f, 0x46])
    ), 16);
    const cipherData = new Uint8Array(Math.ceil(xorText.length / 117) * 128);
    let start = 0;
    for (const [l, r] of accStep(0, xorText.length, 117))
        cipherData.set(toBytes(pow(fromBytes(padPkcs1V1_5(xorText.subarray(l, r))), RSA_n, RSA_e), 128), start, start += 128);
    return Buffer.from(cipherData).toString("base64");
}

function decrypt(cipherData) {
    const cipher_data = new Uint8Array(Buffer.from(cipherData, "base64"));
    let data = [];
    for (const [l, r] of accStep(0, cipher_data.length, 128)) {
        const p = pow(fromBytes(cipher_data.subarray(l, r)), RSA_n, RSA_e);
        const b = toBytes(p);
        data.push(...b.subarray(b.indexOf(0) + 1));
    }
    data = new Uint8Array(data);
    const keyL = genKey(data.subarray(0, 16), 12);
    const tmp = xor(data.subarray(16), keyL).reverse();
    return (new TextDecoder("utf-8")).decode(xor(tmp, new Uint8Array([0x8d, 0xa5, 0xa5, 0x8d])));
}

class ErrorResponse extends Error {
    constructor(message, code=400) {
        super(message);
        this.code = code;
    }
}

async function request115(url, method="GET", headers=null, data=null) {
    const urlp = new URL(url);
    return new Promise((resolve, reject) => {
        const options = {
            hostname: urlp.hostname, 
            path: `${urlp.pathname}${urlp.search}`, 
            method: method, 
            headers: Object.assign({"Cookie": args.cookies}, headers), 
        };
        const req = request(options, (res) => {
            let data = "";
            res.on("data", (chunk) => {
                data += chunk;
            });
            res.on("end", () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    reject(data);
                }
            });
        });
        req.on("error", (e) => {
            reject(e);
        });
        if (data)
            req.write(data);
        req.end();
      });
}

async function getPickcodeToId(id) {
    let pickcode = ID_TO_PICKCODE.get(id);
    if (pickcode) return pickcode;
    const response = await request115(`http://web.api.115.com/files/file?file_id=${id}`);
    if (!response.state) throw new ErrorResponse(JSON.stringify(response), 503);
    ID_TO_PICKCODE.set(id, pickcode=response.data[0].pick_code);
    return pickcode;
}

async function getPickcodeForSha1(sha1) {
    let pickcode = SHA1_TO_PICKCODE.get(sha1);
    if (pickcode) return pickcode;
    const response = await request115(`http://web.api.115.com/files/shasearch?sha1=${sha1}`);
    if (!response.state) throw new ErrorResponse(JSON.stringify(response), 503);
    SHA1_TO_PICKCODE.set(sha1, pickcode=response.data.pick_code);
    return pickcode;
}

async function getPickcodeForName(name, refresh=false) {
    let pickcode;
    if (!refresh)
        if (pickcode = NAME_TO_PICKCODE.get(name))
            return pickcode;
    const api = "http://web.api.115.com/files/search";
    const payload = {"search_value": name, "limit": 1, "type": 99};
    const suffix = extname(name).toLowerCase();
    if (suffix && /^\.[0-9a-z]+$/.test(suffix))
        payload["suffix"] = suffix;
    let response = await request115(`${api}?${new URLSearchParams(payload).toString()}`);
    if (response.errno == 20021 || response.errNo == 20021) {
        delete payload.suffix;
        response = await request115(`${api}?${new URLSearchParams(payload).toString()}`);
    }
    if (!response.state) throw new ErrorResponse(JSON.stringify(response), 503);
    const info = response.data[0];
    if (!info || info.n != name)
        throw new ErrorResponse(`name not found: ${name}`, 404)
    NAME_TO_PICKCODE.set(name, pickcode=info.pc);
    return pickcode;
}

async function shareGetIdForName(share_code, receive_code, name, refresh=false) {
    const key = `${share_code}-${name}`;
    let id = SHARE_NAME_TO_ID.get(key);
    if (!refresh && id && id != "0")
        return id;
    const api = "http://web.api.115.com/share/search";
    const payload = {
        "share_code": share_code, 
        "receive_code": receive_code, 
        "search_value": name, 
        "limit": 1, 
        "type": 99, 
    }
    const suffix = extname(name).toLowerCase();
    if (suffix && /^\.[0-9a-z]+$/.test(suffix))
        payload["suffix"] = suffix;
    let response = await request115(`${api}?${new URLSearchParams(payload).toString()}`);
    if (response.errno == 20021 || response.errNo == 20021) {
        delete payload.suffix;
        response = await request115(`${api}?${new URLSearchParams(payload).toString()}`);
    }
    if (!response.state) throw new ErrorResponse(JSON.stringify(response), 503);
    const info = response.data.list[0];
    if (!info || info.n != name)
        throw new ErrorResponse(`name not found: ${name}`, 404)
    SHARE_NAME_TO_ID.set(key, id=info.fid);
    return id;
}

async function getUrl(pickcode, user_agent="") {
    const data = `data=${encodeURIComponent(encrypt(`{"pick_code":"${pickcode}"}`))}`;
    const response = await request115(
        `http://pro.api.115.com/android/2.0/ufile/download`, 
        "POST", 
        {"User-Agent": user_agent, "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(data)}, 
        data, 
    );
    if (!response.state) throw new ErrorResponse(JSON.stringify(response), 503);
    return JSON.parse(decrypt(response.data)).url
}

async function shareGetUrl(share_code, receive_code, file_id) {
    const data = `data=${encodeURIComponent(encrypt(`{"share_code":"${share_code}","receive_code":"${receive_code}","file_id":"${file_id}"}`))}`;
    const response = await request115(
        "http://pro.api.115.com/app/share/downurl", 
        "POST", 
        {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(data)}, 
        data, 
    );
    if (!response.state) {
        if (response.errno == 4100008 && RECEIVE_CODE_MAP.has(share_code)) {
            RECEIVE_CODE_MAP.delete(share_code);
            const receive_code = await getReceiveCode(share_code);
            return await shareGetUrl(share_code, receive_code, file_id);
        }
        throw new ErrorResponse(JSON.stringify(response), 503);
    }
    response.data = JSON.parse(decrypt(response.data));
    const urlInfo = response.data.url
    if (!urlInfo)
        throw new ErrorResponse(JSON.stringify(response), 404);
    return urlInfo.url;
}

async function getReceiveCode(share_code) {
    let receive_code;
    if (receive_code = RECEIVE_CODE_MAP.get(share_code))
        return receive_code;
    const response = await request115(`http://web.api.115.com/share/shareinfo?share_code=${share_code}`);
    if (!response.state) throw new ErrorResponse(JSON.stringify(response), 503);
    RECEIVE_CODE_MAP.set(share_code, receive_code=response.data.receive_code);
    return receive_code;
}

function getLocalIP() {
    let localIP;
    for (const iface of Object.values(networkInterfaces()))
        for (const address of iface)
            if (address.family === "IPv4" && !address.internal)
                if (localIP = address.address)
                    return localIP;
}

const args = {
    host: "0.0.0.0", 
    port: 8000, 
    cookies: null, 
};

const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
    switch(argv[i]) {
        case "-H":
        case "--host":
            args.host = argv[++i];
            break;
        case "-P":
        case "--port":
            args.port = Number.parseInt(argv[++i]);
            break;
        case "-c":
        case "--cookies":
            args.cookies = argv[++i].trim();
            break;
        case "-cp":
        case "--cookies-path":
            args.cookies = readFileSync(argv[++i], "latin1").trim();
            break;
        case "-v":
        case "--version":
            console.log(VERSION);
            process.exit(0);
        case "-l":
            case "--license":
                console.log(LICENSE);
                console.log(`  by ${AUTHOR}`);
                process.exit(0);
        case "-h":
        case "--help":
            console.log(DOC);
            process.exit(0);
    }
}

if (!args.cookies)
    args.cookies = readFileSync("115-cookies.txt", "latin1").trim();

const server = createServer(async (req, res) => {
    const [start_s, start_ns] = process.hrtime();
    let statusCode = 200;
    try {
        const urlp = parse(req.url, true);
        const query = (urlp.search || "").slice(1);
        const params = urlp.query;
        const share_code = params.share_code;
        const sha1 = (params.sha1 || "").toUpperCase();
        const refresh = params.refresh || false;
        const name = params.name;
        const name2 = decodeURIComponent((urlp.pathname || "").slice(1));
        let fileName = name || name2;
        let pickcode = (params.pickcode || "").toLowerCase();
        let id = params.id || "0";
        let url;
        if (share_code) {
            let receive_code = params["receive_code"];
            if (!receive_code)
                receive_code = await getReceiveCode(share_code);
            else if (receive_code.length != 4)
                throw new ErrorResponse(`bad receive_code: ${receive_code}`);
            if ((!id || id == "0") && fileName)
                id = await shareGetIdForName(share_code, receive_code, fileName, refresh);
            if (!id || id == "0")
                throw new ErrorResponse(`please specify id or name: share_code="${share_code}"`);
            url = await shareGetUrl(share_code, receive_code, id);
        } else {
            if (pickcode) {
                if (!/^[0-9a-z]{17}$/.test(pickcode))
                    throw new ErrorResponse(`bad pickcode: ${pickcode}`);
            } else if (id && id != "0")
                pickcode = await getPickcodeToId(id);
            else if (sha1) {
                if (!/^[0-9A-F]{40}$/.test(sha1))
                    throw new ErrorResponse(`bad sha1: ${sha1}`);
                pickcode = await getPickcodeForSha1(sha1);
            } else {
                const find = query.match(/^([^&=]+)(?=&|$)/);
                const idx = fileName.indexOf("/");
                let remains = "";
                if (find)
                    fileName = decodeURIComponent(find[1]);
                else if (!name && idx > 0) {
                    remains = fileName.slice(idx);
                    fileName = fileName.slice(0, idx);
                }
                if (fileName) {
                    if (/^[0-9a-zA-Z]{17}$/.test(fileName))
                        pickcode = fileName.toLowerCase();
                    else if (/^[0-9a-fA-F]{40}$/.test(fileName))
                        pickcode = await getPickcodeForSha1(fileName.toUpperCase());
                    else if (/^[1-9][0-9]+$/.test(fileName))
                        pickcode = await getPickcodeToId(fileName);
                    else
                        pickcode = await getPickcodeForName(fileName + remains, refresh)
                }
            }
            if (!pickcode)
                throw new ErrorResponse(`not found: ${urlp.pathname}${urlp.search || ""}`)
            url = await getUrl(pickcode, req.headers["user-agent"]);
        }
        statusCode = 302;
        res.writeHead(statusCode, { "location": url });
        res.end();
    } catch (e) {
        statusCode = e instanceof ErrorResponse ? e.code : 500;
        res.writeHead(statusCode, {"content-type": "text/plain; charset=utf-8"});
        res.end(e.message);
    } finally {
        const [stop_s, stop_ns] = process.hrtime();
        let statusColor;
        if (statusCode < 300)
            statusColor = 32;
        else if (statusCode < 400)
            statusColor = 33;
        else 
            statusColor = 31;
        const duration = (stop_s * 1000 + stop_ns / 1e6) - (start_s * 1000 + start_ns / 1e6);
        console.log(`[\x1b[1m${(new Date()).toISOString()}\x1b[0m] \x1b[5;35m${req.socket.remoteAddress}:${req.socket.remotePort}\x1b[0m - "\x1b[1;36m${req.method}\x1b[0m \x1b[1;4;34m${req.url}\x1b[0m \x1b[1mHTTP/${req.httpVersion}\x1b[0m" - \x1b[${statusColor}m${statusCode} ${STATUS_CODES[statusCode]}\x1b[0m - \x1b[32m${duration.toFixed(3)}\x1b[0m \x1b[3mms\x1b[0m`);
    }
});
server.listen(args.port, args.host, () => {
    console.log(DOC);
    console.log("\n * Serving \x1b[1mnodejs\x1b[0m app '\x1b[4;34mweb_115_nano_302.js\x1b[0m'")
    if (args.host == "0.0.0.0")
        console.log(" * Running on all addresses (\x1b[4;34m0.0.0.0\x1b[0m)")
    console.log(` * Running on \x1b[4;34mhttp://127.0.0.1:${args.port}\x1b[0m`)
    if (args.host == "0.0.0.0")
        console.log(` * Running on \x1b[4;34mhttp://${getLocalIP()}:${args.port}\x1b[0m`);
    else
        console.log(` * Running on \x1b[4;34mhttp://${args.host}:${args.port}\x1b[0m`);
    console.log("\x1b[33mPress CTRL+C to quit\x1b[0m")
});
