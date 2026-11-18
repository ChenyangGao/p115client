// :dep base64
// :dep once_cell
// :dep num-bigint
// :dep num-traits

use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use once_cell::sync::Lazy;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, Zero, Pow};
use reqwest::Client;
use std::collections::HashMap;
use std::fs::File;
use std::convert::Into;
use std::iter::Iterator;

// const { createServer, request, STATUS_CODES } = require("http");
// const { networkInterfaces } = require("os");
// const { extname } = require("path");
// const { parse, URL, URLSearchParams } = require("url");

const AUTHOR: &str = "ChenyangGao <https://chenyanggao.github.io>";
const LICENSE: &str = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>";
const VERSION: &str = "0.0.1";
const DOC: Lazy<String> = Lazy::new(|| {
    format!("usage: web_115_nano_302.rs [-h] [-c COOKIES] [-cp COOKIES_PATH] [-H HOST] [-P PORT] [-l] [-v]

    ╭────────────────────── \x1b[31mWelcome to \x1b[1mweb_115_nano_302.js\x1b[0m ────────────────────────╮
    │                                                                              │
    │  \x1b[35mmaintained by\x1b[0m \x1b[3;5;31m❤\x1b[0m     \x1b[32mChenyangGao \x1b[4;34mhttps://chenyanggao.github.io\x1b[0m               │
    │                                                                              │
    │                      \x1b[32mGithub      \x1b[4;34mhttps://github.com/ChenyangGao/p115client/\x1b[0m  │
    │                                                                              │
    │                      \x1b[32mlicense     \x1b[4;34mhttps://www.gnu.org/licenses/gpl-3.0.txt\x1b[0m    │
    │                                                                              │
    │                      \x1b[32mversion     \x1b[1;36m{}\x1b[0m                                       │
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
  -v, --version         输出版本号", &VERSION)
});
const G_kts: [u8; 144] = [
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
];
const RSA_E: Lazy<BigUint> = Lazy::new(|| {
    BigUint::from_bytes_be(b"\x86\x86\x98\x0c\x0f\x5a\x24\xc4\xb9\xd4\x30\x20\xcd\x2c\x22\x70\x3f\xf3\xf4\x50\x75\x65\x29\x05\x8b\x1c\xf8\x8f\x09\xb8\x60\x21\x36\x47\x71\x98\xa6\xe2\x68\x31\x49\x65\x9b\xd1\x22\xc3\x35\x92\xfd\xb5\xad\x47\x94\x4a\xd1\xea\x4d\x36\xc6\xb1\x72\xaa\xd6\x33\x8c\x3b\xb6\xac\x62\x27\x50\x2d\x01\x09\x93\xac\x96\x7d\x1a\xef\x00\xf0\xc8\xe0\x38\xde\x2e\x4d\x3b\xc2\xec\x36\x8a\xf2\xe9\xf1\x0a\x6f\x1e\xda\x4f\x72\x62\xf1\x36\x42\x0c\x07\xc3\x31\xb8\x71\xbf\x13\x9f\x74\xf3\x01\x0e\x3c\x4f\xe5\x7d\xf3\xaf\xb7\x16\x83")
});
const RSA_N: Lazy<BigUint> = Lazy::new(|| {
    FromPrimitive::from_u64(0x10001).unwrap()
});
const SHA1_TO_ID: Lazy<HashMap<String, String>> = Lazy::new(|| {
    HashMap::new()
});
const NAME_TO_ID: Lazy<HashMap<String, String>> = Lazy::new(|| {
    HashMap::new()
});
const SHARE_NAME_TO_ID: Lazy<HashMap<String, String>> = Lazy::new(|| {
    HashMap::new()
});
const RECEIVE_CODE_MAP: Lazy<HashMap<String, String>> = Lazy::new(|| {
    HashMap::new()
});

fn to_bytes(value: &BigUint, length: usize) -> Vec<u8> {
    let mut bytes = BigUint::to_bytes_be(value);
    let bytes_len = bytes.len();
    if length == 0 || length == bytes_len {
        bytes
    } else if bytes_len > length {
        bytes.truncate(length);
        bytes
    } else {
        let mut bytes_vec = vec![0u8; length - bytes_len];
        bytes_vec.extend(&bytes);
        bytes_vec
    }
}

fn from_bytes(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

struct AccStep {
    start: usize,
    stop: usize,
    step: usize
}

impl Iterator for AccStep {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.start;
        if start < self.stop {
            self.start += self.step;
            Some((start, self.start.min(self.stop)))
        } else {
            None
        }
    }
}

fn acc_step(
    start: usize, 
    stop: usize, 
    step: usize
) -> impl Iterator<Item = (usize, usize)> {
    return AccStep {start, stop, step};
}

fn bytes_xor(v1: &[u8], v2: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; v1.len()];
    for i in 0..v1.len() {
        result[i] = v1[i] ^ v2[i];
    }
    result
}

fn gen_key(rand_key: &[u8], sk_len: usize) -> Vec<u8> {
    let mut xor_key = vec![0u8; sk_len];
    let mut length = sk_len * (sk_len - 1);
    let mut index = 0;
    for i in 0..sk_len {
        let x = (rand_key[i] + G_kts[index]) & 0xff;
        xor_key[i] = G_kts[length] ^ x;
        length -= sk_len;
        index += sk_len;
    }
    xor_key
}

fn pad_pkcs_1v1_5(message: &[u8]) -> Vec<u8> {
    let msg_len = message.len();
    let mut buffer: Vec<u8> = vec![0u8; 128];
    let mut start = 127 - msg_len;
    for i in 1..start {
        buffer[i] = 0x02;
    }
    start += 1;
    for i in 0..msg_len {
        buffer[start+i] = message[i];
    }
    buffer
}

fn xor(src: &[u8], key: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0u8; src.len()];
    let i = src.len() & 0b11;
    if i > 0 {
        buffer[..i].copy_from_slice(&bytes_xor(&src[..i], &key[..i]));
    }
    for (j, k) in acc_step(i, src.len(), key.len()) {
        buffer[j..k].copy_from_slice(&bytes_xor(&src[j..k], key));
    }
    buffer
}

fn modpow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.is_one() {
        BigUint::zero()
    } else {
        base.modpow(exponent, modulus)
    }
}

fn encrypt(text: &str) -> String {
    let data = text.as_bytes();
    let mut tmp = xor(data, b"\x8d\xa5\xa5\x8d");
    tmp.reverse();
    let mut xor_data = vec![0u8; 16];
    xor_data.extend(xor(
        &tmp, 
        b"\x78\x06\xad\x4c\x33\x86\x5d\x18\x4c\x01\x3f\x46"
    ));
    let mut cipher_data = vec![0u8; ((xor_data.len() + 116) / 117) * 128];
    let mut start = 0;
    for (l, r) in acc_step(0, xor_data.len(), 117) {
        let p = modpow(&from_bytes(&pad_pkcs_1v1_5(&xor_data[l..r])), &RSA_N, &RSA_E);
        let slice = to_bytes(&p, 128);
        cipher_data[start..(start+128)].copy_from_slice(&slice);
        start += 128
    }
    STANDARD.encode(cipher_data)
}

fn decrypt(text: String) -> String {
    let cipher_data = STANDARD.decode(text);
    let mut data: Vec<u8> = Vec.new();
    for (l, r) in acc_step(0, cipher_data.len(), 128) {
        let p = modpow(&from_bytes(&cipher_data[l..r]), &RSA_N, &RSA_E);
        let b = to_bytes(p);
        data.extend(b[..(b.iter().position(0) + 1)]);
    }
    let key_l = gen_key(data[..16], 12);
    let mut tmp = xor(data[..16], key_l);
    tmp.revserse();
    return xor(tmp, b"\x8d\xa5\xa5\x8d").to_string()
}




async fn pickcode_to_id(pickcode: &str) -> usize {
    ...
}

async fn getPickcodeForSha1(sha1) {
    let pickcode = SHA1_TO_ID.get(sha1);
    if (pickcode) return pickcode;
    const response = await request115(`http://web.api.115.com/files/shasearch?sha1=${sha1}`);
    if (!response.state) throw new ErrorResponse(JSON.stringify(response), 503);
    SHA1_TO_ID.set(sha1, pickcode=response.data.pick_code);
    return pickcode;
}

async fn getPickcodeForName(name, refresh=false) {
    let pickcode;
    if (!refresh)
        if (pickcode = NAME_TO_ID.get(name))
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
    NAME_TO_ID.set(name, pickcode=info.pc);
    return pickcode;
}

async fn shareGetIdForName(share_code, receive_code, name, refresh=false) {
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

async fn getUrl(pickcode, user_agent="") {
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

async fn shareGetUrl(share_code, receive_code, file_id) {
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

async fn getReceiveCode(share_code) {
    let receive_code;
    if (receive_code = RECEIVE_CODE_MAP.get(share_code))
        return receive_code;
    const response = await request115(`http://web.api.115.com/share/shareinfo?share_code=${share_code}`);
    if (!response.state) throw new ErrorResponse(JSON.stringify(response), 503);
    RECEIVE_CODE_MAP.set(share_code, receive_code=response.data.receive_code);
    return receive_code;
}

fn getLocalIP() {
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
for (let i = 0; i < argv.len(); i++) {
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
            else if (receive_code.len() != 4)
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
