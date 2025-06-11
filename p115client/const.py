#!/usr/bin/env python3
# encoding: utf-8

from __future__ import annotations

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = [
    "AVAILABLE_APPS", "APP_TO_SSOENT", "SSOENT_TO_APP", "CLIENT_API_MAP", 
    "CLASS_TO_TYPE", "SUFFIX_TO_TYPE", "errno", 
]

from enum import IntEnum
from typing import Final


#: 目前可用的登录设备
AVAILABLE_APPS: Final[tuple[str, ...]] = (
    "web", "ios", "115ios", "android", "115android", "115ipad", "tv", "qandroid", 
    "windows", "mac", "linux", "wechatmini", "alipaymini", "harmony", 
)

#: 目前已知的登录设备和对应的 ssoent
APP_TO_SSOENT: Final[dict[str, str]] = {
    "web": "A1", 
    "desktop": "A1", # 临时
    "ios": "D1", 
    "bios": "D1", # 临时
    "115ios": "D3", 
    "android": "F1", 
    "bandroid": "F1", # 临时
    "115android": "F3", 
    "ipad": "H1", 
    "115ipad": "H3", 
    "tv": "I1", 
    "qandroid": "M1", 
    "qios": "N1", 
    "windows": "P1", 
    "mac": "P2", 
    "linux": "P3", 
    "wechatmini": "R1", 
    "alipaymini": "R2", 
    "harmony": "S1", 
}

#: 目前已知的 ssoent 和对应的登录设备，一部分因为不知道具体的设备名，所以使用目前可用的设备名，作为临时代替
SSOENT_TO_APP: Final[dict[str, str]] = {
    "A1": "web", 
    "A2": "android", # 临时代替
    "A3": "ios",     # 临时代替
    "A4": "115ipad", # 临时代替
    "B1": "android", # 临时代替
    "D1": "ios", 
    "D2": "ios",     # 临时代替
    "D3": "115ios",  
    "F1": "android", 
    "F2": "android", # 临时代替
    "F3": "115android", 
    "H1": "115ipad", # 临时代替
    "H2": "115ipad", # 临时代替
    "H3": "115ipad", 
    "I1": "tv", 
    "M1": "qandroid", 
    "N1": "ios",     # 临时代替
    "P1": "windows", 
    "P2": "mac", 
    "P3": "linux", 
    "R1": "wechatmini", 
    "R2": "alipaymini", 
    "S1": "harmony", 
}

#: 所有已封装的 115 接口以及对应的方法名
CLIENT_API_MAP: Final[dict[str, str]] = {}

#: 文件的 class 属性对应的所属类型的整数代码
CLASS_TO_TYPE: Final[dict[str, int]] = {
    "JG_DOC": 1, 
    "DOC": 1, 
    "JG_PIC": 2, 
    "PIC": 2, 
    "JG_MUS": 3, 
    "MUS": 3, 
    "JG_AVI": 4, 
    "AVI": 4, 
    "JG_RAR": 5, 
    "RAR": 5, 
    "RAR_EXTRACT": 5, 
    "JG_EXE": 6, 
    "EXE": 6, 
    "JG_BOOK": 7, 
    "BOOK": 7
}

#: 文件后缀对应的所属类型的整数代码（尚需补充）
SUFFIX_TO_TYPE: Final[dict[str, int]] = {
    ".ass": 1, 
    ".chm": 1, 
    ".doc": 1, 
    ".docm": 1, 
    ".docx": 1, 
    ".dotm": 1, 
    ".dot": 1, 
    ".dwg": 1, 
    ".htm": 1, 
    ".html": 1, 
    ".idx": 1, 
    ".jar": 1, 
    ".key": 1, 
    ".log": 1, 
    ".lrc": 1, 
    ".mdb": 1, 
    ".mdf": 1, 
    ".numbers": 1, 
    ".ods": 1, 
    ".odt": 1, 
    ".pages": 1, 
    ".pdf": 1, 
    ".pot": 1, 
    ".pps": 1, 
    ".ppt": 1, 
    ".pptm": 1, 
    ".pptx": 1, 
    ".rtf": 1, 
    ".srt": 1, 
    ".ssa": 1, 
    ".sub": 1, 
    ".torrent": 1, 
    ".txt": 1, 
    ".wps": 1, 
    ".wri": 1, 
    ".xlam": 1, 
    ".xls": 1, 
    ".xlsb": 1, 
    ".xlsm": 1, 
    ".xlsx": 1, 
    ".xltm": 1, 
    ".xltx": 1, 
    ".vtt": 1, 
    ".bmp": 2, 
    ".exif": 2, 
    ".gif": 2, 
    ".heic": 2, 
    ".heif": 2, 
    ".jpeg": 2, 
    ".jpg": 2, 
    ".png": 2, 
    ".raw": 2, 
    ".svg": 2, 
    ".tif": 2, 
    ".tiff": 2, 
    ".webp": 2, 
    ".aac": 3, 
    ".aiff": 3, 
    ".amr": 3, 
    ".ape": 3, 
    ".au": 3, 
    ".flac": 3, 
    ".m4a": 3, 
    ".mid": 3, 
    ".midi": 3, 
    ".mp3": 3, 
    ".ogg": 3, 
    ".wav": 3, 
    ".wma": 3, 
    ".3g2": 4, 
    ".3gp": 4, 
    ".3gp2": 4, 
    ".3gpp": 4, 
    ".asf": 4, 
    ".avi": 4, 
    ".dat": 4, 
    ".divx": 4, 
    ".f4v": 4, 
    ".flv": 4, 
    ".iso": 4, 
    ".m2ts": 4, 
    ".m4v": 4, 
    ".mkv": 4, 
    ".mov": 4, 
    ".mp4": 4, 
    ".mpe": 4, 
    ".mpeg": 4, 
    ".mpeg4": 4, 
    ".mpg": 4, 
    ".mts": 4, 
    ".ram": 4, 
    ".rm": 4, 
    ".rmvb": 4, 
    ".swf": 4, 
    ".ts": 4, 
    ".vob": 4, 
    ".webm": 4, 
    ".wmv": 4, 
    ".7z": 5, 
    ".cab": 5, 
    ".dmg": 5, 
    ".msi": 5, 
    ".rar": 5, 
    ".tar": 5, 
    ".xz": 5, 
    ".z": 5, 
    ".zip": 5, 
    ".apk": 6, 
    ".bat": 6, 
    ".deb": 6, 
    ".exe": 6, 
    ".ipa": 6, 
    ".pkg": 6, 
    ".azw": 7, 
    ".azw3": 7, 
    ".epub": 7, 
    ".fb2": 7, 
    ".lit": 7, 
    ".lrf": 7, 
    ".mobi": 7, 
    ".prc": 7, 
}

class errno(IntEnum):
    """OSError 的错误码的枚举

    .. admonition:: Reference

        https://docs.python.org/3/library/errno.html
    """
    EPERM = 1
    ENOENT = 2
    ESRCH = 3
    EINTR = 4
    EIO = 5
    ENXIO = 6
    E2BIG = 7
    ENOEXEC = 8
    EBADF = 9
    ECHILD = 10
    EAGAIN = 11
    ENOMEM = 12
    EACCES = 13
    EFAULT = 14
    ENOTBLK = 15
    EBUSY = 16
    EEXIST = 17
    EXDEV = 18
    ENODEV = 19
    ENOTDIR = 20
    EISDIR = 21
    EINVAL = 22
    ENFILE = 23
    EMFILE = 24
    ENOTTY = 25
    ETXTBSY = 26
    EFBIG = 27
    ENOSPC = 28
    ESPIPE = 29
    EROFS = 30
    EMLINK = 31
    EPIPE = 32
    EDOM = 33
    ERANGE = 34
    EDEADLK = 35
    ENAMETOOLONG = 36
    ENOLCK = 37
    ENOSYS = 38
    ENOTEMPTY = 39
    ELOOP = 40
    EWOULDBLOCK = 41
    ENOMSG = 42
    EIDRM = 43
    ECHRNG = 44
    EL2NSYNC = 45
    EL3HLT = 46
    EL3RST = 47
    ELNRNG = 48
    EUNATCH = 49
    ENOCSI = 50
    EL2HLT = 51
    EBADE = 52
    EBADR = 53
    EXFULL = 54
    ENOANO = 55
    EBADRQC = 56
    EBADSLT = 57
    EDEADLOCK = 58
    EBFONT = 59
    ENOSTR = 60
    ENODATA = 61
    ETIME = 62
    ENOSR = 63
    ENONET = 64
    ENOPKG = 65
    EREMOTE = 66
    ENOLINK = 67
    EADV = 68
    ESRMNT = 69
    ECOMM = 70
    EPROTO = 71
    EMULTIHOP = 72
    EDOTDOT = 73
    EBADMSG = 74
    EOVERFLOW = 75
    ENOTUNIQ = 76
    EBADFD = 77
    EREMCHG = 78
    ELIBACC = 79
    ELIBBAD = 80
    ELIBSCN = 81
    ELIBMAX = 82
    ELIBEXEC = 83
    EILSEQ = 84
    ERESTART = 85
    ESTRPIPE = 86
    EUSERS = 87
    ENOTSOCK = 88
    EDESTADDRREQ = 89
    EMSGSIZE = 90
    EPROTOTYPE = 91
    ENOPROTOOPT = 92
    EPROTONOSUPPORT = 93
    ESOCKTNOSUPPORT = 94
    EOPNOTSUPP = 95
    ENOTSUP = 96
    EPFNOSUPPORT = 97
    EAFNOSUPPORT = 98
    EADDRINUSE = 99
    EADDRNOTAVAIL = 100
    ENETDOWN = 101
    ENETUNREACH = 102
    ENETRESET = 103
    ECONNABORTED = 104
    ECONNRESET = 105
    ENOBUFS = 106
    EISCONN = 107
    ENOTCONN = 108
    ESHUTDOWN = 109
    ETOOMANYREFS = 110
    ETIMEDOUT = 111
    ECONNREFUSED = 112
    EHOSTDOWN = 113
    EHOSTUNREACH = 114
    EALREADY = 115
    EINPROGRESS = 116
    ESTALE = 117
    EUCLEAN = 118
    ENOTNAM = 119
    ENAVAIL = 120
    EISNAM = 121
    EREMOTEIO = 122
    EDQUOT = 123
    EQFULL = 124
    ENOMEDIUM = 125
    EMEDIUMTYPE = 126
    ENOKEY = 127
    EKEYEXPIRED = 128
    EKEYREVOKED = 129
    EKEYREJECTED = 130
    ERFKILL = 131
    ELOCKUNMAPPED = 132
    ENOTACTIVE = 133
    EAUTH = 134
    EBADARCH = 135
    EBADEXEC = 136
    EBADMACHO = 137
    EDEVERR = 138
    EFTYPE = 139
    ENEEDAUTH = 140
    ENOATTR = 141
    ENOPOLICY = 142
    EPROCLIM = 143
    EPROCUNAVAIL = 144
    EPROGMISMATCH = 145
    EPROGUNAVAIL = 146
    EPWROFF = 147
    EBADRPC = 148
    ERPCMISMATCH = 149
    ESHLIBVERS = 150
    ENOTCAPABLE = 151
    ECANCELED = 152
    EOWNERDEAD = 153
    ENOTRECOVERABLE = 154

    def of(key: int | str | errno, /) -> errno:
        if isinstance(key, errno):
            return key
        if isinstance(key, int):
            return errno(key)
        try:
            return errno[key]
        except KeyError as e:
            raise ValueError(key) from e

