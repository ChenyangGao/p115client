#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__all__ = ["get_attr", "type_of_attr"]
__doc__ = "这个模块提供了一些和文件或目录信息有关的函数"

from collections.abc import Mapping
from typing import overload, Literal

from iterutils import run_gen_step
from p115client import check_response, normalize_attr_web, P115Client
from p115client.const import CLASS_TO_TYPE, SUFFIX_TO_TYPE
from posixpatht import splitext


@overload
def get_attr(
    client: str | P115Client, 
    id: int, 
    skim: bool = False, 
    *, 
    async_: Literal[False] = False, 
    **request_kwargs, 
) -> dict:
    ...
@overload
def get_attr(
    client: str | P115Client, 
    id: int, 
    skim: bool = False, 
    *, 
    async_: Literal[True], 
    **request_kwargs, 
) -> dict:
    ...
def get_attr(
    client: str | P115Client, 
    id: int, 
    skim: bool = False, 
    *, 
    async_: Literal[False, True] = False, 
    **request_kwargs, 
) -> dict:
    """获取文件或目录的信息

    :param client: 115 客户端或 cookies
    :param id: 文件或目录的 id
    :param skim: 是否获取简要信息（可避免风控）
    :param async_: 是否异步
    :param request_kwargs: 其它请求参数

    :return: 文件或目录的信息
    """
    if isinstance(client, str):
        client = P115Client(client, check_for_relogin=True)
    def gen_step():
        if skim:
            from dictattr import AttrDict
            resp = yield client.fs_file_skim(id, async_=async_, **request_kwargs)
            check_response(resp)
            info = resp["data"][0]
            return AttrDict(
                id=int(info["file_id"]), 
                name=info["file_name"], 
                pickcode=info["pick_code"], 
                sha1=info["sha1"], 
                size=int(info["file_size"]), 
                is_dir=not info["sha1"], 
            )
        else:
            resp = yield client.fs_file(id, async_=async_, **request_kwargs)
            check_response(resp)
            return normalize_attr_web(resp["data"][0])
    return run_gen_step(gen_step, may_call=False, async_=async_)


def type_of_attr(attr: Mapping, /) -> int:
    """推断文件信息所属类型（试验版，未必准确）

    :param attr: 文件信息

    :return: 返回类型代码

        - 0: 目录
        - 1: 文档
        - 2: 图片
        - 3: 音频
        - 4: 视频
        - 5: 压缩包
        - 6: 应用
        - 7: 书籍
        - 99: 其它文件
"""
    if attr.get("is_dir") or attr.get("is_directory"):
        return 0
    type: None | int
    if type := CLASS_TO_TYPE.get(attr.get("class", "")):
        return type
    if type := SUFFIX_TO_TYPE.get(splitext(attr["name"])[1].lower()):
        return type
    if attr.get("is_video") or "defination" in attr:
        return 4
    return 99

