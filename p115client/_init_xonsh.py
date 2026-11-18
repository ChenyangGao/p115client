#!/usr/bin/env python3
# encoding: utf-8

try:
    # 或者 from xonsh.built_ins import XSH as _XSH
    _XSH = __xonsh__ # type: ignore
except NameError:
    pass
else:
    from p115client import P115Client
    from p115client.tool import *
    try:
        client = P115Client.from_path()
        fs = client.fs
    except OSError:
        pass

    def _load_magics():
        from collections.abc import Callable
        from functools import partial

        def alias(
            func: None | str | Callable = None, 
            /, 
            name: str = "", 
        ):
            if callable(func):
                if not name:
                    name = func.__name__
                _XSH.aliases[name] = func
                return func
            return partial(alias, name=name or func or "")

        from ._init_magics import __all__

        for name in __all__:
            exec(f"""\
@alias
def {name}(args, stdin=None):
    from ._init_magics import {name}
    client = _XSH.ctx["client"]
    return {name}(client, args)""", globals(), locals())

        print(f"检测到你正在使用 xonsh，已自动加载魔法函数 {__all__}")

    _load_magics()
    _XSH.ctx.update((k, v) for k, v in globals().items() if not k.startswith("_"))
