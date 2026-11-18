#!/usr/bin/env python3
# encoding: utf-8

try:
    _ipython = get_ipython() # type: ignore
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
        from IPython.core.magic import register_line_magic

        from ._init_magics import __all__

        for name in __all__:
            exec(f"""\
@register_line_magic
def {name}(line):
    from ._init_magics import {name}
    client = _ipython.user_ns["client"]
    return {name}(client, line)""", globals(), locals())

        print(f"检测到你正在使用 ipython，已自动加载魔法函数 {__all__}")

    _load_magics()
    _ipython.user_ns.update((k, v) for k, v in globals().items() if not k.startswith("_"))
