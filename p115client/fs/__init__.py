#!/usr/bin/env python3
# encoding: utf-8

if False:
    from .fs import *
    from .fs_base import *
    from .fs_share import *
    from .fs_zip import *

from importlib import import_module
from pathlib import Path

ns = globals()
__all__: list[str] = []
module_prefix = __name__ + "."
for path in Path(__path__[0]).glob("*.py"):
    if path.name.startswith(("_", "#")):
        continue
    module = import_module(module_prefix + path.stem)
    __all__.extend(module.__all__)
    for attr in module.__all__:
        ns[attr] = getattr(module, attr)

# TODO: 各种接口支持 app 参数
# TODO: 实现一下 fsspec 的各种方法，但不需要完全一致
