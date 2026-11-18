#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 0, 9)

if False:
    from .client import *
    from .const import *
    from .exception import *
    from .fs import *
    from .tool import *
    from .type import *
    from .util import *

from importlib import import_module
from importlib.machinery import all_suffixes
from pathlib import Path

ns = globals()
__all__: list[str] = []
for path in Path(__path__[0]).glob("*.py"):
    if path.name.startswith(("_", "#")):
        continue
    if path.is_symlink():
        continue
    elif path.is_file(follow_symlinks=False) and path.suffix not in all_suffixes():
        continue
    module = import_module("." + path.stem, __name__)
    __all__.extend(module.__all__)
    for attr in module.__all__:
        ns[attr] = getattr(module, attr)

from . import _init_ipython, _init_xonsh
del _init_ipython, _init_xonsh
