#!/usr/bin/env python3
# encoding: utf-8

__author__ = "ChenyangGao <https://chenyanggao.github.io>"
__version__ = (0, 2, 1)
__license__ = "GPLv3 <https://www.gnu.org/licenses/gpl-3.0.txt>"

__FALSE = False
if __FALSE:
    from .app import *

def __getattr__(attr, /):
    from importlib import import_module

    app = import_module('.app', package=__package__)
    all = {"__all__": app.__all__}
    for name in app.__all__:
        all[name] = getattr(app, name)
    globals().update(all)
    del globals()["__getattr__"]
    return getattr(app, attr)
