#!/usr/bin/env python3
# encoding: utf-8

from ..util import *

if False:
    from .attr import *
    from .auth import *
    from .clouddownload import *
    from .download import *
    from .edit import *
    from .export_dir import *
    from .extract import *
    from .fs_files import *
    from .history import *
    from .iterdir import *
    from .iter_nodes import *
    from .life import *
    from .querydb import *
    from .tinydb import *
    from .updatedb import *
    from .upload import *
    from .xys import *

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

# TODO: 各种接口，除了能接受 id、pickcode、path、sha1，最好也能接受 attr（mapping）
