"""The old name for `firegex.pyfilters`, kept working.

The feature is called pyfilters. It was called nfproxy when it was one of several
modules, and that name is at the top of every filter file anyone has already written —
including the ones sitting in a running firegex's database, which would stop loading the
moment the import failed. So the old path still resolves, and resolves to *the same
objects*.

That last part is the whole point, and why this is `sys.modules` aliasing rather than a
file of re-exports. `type_annotations_associations` maps model **classes** to protocols,
and both the library and the datapath decide when to call a filter by looking the
annotation up in that table. A shim that built second copies of `HttpRequest` and friends
would leave a filter written against the old path annotating a class the table has never
heard of: it would import cleanly and then never be called, or be refused as speaking an
unknown protocol. Aliasing the modules keeps one class per model, so `firegex.nfproxy`
and `firegex.pyfilters` are two spellings of one thing rather than two libraries.
"""

import sys

from firegex import pyfilters as _pyfilters

# Every submodule, under both names. Listed rather than walked: an explicit list is what
# makes it obvious at review time which import paths are promised to keep working, and a
# walk would quietly start promising whatever happened to be added next.
for _name in (
    "",
    ".models",
    ".models.http",
    ".models.tcp",
    ".internals",
    ".internals.data",
    ".internals.models",
    ".internals.exceptions",
    ".proxysim",
):
    _module = sys.modules.get("firegex.pyfilters" + _name)
    if _module is None:
        import importlib

        _module = importlib.import_module("firegex.pyfilters" + _name)
    sys.modules["firegex.nfproxy" + _name] = _module

# `firegex.nfproxy` itself is this module, not the aliased one, or `import firegex.nfproxy`
# would hand back a package whose `__name__` says pyfilters and whose docstring does not
# explain why. Its contents are the same objects either way.
from firegex.pyfilters import *  # noqa: F401,F403,E402
from firegex.pyfilters import __all__  # noqa: F401,E402
