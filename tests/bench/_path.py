"""Make `helpers` importable from a script run out of this directory.

These are standalone CLI tools rather than pytest modules, so nothing has arranged
`sys.path` for them. `import _path` at the top of one is the whole of the arrangement.
"""

import os
import sys

TESTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)
