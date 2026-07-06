"""Pytest setup: auto-discover domain folders and make their scripts importable.

The repo is organized by use case (observability/, security/, ...), so we add every
top-level directory that contains a `.py` file to ``sys.path``. This keeps the tests
working no matter where a script lives.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for d in ROOT.iterdir():
    if not d.is_dir() or d.name.startswith(".") or d.name == "tests":
        continue
    if any(d.glob("*.py")):
        sys.path.insert(0, str(d))
