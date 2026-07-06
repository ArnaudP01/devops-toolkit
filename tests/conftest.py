"""Pytest setup: make the standalone scripts importable as modules."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts" / "python"

# Allow `import password_gen`, `import log_analyzer`, etc. directly.
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
