"""Shared test configuration."""

import sys
from pathlib import Path

# Make the repo root importable so ``import otrs`` works without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# The FS07 comparison scheme needs libsodium; the design does not. Skip its
# tests rather than fail when the library is missing.
collect_ignore_glob = []
try:
    import fs07  # noqa: F401
    fs07.keygen()
except Exception:  # noqa: BLE001
    collect_ignore_glob.append("test_fs07*.py")
