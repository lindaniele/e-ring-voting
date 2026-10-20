"""Shared test fixtures."""

import sys
from pathlib import Path

# Make the repo root importable so ``import trs`` works without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
