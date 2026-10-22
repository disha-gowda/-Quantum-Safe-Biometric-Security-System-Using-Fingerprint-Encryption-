"""Group encrypt/decrypt requires fingerprint AND face (see test_dual_factor.py)."""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

spec = importlib.util.spec_from_file_location(
    "test_dual_factor", Path(__file__).resolve().parent / "test_dual_factor.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.main()
