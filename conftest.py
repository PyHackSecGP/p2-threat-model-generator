"""Make project modules importable without pip install (for pytest + CI)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
