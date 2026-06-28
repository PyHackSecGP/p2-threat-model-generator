"""Export ThreatModel to JSON."""
from __future__ import annotations
import dataclasses
import json
from pathlib import Path
from models import ThreatModel


def _serialize(obj):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)


def generate_json(tm: ThreatModel, output_path: str) -> None:
    data = dataclasses.asdict(tm)
    Path(output_path).write_text(
        json.dumps(data, indent=2, default=_serialize),
        encoding="utf-8",
    )
