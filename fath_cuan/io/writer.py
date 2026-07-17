from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_to_file(data: dict[str, Any], path: Path, filename: str) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    output_path = path / filename
    output_path.write_text(json.dumps(data, indent=2) + "\n")
    return output_path


def write_to_stdout(data: dict[str, Any]) -> None:
    print(json.dumps(data, indent=2))
