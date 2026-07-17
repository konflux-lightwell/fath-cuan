from __future__ import annotations

import json
import sys
from typing import Any, cast


def read_input(source: str | None) -> dict[str, Any]:
    if source is None or source == "-":
        raw = sys.stdin.read()
    else:
        with open(source) as f:
            raw = f.read()
    return cast(dict[str, Any], json.loads(raw))
