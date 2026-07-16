"""Ingest an external live/dynamic execution trace (addr,target pairs) so a
computed jump actually observed on real hardware/emulator resolves with
confidence 1.0, ahead of any static heuristic guess.

Format: CSV (`addr,target` per line, optional trailing columns ignored,
`#`-prefixed comment lines skipped) or JSON (a list of [addr, target] pairs
or {"addr": ..., "target": ...} objects). Addresses may be plain decimal or
0x-prefixed hex.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path


def load_trace(path: Path | str) -> dict[int, list[int]]:
    path = Path(path)
    pairs: list[tuple[int, int]] = []

    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        for row in data:
            if isinstance(row, dict):
                pairs.append((_to_int(row["addr"]), _to_int(row["target"])))
            else:
                pairs.append((_to_int(row[0]), _to_int(row[1])))
    else:
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if not row or row[0].strip().startswith("#"):
                    continue
                pairs.append((_to_int(row[0]), _to_int(row[1])))

    result: dict[int, list[int]] = {}
    for addr, target in pairs:
        bucket = result.setdefault(addr, [])
        if target not in bucket:
            bucket.append(target)
    return result


def _to_int(value) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text)
