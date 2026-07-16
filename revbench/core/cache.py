"""Generic JSON-backed keyed cache. Used both for the computed-jump
resolution cache (analysis/jumptrace.py) and the pattern collection store
(analysis/patterns.py) -- one storage abstraction, two uses.

JSON is deliberately chosen over e.g. sqlite: at lab scale (hundreds, not
millions, of entries) it stays human-diffable/greppable, which matters for a
reverse-engineering tool where a human will want to eyeball or hand-edit an
entry. Swapping to sqlite later would only mean rewriting this one file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Optional


class KeyedCache:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._data: dict[str, dict] = {}
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as f:
                self._data = json.load(f)
        else:
            self._data = {}
        self._loaded = True

    def get(self, key: str) -> Optional[dict]:
        self._ensure_loaded()
        return self._data.get(key)

    def put(self, key: str, entry: dict) -> None:
        self._ensure_loaded()
        self._data[key] = entry

    def keys(self):
        self._ensure_loaded()
        return list(self._data.keys())

    def __len__(self) -> int:
        self._ensure_loaded()
        return len(self._data)

    def save(self) -> None:
        self._ensure_loaded()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, sort_keys=True)

    def merge_from(self, other_path: Path | str,
                    winner: Callable[[dict, dict], dict] = None) -> int:
        """Union-merge entries from another cache file on disk into this one.
        On a key collision, `winner(existing, incoming)` picks which entry to
        keep (default: whichever has more `seen_addrs` provenance entries).
        Returns the number of keys added or replaced."""
        self._ensure_loaded()
        other_path = Path(other_path)
        if not other_path.exists():
            return 0
        with open(other_path, "r", encoding="utf-8") as f:
            incoming = json.load(f)

        if winner is None:
            winner = _prefer_more_provenance

        changed = 0
        for key, entry in incoming.items():
            if key not in self._data:
                self._data[key] = entry
                changed += 1
            else:
                chosen = winner(self._data[key], entry)
                if chosen is not self._data[key]:
                    self._data[key] = chosen
                    changed += 1
        return changed


def _prefer_more_provenance(existing: dict, incoming: dict) -> dict:
    existing_seen = len(existing.get("seen_addrs", []))
    incoming_seen = len(incoming.get("seen_addrs", []))
    return incoming if incoming_seen > existing_seen else existing
