"""INI-backed settings, in data/settings.ini next to the app. DEFAULTS seeds
every key so a missing/older INI file never KeyErrors."""

from __future__ import annotations

import configparser
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
SETTINGS_PATH = DATA_DIR / "settings.ini"

DEFAULTS = {
    "options": {
        "tooltips": "true",
        "backend": "m68k",
        "cache_context_window": "6",       # K instructions for jump-cache signature
        "pattern_strictness": "structural",  # exact | structural | loose
    },
    "paths": {
        "jump_cache": "data/jump_cache.json",
        "patterns": "data/patterns.json",
    },
}


def load(path: Path = SETTINGS_PATH) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_dict(DEFAULTS)
    if path.exists():
        cfg.read(path)
    return cfg


def save(cfg: configparser.ConfigParser, path: Path = SETTINGS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="ascii") as f:
        cfg.write(f)
