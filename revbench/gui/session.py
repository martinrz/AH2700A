"""Per-project session persistence: one directory per project (binary +
listing + session.cfg gathered together), a registry.cfg tracking every known
project for the startup resume dialog, and a stranded-file scan for the
Maintenance tab. Mirrors gui/config.py's configparser-based INI conventions.
"""

from __future__ import annotations

import configparser
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from revbench.gui import config as cfgmod

SESSIONS_ROOT = cfgmod.DATA_DIR.parent / "sessions"
REGISTRY_PATH = SESSIONS_ROOT / "registry.cfg"
STRANDED_FILES_PATH = SESSIONS_ROOT / "stranded_files.txt"

SESSION_CFG_NAME = "session.cfg"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ProjectEntry:
    name: str
    dir: Path
    binary: str
    listing: str = ""
    backend: str = "m68k"
    created: str = ""
    last_opened: str = ""


def _load_registry() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if REGISTRY_PATH.exists():
        cfg.read(REGISTRY_PATH)
    return cfg


def _save_registry(cfg: configparser.ConfigParser) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REGISTRY_PATH, "w", encoding="ascii") as f:
        cfg.write(f)


def _section_name(project_name: str) -> str:
    return f"project:{project_name}"


def list_projects() -> list[ProjectEntry]:
    cfg = _load_registry()
    entries = []
    for section in cfg.sections():
        if not section.startswith("project:"):
            continue
        name = section.split(":", 1)[1]
        s = cfg[section]
        entries.append(ProjectEntry(
            name=name, dir=Path(s.get("dir")), binary=s.get("binary", ""),
            listing=s.get("listing", ""), backend=s.get("backend", "m68k"),
            created=s.get("created", ""), last_opened=s.get("last_opened", ""),
        ))
    entries.sort(key=lambda e: e.last_opened, reverse=True)
    return entries


def _write_entry(entry: ProjectEntry) -> None:
    cfg = _load_registry()
    section = _section_name(entry.name)
    if not cfg.has_section(section):
        cfg.add_section(section)
    cfg[section]["dir"] = str(entry.dir)
    cfg[section]["binary"] = entry.binary
    cfg[section]["listing"] = entry.listing
    cfg[section]["backend"] = entry.backend
    cfg[section]["created"] = entry.created
    cfg[section]["last_opened"] = entry.last_opened
    _save_registry(cfg)


def touch_last_opened(project_name: str) -> None:
    cfg = _load_registry()
    section = _section_name(project_name)
    if cfg.has_section(section):
        cfg[section]["last_opened"] = _now()
        _save_registry(cfg)


def create_or_reuse_project(binary_path: Path, project_name: str, backend: str = "m68k") -> ProjectEntry:
    """If `project_name` is already registered, reuse its directory (and
    leave its files alone -- the caller re-opens what's already there).
    Otherwise create a fresh project directory and copy the binary in."""
    existing = {e.name: e for e in list_projects()}
    if project_name in existing:
        entry = existing[project_name]
        entry.last_opened = _now()
        _write_entry(entry)
        return entry

    project_dir = SESSIONS_ROOT / project_name
    project_dir.mkdir(parents=True, exist_ok=True)
    dest = project_dir / Path(binary_path).name
    if Path(binary_path).resolve() != dest.resolve():
        shutil.copy2(binary_path, dest)
    now = _now()
    entry = ProjectEntry(name=project_name, dir=project_dir, binary=dest.name,
                          backend=backend, created=now, last_opened=now)
    _write_entry(entry)
    write_session_cfg(entry)
    return entry


def attach_listing(entry: ProjectEntry, listing_path: Path) -> ProjectEntry:
    """Copy `listing_path` into the project's directory (if not already
    there) and record it on the project's registry entry."""
    dest = entry.dir / Path(listing_path).name
    if Path(listing_path).resolve() != dest.resolve():
        shutil.copy2(listing_path, dest)
    entry.listing = dest.name
    entry.last_opened = _now()
    _write_entry(entry)
    write_session_cfg(entry)
    return entry


def write_session_cfg(entry: ProjectEntry) -> None:
    """A per-project session.cfg redundant with registry.cfg, so a project
    directory copied/moved elsewhere is still self-describing and openable
    directly (registry.cfg only lives at the sessions root)."""
    cfg = configparser.ConfigParser()
    cfg["session"] = {
        "name": entry.name,
        "binary": entry.binary,
        "listing": entry.listing,
        "backend": entry.backend,
        "created": entry.created,
        "last_opened": entry.last_opened,
    }
    entry.dir.mkdir(parents=True, exist_ok=True)
    with open(entry.dir / SESSION_CFG_NAME, "w", encoding="ascii") as f:
        cfg.write(f)


def read_session_cfg(session_cfg_path: Path) -> ProjectEntry:
    cfg = configparser.ConfigParser()
    cfg.read(session_cfg_path)
    s = cfg["session"]
    return ProjectEntry(
        name=s.get("name"), dir=Path(session_cfg_path).resolve().parent,
        binary=s.get("binary", ""), listing=s.get("listing", ""),
        backend=s.get("backend", "m68k"), created=s.get("created", ""),
        last_opened=s.get("last_opened", ""),
    )


def register_from_session_cfg(session_cfg_path: Path) -> ProjectEntry:
    """Used by "Open session file...": register (or refresh) a project found
    by browsing to a session.cfg directly, e.g. one copied in from elsewhere."""
    entry = read_session_cfg(session_cfg_path)
    entry.last_opened = _now()
    _write_entry(entry)
    return entry


def scan_stranded_files() -> list[Path]:
    """Every path directly under SESSIONS_ROOT that isn't the registry, the
    manifest itself, or inside a directory a known project actually uses."""
    if not SESSIONS_ROOT.exists():
        return []
    known_dirs = {e.dir.resolve() for e in list_projects()}
    stranded: list[Path] = []
    for path in SESSIONS_ROOT.iterdir():
        if path.resolve() in {REGISTRY_PATH.resolve(), STRANDED_FILES_PATH.resolve()}:
            continue
        if path.is_dir() and path.resolve() in known_dirs:
            continue
        stranded.append(path)
    STRANDED_FILES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(STRANDED_FILES_PATH, "w", encoding="utf-8") as f:
        for path in stranded:
            f.write(str(path) + "\n")
    return stranded


def delete_stranded_files(paths: list[Path]) -> None:
    for path in paths:
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        elif path.exists():
            path.unlink()
