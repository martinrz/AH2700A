from __future__ import annotations

import pytest

from revbench.gui import session as sessionmod


@pytest.fixture(autouse=True)
def isolated_sessions_root(tmp_path, monkeypatch):
    """Every test gets its own sessions root -- these functions must never
    touch the real projects/revbench/sessions/ directory during tests."""
    root = tmp_path / "sessions"
    monkeypatch.setattr(sessionmod, "SESSIONS_ROOT", root)
    monkeypatch.setattr(sessionmod, "REGISTRY_PATH", root / "registry.cfg")
    monkeypatch.setattr(sessionmod, "STRANDED_FILES_PATH", root / "stranded_files.txt")
    return root


@pytest.fixture
def fake_binary(tmp_path):
    path = tmp_path / "firmware.bin"
    path.write_bytes(b"\x00" * 32)
    return path


def test_create_or_reuse_project_creates_directory_and_copies_binary(fake_binary):
    entry = sessionmod.create_or_reuse_project(fake_binary, "AH2700A")
    assert entry.dir.is_dir()
    assert (entry.dir / entry.binary).read_bytes() == fake_binary.read_bytes()
    assert entry.binary == "firmware.bin"


def test_create_or_reuse_project_reuses_existing_directory(fake_binary):
    first = sessionmod.create_or_reuse_project(fake_binary, "AH2700A")
    second = sessionmod.create_or_reuse_project(fake_binary, "AH2700A")
    assert first.dir == second.dir


def test_create_or_reuse_project_writes_registry_entry(fake_binary):
    sessionmod.create_or_reuse_project(fake_binary, "AH2700A")
    projects = sessionmod.list_projects()
    assert len(projects) == 1
    assert projects[0].name == "AH2700A"


def test_create_or_reuse_project_writes_session_cfg(fake_binary):
    entry = sessionmod.create_or_reuse_project(fake_binary, "AH2700A")
    cfg_path = entry.dir / sessionmod.SESSION_CFG_NAME
    assert cfg_path.exists()
    reread = sessionmod.read_session_cfg(cfg_path)
    assert reread.name == "AH2700A"
    assert reread.binary == "firmware.bin"


def test_attach_listing_copies_file_and_updates_entry(fake_binary, tmp_path):
    entry = sessionmod.create_or_reuse_project(fake_binary, "AH2700A")
    listing_path = tmp_path / "firmware.lst"
    listing_path.write_text("; a listing\n")
    updated = sessionmod.attach_listing(entry, listing_path)
    assert updated.listing == "firmware.lst"
    assert (entry.dir / "firmware.lst").read_text() == "; a listing\n"


def test_list_projects_sorted_by_last_opened_descending(fake_binary, tmp_path):
    sessionmod.create_or_reuse_project(fake_binary, "OLDER")
    other_binary = tmp_path / "other.bin"
    other_binary.write_bytes(b"\x01" * 8)
    sessionmod.create_or_reuse_project(other_binary, "NEWER")
    sessionmod.touch_last_opened("NEWER")
    projects = sessionmod.list_projects()
    assert projects[0].name == "NEWER"


def test_register_from_session_cfg_round_trips(fake_binary):
    entry = sessionmod.create_or_reuse_project(fake_binary, "AH2700A")
    cfg_path = entry.dir / sessionmod.SESSION_CFG_NAME
    reregistered = sessionmod.register_from_session_cfg(cfg_path)
    assert reregistered.name == "AH2700A"
    assert reregistered.dir == entry.dir


def test_scan_stranded_files_flags_stray_file_outside_any_project(fake_binary, isolated_sessions_root):
    sessionmod.create_or_reuse_project(fake_binary, "AH2700A")
    stray = isolated_sessions_root / "leftover.bin"
    stray.write_bytes(b"\x00")
    stranded = sessionmod.scan_stranded_files()
    assert stray in stranded


def test_scan_stranded_files_does_not_flag_registered_project_dir(fake_binary):
    entry = sessionmod.create_or_reuse_project(fake_binary, "AH2700A")
    stranded = sessionmod.scan_stranded_files()
    assert entry.dir not in stranded


def test_scan_stranded_files_writes_manifest(fake_binary, isolated_sessions_root):
    sessionmod.create_or_reuse_project(fake_binary, "AH2700A")
    stray = isolated_sessions_root / "leftover.bin"
    stray.write_bytes(b"\x00")
    sessionmod.scan_stranded_files()
    assert sessionmod.STRANDED_FILES_PATH.exists()
    assert str(stray) in sessionmod.STRANDED_FILES_PATH.read_text()


def test_delete_stranded_files_removes_file(isolated_sessions_root):
    isolated_sessions_root.mkdir(parents=True, exist_ok=True)
    stray = isolated_sessions_root / "leftover.bin"
    stray.write_bytes(b"\x00")
    sessionmod.delete_stranded_files([stray])
    assert not stray.exists()


def test_delete_stranded_files_removes_directory(isolated_sessions_root):
    stray_dir = isolated_sessions_root / "orphaned_project"
    stray_dir.mkdir(parents=True)
    (stray_dir / "file.bin").write_bytes(b"\x00")
    sessionmod.delete_stranded_files([stray_dir])
    assert not stray_dir.exists()
