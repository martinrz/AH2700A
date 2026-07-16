from __future__ import annotations

from revbench.core.cache import KeyedCache


def test_put_get_roundtrip(tmp_path):
    cache = KeyedCache(tmp_path / "c.json")
    assert cache.get("missing") is None
    cache.put("k1", {"value": 1})
    assert cache.get("k1") == {"value": 1}
    assert len(cache) == 1


def test_save_and_reload(tmp_path):
    path = tmp_path / "c.json"
    cache = KeyedCache(path)
    cache.put("k1", {"value": 1})
    cache.save()

    reloaded = KeyedCache(path)
    assert reloaded.get("k1") == {"value": 1}
    assert len(reloaded) == 1


def test_merge_from_prefers_more_provenance(tmp_path):
    a_path, b_path = tmp_path / "a.json", tmp_path / "b.json"

    a = KeyedCache(a_path)
    a.put("shared", {"seen_addrs": ["0x1000"]})
    a.save()

    b = KeyedCache(b_path)
    b.put("shared", {"seen_addrs": ["0x1000", "0x5000", "0x9000"]})
    b.put("only_in_b", {"seen_addrs": []})
    b.save()

    a2 = KeyedCache(a_path)
    changed = a2.merge_from(b_path)
    assert changed == 2
    assert a2.get("shared")["seen_addrs"] == ["0x1000", "0x5000", "0x9000"]
    assert a2.get("only_in_b") is not None


def test_merge_from_missing_file_is_noop(tmp_path):
    cache = KeyedCache(tmp_path / "a.json")
    cache.put("k1", {"value": 1})
    changed = cache.merge_from(tmp_path / "does_not_exist.json")
    assert changed == 0
    assert len(cache) == 1
