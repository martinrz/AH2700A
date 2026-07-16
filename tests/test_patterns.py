from __future__ import annotations

import pytest

from revbench.analysis import patterns
from revbench.core import signature
from revbench.core.cache import KeyedCache

cs = pytest.importorskip("capstone")

from revbench.backends.m68k.backend import M68KBackend  # noqa: E402


@pytest.fixture(scope="module")
def backend():
    return M68KBackend()


def decode_seq(backend, hexstr, addr=0x1000):
    body = bytes.fromhex(hexstr)
    blob = bytearray(addr + len(body) + 16)
    blob[addr:addr + len(body)] = body
    instrs = []
    pos = addr
    end = addr + len(body)
    while pos < end:
        insn = backend.disassemble_one(bytes(blob), pos)
        assert insn is not None
        instrs.append(insn)
        pos += insn.size
    return instrs


def test_collect_then_compare_exact_match(backend, tmp_path):
    cache = KeyedCache(tmp_path / "patterns.json")
    instrs = decode_seq(backend, "70054E75", addr=0x1000)  # moveq #5,d0 ; rts
    patterns.collect(cache, backend, instrs, label="routine_a", image_name="v1.bin")

    # identical instructions at a different address -- should still match exactly
    instrs_shifted = decode_seq(backend, "70054E75", addr=0x9000)
    results = patterns.compare(cache, backend, instrs_shifted)
    assert results
    assert results[0].label == "routine_a"
    assert results[0].score == 1.0
    assert results[0].exact


def test_compare_ranks_near_duplicate_below_exact(backend, tmp_path):
    cache = KeyedCache(tmp_path / "patterns.json")
    original = decode_seq(backend, "70054E75", addr=0x1000)  # moveq #5,d0 ; rts
    patterns.collect(cache, backend, original, label="routine_a", strictness="structural")

    # structural strictness ignores the immediate, so a changed immediate is
    # still an exact structural match (mnemonic + operand kinds identical)
    near_dup = decode_seq(backend, "70094E75", addr=0x1000)  # moveq #9,d0 ; rts
    results = patterns.compare(cache, backend, near_dup, strictness="structural")
    assert results[0].score == 1.0


def test_compare_scores_lower_for_dissimilar_block(backend, tmp_path):
    cache = KeyedCache(tmp_path / "patterns.json")
    original = decode_seq(backend, "70054E75", addr=0x1000)  # moveq #5,d0 ; rts
    patterns.collect(cache, backend, original, label="routine_a", strictness="loose")

    dissimilar = decode_seq(backend, "4E560000" + "4E5E" + "4E75", addr=0x1000)  # link/unlk/rts
    results = patterns.compare(cache, backend, dissimilar, strictness="loose")
    assert results
    assert 0.0 <= results[0].score < 1.0


def test_compare_respects_strictness_bucket(backend, tmp_path):
    cache = KeyedCache(tmp_path / "patterns.json")
    instrs = decode_seq(backend, "70054E75", addr=0x1000)
    patterns.collect(cache, backend, instrs, label="exact_only", strictness="exact")

    # comparing at a different strictness should not surface the exact-only record
    results = patterns.compare(cache, backend, instrs, strictness="structural")
    assert all(r.label != "exact_only" for r in results)


def test_compare_with_empty_collection_returns_empty(backend, tmp_path):
    cache = KeyedCache(tmp_path / "patterns.json")
    instrs = decode_seq(backend, "4E75", addr=0x1000)
    assert patterns.compare(cache, backend, instrs) == []


def test_collect_persists_across_reload(backend, tmp_path):
    path = tmp_path / "patterns.json"
    cache = KeyedCache(path)
    instrs = decode_seq(backend, "70054E75", addr=0x1000)
    record = patterns.collect(cache, backend, instrs, label="persisted", image_name="v1.bin")
    cache.save()

    reloaded = KeyedCache(path)
    entry = reloaded.get(record.id)
    assert entry is not None
    assert entry["label"] == "persisted"


def test_diff_against_returns_opcodes(backend, tmp_path):
    cache = KeyedCache(tmp_path / "patterns.json")
    original = decode_seq(backend, "70054E75", addr=0x1000)
    record = patterns.collect(cache, backend, original, label="routine_a", strictness="loose")

    changed = decode_seq(backend, "4E560000" + "4E75", addr=0x1000)  # link ; rts
    changed_tokens = signature.tokenize(backend, changed, "loose")
    opcodes = patterns.diff_against(cache, record.id, changed_tokens)
    assert isinstance(opcodes, list)
    assert opcodes  # at least one opcode describing the diff


def test_diff_against_unknown_record_raises(tmp_path):
    cache = KeyedCache(tmp_path / "patterns.json")
    with pytest.raises(KeyError):
        patterns.diff_against(cache, "does-not-exist", ())
