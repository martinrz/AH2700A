from __future__ import annotations

import struct

import pytest

from revbench.analysis import jumptrace
from revbench.core.cache import KeyedCache

cs = pytest.importorskip("capstone")

from revbench.backends.m68k.backend import M68KBackend  # noqa: E402


@pytest.fixture(scope="module")
def backend():
    return M68KBackend()


def build_switch_image(base_addr: int, total_len: int = 0x4000):
    """moveq #5,d0 ; jmp $2(pc,d0.w) ; <3-entry offset table>.

    The jmp is placed right after the moveq; disp=2 makes the switch table's
    `base` land exactly where the table entries start (base = jmp_addr + 2 +
    disp = jmp_addr + size-of-jmp = right after the jmp instruction).
    """
    blob = bytearray(total_len)
    moveq_addr = base_addr
    blob[moveq_addr:moveq_addr + 2] = bytes.fromhex("7005")  # moveq #5,d0

    jmp_addr = moveq_addr + 2
    blob[jmp_addr:jmp_addr + 4] = bytes.fromhex("4EFB0802")  # jmp $2(pc,d0.w)

    table_base = jmp_addr + 4
    offsets = [0x10, 0x20, 0x30]
    for i, off in enumerate(offsets):
        struct.pack_into(">h", blob, table_base + i * 2, off)
    targets = [table_base + off for off in offsets]

    return bytes(blob), moveq_addr, jmp_addr, targets


def decode_instructions(backend, blob, start, count):
    instrs = []
    addr = start
    for _ in range(count):
        insn = backend.disassemble_one(blob, addr)
        assert insn is not None
        instrs.append(insn)
        addr += insn.size
    return instrs


def test_static_switch_table_resolves_expected_targets(backend, tmp_path):
    blob, moveq_addr, jmp_addr, expected_targets = build_switch_image(0x1000)
    instrs = decode_instructions(backend, blob, moveq_addr, 2)  # moveq, jmp
    jump_index = 1

    cache = KeyedCache(tmp_path / "jump_cache.json")
    cj = jumptrace.resolve(backend, blob, instrs, jump_index, cache, image_name="test.bin")

    assert cj.resolved
    assert cj.resolution_source == "static_switch_table"
    assert [t.addr for t in cj.targets] == expected_targets


def test_cache_key_is_stable_across_address_drift(backend, tmp_path):
    """The same relative instruction sequence at two different base addresses
    (simulating the same routine shifted in a later firmware revision) must
    produce the SAME cache key, and the second resolve must be a cache hit."""
    blob_a, moveq_a, jmp_a, targets_a = build_switch_image(0x1000)
    blob_b, moveq_b, jmp_b, targets_b = build_switch_image(0x9000, total_len=0x10000)

    instrs_a = decode_instructions(backend, blob_a, moveq_a, 2)
    instrs_b = decode_instructions(backend, blob_b, moveq_b, 2)

    sig_a, count_a, len_a = jumptrace.context_signature(backend, instrs_a, 1)
    sig_b, count_b, len_b = jumptrace.context_signature(backend, instrs_b, 1)
    assert sig_a == sig_b
    assert count_a == count_b
    assert len_a == len_b

    cache = KeyedCache(tmp_path / "jump_cache.json")

    cj_a = jumptrace.resolve(backend, blob_a, instrs_a, 1, cache, image_name="v1.bin")
    assert cj_a.resolution_source == "static_switch_table"
    assert [t.addr - jmp_a for t in cj_a.targets] == [t - jmp_a for t in targets_a]

    cj_b = jumptrace.resolve(backend, blob_b, instrs_b, 1, cache, image_name="v2.bin")
    assert cj_b.resolution_source == "static_switch_table (from cache)"
    # relative offsets from the jump address must match -- same routine, shifted
    assert [t.addr - jmp_a for t in cj_a.targets] == [t.addr - jmp_b for t in cj_b.targets]

    key = jumptrace.cache_key(backend.name, backend.is_computed_jump(instrs_a[1]), sig_a)
    entry = cache.get(key)
    assert set(entry["seen_addrs"]) == {hex(jmp_a), hex(jmp_b)}


def test_dynamic_trace_outranks_static_heuristic(backend, tmp_path):
    blob, moveq_addr, jmp_addr, static_targets = build_switch_image(0x1000)
    instrs = decode_instructions(backend, blob, moveq_addr, 2)
    cache = KeyedCache(tmp_path / "jump_cache.json")

    observed_target = static_targets[0] + 0x100  # something the static heuristic would never find
    cj = jumptrace.resolve(backend, blob, instrs, 1, cache,
                            dynamic_targets={jmp_addr: [observed_target]}, image_name="live.bin")

    assert cj.resolution_source == "dynamic_trace"
    assert [t.addr for t in cj.targets] == [observed_target]
    assert cj.targets[0].confidence == 1.0


def test_manual_resolution_is_cached_and_reused(backend, tmp_path):
    blob, moveq_addr, jmp_addr, _ = build_switch_image(0x1000)
    instrs = decode_instructions(backend, blob, moveq_addr, 2)
    cache = KeyedCache(tmp_path / "jump_cache.json")

    manual_target = 0x1234
    cj = jumptrace.resolve_manual(backend, instrs, 1, cache, [manual_target], image_name="test.bin")
    assert cj.resolved
    assert cj.resolution_source == "manual"

    # a fresh resolve() call over the identical layout should now hit that cache entry
    cj2 = jumptrace.resolve(backend, blob, instrs, 1, cache, image_name="test.bin")
    assert cj2.resolution_source == "manual (from cache)"
    assert [t.addr for t in cj2.targets] == [manual_target]


def test_unresolvable_computed_jump_is_explicit_not_a_crash(backend, tmp_path):
    blob = bytearray(0x2000)
    blob[0x1000:0x1002] = bytes.fromhex("4ED0")  # jmp (a0) -- no static provenance available
    instrs = decode_instructions(backend, bytes(blob), 0x1000, 1)
    cache = KeyedCache(tmp_path / "jump_cache.json")

    cj = jumptrace.resolve(backend, bytes(blob), instrs, 0, cache, image_name="test.bin")
    assert cj.resolved is False
    assert cj.targets == []
    assert "needs a live/dynamic trace" in cj.notes
