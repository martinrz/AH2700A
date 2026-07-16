from __future__ import annotations

import pytest

from revbench.analysis import blockeval

cs = pytest.importorskip("capstone")

from revbench.backends.m68k.backend import M68KBackend  # noqa: E402


@pytest.fixture(scope="module")
def backend():
    return M68KBackend()


def make_blob(addr: int, body: bytes, total_len: int) -> bytes:
    blob = bytearray(total_len)
    blob[addr:addr + len(body)] = body
    return bytes(blob)


def test_link_rts_is_likely_code(backend):
    # link a6,#0 ; rts
    body = bytes.fromhex("4E5600004E75")
    blob = make_blob(0x1000, body, 0x2000)
    result = blockeval.evaluate(backend, blob, 0x1000, len(body))
    assert result.verdict == blockeval.Verdict.LIKELY_CODE
    assert result.invalid_fraction == 0.0
    assert len(result.block.instructions) == 2


def test_fill_bytes_are_likely_data(backend):
    body = b"\xff" * 64
    blob = make_blob(0x1000, body, 0x2000)
    result = blockeval.evaluate(backend, blob, 0x1000, len(body))
    assert result.verdict == blockeval.Verdict.LIKELY_DATA
    assert result.fill_run_fraction > 0.5


def test_ascii_string_is_likely_data(backend):
    body = b"WIZARD ELBERETH\x00" * 4
    blob = make_blob(0x1000, body, 0x2000)
    result = blockeval.evaluate(backend, blob, 0x1000, len(body))
    assert result.verdict == blockeval.Verdict.LIKELY_DATA
    assert result.ascii_density > 0.85


def test_verdict_is_advisory_instructions_always_returned(backend):
    body = b"\xff" * 64
    blob = make_blob(0x1000, body, 0x2000)
    result = blockeval.evaluate(backend, blob, 0x1000, len(body))
    # even though verdict says "data", the raw (empty, since 0xFFFF decodes to
    # nothing valid here) instruction list is still populated when decodable --
    # the caller always gets the block, never just a verdict.
    assert result.block is not None
    assert result.block.start == 0x1000
