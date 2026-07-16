from __future__ import annotations

import struct

import pytest

from revbench.backends.m68k import jumptables

cs = pytest.importorskip("capstone")

from revbench.backends.m68k.backend import M68KBackend  # noqa: E402


@pytest.fixture(scope="module")
def backend():
    return M68KBackend()


def decode_seq(backend, hexstr, addr, total_len=0x6000):
    body = bytes.fromhex(hexstr)
    blob = bytearray(max(addr + len(body) + 0x1000, total_len))
    blob[addr:addr + len(body)] = body
    instrs, pos = [], addr
    end = addr + len(body)
    while pos < end:
        insn = backend.disassemble_one(bytes(blob), pos)
        assert insn is not None, f"failed to decode at {pos:#x}"
        instrs.append(insn)
        pos += insn.size
    return bytes(blob), instrs


def test_resolve_pointer_table_via_plain_register_indirect_jump(backend):
    """Regression test: capstone stores the base register in `op.reg` (not
    `op.mem.base_reg`) for the plain (An) addressing mode, which used to make
    resolve_pointer_table() read base_reg=0 (falsy) and bail out on exactly
    this -- the most common indirect-jump form, `jmp (a0)`."""
    table_addr = 0x3000
    # lea $3000.l,a0 ; jmp (a0)
    lea = "41F900003000"
    jmp = "4ED0"
    blob, instrs = decode_seq(backend, lea + jmp, addr=0x1000)

    blob = bytearray(blob)
    pointer_targets = [0x4000, 0x4010, 0x4020]
    for i, t in enumerate(pointer_targets):
        struct.pack_into(">I", blob, table_addr + i * 4, t)
    blob = bytes(blob)

    jump_index = 1  # the jmp (a0)
    result = jumptables.resolve_pointer_table(blob, backend, instrs, jump_index)
    assert result is not None
    assert [r.addr for r in result] == pointer_targets
    assert all(r.source == "static_pointer_table" for r in result)


def test_resolve_pointer_table_returns_none_without_a_preceding_load(backend):
    _, instrs = decode_seq(backend, "4ED0", addr=0x1000)  # jmp (a0), nothing before it
    blob = bytes(0x2000)
    assert jumptables.resolve_pointer_table(blob, backend, instrs, 0) is None


def test_resolve_pointer_table_returns_none_for_short_runs(backend):
    table_addr = 0x3000
    blob, instrs = decode_seq(backend, "41F900003000" + "4ED0", addr=0x1000)
    blob = bytearray(blob)
    # only 2 valid-looking pointers -- below the ">= 3" bar
    struct.pack_into(">I", blob, table_addr, 0x4000)
    struct.pack_into(">I", blob, table_addr + 4, 0x4010)
    struct.pack_into(">I", blob, table_addr + 8, 0)  # terminator
    assert jumptables.resolve_pointer_table(bytes(blob), backend, instrs, 1) is None
