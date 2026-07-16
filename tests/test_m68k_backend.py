"""Unit tests for the M68K backend, derived from the _claude/68000.md opcode
cheat-sheet -- each case is a hand-verified known-good test vector."""

from __future__ import annotations

import pytest

from revbench.backends.m68k.backend import M68KBackend
from revbench.core.isa import ComputedJumpKind, OperandKind

cs = pytest.importorskip("capstone")


@pytest.fixture(scope="module")
def backend():
    return M68KBackend()


def decode(backend, hexstr, addr=0x1000):
    # blob is indexed by absolute address (base 0), so place the instruction
    # bytes at `addr` with enough lookahead padding after it.
    insn_bytes = bytes.fromhex(hexstr)
    blob = bytearray(addr + len(insn_bytes) + 16)
    blob[addr:addr + len(insn_bytes)] = insn_bytes
    insn = backend.disassemble_one(bytes(blob), addr)
    assert insn is not None, f"failed to decode {hexstr!r}"
    return insn


def test_link_a6_is_function_prologue(backend):
    insn = decode(backend, "4E560000")
    assert insn.base_mnemonic == "link"
    assert backend.is_function_prologue([insn])


def test_unlk_is_not_prologue_or_return(backend):
    insn = decode(backend, "4E5E")
    assert not backend.is_function_prologue([insn])
    assert not backend.is_return(insn)


@pytest.mark.parametrize("hexstr", ["4E75", "4E73", "4E77"])  # rts / rte / rtr
def test_returns(backend, hexstr):
    insn = decode(backend, hexstr)
    assert backend.is_return(insn)
    assert backend.direct_targets(insn) == []


def test_jsr_absolute_is_call_with_static_target(backend):
    insn = decode(backend, "4EB9000012340000")
    assert backend.is_call(insn)
    assert backend.is_computed_jump(insn) is None
    assert backend.direct_targets(insn) == [0x1234]


def test_jmp_absolute_is_jump_with_static_target(backend):
    insn = decode(backend, "4EF9000012340000")
    assert backend.is_unconditional_jump(insn)
    assert backend.direct_targets(insn) == [0x1234]


def test_bsr_word_is_call_with_pc_relative_target(backend):
    insn = decode(backend, "61000010", addr=0x1000)
    assert backend.is_call(insn)
    # 68000.md: target = (instruction address + 2) + displacement
    assert backend.direct_targets(insn) == [0x1012]


def test_bra_word_is_unconditional_jump(backend):
    insn = decode(backend, "60000010", addr=0x1000)
    assert backend.is_unconditional_jump(insn)
    assert backend.direct_targets(insn) == [0x1012]


def test_beq_byte_is_conditional_branch(backend):
    insn = decode(backend, "6710", addr=0x1000)
    assert backend.is_conditional_branch(insn)
    assert backend.direct_targets(insn) == [0x1012]


def test_moveq_is_plain_instruction(backend):
    insn = decode(backend, "7005")
    assert not backend.is_call(insn)
    assert not backend.is_unconditional_jump(insn)
    assert not backend.is_conditional_branch(insn)
    assert not backend.is_return(insn)
    assert backend.is_computed_jump(insn) is None
    assert backend.direct_targets(insn) == []


def test_jmp_register_indirect_is_computed_unresolvable(backend):
    insn = decode(backend, "4ED0")  # jmp (a0)
    assert backend.is_unconditional_jump(insn)
    assert backend.is_computed_jump(insn) == ComputedJumpKind.REGISTER_INDIRECT
    assert backend.direct_targets(insn) is None


def test_jmp_displacement_indirect_is_computed_unresolvable(backend):
    insn = decode(backend, "4EE80010")  # jmp $10(a0)
    assert backend.is_computed_jump(insn) == ComputedJumpKind.REGISTER_INDIRECT
    assert backend.direct_targets(insn) is None


def test_jmp_pc_indexed_is_computed_switch_kind(backend):
    insn = decode(backend, "4EFB0800")  # jmp d8(pc,d0.w) -- switch-table dispatch pattern
    assert backend.is_computed_jump(insn) == ComputedJumpKind.PC_INDEXED_SWITCH
    assert backend.direct_targets(insn) is None


def test_jmp_pc_displacement_only_is_statically_resolvable(backend):
    insn = decode(backend, "4EFA0010", addr=0x1000)  # jmp $10(pc) -- no index register
    assert backend.is_computed_jump(insn) is None
    assert backend.direct_targets(insn) == [0x1012]


def test_cmpi_worked_listing_example(backend):
    # 68000.md worked example: 0C79 BE55 23FFFE -> cmpi.w #$be55, $23fffe.l
    insn = decode(backend, "0C79BE5500023FFFFE")
    assert insn.mnemonic.startswith("cmpi")
    assert not backend.is_call(insn)
    assert backend.direct_targets(insn) == []


def test_normalize_for_signature_keeps_only_immediates(backend):
    insn = decode(backend, "7005")  # moveq #5,d0
    mnemonic, immediates = backend.normalize_for_signature(insn)
    assert mnemonic == "moveq"
    assert immediates == (5,)


def test_normalize_for_signature_strips_absolute_addresses(backend):
    insn = decode(backend, "4EB9000012340000")  # jsr $1234.l -- address, not an immediate
    mnemonic, immediates = backend.normalize_for_signature(insn)
    assert mnemonic == "jsr"
    assert immediates == ()


def test_odd_address_never_decodes(backend):
    blob = bytearray(4)
    blob[1:3] = bytes.fromhex("4E75")
    assert backend.disassemble_one(bytes(blob), 1) is None


def test_vector_table_seeds_reads_even_in_range_longwords(backend):
    blob = bytearray(0x400 + 0x100)
    # vector 0: initial SSP -- an even value, but well outside the image, so
    # it must NOT be seeded (68000.md: only in-range longwords are candidates)
    blob[0:4] = (0x2000).to_bytes(4, "big")
    # vector 1: reset PC -- even and in range
    blob[4:8] = (0x400).to_bytes(4, "big")
    # an odd value should be excluded
    blob[8:12] = (0x401).to_bytes(4, "big")
    # an out-of-range value should be excluded
    blob[12:16] = (0xFFFFFF00).to_bytes(4, "big")
    seeds = backend.vector_table_seeds(bytes(blob))
    assert 0x2000 not in seeds
    assert 0x400 in seeds
    assert 0x401 not in seeds
    assert 0xFFFFFF00 not in seeds


def test_explain_never_crashes_on_any_decoded_instruction(backend):
    for hexstr in ["4E560000", "4E75", "7005", "4ED0"]:
        insn = decode(backend, hexstr)
        text = backend.explain(insn)
        assert isinstance(text, str) and text
