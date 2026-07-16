from __future__ import annotations

import pytest

from revbench.backends.m68k.semantics import ADDR_MODE_NOTES, SEMANTICS
from revbench.core.isa import OperandKind

cs = pytest.importorskip("capstone")

from revbench.backends.m68k.backend import M68KBackend  # noqa: E402


@pytest.fixture(scope="module")
def backend():
    return M68KBackend()


def decode(backend, hexstr, addr=0x1000):
    body = bytes.fromhex(hexstr)
    blob = bytearray(addr + len(body) + 16)
    blob[addr:addr + len(body)] = body
    insn = backend.disassemble_one(bytes(blob), addr)
    assert insn is not None
    return insn


CHEAT_SHEET_CASES = [
    ("4E560000", "link"),
    ("4E5E", "unlk"),
    ("4E75", "rts"),
    ("4E73", "rte"),
    ("4E77", "rtr"),
    ("4EB9000012340000", "jsr"),
    ("4EF9000012340000", "jmp"),
    ("61000010", "bsr"),
    ("60000010", "bra"),
    ("6710", "beq"),
    ("7005", "moveq"),
    ("0C79BE5500023FFFFE", "cmpi"),
]


@pytest.mark.parametrize("hexstr,expected_base", CHEAT_SHEET_CASES)
def test_explain_produces_real_description_for_seeded_mnemonics(backend, hexstr, expected_base):
    insn = decode(backend, hexstr)
    assert insn.base_mnemonic == expected_base
    text = backend.explain(insn)
    assert text
    assert "no semantic description available" not in text


def test_explain_fills_operand_placeholders():
    from revbench.core.isa import Instruction, InsnFlags, Operand

    insn = Instruction(
        address=0x1000, size=2, mnemonic="moveq", op_str="#5, d0",
        raw_bytes=b"\x70\x05",
        operands=(Operand(kind=OperandKind.IMMEDIATE, text="#$5", value=5),
                   Operand(kind=OperandKind.REG, text="d0", value=None)),
        flags=InsnFlags.NONE,
    )
    from revbench.core.isa import compose_explanation
    text = compose_explanation(insn, SEMANTICS)
    assert "#$5" in text
    assert "d0" in text


def test_explain_never_crashes_on_unseeded_mnemonic():
    from revbench.core.isa import Instruction, InsnFlags, compose_explanation

    insn = Instruction(address=0, size=2, mnemonic="dbra", op_str="d0, $2000",
                        raw_bytes=b"\x00\x00", operands=(), flags=InsnFlags.NONE)
    text = compose_explanation(insn, SEMANTICS)
    assert "no semantic description available" in text


def test_explain_falls_back_when_template_needs_more_operands_than_present():
    from revbench.core.isa import Instruction, InsnFlags, compose_explanation

    # CMPI's template references {op1} and {op2}, but this instruction only
    # carries one operand -- must degrade gracefully, never raise.
    insn = Instruction(address=0, size=2, mnemonic="cmpi.w", op_str="#$1",
                        raw_bytes=b"\x00\x00", operands=(), flags=InsnFlags.NONE)
    text = compose_explanation(insn, SEMANTICS)
    assert "no semantic description available" in text


def test_explain_operand_combines_text_and_addressing_mode_note(backend):
    insn = decode(backend, "4ED0")  # jmp (a0)
    text = backend.explain_operand(insn, 0)
    assert "(a0)" in text
    assert ADDR_MODE_NOTES[OperandKind.REGISTER_INDIRECT] in text


def test_explain_operand_out_of_range_returns_empty(backend):
    insn = decode(backend, "4E75")  # rts -- no operands
    assert backend.explain_operand(insn, 0) == ""


def test_every_operand_kind_has_an_addr_mode_note():
    for kind in OperandKind:
        assert kind in ADDR_MODE_NOTES
