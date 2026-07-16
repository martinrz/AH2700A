"""M68K ISABackend implementation, wrapping capstone's M68K decoder.

This is the ONLY file in the project allowed to import capstone. All the
classification logic here (call/jump/branch/return/computed-jump detection,
static target extraction, function-prologue recognition, vector-table seeds,
and signature normalization) is distilled from `_claude/68000.md`'s opcode
cheat-sheet and gotchas checklist -- see that file for the reasoning.
"""

from __future__ import annotations

import struct
from typing import Optional

import capstone as cs
import capstone.m68k as cs_m68k

from revbench.core.isa import (
    ComputedJumpKind,
    ISABackend,
    Instruction,
    InsnFlags,
    Operand,
    OperandKind,
)

# Addressing modes that resolve to a fixed address at disassembly time (no
# register value needed) -- everything else on a jsr/jmp is a computed jump.
_STATIC_ABSOLUTE_MODES = {cs_m68k.M68K_AM_ABSOLUTE_DATA_LONG, cs_m68k.M68K_AM_ABSOLUTE_DATA_SHORT}
_STATIC_PC_MODES = {cs_m68k.M68K_AM_PCI_DISP}

_CALL_MNEMONICS = {"jsr", "bsr"}
_UNCOND_JUMP_MNEMONICS = {"jmp", "bra"}
_RETURN_MNEMONICS = {"rts", "rte", "rtr"}

# capstone stores the base address register in `op.reg` for the plain
# (An)/(An)+/-(An) modes, but in `op.mem.base_reg` for displacement/indexed
# modes -- `op.mem.base_reg` reads as 0 (M68K_REG_INVALID) for the former,
# which looks like "no register" if you only check `op.mem.base_reg`.
_BASE_REG_IN_OP_REG_MODES = {
    cs_m68k.M68K_AM_REGI_ADDR,
    cs_m68k.M68K_AM_REGI_ADDR_POST_INC,
    cs_m68k.M68K_AM_REGI_ADDR_PRE_DEC,
}


def mem_base_reg(op) -> int:
    """Normalized base-register accessor for an M68K_OP_MEM operand --
    see _BASE_REG_IN_OP_REG_MODES above for why this can't just be
    `op.mem.base_reg` uniformly. Returns 0 (M68K_REG_INVALID) if there is
    genuinely no base register (e.g. absolute addressing)."""
    if op.address_mode in _BASE_REG_IN_OP_REG_MODES:
        return op.reg
    return op.mem.base_reg

_ADDR_MODE_TO_OPERAND_KIND = {
    cs_m68k.M68K_AM_REG_DIRECT_DATA: OperandKind.REG,
    cs_m68k.M68K_AM_REG_DIRECT_ADDR: OperandKind.REG,
    cs_m68k.M68K_AM_REGI_ADDR: OperandKind.REGISTER_INDIRECT,
    cs_m68k.M68K_AM_REGI_ADDR_POST_INC: OperandKind.REGISTER_INDIRECT,
    cs_m68k.M68K_AM_REGI_ADDR_PRE_DEC: OperandKind.REGISTER_INDIRECT,
    cs_m68k.M68K_AM_REGI_ADDR_DISP: OperandKind.DISPLACEMENT,
    cs_m68k.M68K_AM_AREGI_INDEX_8_BIT_DISP: OperandKind.INDEXED,
    cs_m68k.M68K_AM_AREGI_INDEX_BASE_DISP: OperandKind.INDEXED,
    cs_m68k.M68K_AM_MEMI_POST_INDEX: OperandKind.INDEXED,
    cs_m68k.M68K_AM_MEMI_PRE_INDEX: OperandKind.INDEXED,
    cs_m68k.M68K_AM_PC_MEMI_POST_INDEX: OperandKind.INDEXED,
    cs_m68k.M68K_AM_PC_MEMI_PRE_INDEX: OperandKind.INDEXED,
    cs_m68k.M68K_AM_ABSOLUTE_DATA_SHORT: OperandKind.ABSOLUTE,
    cs_m68k.M68K_AM_ABSOLUTE_DATA_LONG: OperandKind.ABSOLUTE,
    cs_m68k.M68K_AM_IMMEDIATE: OperandKind.IMMEDIATE,
    cs_m68k.M68K_AM_PCI_DISP: OperandKind.PC_RELATIVE,
    cs_m68k.M68K_AM_PCI_INDEX_8_BIT_DISP: OperandKind.PC_RELATIVE,
    cs_m68k.M68K_AM_PCI_INDEX_BASE_DISP: OperandKind.PC_RELATIVE,
    cs_m68k.M68K_AM_BRANCH_DISPLACEMENT: OperandKind.PC_RELATIVE,
}


class M68KBackend(ISABackend):
    name = "m68k"
    endian = "big"
    max_insn_len = 10  # move.l #imm32,$abs.l is the longest M68000 encoding

    def __init__(self) -> None:
        self._md = cs.Cs(cs.CS_ARCH_M68K, cs.CS_MODE_M68K_000 | cs.CS_MODE_BIG_ENDIAN)
        self._md.detail = True

    # --- decode -------------------------------------------------------------

    def disassemble_one(self, blob: bytes, addr: int) -> Optional[Instruction]:
        if addr % 2 != 0:
            return None  # odd address is never valid M68K code (68000.md gotcha #1)
        window = blob[addr:addr + self.max_insn_len]
        if not window:
            return None
        try:
            insns = list(self._md.disasm(window, addr, count=1))
        except cs.CsError:
            return None
        if not insns:
            return None
        ci = insns[0]
        if ci.id == 0:
            # capstone falls back to a "dc.w $xxxx" data placeholder (id=0)
            # for bytes it can't decode as a real M68K instruction, rather
            # than raising -- treat that the same as a decode failure.
            return None
        return self._to_instruction(ci)

    def _to_instruction(self, ci) -> Instruction:
        operands = tuple(self._to_operand(op, ci.address) for op in ci.operands)
        flags = self._classify_flags(ci, operands)
        return Instruction(
            address=ci.address,
            size=ci.size,
            mnemonic=ci.mnemonic,
            op_str=ci.op_str,
            raw_bytes=bytes(ci.bytes[:ci.size]),
            operands=operands,
            flags=flags,
            backend_obj=ci,
        )

    def _to_operand(self, op, insn_address: int) -> Operand:
        kind = _ADDR_MODE_TO_OPERAND_KIND.get(op.address_mode, OperandKind.OTHER)
        value: Optional[int] = None
        size: Optional[int] = None
        if op.type == cs_m68k.M68K_OP_IMM:
            value = op.imm
        elif op.type == cs_m68k.M68K_OP_MEM:
            if op.address_mode in _STATIC_ABSOLUTE_MODES:
                value = op.imm
            elif op.address_mode in _STATIC_PC_MODES or kind in (OperandKind.DISPLACEMENT, OperandKind.INDEXED, OperandKind.PC_RELATIVE):
                value = op.mem.disp
        elif op.type == cs_m68k.M68K_OP_BR_DISP:
            value = op.br_disp.disp
        text = self._render_operand_text(op, insn_address)
        return Operand(kind=kind, text=text, value=value, size=size)

    def _render_operand_text(self, op, insn_address: int) -> str:
        """Per-operand display text, used by the Feature 3 instruction
        tooltip (compose_explanation() fills {op1}/{op2}/... placeholders
        from this) as well as any UI that wants an operand-by-operand
        breakdown rather than capstone's single rendered op_str."""
        if op.type == cs_m68k.M68K_OP_REG:
            return self._md.reg_name(op.reg)
        if op.type == cs_m68k.M68K_OP_IMM:
            return f"#${op.imm:x}" if op.imm >= 0 else f"#{op.imm}"
        if op.type == cs_m68k.M68K_OP_BR_DISP:
            target = insn_address + 2 + op.br_disp.disp
            return f"${target:x}"
        if op.type == cs_m68k.M68K_OP_MEM:
            mode = op.address_mode
            mem = op.mem
            if mode in _STATIC_ABSOLUTE_MODES:
                return f"${op.imm:x}"
            if mode == cs_m68k.M68K_AM_REGI_ADDR:
                return f"({self._md.reg_name(mem_base_reg(op))})"
            if mode == cs_m68k.M68K_AM_REGI_ADDR_POST_INC:
                return f"({self._md.reg_name(mem_base_reg(op))})+"
            if mode == cs_m68k.M68K_AM_REGI_ADDR_PRE_DEC:
                return f"-({self._md.reg_name(mem_base_reg(op))})"
            if mode == cs_m68k.M68K_AM_REGI_ADDR_DISP:
                return f"${mem.disp:x}({self._md.reg_name(mem_base_reg(op))})"
            if mode in (cs_m68k.M68K_AM_AREGI_INDEX_8_BIT_DISP, cs_m68k.M68K_AM_AREGI_INDEX_BASE_DISP):
                index = self._md.reg_name(mem.index_reg) if mem.index_reg else "?"
                return f"${mem.disp:x}({self._md.reg_name(mem_base_reg(op))},{index})"
            if mode == cs_m68k.M68K_AM_PCI_DISP:
                target = insn_address + 2 + mem.disp
                return f"${target:x}(pc)"
            if mode in (cs_m68k.M68K_AM_PCI_INDEX_8_BIT_DISP, cs_m68k.M68K_AM_PCI_INDEX_BASE_DISP):
                index = self._md.reg_name(mem.index_reg) if mem.index_reg else "?"
                base = insn_address + 2 + mem.disp
                return f"${base:x}(pc,{index})"
        return "?"

    def _classify_flags(self, ci, operands: tuple[Operand, ...]) -> InsnFlags:
        base = ci.mnemonic.split(".", 1)[0]
        flags = InsnFlags.NONE
        if base in _CALL_MNEMONICS:
            flags |= InsnFlags.CALL
        elif base in _UNCOND_JUMP_MNEMONICS:
            flags |= InsnFlags.JUMP
        elif base.startswith("b") and base not in ("bra", "bsr") and cs_m68k.M68K_GRP_BRANCH_RELATIVE in ci.groups:
            flags |= InsnFlags.BRANCH
        if base in _RETURN_MNEMONICS:
            flags |= InsnFlags.RETURN
        if (flags & (InsnFlags.CALL | InsnFlags.JUMP)) and self._is_computed_operand(ci):
            flags |= InsnFlags.COMPUTED
        return flags

    @staticmethod
    def _is_computed_operand(ci) -> bool:
        for op in ci.operands:
            if op.type != cs_m68k.M68K_OP_MEM:
                continue
            if op.address_mode in _STATIC_ABSOLUTE_MODES or op.address_mode in _STATIC_PC_MODES:
                return False
            return True  # register-indirect / indexed / memory-indirect: needs a register value
        return False

    # --- classification predicates -------------------------------------------

    def is_call(self, insn: Instruction) -> bool:
        return bool(insn.flags & InsnFlags.CALL)

    def is_unconditional_jump(self, insn: Instruction) -> bool:
        return bool(insn.flags & InsnFlags.JUMP)

    def is_conditional_branch(self, insn: Instruction) -> bool:
        return bool(insn.flags & InsnFlags.BRANCH)

    def is_return(self, insn: Instruction) -> bool:
        return bool(insn.flags & InsnFlags.RETURN)

    def is_computed_jump(self, insn: Instruction) -> Optional[ComputedJumpKind]:
        if not (insn.flags & InsnFlags.COMPUTED):
            return None
        ci = insn.backend_obj
        for op in ci.operands:
            if op.type != cs_m68k.M68K_OP_MEM:
                continue
            if op.address_mode in (cs_m68k.M68K_AM_PCI_INDEX_8_BIT_DISP, cs_m68k.M68K_AM_PCI_INDEX_BASE_DISP,
                                    cs_m68k.M68K_AM_PC_MEMI_POST_INDEX, cs_m68k.M68K_AM_PC_MEMI_PRE_INDEX):
                return ComputedJumpKind.PC_INDEXED_SWITCH
            if op.address_mode in (cs_m68k.M68K_AM_REGI_ADDR, cs_m68k.M68K_AM_REGI_ADDR_POST_INC,
                                    cs_m68k.M68K_AM_REGI_ADDR_PRE_DEC, cs_m68k.M68K_AM_REGI_ADDR_DISP):
                return ComputedJumpKind.REGISTER_INDIRECT
            return ComputedJumpKind.MEMORY_INDIRECT
        return ComputedJumpKind.OTHER

    def direct_targets(self, insn: Instruction) -> Optional[list[int]]:
        if not (insn.flags & (InsnFlags.CALL | InsnFlags.JUMP | InsnFlags.BRANCH)):
            return []
        if insn.flags & InsnFlags.COMPUTED:
            return None
        ci = insn.backend_obj
        for op in ci.operands:
            if op.type == cs_m68k.M68K_OP_BR_DISP:
                # 68000.md: PC-relative branch target = (addr of extension word
                # base, i.e. instruction address + 2) + signed displacement.
                return [insn.address + 2 + op.br_disp.disp]
            if op.type == cs_m68k.M68K_OP_MEM:
                if op.address_mode in _STATIC_ABSOLUTE_MODES:
                    return [op.imm]
                if op.address_mode in _STATIC_PC_MODES:
                    return [insn.address + 2 + op.mem.disp]
        return None

    def is_function_prologue(self, window: list[Instruction]) -> bool:
        # 68000.md #3: `link a6,#n` is the fingerprint of a function entry.
        if not window:
            return False
        return window[0].base_mnemonic == "link"

    def vector_table_seeds(self, blob: bytes) -> list[int]:
        # 68000.md #2: 256 longwords at address 0; seed every even, in-range
        # one. Deduplicated (first-occurrence order) since unused vectors are
        # commonly all zero or all point at one shared default handler --
        # without this a real image can turn into hundreds of redundant
        # copies of the same seed address.
        seeds: list[int] = []
        seen: set[int] = set()
        table = blob[:0x400]
        for i in range(0, len(table) - 3, 4):
            (value,) = struct.unpack_from(">I", table, i)
            if value % 2 == 0 and 0 <= value < len(blob) and value not in seen:
                seen.add(value)
                seeds.append(value)
        return seeds

    def normalize_for_signature(self, insn: Instruction) -> tuple[str, tuple]:
        # 68000.md #9: hash mnemonic + immediates only; absolute addresses and
        # branch targets are stripped since they drift across firmware revisions.
        immediates = tuple(op.value for op in insn.operands if op.kind == OperandKind.IMMEDIATE)
        return (insn.base_mnemonic, immediates)

    def static_resolvers(self) -> list:
        from revbench.backends.m68k.jumptables import resolve_pc_indexed_switch, resolve_pointer_table
        return [resolve_pc_indexed_switch, resolve_pointer_table]

    # --- Feature 3: instruction tooltip ---------------------------------------

    def explain(self, insn: Instruction) -> str:
        from revbench.backends.m68k.semantics import SEMANTICS
        from revbench.core.isa import compose_explanation
        return compose_explanation(insn, SEMANTICS)

    def explain_operand(self, insn: Instruction, index: int) -> str:
        """Longer-hover / right-click detail for a single operand: its
        rendered text plus what its addressing mode means in plain English."""
        from revbench.backends.m68k.semantics import ADDR_MODE_NOTES
        if not (0 <= index < len(insn.operands)):
            return ""
        op = insn.operands[index]
        note = ADDR_MODE_NOTES.get(op.kind, "an addressing mode not yet described")
        return f"{op.text}: {note}"
