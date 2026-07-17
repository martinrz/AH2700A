"""M68K static computed-jump resolution heuristics, distilled from
_claude/68000.md #6 (jump tables & switch statements).

Two are exposed as automatic `ISABackend.static_resolvers()` entries
(`resolve_pc_indexed_switch`, `resolve_pointer_table`); the dispatch/command
table scan (`scan_dispatch_table`) needs record-layout parameters a human
supplies, so it is called directly from the Jump Trace UI, not chained
automatically.
"""

from __future__ import annotations

import struct
from typing import Optional

import capstone.m68k as cs_m68k

from revbench.backends.m68k.backend import mem_base_reg, resolve_address_bias
from revbench.core.formats import printable_ascii_density
from revbench.core.isa import ComputedJumpKind, Instruction, ISABackend, ResolvedTarget

_MAX_SWITCH_ENTRIES = 256
_MAX_POINTER_ENTRIES = 64
_MAX_DISPATCH_ENTRIES = 256


def resolve_pc_indexed_switch(
    blob: bytes, backend: ISABackend, instructions: list[Instruction], jump_index: int
) -> Optional[list[ResolvedTarget]]:
    """68000.md #6: `move.w $base(pc,dN.w),dN ; jmp $base(pc,dN.w)`. The jump's
    own PC-relative displacement gives `base` directly; at `base` sits an
    array of 16-bit signed offsets, one per case, target = base + offset."""
    insn = instructions[jump_index]
    if backend.is_computed_jump(insn) != ComputedJumpKind.PC_INDEXED_SWITCH:
        return None
    ci = insn.backend_obj
    disp = None
    for op in ci.operands:
        if op.type == cs_m68k.M68K_OP_MEM and op.address_mode in (
            cs_m68k.M68K_AM_PCI_INDEX_8_BIT_DISP,
            cs_m68k.M68K_AM_PCI_INDEX_BASE_DISP,
            cs_m68k.M68K_AM_PC_MEMI_POST_INDEX,
            cs_m68k.M68K_AM_PC_MEMI_PRE_INDEX,
        ):
            disp = op.mem.disp
            break
    if disp is None:
        return None
    base = insn.address + 2 + disp

    targets: list[int] = []
    for i in range(_MAX_SWITCH_ENTRIES):
        off_bytes = blob[base + i * 2: base + i * 2 + 2]
        if len(off_bytes) < 2:
            break
        (offset,) = struct.unpack(">h", off_bytes)  # signed 16-bit
        if offset == 0:
            # A zero offset is treated as the end-of-table sentinel: real case
            # tables are vanishingly unlikely to target their own base, while
            # zero-filled padding after a short table reads as an endless run
            # of zero offsets. Without a bounds-check instruction to size the
            # table exactly (a further refinement), this is the practical stop
            # condition -- 68000.md flags this kind of judgment call as
            # needing a manual override when the heuristic guesses wrong.
            break
        target = base + offset
        if target < 0 or target >= len(blob) or target % 2 != 0:
            break  # 68000.md: bound the table by the first target that leaves the image
        targets.append(target)

    if len(targets) < 2:
        return None  # too few entries to trust this as a real table
    return [ResolvedTarget(addr=t, confidence=0.7, source="static_switch_table") for t in targets]


def resolve_pointer_table(
    blob: bytes, backend: ISABackend, instructions: list[Instruction], jump_index: int,
    lookback: int = 8,
) -> Optional[list[ResolvedTarget]]:
    """68000.md #6: a flat run of aligned longword code pointers, jsr/jmp'd via
    a register. Looks back a few instructions for a static load
    (`lea`/`movea`/`move` #imm or $abs.l) of the jump's base register, then
    scans forward from that address for a run of plausible code pointers."""
    insn = instructions[jump_index]
    if backend.is_computed_jump(insn) != ComputedJumpKind.REGISTER_INDIRECT:
        return None
    ci = insn.backend_obj
    base_reg = None
    for op in ci.operands:
        if op.type == cs_m68k.M68K_OP_MEM:
            base_reg = mem_base_reg(op)
            break
    if not base_reg:
        return None

    start = max(0, jump_index - lookback)
    table_base = None
    for prior in reversed(instructions[start:jump_index]):
        pci = prior.backend_obj
        if pci is None or not pci.operands:
            continue
        if prior.base_mnemonic not in ("lea", "movea", "move"):
            continue
        dest = pci.operands[-1]
        if dest.type != cs_m68k.M68K_OP_REG or dest.reg != base_reg:
            continue
        src = pci.operands[0]
        if src.type == cs_m68k.M68K_OP_MEM and src.address_mode in (
            cs_m68k.M68K_AM_ABSOLUTE_DATA_LONG, cs_m68k.M68K_AM_ABSOLUTE_DATA_SHORT,
        ):
            table_base = src.imm
        elif src.type == cs_m68k.M68K_OP_IMM:
            table_base = src.imm
        break  # first (nearest) write to base_reg wins or disqualifies

    if table_base is None:
        return None
    # disasm/findings.md "The address bias": a static table-base load is an
    # absolute operand, so it's as likely to carry the firmware's +0x100000
    # VBR-relocation bias as any jsr/bsr target -- resolve it the same way.
    table_base = resolve_address_bias(table_base, len(blob))
    if table_base is None:
        return None

    targets: list[int] = []
    for i in range(_MAX_POINTER_ENTRIES):
        word = blob[table_base + i * 4: table_base + i * 4 + 4]
        if len(word) < 4:
            break
        (raw_value,) = struct.unpack(">I", word)
        if raw_value == 0 or raw_value % 2 != 0:
            break
        value = resolve_address_bias(raw_value, len(blob))
        if value is None:
            break
        targets.append(value)

    if len(targets) < 3:
        return None  # 68000.md: a run of >=3 is the bar for "looks like a table"
    return [ResolvedTarget(addr=t, confidence=0.5, source="static_pointer_table") for t in targets]


def scan_dispatch_table(
    blob: bytes, base: int, stride: int, name_ptr_offset: int, handler_ptr_offset: int,
    max_entries: int = _MAX_DISPATCH_ENTRIES,
) -> list[ResolvedTarget]:
    """68000.md #6: command/dispatch tables -- records of {name_ptr, handler_ptr,
    ...}. Record layout (stride + offsets) is architecture-instance-specific,
    so a human supplies it (via the Jump Trace UI); this is not chained into
    `static_resolvers()`. Stops at the first record that doesn't look like a
    {ASCII name, in-range even code pointer} pair."""
    targets: list[ResolvedTarget] = []
    for i in range(max_entries):
        rec = base + i * stride
        name_bytes = blob[rec + name_ptr_offset: rec + name_ptr_offset + 4]
        handler_bytes = blob[rec + handler_ptr_offset: rec + handler_ptr_offset + 4]
        if len(name_bytes) < 4 or len(handler_bytes) < 4:
            break
        (raw_name_ptr,) = struct.unpack(">I", name_bytes)
        (raw_handler_ptr,) = struct.unpack(">I", handler_bytes)
        if raw_handler_ptr % 2 != 0:
            break
        name_ptr = resolve_address_bias(raw_name_ptr, len(blob))
        handler_ptr = resolve_address_bias(raw_handler_ptr, len(blob))
        if name_ptr is None or handler_ptr is None:
            break
        text = blob[name_ptr: name_ptr + 32]
        nul = text.find(b"\x00")
        candidate = text[:nul] if nul >= 0 else text
        if not candidate or printable_ascii_density(candidate) < 0.9:
            break
        targets.append(ResolvedTarget(addr=handler_ptr, confidence=0.6, source="static_dispatch_table"))
    return targets
