"""Feature 1a: instant range disassembly + code/data plausibility scoring.

Deliberately does NOT chase calls/branches outside the requested range -- that
recursive-descent-to-a-fixpoint job belongs to the external batch pipeline.
This is a fast "just this range, right now" view so a suspected block can be
eyeballed without re-running the whole batch. The verdict is always advisory:
the raw instruction table is shown regardless of what it says.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from revbench.core.formats import printable_ascii_density
from revbench.core.isa import Block, BlockKind, ISABackend, Instruction, InsnFlags


class Verdict(Enum):
    LIKELY_CODE = "likely_code"
    LIKELY_DATA = "likely_data"
    AMBIGUOUS = "ambiguous"


@dataclass
class BlockEvalResult:
    block: Block
    verdict: Verdict
    summary: str
    invalid_fraction: float
    ascii_density: float
    fill_run_fraction: float
    invalid_regions: list[tuple[int, int]] = field(default_factory=list)


def evaluate(backend: ISABackend, blob: bytes, addr: int, length: int) -> BlockEvalResult:
    end = addr + length
    instructions: list[Instruction] = []
    invalid_regions: list[tuple[int, int]] = []
    pos = addr
    invalid_bytes = 0
    invalid_run_start = None

    while pos < end:
        insn = backend.disassemble_one(blob, pos)
        if insn is None:
            invalid_bytes += 1
            if invalid_run_start is None:
                invalid_run_start = pos
            pos += 1
            continue
        if invalid_run_start is not None:
            invalid_regions.append((invalid_run_start, pos))
            invalid_run_start = None
        instructions.append(insn)
        pos += insn.size
        if insn.flags & InsnFlags.RETURN:
            break
        # A computed jump is flagged inline on the instruction (see
        # InsnFlags.COMPUTED) and surfaced in the Block tab for "Trace...";
        # it is not a stop condition here.

    if invalid_run_start is not None:
        invalid_regions.append((invalid_run_start, pos))

    total_bytes = max(1, pos - addr)
    invalid_fraction = invalid_bytes / total_bytes
    density = printable_ascii_density(blob[addr:end])
    fill_fraction = _fill_run_fraction(blob[addr:end])

    verdict, summary = _score(instructions, invalid_fraction, density, fill_fraction)
    kind = {Verdict.LIKELY_CODE: BlockKind.CODE,
            Verdict.LIKELY_DATA: BlockKind.DATA,
            Verdict.AMBIGUOUS: BlockKind.UNKNOWN}[verdict]

    block = Block(start=addr, end=pos, instructions=instructions, kind=kind, seed_reasons=["manual"])

    return BlockEvalResult(block=block, verdict=verdict, summary=summary,
                            invalid_fraction=invalid_fraction, ascii_density=density,
                            fill_run_fraction=fill_fraction, invalid_regions=invalid_regions)


def _fill_run_fraction(data: bytes) -> float:
    if not data:
        return 0.0
    longest = current = 0
    prev = None
    for b in data:
        is_fill = b in (0x00, 0xFF)
        current = current + 1 if (is_fill and b == prev) else (1 if is_fill else 0)
        longest = max(longest, current)
        prev = b
    return longest / len(data)


def _score(instructions: list[Instruction], invalid_fraction: float, density: float,
           fill_fraction: float) -> tuple[Verdict, str]:
    if invalid_fraction > 0.3 or fill_fraction > 0.5:
        return Verdict.LIKELY_DATA, (
            f"Likely data -- {invalid_fraction:.0%} invalid opcodes, "
            f"longest fill-byte run {fill_fraction:.0%} of range"
        )
    if density > 0.85:
        return Verdict.LIKELY_DATA, f"Likely data -- {density:.0%} printable-ASCII density"
    if invalid_fraction == 0.0 and instructions:
        return Verdict.LIKELY_CODE, f"Likely code -- {len(instructions)} instrs, 0 invalid opcodes"
    return Verdict.AMBIGUOUS, (
        f"Ambiguous -- {len(instructions)} instrs, {invalid_fraction:.0%} invalid opcodes, "
        f"{density:.0%} ASCII density"
    )
