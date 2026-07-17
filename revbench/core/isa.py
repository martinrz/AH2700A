"""ISA-agnostic core data model.

Every feature (block eval, jump trace, formats, patterns, tooltips) is built
against `ISABackend` and the dataclasses below -- never against capstone or
any other decoder library directly. A future backend (ARM, x86, ...) only
needs to implement `ISABackend`; nothing in core/, analysis/, or gui/ changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Flag, auto, Enum
from typing import Any, Iterator, Optional


class OperandKind(Enum):
    REG = "reg"
    IMMEDIATE = "immediate"
    ABSOLUTE = "absolute"
    DISPLACEMENT = "displacement"
    INDEXED = "indexed"
    PC_RELATIVE = "pc_relative"
    REGISTER_INDIRECT = "register_indirect"
    OTHER = "other"          # escape hatch for anything a backend can't classify yet


class InsnFlags(Flag):
    NONE = 0
    CALL = auto()
    JUMP = auto()
    BRANCH = auto()          # conditional branch
    RETURN = auto()
    COMPUTED = auto()        # target is not a static literal (register/memory-indirect)


class ComputedJumpKind(Enum):
    PC_INDEXED_SWITCH = "pc_indexed_switch"
    REGISTER_INDIRECT = "register_indirect"
    MEMORY_INDIRECT = "memory_indirect"
    OTHER = "other"


class BlockKind(Enum):
    CODE = "code"
    DATA = "data"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Operand:
    kind: OperandKind
    text: str                       # backend's rendered operand text, e.g. "d0", "$8(a6)"
    value: Optional[int] = None     # resolved numeric value when it means something (immediate/absolute)
    size: Optional[int] = None      # operand width in bytes, if known


@dataclass(frozen=True)
class Instruction:
    address: int
    size: int                       # bytes consumed
    mnemonic: str                   # full mnemonic incl. size suffix, e.g. "move.l"
    op_str: str                     # backend's rendered operand string (for display)
    raw_bytes: bytes
    operands: tuple[Operand, ...] = field(default_factory=tuple)
    flags: InsnFlags = InsnFlags.NONE
    backend_obj: Any = None         # raw backend-native decode result (e.g. capstone CsInsn)

    @property
    def base_mnemonic(self) -> str:
        """Mnemonic with any size suffix stripped, e.g. 'move.l' -> 'move'."""
        return self.mnemonic.split(".", 1)[0]


@dataclass
class Block:
    start: int
    end: int
    instructions: list[Instruction] = field(default_factory=list)
    kind: BlockKind = BlockKind.UNKNOWN
    seed_reasons: list[str] = field(default_factory=list)


@dataclass
class ResolvedTarget:
    addr: int
    confidence: float               # 0.0-1.0
    source: str                     # "static_switch_table" | "dynamic_trace" | "manual" | ...


@dataclass
class ComputedJump:
    address: int
    kind: ComputedJumpKind
    context_sig: str = ""           # hash of the normalized instruction window ending at this jump
    resolved: bool = False
    targets: list[ResolvedTarget] = field(default_factory=list)
    resolution_source: str = ""
    notes: str = ""                 # e.g. "base computed at runtime; needs a live/dynamic trace"


class ISABackend(ABC):
    """Interface every architecture backend implements. Only backends/<arch>/
    may import a real decoder library (e.g. capstone) -- core/ and analysis/
    only ever talk to this interface."""

    name: str = ""
    endian: str = "big"             # "big" | "little"
    max_insn_len: int = 1           # lookahead bytes to feed the decoder per instruction

    @abstractmethod
    def disassemble_one(self, blob: bytes, addr: int) -> Optional[Instruction]:
        """Decode exactly one instruction at `addr`. `blob` is the full image;
        implementations must slice their own lookahead window
        (blob[addr:addr+self.max_insn_len]) rather than trust the caller."""
        raise NotImplementedError

    def disassemble_range(self, blob: bytes, base: int, start: int, end: int) -> Iterator[Instruction]:
        """Default sequential-decode implementation; backends may override
        for efficiency but rarely need to."""
        addr = start
        while addr < end:
            insn = self.disassemble_one(blob, addr)
            if insn is None:
                break
            yield insn
            addr += insn.size

    @abstractmethod
    def is_call(self, insn: Instruction) -> bool:
        raise NotImplementedError

    @abstractmethod
    def is_unconditional_jump(self, insn: Instruction) -> bool:
        raise NotImplementedError

    @abstractmethod
    def is_conditional_branch(self, insn: Instruction) -> bool:
        raise NotImplementedError

    @abstractmethod
    def is_return(self, insn: Instruction) -> bool:
        raise NotImplementedError

    @abstractmethod
    def is_computed_jump(self, insn: Instruction) -> Optional[ComputedJumpKind]:
        """None if `insn` is not a computed jump at all."""
        raise NotImplementedError

    @abstractmethod
    def direct_targets(self, insn: Instruction, blob_len: Optional[int] = None) -> Optional[list[int]]:
        """Static branch/call/jump targets. Returns None (not []) when the
        target cannot be determined statically -- that is the deliberate
        signal that this is a computed jump needing trace/heuristic
        resolution, not a decode failure.

        `blob_len` is optional and defaults to None for backward
        compatibility; when supplied, a backend MAY use it to resolve an
        image-specific addressing bias (e.g. M68K's +0x100000 VBR-relocation
        bias -- see backends/m68k/backend.py's resolve_address_bias()) so a
        biased absolute target still lands inside the loaded blob. Without
        it, a backend returns the raw operand address unresolved."""
        raise NotImplementedError

    @abstractmethod
    def is_function_prologue(self, window: list[Instruction]) -> bool:
        """True if `window` (instructions starting at some address) looks like
        a function entry (e.g. `link a6,#n` on M68K)."""
        raise NotImplementedError

    def vector_table_seeds(self, blob: bytes) -> list[int]:
        """Reset vector + exception/interrupt vector table entries, if this
        architecture has one at a fixed image offset. Empty list if N/A."""
        return []

    def static_resolvers(self) -> list:
        """Backend-specific computed-jump resolution heuristics (e.g. M68K's
        PC-indexed switch-table and pointer-table scanners). Each callable has
        signature (blob, backend, instructions, jump_index) -> list[ResolvedTarget]
        | None (None/empty = this heuristic found nothing). Tried in order by
        analysis/jumptrace.py; empty by default. Keeping this on the backend
        (rather than analysis importing backends/<arch>/jumptables.py
        directly) is what keeps analysis/ architecture-agnostic."""
        return []

    @abstractmethod
    def normalize_for_signature(self, insn: Instruction) -> tuple[str, tuple]:
        """(mnemonic, immediates) with absolute addresses / branch targets
        stripped -- the stable fingerprint used for both jump-cache keys and
        cross-block pattern signatures."""
        raise NotImplementedError

    def explain(self, insn: Instruction) -> str:
        """Plain-English explanation of what `insn` does, for the instruction
        tooltip. Must never raise for an unrecognized mnemonic -- fall back to
        a generic message instead."""
        return f"{insn.mnemonic} {insn.op_str} (no semantic description available for this backend yet)"

    def format_hex_bytes(self, insn: Instruction) -> str:
        """Display text for `insn.raw_bytes`, for any UI showing a
        disassembly listing. Default is a flat lowercase hex run; a backend
        may override to match its own project's established listing
        convention (e.g. M68K groups bytes per opcode/extension-word and
        uppercases them -- see backends/m68k/backend.py)."""
        return insn.raw_bytes.hex()

    def annotate_op_str(self, insn: Instruction, blob_len: Optional[int] = None) -> str:
        """Operand display text for a listing view. Default: `insn.op_str`
        unchanged. A backend may override to append a note resolving its own
        image-specific addressing quirks (e.g. M68K appends the physical
        target when an operand carries its +0x100000 VBR-relocation bias --
        see backends/m68k/backend.py). `blob_len` is optional; omit it (or
        pass None) to get the unannotated `op_str`."""
        return insn.op_str


_NO_DESCRIPTION_SUFFIX = "(no semantic description available for this backend yet)"


def compose_explanation(insn: Instruction, semantics: dict) -> str:
    """Shared Feature 3 composition helper: any backend can build its
    `explain()` on top of this by supplying its own {MNEMONIC: template}
    table (see backends/m68k/semantics.py). Templates reference operands as
    "{op1}", "{op2}", ... (1-indexed, filled from each Operand.text) and may
    use "{size_note}" for a "(<suffix>-sized)" annotation when the mnemonic
    carries a size suffix (e.g. "move.l"). Never raises: a missing mnemonic,
    or a template referencing more operands than the instruction has, both
    fall back to the same generic message as the ISABackend default."""
    template = semantics.get(insn.base_mnemonic.upper())
    if template is None:
        return f"{insn.mnemonic} {insn.op_str} {_NO_DESCRIPTION_SUFFIX}"

    size_note = ""
    if "." in insn.mnemonic:
        size_note = f" ({insn.mnemonic.split('.', 1)[1]}-sized)"
    fmt_args = {"size_note": size_note}
    for i, op in enumerate(insn.operands, start=1):
        fmt_args[f"op{i}"] = op.text or "(?)"

    try:
        return template.format(**fmt_args)
    except (KeyError, IndexError):
        return f"{insn.mnemonic} {insn.op_str} {_NO_DESCRIPTION_SUFFIX}"
