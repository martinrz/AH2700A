"""Import an EXISTING .lst disassembly listing (produced by the separate
batch pipeline, disasm/rd68k.py -- not part of this repo).

Two levels of parsing:
  - `parse_listing()` -- bookmarks/seeds only (used by the Block tab's
    bookmark dropdown). Deliberately does NOT reconstruct Instruction/Block
    objects from the rendered text: real decoding still goes through the
    real ISABackend against the paired binary.
  - `parse_full_listing()` -- everything `parse_listing()` returns, PLUS
    every line's verbatim text (for the Listing tab, which displays an
    attached listing exactly as authored, hand-written comments included)
    and cross-reference indexes (subroutines, jump/branch/call targets) for
    the Labels/Subroutines/Jumps tabs.

Line format this parses against (rd68k.py's exact rendering):
  "  {addr:06X}  {hexgroups:<26}{mnem_op:<36}[; comment]"
  "{label}:" or "{label}:  ; {desc}"          (label line, own line above)
Lines to recognize and skip (not code/labels):
  - ";"-prefixed header/comment lines
  - blank lines
  - DATA hex+ASCII dump lines (distinguished by a trailing "|...|" column)
  - dc.b / dc.w / dc.l / dcb.* pseudo-op lines (vector table, jump tables --
    not call-graph-confirmed code)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from revbench.backends.m68k.backend import ALIAS_BASE

_ADDR_LINE_RE = re.compile(r"^  ([0-9A-Fa-f]{6})  (.*)$")
_LABEL_LINE_RE = re.compile(r"^([A-Za-z_]\w*):\s*(?:;\s*(.*))?$")
_DC_RE = re.compile(r"^dc\.?[bwl]?\b", re.IGNORECASE)
_TARGET_RE = re.compile(r"\$([0-9A-Fa-f]+)")

# rd68k.py's HEX_COL: the hex-bytes field is left-justified/padded to exactly
# this many characters before the mnemonic column starts (real instruction
# lines only -- dc.*/dcb.* pseudo-op lines skip the hex-bytes field entirely).
_HEX_COL = 26

# disasm/rd68k.py's mnemonic classification sets (mirrored locally -- rd68k.py
# is a standalone script outside this package, not an importable dependency).
_CALL_MNEM = {"bsr", "jsr"}
_BCC_MNEM = {
    "bhi", "bls", "bcc", "bcs", "bne", "beq", "bvc", "bvs", "bpl", "bmi", "bge", "blt", "bgt", "ble",
    "dbra", "dbf", "dbt", "dbhi", "dbls", "dbcc", "dbcs", "dbne", "dbeq", "dbvc", "dbvs", "dbpl",
    "dbmi", "dbge", "dblt", "dbgt", "dble",
}
_UNCOND_JUMP = {"bra", "jmp"}
_BRANCH_LIKE_MNEM = _CALL_MNEM | _BCC_MNEM | _UNCOND_JUMP

# Auto-generated address-derived names (rd68k.py's default naming for any
# code address it can't identify from a string/dispatch-table reference) --
# as opposed to a meaningfully hand- or string-named label. Used by the
# Listing/Labels tabs' "hide generic" filter.
GENERIC_LABEL_RE = re.compile(r"^(sub_|loc_)[0-9A-Fa-f]+$")

_KNOWN_VARIABLE_OPERAND_RE = re.compile(r"\$[0-9A-Fa-f]+\.[wl]\b")


@dataclass
class ListingInfo:
    bookmarks: list[tuple[int, str]] = field(default_factory=list)   # (addr, label)
    seeds: list[int] = field(default_factory=list)                   # every real-code instr address


@dataclass
class ListingLine:
    line_no: int
    raw_text: str                    # verbatim original line -- exact-fidelity display
    kind: str                        # "label" | "instr" | "data" | "vector" | "other"
    address: int | None = None
    label: str | None = None
    mnemonic: str | None = None
    comment: str | None = None


@dataclass
class JumpRef:
    address: int
    mnemonic: str
    raw_target_text: str
    resolved_label: str | None = None


@dataclass
class FullListingInfo:
    lines: list[ListingLine] = field(default_factory=list)
    addr_to_line: dict[int, int] = field(default_factory=dict)       # address -> index into `lines`
    bookmarks: list[tuple[int, str]] = field(default_factory=list)
    seeds: list[int] = field(default_factory=list)
    subroutines: list[tuple[int, str]] = field(default_factory=list)
    jump_refs: list[JumpRef] = field(default_factory=list)


def _resolve_candidates(addr: int, known: dict[int, str]) -> tuple[int, str | None]:
    """Best-effort +ALIAS_BASE bias resolution against a listing's own known
    addresses (no blob length available here -- this is a text-only parse).
    Returns (best_addr, label_if_any); best_addr prefers whichever candidate
    has a known label, falling back to the bias-corrected address."""
    candidates = [addr]
    if addr >= ALIAS_BASE:
        candidates.append(addr - ALIAS_BASE)
    for cand in candidates:
        if cand in known:
            return cand, known[cand]
    return candidates[-1], None


def parse_full_listing(path: Path) -> FullListingInfo:
    info = FullListingInfo()
    pending_label_indices: list[int] = []
    call_target_addrs: set[int] = set()
    unresolved_jump_refs: list[JumpRef] = []

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n").rstrip("\r")

            if not line.strip() or line.lstrip().startswith(";"):
                info.lines.append(ListingLine(line_no, line, "other"))
                pending_label_indices = []
                continue

            if "|" in line:
                # DATA hex+ASCII dump line -- not code. A label can precede
                # a DATA block (e.g. a named table) same as an instruction.
                addr_m = _ADDR_LINE_RE.match(line)
                addr = int(addr_m.group(1), 16) if addr_m else None
                if addr is not None:
                    for idx in pending_label_indices:
                        info.lines[idx].address = addr
                        info.bookmarks.append((addr, info.lines[idx].label))
                    info.addr_to_line[addr] = len(info.lines)
                pending_label_indices = []
                info.lines.append(ListingLine(line_no, line, "data", address=addr))
                continue

            label_m = _LABEL_LINE_RE.match(line)
            if label_m:
                name = label_m.group(1)
                info.lines.append(ListingLine(line_no, line, "label", label=name))
                pending_label_indices.append(len(info.lines) - 1)
                continue

            addr_m = _ADDR_LINE_RE.match(line)
            if not addr_m:
                info.lines.append(ListingLine(line_no, line, "other"))
                pending_label_indices = []
                continue

            addr = int(addr_m.group(1), 16)
            # `addr_m.group(2)` is the hexgroups+mnem_op+comment tail as one
            # blob -- the hex-bytes column and the mnemonic column are fixed
            # WIDTH-separated (rd68k.py's HEX_COL=26), not whitespace
            # -separated, so splitting on the first space would grab a hex
            # byte group instead of the mnemonic for a real instruction line.
            # Exception: dc.*/dcb.* vector/pseudo-op lines are rendered by a
            # different path with NO hex-bytes column at all -- mnemonic
            # starts at column 0 of this tail for those.
            content, _sep, comment_part = addr_m.group(2).partition(";")
            comment = comment_part.strip() or None
            if _DC_RE.match(content.lstrip()):
                mnem_op = content.strip()
            else:
                mnem_op = content[_HEX_COL:].strip() if len(content) > _HEX_COL else ""
            first_token = mnem_op.split(" ", 1)[0] if mnem_op else ""

            for idx in pending_label_indices:
                info.lines[idx].address = addr
                info.bookmarks.append((addr, info.lines[idx].label))
            pending_label_indices = []
            info.addr_to_line[addr] = len(info.lines)

            if _DC_RE.match(first_token):
                # Vector-table / jump-table pseudo-op entry, not real code.
                info.lines.append(ListingLine(line_no, line, "vector", address=addr,
                                               mnemonic=first_token, comment=comment))
                continue

            info.seeds.append(addr)
            info.lines.append(ListingLine(line_no, line, "instr", address=addr,
                                           mnemonic=first_token, comment=comment))

            base_mnem = first_token.split(".", 1)[0].lower()
            if base_mnem in _BRANCH_LIKE_MNEM:
                target_m = _TARGET_RE.search(mnem_op)
                if target_m:
                    raw_target = int(target_m.group(1), 16)
                    ref = JumpRef(address=addr, mnemonic=first_token, raw_target_text=target_m.group(0))
                    unresolved_jump_refs.append(ref)
                    if base_mnem in _CALL_MNEM:
                        call_target_addrs.add(raw_target)

    label_by_addr = dict(info.bookmarks)
    resolved_call_targets: set[int] = set()
    for raw_target in call_target_addrs:
        resolved, _label = _resolve_candidates(raw_target, label_by_addr)
        resolved_call_targets.add(resolved)

    for ref in unresolved_jump_refs:
        raw_target = int(ref.raw_target_text.lstrip("$"), 16)
        _resolved, label = _resolve_candidates(raw_target, label_by_addr)
        ref.resolved_label = label
        info.jump_refs.append(ref)

    seen_sub_addrs: set[int] = set()
    for addr, name in info.bookmarks:
        if addr in seen_sub_addrs:
            continue
        if name.startswith("sub_") or addr in resolved_call_targets:
            info.subroutines.append((addr, name))
            seen_sub_addrs.add(addr)

    return info


def parse_listing(path: Path) -> ListingInfo:
    """Bookmarks/seeds only -- thin wrapper over parse_full_listing() kept
    for the Block tab's existing bookmark-dropdown caller."""
    full = parse_full_listing(path)
    return ListingInfo(bookmarks=full.bookmarks, seeds=full.seeds)


def is_generic_label(name: str) -> bool:
    """True for auto-generated address-derived names (sub_XXXXXX/loc_XXXXXX)
    as opposed to a meaningfully hand- or string-named label."""
    return bool(GENERIC_LABEL_RE.match(name))


def is_known_variable_line(line: ListingLine, addr_to_line: dict[int, int], lines: list[ListingLine]) -> bool:
    """A label whose address falls on a DATA-classified line, OR an
    instruction line carrying an absolute-address operand ($abs.w/$abs.l)
    AND a comment -- this lab's convention for annotating a recognized
    hardware register or data reference (see disasm/findings.md's I/O
    register map and MANUAL_NOTES entries)."""
    if line.kind == "label" and line.address is not None:
        content_idx = addr_to_line.get(line.address)
        return content_idx is not None and lines[content_idx].kind == "data"
    if line.kind == "instr" and line.comment:
        return bool(_KNOWN_VARIABLE_OPERAND_RE.search(line.raw_text))
    return False


def _base_mnem(line: ListingLine) -> str | None:
    if line.kind != "instr" or not line.mnemonic:
        return None
    return line.mnemonic.split(".", 1)[0].lower()


def is_computed_call_line(line: ListingLine, resolved_addrs: set[int]) -> bool:
    """A bsr/jsr line with no resolvable static target -- i.e. no JumpRef
    was produced for it (register-indirect addressing)."""
    base = _base_mnem(line)
    return base in _CALL_MNEM and line.address not in resolved_addrs


def is_computed_jump_line(line: ListingLine, resolved_addrs: set[int]) -> bool:
    """A bra/jmp/bcc/dbcc line with no resolvable static target -- i.e. no
    JumpRef was produced for it (register-indirect or PC-indexed switch)."""
    base = _base_mnem(line)
    return base in (_BCC_MNEM | _UNCOND_JUMP) and line.address not in resolved_addrs


def find_binary_hint(lst_path: Path) -> Path | None:
    """Best-effort: if exactly one *.bin sibling exists next to the listing,
    assume it's the paired binary. Otherwise the caller should prompt."""
    candidates = sorted(Path(lst_path).parent.glob("*.bin"))
    if len(candidates) == 1:
        return candidates[0]
    return None
