"""Per-session analysis state. One Context per opened image; App holds a list
of these plus an active index so multiple binaries/listings can stay open and
be switched between without clobbering each other's Block/Values state.

jump_cache/pattern_cache stay on App (shared, content-hash keyed) -- they are
not part of a Context."""

from __future__ import annotations

from dataclasses import dataclass, field

from revbench.core.isa import Instruction
from revbench.gui.session import ProjectEntry
from revbench.io.listing import JumpRef, ListingLine


@dataclass
class Context:
    name: str
    image_blob: bytes | None = None
    image_backend: object | None = None
    image_seeds: list[int] = field(default_factory=list)
    bookmarks: list[tuple[int, str]] = field(default_factory=list)  # (addr, label)
    current_block_result: object | None = None       # blockeval.BlockEvalResult
    block_row_info: dict = field(default_factory=dict)   # tree row id -> (Instruction, index)

    # --- session persistence ------------------------------------------------
    project_entry: ProjectEntry | None = None

    # --- full-listing state (populated by "Attach listing...") -------------
    listing_lines: list[ListingLine] = field(default_factory=list)
    addr_to_line: dict[int, int] = field(default_factory=dict)
    subroutines: list[tuple[int, str]] = field(default_factory=list)
    jump_refs: list[JumpRef] = field(default_factory=list)

    # --- Listing tab (binary-only, no attached listing) ---------------------
    # Every instruction ever decoded via the Block tab's "Evaluate", keyed by
    # address -- later evaluations overwrite earlier ones at the same address
    # so overlapping re-evaluations don't duplicate rows. Lets the Listing
    # tab accumulate coverage across repeated Block-tab evaluations instead
    # of only ever showing the single most recent range.
    evaluated_instructions: dict[int, Instruction] = field(default_factory=dict)

    # --- Hex view tab (cached -- regenerating a whole-image dump on every
    # tab switch is wasteful) -------------------------------------------------
    hex_view_text: str | None = None
