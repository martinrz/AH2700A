"""Listing tab: whole-disassembly text view.

If the active context has an attached listing, shows its lines verbatim
(labels, instructions, hand-written comments -- exact fidelity to the
source .lst, see revbench/io/listing.py's parse_full_listing()). For a
binary-only context (no listing attached), shows every instruction decoded
so far via the Block tab's "Evaluate" (revbench/gui/context.py's
Context.evaluated_instructions), laid out with disasm/rd68k.py's own column
widths -- mirrored locally here, same precedent as io/listing.py and
backends/m68k/backend.py's format_hex_bytes/annotate_op_str.

A filter bar above the text view narrows the view to matching lines only
(search substring AND'd with an OR of any checked category); see
io/listing.py's is_generic_label/is_known_variable_line/
is_computed_call_line/is_computed_jump_line for the attached-listing
classification, and Instruction.flags/backend predicates for the more
accurate binary-only (real-decode) classification.
"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

from revbench.core.isa import InsnFlags
from revbench.gui.widgets.scrolled import log_widget
from revbench.gui.widgets.tooltip import tip
from revbench.io import listing as listingmod

HEX_COL = 26
MNEM_COL = 36
_FONT = ("Consolas", 11)


def build(notebook: ttk.Notebook, app) -> ttk.Frame:
    frame = ttk.Frame(notebook)

    bar = ttk.Frame(frame)
    bar.pack(side="top", fill="x", padx=6, pady=(6, 0))

    ttk.Label(bar, text="Search:").pack(side="left")
    search_var = tk.StringVar()
    search_entry = tip(ttk.Entry(bar, textvariable=search_var, width=24),
                        "Show only lines containing this text (case-insensitive).")
    search_entry.pack(side="left", padx=(2, 12))
    search_entry.bind("<KeyRelease>", lambda e: refresh(app))
    app.listing_search_var = search_var

    filter_vars: dict[str, tk.BooleanVar] = {}
    filter_checks: dict[str, ttk.Checkbutton] = {}
    for key, label, tooltip in (
        ("computed_jumps", "Computed jumps",
         "Show only bra/jmp/bcc lines with no resolvable static target "
         "(register-indirect or PC-indexed switch dispatch)."),
        ("computed_calls", "Computed calls",
         "Show only bsr/jsr lines with no resolvable static target "
         "(register-indirect)."),
        ("known_variables", "Known variables",
         "Show only labels pointing at a DATA block, or instruction lines "
         "with an absolute-address operand and a comment (a recognized "
         "hardware register or data reference)."),
        ("known_subroutines", "Known subroutines",
         "Show only lines belonging to a recognized subroutine (see the "
         "Subroutines tab)."),
        ("hide_generic", "Hide generic",
         "Hide auto-generated sub_XXXXXX/loc_XXXXXX label lines, to surface "
         "meaningfully hand- or string-named ones."),
    ):
        var = tk.BooleanVar(value=False)
        check = tip(ttk.Checkbutton(bar, text=label, variable=var, command=lambda: refresh(app)),
                    tooltip)
        check.pack(side="left", padx=(0, 8))
        filter_vars[key] = var
        filter_checks[key] = check
    app.listing_filter_vars = filter_vars
    app.listing_filter_checks = filter_checks

    text_frame, text = log_widget(frame, height=30)
    text.configure(font=_FONT, bg="white", fg="black", wrap="word")
    text_frame.pack(fill="both", expand=True, padx=6, pady=6)
    tip(text, "The active context's disassembly listing. Double-click a row "
              "in Labels/Subroutines/Jumps to jump here. Use the filter bar "
              "above to narrow thousands of lines down to what matters.")
    app.listing_text = text
    app.listing_char_width_px = tkfont.Font(font=_FONT).measure("0")

    return frame


def _synthesize_line(backend, insn, blob_len: int) -> tuple[str, int]:
    """Returns (line_text, comment_start_col) -- comment_start_col is where
    a wrapped continuation should align (MNEM_COL, since annotate_op_str's
    "-> $addr" note and any future comment both start after the mnemonic
    field in this synthesized format)."""
    hexgroups = backend.format_hex_bytes(insn)
    mnem_op = backend.annotate_op_str(insn, blob_len)
    line = f"  {insn.address:06X}  {hexgroups:<{HEX_COL}}{mnem_op:<{MNEM_COL}}"
    return line.rstrip(), HEX_COL + 10 + MNEM_COL  # 10 = "  {addr:06X}  "


def _matches_filters(app, line: listingmod.ListingLine, ctx, resolved_addrs: set[int],
                      subroutine_addrs: set[int]) -> bool:
    search = app.listing_search_var.get().strip().lower()
    if search and search not in line.raw_text.lower():
        return False

    fv = app.listing_filter_vars
    if fv["hide_generic"].get() and line.kind == "label" and listingmod.is_generic_label(line.label or ""):
        return False

    any_checked = any(fv[k].get() for k in ("computed_jumps", "computed_calls", "known_variables", "known_subroutines"))
    if not any_checked:
        return True

    if fv["computed_jumps"].get() and listingmod.is_computed_jump_line(line, resolved_addrs):
        return True
    if fv["computed_calls"].get() and listingmod.is_computed_call_line(line, resolved_addrs):
        return True
    if fv["known_variables"].get() and listingmod.is_known_variable_line(line, ctx.addr_to_line, ctx.listing_lines):
        return True
    if fv["known_subroutines"].get() and line.address is not None and line.address in subroutine_addrs:
        return True
    return False


def _apply_wrap_tags(text: tk.Text, line_no: int, comment_col: int, char_width_px: int) -> None:
    tag = f"wrap{line_no}"
    text.tag_configure(tag, lmargin2=comment_col * char_width_px)
    text.tag_add(tag, f"{line_no}.0", f"{line_no}.0 lineend")


def refresh(app) -> None:
    text = app.listing_text
    text.configure(state="normal")
    text.delete("1.0", "end")
    for tag in text.tag_names():
        if tag.startswith("wrap"):
            text.tag_delete(tag)
    app.listing_addr_to_text_line: dict[int, int] = {}

    ctx = app.ctx
    has_listing = ctx is not None and bool(ctx.listing_lines)
    for key in ("known_variables", "known_subroutines"):
        app.listing_filter_checks[key].configure(state="normal" if has_listing else "disabled")

    if ctx is None:
        text.configure(state="disabled")
        return

    char_width_px = app.listing_char_width_px

    if ctx.listing_lines:
        resolved_addrs = {ref.address for ref in ctx.jump_refs}
        subroutine_addrs = {addr for addr, _name in ctx.subroutines}
        text_line_no = 1
        for line in ctx.listing_lines:
            if not _matches_filters(app, line, ctx, resolved_addrs, subroutine_addrs):
                continue
            text.insert("end", line.raw_text + "\n")
            if line.address is not None:
                app.listing_addr_to_text_line.setdefault(line.address, text_line_no)
            if line.comment is not None and ";" in line.raw_text:
                _apply_wrap_tags(text, text_line_no, line.raw_text.index(";"), char_width_px)
            text_line_no += 1
    elif ctx.evaluated_instructions:
        backend = ctx.image_backend
        blob_len = len(ctx.image_blob) if ctx.image_blob else 0
        search = app.listing_search_var.get().strip().lower()
        fv = app.listing_filter_vars
        want_computed_jump = fv["computed_jumps"].get()
        want_computed_call = fv["computed_calls"].get()
        any_checked = want_computed_jump or want_computed_call
        text_line_no = 1
        for addr in sorted(ctx.evaluated_instructions):
            insn = ctx.evaluated_instructions[addr]
            line_text, comment_col = _synthesize_line(backend, insn, blob_len)
            if search and search not in line_text.lower():
                continue
            if any_checked:
                is_computed = bool(insn.flags & InsnFlags.COMPUTED)
                is_call = backend.is_call(insn)
                is_jump = backend.is_unconditional_jump(insn) or backend.is_conditional_branch(insn)
                matches = (want_computed_jump and is_computed and is_jump) or \
                          (want_computed_call and is_computed and is_call)
                if not matches:
                    continue
            text.insert("end", line_text + "\n")
            app.listing_addr_to_text_line[addr] = text_line_no
            if "->" in line_text or ";" in line_text:
                _apply_wrap_tags(text, text_line_no, comment_col, char_width_px)
            text_line_no += 1
    else:
        text.insert("end", "No listing attached, and nothing evaluated on the "
                            "Block tab yet.\n")

    text.configure(state="disabled")


def goto(app, addr: int) -> None:
    line_no = getattr(app, "listing_addr_to_text_line", {}).get(addr)
    if line_no is None:
        return
    text = app.listing_text
    text.tag_remove("goto_highlight", "1.0", "end")
    text.tag_configure("goto_highlight", background="#ffe38a")
    text.tag_add("goto_highlight", f"{line_no}.0", f"{line_no}.0 lineend")
    text.see(f"{line_no}.0")
