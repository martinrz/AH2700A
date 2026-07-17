"""Jumps tab: every branch/call/jump line found in an attached listing, plus
its target (resolved against known labels, including the +0x100000-bias
case -- see revbench/io/listing.py's parse_full_listing() ->
FullListingInfo.jump_refs). Double-click moves the Listing/Hex view tabs to
the jump SITE's address. A search box narrows the list live."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from revbench.gui.widgets.scrolled import scrolled_tree
from revbench.gui.widgets.tooltip import tip


def build(notebook: ttk.Notebook, app) -> ttk.Frame:
    frame = ttk.Frame(notebook)

    bar = ttk.Frame(frame)
    bar.pack(side="top", fill="x", padx=6, pady=6)
    ttk.Label(bar, text="Search:").pack(side="left")
    search_var = tk.StringVar()
    search_entry = tip(ttk.Entry(bar, textvariable=search_var, width=24),
                        "Show only jump rows whose mnemonic, target, or "
                        "resolved label contains this text (case-insensitive).")
    search_entry.pack(side="left", padx=(2, 12))
    search_entry.bind("<KeyRelease>", lambda e: refresh(app))
    app.jumps_search_var = search_var

    columns = ("addr", "mnemonic", "target", "label")
    tree_frame, tree = scrolled_tree(frame, columns, height=24)
    for col, width in zip(columns, (90, 80, 100, 260)):
        tree.column(col, width=width, anchor="w")
    tree_frame.pack(fill="both", expand=True, padx=6, pady=(0, 6))
    tip(tree, "Double-click a jump to move the Listing/Hex view tabs to the JUMP SITE's address.")
    tree.bind("<Double-1>", lambda e: _on_double_click(app, tree))
    app.jumps_tree = tree
    return frame


def _on_double_click(app, tree: ttk.Treeview) -> None:
    selection = tree.selection()
    if not selection:
        return
    addr_text = tree.item(selection[0], "values")[0]
    app.goto_address(int(addr_text, 16))


def refresh(app) -> None:
    tree = app.jumps_tree
    for row in tree.get_children():
        tree.delete(row)
    ctx = app.ctx
    if ctx is None:
        return
    search = app.jumps_search_var.get().strip().lower()
    for ref in ctx.jump_refs:
        haystack = f"{ref.mnemonic} {ref.raw_target_text} {ref.resolved_label or ''}".lower()
        if search and search not in haystack:
            continue
        tree.insert("", "end", values=(
            hex(ref.address), ref.mnemonic, ref.raw_target_text, ref.resolved_label or ""))
