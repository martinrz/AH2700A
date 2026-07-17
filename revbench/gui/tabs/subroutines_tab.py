"""Subroutines tab: labels matching sub_* or reached via jsr/bsr in an
attached listing (revbench/io/listing.py's parse_full_listing() ->
FullListingInfo.subroutines). Double-click moves the Listing/Hex view tabs
to that address. A search box narrows the list live."""

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
                        "Show only subroutines whose name contains this text "
                        "(case-insensitive).")
    search_entry.pack(side="left", padx=(2, 12))
    search_entry.bind("<KeyRelease>", lambda e: refresh(app))
    app.subroutines_search_var = search_var

    columns = ("addr", "name")
    tree_frame, tree = scrolled_tree(frame, columns, height=24)
    for col, width in zip(columns, (90, 340)):
        tree.column(col, width=width, anchor="w")
    tree_frame.pack(fill="both", expand=True, padx=6, pady=(0, 6))
    tip(tree, "Double-click a subroutine to jump the Listing/Hex view tabs to its address.")
    tree.bind("<Double-1>", lambda e: _on_double_click(app, tree))
    app.subroutines_tree = tree
    return frame


def _on_double_click(app, tree: ttk.Treeview) -> None:
    selection = tree.selection()
    if not selection:
        return
    addr_text = tree.item(selection[0], "values")[0]
    app.goto_address(int(addr_text, 16))


def refresh(app) -> None:
    tree = app.subroutines_tree
    for row in tree.get_children():
        tree.delete(row)
    ctx = app.ctx
    if ctx is None:
        return
    search = app.subroutines_search_var.get().strip().lower()
    for addr, name in ctx.subroutines:
        if search and search not in name.lower():
            continue
        tree.insert("", "end", values=(hex(addr), name))
