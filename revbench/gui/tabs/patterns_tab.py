"""Patterns tab: Feature 2b -- collect a block's address-normalized signature
and compare it against previously collected patterns.

M0: shell only -- wiring to core/signature.py and analysis/patterns.py lands
in M5."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from revbench.gui.widgets.scrolled import scrolled_tree
from revbench.gui.widgets.tooltip import tip


def build(notebook: ttk.Notebook, app) -> ttk.Frame:
    frame = ttk.Frame(notebook)

    bar = ttk.Frame(frame)
    bar.pack(side="top", fill="x", padx=6, pady=6)

    tip(ttk.Button(bar, text="Collect from current block", command=lambda: app.collect_pattern()),
        "Store the current Block-tab selection's signature into the pattern "
        "collection, for future comparison against other blocks."
        ).pack(side="left")

    tip(ttk.Button(bar, text="Compare current block", command=lambda: app.compare_pattern()),
        "Rank every stored pattern by similarity to the current Block-tab "
        "selection (exact / structural / loose, per Settings)."
        ).pack(side="left", padx=(8, 0))

    columns = ("label", "score", "arch", "instrs", "source")
    tree_frame, tree = scrolled_tree(frame, columns, height=18)
    for col, width in zip(columns, (160, 70, 60, 70, 260)):
        tree.column(col, width=width, anchor="w")
    tree_frame.pack(side="top", fill="both", expand=True, padx=6, pady=6)
    app.patterns_tree = tree

    return frame
