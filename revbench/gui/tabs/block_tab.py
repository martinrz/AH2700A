"""Block tab: Feature 1 home -- instant range disassembly/evaluation, and the
computed-jump trace facility. Row-level instruction tooltips (Feature 3) are
wired in gui/app.py via RowToolTip on app.block_tree."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from revbench.gui.widgets.scrolled import scrolled_tree
from revbench.gui.widgets.tooltip import tip


def build(notebook: ttk.Notebook, app) -> ttk.Frame:
    frame = ttk.Frame(notebook)

    bar = ttk.Frame(frame)
    bar.pack(side="top", fill="x", padx=6, pady=6)

    ttk.Label(bar, text="Start addr:").pack(side="left")
    start_var = tk.StringVar()
    tip(ttk.Entry(bar, textvariable=start_var, width=12),
        "First address of the byte range to evaluate (hex)."
        ).pack(side="left", padx=(2, 12))

    ttk.Label(bar, text="Length:").pack(side="left")
    len_var = tk.StringVar()
    tip(ttk.Entry(bar, textvariable=len_var, width=10),
        "Number of bytes to decode from Start addr. Decoding never chases "
        "calls/branches outside this range -- that is the batch pipeline's job; "
        "this view is a fast look at just this range."
        ).pack(side="left", padx=(2, 12))

    tip(ttk.Button(bar, text="Evaluate", command=lambda: app.evaluate_block()),
        "Decode the range and show a plausibility verdict (likely code / likely "
        "data / ambiguous) plus the instruction table below."
        ).pack(side="left")

    app.block_start_var, app.block_len_var = start_var, len_var

    verdict = ttk.Label(frame, text="Load an image on the Image tab first.", foreground="#888")
    verdict.pack(side="top", anchor="w", padx=6)
    app.block_verdict_label = verdict

    columns = ("addr", "bytes", "mnemonic", "operands", "flags")
    tree_frame, tree = scrolled_tree(frame, columns, height=18)
    for col, width in zip(columns, (90, 140, 90, 220, 120)):
        tree.column(col, width=width, anchor="w")
    tree_frame.pack(side="top", fill="both", expand=True, padx=6, pady=6)
    app.block_tree = tree

    action_bar = ttk.Frame(frame)
    action_bar.pack(side="top", fill="x", padx=6, pady=(0, 6))

    tip(ttk.Button(action_bar, text="Trace selected jump...", command=lambda: app.trace_selected_jump()),
        "Open the Jump Trace dialog for the selected row, if it's a computed "
        "jump (register/memory-indirect or PC-indexed switch dispatch)."
        ).pack(side="left")

    tip(ttk.Button(action_bar, text="To Values", command=lambda: app.send_block_selection_to_values()),
        "Send the selected instruction's address to the Values tab for "
        "multi-format inspection."
        ).pack(side="left", padx=(6, 0))

    return frame
