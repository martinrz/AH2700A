"""Values tab: Feature 2a -- multi-format (int/hex/float/ASCII/BCD) inspector
for a byte range, linked to the current Block-tab selection via
app.send_block_selection_to_values() (see gui/app.py)."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from revbench.gui.widgets.scrolled import scrolled_tree
from revbench.gui.widgets.tooltip import tip


def build(notebook: ttk.Notebook, app) -> ttk.Frame:
    frame = ttk.Frame(notebook)

    bar = ttk.Frame(frame)
    bar.pack(side="top", fill="x", padx=6, pady=6)

    ttk.Label(bar, text="Addr:").pack(side="left")
    addr_var = tk.StringVar(value="0x0")
    tip(ttk.Entry(bar, textvariable=addr_var, width=12),
        "Address (in the loaded image) to inspect."
        ).pack(side="left", padx=(2, 12))
    app.values_addr_var = addr_var

    tip(ttk.Button(bar, text="Inspect", command=lambda: app.inspect_values()),
        "Show every interpretation (hex, signed/unsigned int, float, ASCII, BCD) "
        "of the bytes at Addr."
        ).pack(side="left", padx=(0, 12))

    ttk.Label(bar, text="Width:").pack(side="left")
    width_var = tk.StringVar(value="4")
    tip(ttk.Combobox(bar, textvariable=width_var, values=("1", "2", "4", "8"),
                      state="readonly", width=4),
        "Byte width used for the integer/float interpretations below."
        ).pack(side="left", padx=(2, 12))

    endian_var = tk.StringVar(value="big")
    tip(ttk.Combobox(bar, textvariable=endian_var, values=("big", "little"),
                      state="readonly", width=8),
        "Byte order used for the integer/float interpretations below."
        ).pack(side="left", padx=(2, 12))

    tip(ttk.Button(bar, text="Step -1", command=lambda: app.values_step(-1)),
        "Move the inspected offset back one byte."
        ).pack(side="left")
    tip(ttk.Button(bar, text="Step +1", command=lambda: app.values_step(1)),
        "Advance the inspected offset by one byte -- useful for scanning a "
        "suspected lookup table entry by entry."
        ).pack(side="left", padx=(4, 0))

    app.values_width_var, app.values_endian_var = width_var, endian_var

    columns = ("interpretation", "value", "note")
    tree_frame, tree = scrolled_tree(frame, columns, height=14)
    for col, width in zip(columns, (140, 220, 320)):
        tree.column(col, width=width, anchor="w")
    tree_frame.pack(side="top", fill="both", expand=True, padx=6, pady=6)
    app.values_tree = tree

    hint = ttk.Label(frame, text="Select bytes on the Block tab, or enter a range here, "
                                  "to populate this view.", foreground="#888")
    hint.pack(side="top", anchor="w", padx=6, pady=(0, 6))

    return frame
