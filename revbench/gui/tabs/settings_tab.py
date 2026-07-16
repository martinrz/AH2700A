"""Settings tab: live INI editor, per the lab UI.md convention (section/key/
value tree, double-click to edit, Apply writes the file)."""

from __future__ import annotations

from tkinter import ttk

from revbench.gui.widgets.scrolled import scrolled_tree
from revbench.gui.widgets.tooltip import tip


def build(notebook: ttk.Notebook, app) -> ttk.Frame:
    frame = ttk.Frame(notebook)

    columns = ("section", "key", "value")
    tree_frame, tree = scrolled_tree(frame, columns, height=16)
    for col, width in zip(columns, (120, 200, 220)):
        tree.column(col, width=width, anchor="w")
    tree_frame.pack(side="top", fill="both", expand=True, padx=6, pady=6)
    app.settings_tree = tree

    for section in app.settings_cfg.sections():
        for key, value in app.settings_cfg.items(section):
            tree.insert("", "end", values=(section, key, value))

    bar = ttk.Frame(frame)
    bar.pack(side="bottom", fill="x", padx=6, pady=6)
    tip(ttk.Button(bar, text="Apply", command=lambda: app.apply_settings()),
        "Write the values above to data/settings.ini."
        ).pack(side="right")

    return frame
