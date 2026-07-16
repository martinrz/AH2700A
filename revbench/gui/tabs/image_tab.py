"""Image tab: load a firmware binary, pick an ISA backend, set base address /
endian, manage seeds, run a background recursive-descent fixpoint pass.

M0: shell only (no image loaded yet -- feature wiring lands in M5)."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from revbench.core import registry
from revbench.gui.widgets.tooltip import tip


def build(notebook: ttk.Notebook, app) -> ttk.Frame:
    frame = ttk.Frame(notebook)

    bar = ttk.Frame(frame)
    bar.pack(side="top", fill="x", padx=6, pady=6)

    tip(ttk.Button(bar, text="Load image...", command=lambda: app.load_image_dialog()),
        "Pick a firmware binary to open. Nothing is loaded yet in this build."
        ).pack(side="left")

    ttk.Label(bar, text="Backend:").pack(side="left", padx=(12, 2))
    backend_var = tk.StringVar(value="m68k")
    combo = ttk.Combobox(bar, textvariable=backend_var, values=registry.available(),
                          state="readonly", width=10)
    combo.pack(side="left")
    tip(combo, "ISA backend used to decode this image. Only M68K (capstone) ships today; "
               "the core is architecture-agnostic so more can be added later.")
    app.backend_var = backend_var

    ttk.Label(bar, text="Base addr:").pack(side="left", padx=(12, 2))
    base_var = tk.StringVar(value="0x0")
    entry = ttk.Entry(bar, textvariable=base_var, width=12)
    entry.pack(side="left")
    tip(entry, "Address the first byte of the image is loaded at (hex, e.g. 0x0).")
    app.base_addr_var = base_var

    info = ttk.Label(frame, text="No image loaded. Use Load image... to open a firmware binary.",
                      foreground="#888")
    info.pack(side="top", anchor="w", padx=6, pady=(0, 6))
    app.image_info_label = info

    return frame
