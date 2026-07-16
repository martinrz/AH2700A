"""Scrollable display boxes, adapted from the lab UI.md convention: every log
pane / table supports both a scrollbar and mouse-wheel-on-hover (no
click-to-focus needed)."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


def log_widget(parent, height=12):
    """Dark read-only text log pane + vertical scrollbar, packed into a frame.
    Returns (frame, text_widget). Insert lines via append_log()."""
    frame = ttk.Frame(parent)
    text = tk.Text(frame, height=height, bg="#101317", fg="#dde1ec",
                    state="disabled", wrap="word")
    sb = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
    text.configure(yscrollcommand=sb.set)
    text.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return frame, text


def append_log(text_widget, line: str) -> None:
    text_widget.configure(state="normal")
    text_widget.insert("end", line.rstrip("\n") + "\n")
    text_widget.configure(state="disabled")
    text_widget.see("end")


def scrolled_tree(parent, columns, height=12):
    """ttk.Treeview + vertical scrollbar, packed into a frame.
    Returns (frame, tree)."""
    frame = ttk.Frame(parent)
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=height)
    for col in columns:
        tree.heading(col, text=col)
    sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return frame, tree


def wheel_everywhere(root: tk.Misc) -> None:
    """Bind a single app-wide MouseWheel redirect: whatever Text/Treeview is
    under the pointer scrolls, regardless of Tk focus. Call once, on the root
    window, after all tabs are built."""

    def _redirect(event):
        widget = root.winfo_containing(event.x_root, event.y_root)
        target = widget
        while target is not None and not isinstance(target, (tk.Text, ttk.Treeview)):
            target = target.master
        if target is None:
            return
        delta = -1 if event.delta > 0 else 1
        target.yview_scroll(delta, "units")

    root.bind_all("<MouseWheel>", _redirect)
    # Linux/X11 wheel events arrive as Button-4/5, not <MouseWheel>.
    root.bind_all("<Button-4>", lambda e: _redirect(_WheelEvent(e, 120)))
    root.bind_all("<Button-5>", lambda e: _redirect(_WheelEvent(e, -120)))


class _WheelEvent:
    """Adapter so Button-4/5 (Linux) can reuse the <MouseWheel> (Windows)
    redirect logic, which expects an event with .delta/.x_root/.y_root."""

    def __init__(self, event, delta):
        self.x_root = event.x_root
        self.y_root = event.y_root
        self.delta = delta
