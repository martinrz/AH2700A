"""Hover tooltips. The _ToolTip class and tip() helper below are copied
VERBATIM from the lab standard (_claude/tooltips.md) -- do not "improve" them,
keep this file byte-for-byte compatible with the reference pattern so this app
stays consistent with every other lab GUI.

RowToolTip below is an adaptation of the same pattern for Treeview rows (a
Treeview has no per-row widget to bind tip() to), used for the per-instruction
hover explanations in the Block tab (see gui/tabs/block_tab.py).
"""

import contextlib
import tkinter as tk
from tkinter import ttk  # noqa: F401  (kept for parity with the reference file)

_tips_on = {"v": True}          # bottom-bar checkbox flips this


class _ToolTip:
    def __init__(self, widget, text):
        self.widget, self.text, self.tw, self._after = widget, text, None, None
        widget.bind("<Enter>", self._enter, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _enter(self, _e=None):
        if not _tips_on["v"]:
            return
        self._cancel()
        self._after = self.widget.after(600, self._show)   # hover delay

    def _cancel(self):
        if self._after:
            with contextlib.suppress(Exception):
                self.widget.after_cancel(self._after)
            self._after = None

    def _show(self):
        if self.tw is not None or not _tips_on["v"]:
            return
        x = self.widget.winfo_rootx() + 18
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tw, text=self.text, justify="left", bg="#ffffe0",
                 fg="#111", relief="solid", borderwidth=1, wraplength=380,
                 font=("Segoe UI", 8)).pack(ipadx=4, ipady=2)

    def _hide(self, _e=None):
        self._cancel()
        if self.tw is not None:
            with contextlib.suppress(Exception):
                self.tw.destroy()
            self.tw = None


def tip(widget, text):
    """Attach a hover tooltip; returns the widget (chainable with .pack)."""
    _ToolTip(widget, text)
    return widget


class RowToolTip:
    """Instruction-hover adaptation of the standard tip() pattern for a
    ttk.Treeview: there is no per-row widget to attach _ToolTip to, so this
    binds once on the tree, uses identify_row() to find the hovered row, and
    calls `text_fn(row_id)` LAZILY (only when a tooltip is about to be shown,
    not for every row up front) so large listings stay responsive.

    text_fn(row_id) -> str, or None to show nothing for that row.
    """

    def __init__(self, tree, text_fn):
        self.tree, self.text_fn = tree, text_fn
        self.tw = None
        self._after = None
        self._row = None
        tree.bind("<Motion>", self._motion, add="+")
        tree.bind("<Leave>", self._hide, add="+")
        tree.bind("<ButtonPress>", self._hide, add="+")

    def _motion(self, event):
        if not _tips_on["v"]:
            return
        row = self.tree.identify_row(event.y)
        if row != self._row:
            self._row = row
            self._hide()
            if row:
                self._after = self.tree.after(600, lambda: self._show(row, event.x_root, event.y_root))

    def _show(self, row, x_root, y_root):
        if self.tw is not None or not _tips_on["v"]:
            return
        text = self.text_fn(row)
        if not text:
            return
        self.tw = tk.Toplevel(self.tree)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x_root + 18}+{y_root + 12}")
        tk.Label(self.tw, text=text, justify="left", bg="#ffffe0",
                 fg="#111", relief="solid", borderwidth=1, wraplength=460,
                 font=("Segoe UI", 8)).pack(ipadx=4, ipady=2)

    def _hide(self, _e=None):
        if self._after:
            with contextlib.suppress(Exception):
                self.tree.after_cancel(self._after)
            self._after = None
        if self.tw is not None:
            with contextlib.suppress(Exception):
                self.tw.destroy()
            self.tw = None
