"""Hex view tab: whole-image raw hex dump (16 bytes/row, address + hex +
ASCII gutter), matching disasm/AH2700A_fw.lst's own DATA-block dump style.
Generated once per context and cached on Context.hex_view_text -- rebuilding
a multi-hundred-KB dump on every tab switch would be wasteful."""

from __future__ import annotations

from tkinter import ttk

from revbench.gui.widgets.scrolled import log_widget
from revbench.gui.widgets.tooltip import tip

_ROW_BYTES = 16
_HEX_COL_WIDTH = _ROW_BYTES * 3 - 1  # "XX " * 16, minus the trailing space
_FONT = ("Consolas", 11)


def build(notebook: ttk.Notebook, app) -> ttk.Frame:
    frame = ttk.Frame(notebook)
    text_frame, text = log_widget(frame, height=30)
    text.configure(font=_FONT, bg="white", fg="black")
    text_frame.pack(fill="both", expand=True, padx=6, pady=6)
    tip(text, "Raw hex dump of the active context's whole image. Double-click "
              "a row in Labels/Subroutines/Jumps to jump here.")
    app.hex_text = text
    return frame


def _generate_hex_text(blob: bytes) -> str:
    lines = []
    for offset in range(0, len(blob), _ROW_BYTES):
        chunk = blob[offset:offset + _ROW_BYTES]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"  {offset:06X}  {hex_part:<{_HEX_COL_WIDTH}}  |{ascii_part}|")
    return "\n".join(lines)


def refresh(app) -> None:
    text = app.hex_text
    text.configure(state="normal")
    text.delete("1.0", "end")
    ctx = app.ctx
    if ctx is None or ctx.image_blob is None:
        text.configure(state="disabled")
        return
    if ctx.hex_view_text is None:
        ctx.hex_view_text = _generate_hex_text(ctx.image_blob)
    text.insert("end", ctx.hex_view_text)
    text.configure(state="disabled")


def goto(app, addr: int) -> None:
    ctx = app.ctx
    if ctx is None:
        return
    line_no = addr // _ROW_BYTES + 1
    text = app.hex_text
    text.tag_remove("goto_highlight", "1.0", "end")
    text.tag_configure("goto_highlight", background="#ffe38a")
    text.tag_add("goto_highlight", f"{line_no}.0", f"{line_no}.0 lineend")
    text.see(f"{line_no}.0")
