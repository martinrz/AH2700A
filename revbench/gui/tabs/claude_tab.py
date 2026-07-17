"""Claude tab: hand work back and forth with Claude (via gui/claude_bridge.py
shelling out to the `claude` CLI) without leaving revbench.

Two modes:
  - Quick Q&A: a free-text question plus whatever context you attach (the
    Block tab's selected instruction, or the last goto_address target).
  - Full pass: reviews whatever is CURRENTLY DISPLAYED on the Listing tab --
    respects that tab's filter bar, so filtering to e.g. "Computed jumps"
    first scopes the review to just those lines.

No auto-save of replies back into bookmarks/comments -- a scratch
conversation surface only.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from revbench.gui import claude_bridge
from revbench.gui.widgets.scrolled import log_widget
from revbench.gui.widgets.tooltip import tip

_QUESTION_TIMEOUT = 120
_FULL_PASS_TIMEOUT = 600
_FONT = ("Consolas", 11)


def build(notebook: ttk.Notebook, app) -> ttk.Frame:
    frame = ttk.Frame(notebook)

    context_bar = ttk.Frame(frame)
    context_bar.pack(side="top", fill="x", padx=6, pady=(6, 0))
    ttk.Label(context_bar, text="Context:").pack(side="left", anchor="n")
    tip(ttk.Button(context_bar, text="Attach current selection",
                    command=lambda: _attach_current_selection(app)),
        "Pull in the Block tab's selected instruction, or the last "
        "Labels/Subroutines/Jumps navigation target, as context."
        ).pack(side="left", padx=(6, 0))

    context_frame, context_text = log_widget(frame, height=4)
    context_text.configure(font=_FONT, bg="white", fg="black", state="normal")
    context_frame.pack(side="top", fill="x", padx=6, pady=6)
    tip(context_text, "Freely editable -- type your own context here, or use "
                       "'Attach current selection' above.")
    app.claude_context_text = context_text

    question_bar = ttk.Frame(frame)
    question_bar.pack(side="top", fill="x", padx=6, pady=(0, 6))
    ttk.Label(question_bar, text="Question:").pack(side="left")
    question_var = tk.StringVar()
    tip(ttk.Entry(question_bar, textvariable=question_var, width=60),
        "What you want to ask Claude about the context above."
        ).pack(side="left", padx=(4, 12), fill="x", expand=True)
    app.claude_question_var = question_var

    tip(ttk.Button(question_bar, text="Send to Claude", command=lambda: _send_question(app)),
        "Send the context + question to Claude (claude -p), one-shot -- "
        "no running conversation memory between sends."
        ).pack(side="left")
    tip(ttk.Button(question_bar, text="Full pass...", command=lambda: _full_pass(app)),
        "Send whatever is CURRENTLY DISPLAYED on the Listing tab (respects "
        "its filter bar) for a broader review: unresolved computed jumps, "
        "unlabeled subroutines, anything suspicious. Can take a while."
        ).pack(side="left", padx=(6, 0))

    reply_frame, reply_text = log_widget(frame, height=20)
    reply_text.configure(font=_FONT, bg="white", fg="black")
    reply_frame.pack(side="top", fill="both", expand=True, padx=6, pady=(0, 6))
    tip(reply_text, "Claude's reply. Not auto-saved anywhere -- copy anything "
                     "worth keeping into a bookmark/comment yourself.")
    app.claude_reply_text = reply_text

    return frame


def _attach_current_selection(app) -> None:
    summary = _current_selection_summary(app)
    text = app.claude_context_text
    text.configure(state="normal")
    text.delete("1.0", "end")
    if summary:
        text.insert("end", summary)
    text.configure(state="normal")


def _current_selection_summary(app) -> str:
    ctx = app.ctx
    if ctx is None:
        return ""

    selection = app.block_tree.selection()
    if selection:
        entry = ctx.block_row_info.get(selection[0])
        if entry is not None:
            insn, _idx = entry
            blob_len = len(ctx.image_blob) if ctx.image_blob else 0
            op_text = ctx.image_backend.annotate_op_str(insn, blob_len)
            return f"{ctx.name} @ {hex(insn.address)}: {insn.mnemonic} {op_text}"

    if app.last_goto_addr is not None:
        addr = app.last_goto_addr
        line_idx = ctx.addr_to_line.get(addr)
        if line_idx is not None and ctx.listing_lines:
            return f"{ctx.name} @ {hex(addr)}:\n{ctx.listing_lines[line_idx].raw_text}"
        return f"{ctx.name} @ {hex(addr)}"

    return ""


def _send_question(app) -> None:
    question = app.claude_question_var.get().strip()
    if not question:
        messagebox.showinfo("No question", "Type a question first.")
        return
    context_text = app.claude_context_text.get("1.0", "end").strip()
    prompt = claude_bridge.build_question_prompt(context_text, question)
    if len(prompt) > claude_bridge.MAX_CONTEXT_CHARS:
        messagebox.showerror("Context too large",
                              f"That context + question is {len(prompt)} characters, over the "
                              f"{claude_bridge.MAX_CONTEXT_CHARS}-character limit. Trim the context box.")
        return
    app._submit(claude_bridge.run_prompt, (prompt, _QUESTION_TIMEOUT),
                on_ok=lambda reply: _show_reply(app, reply), on_err=app._on_job_error,
                busy="Waiting for Claude...")


def _full_pass(app) -> None:
    listing_text = app.listing_text.get("1.0", "end").strip()
    if not listing_text:
        messagebox.showinfo("Nothing to review", "The Listing tab is empty -- "
                                                   "attach a listing or evaluate a block first.")
        return
    prompt = claude_bridge.build_full_pass_prompt(listing_text)
    if len(prompt) > claude_bridge.MAX_CONTEXT_CHARS:
        messagebox.showerror("Listing too large",
                              f"The current Listing tab view is {len(listing_text)} characters, over "
                              f"the {claude_bridge.MAX_CONTEXT_CHARS}-character limit for a single "
                              "pass. Narrow it with the Listing tab's filter bar first (e.g. check "
                              "\"Computed jumps\" to review just those).")
        return
    app._submit(claude_bridge.run_prompt, (prompt, _FULL_PASS_TIMEOUT),
                on_ok=lambda reply: _show_reply(app, reply), on_err=app._on_job_error,
                busy="Running full pass (this may take a while)...")


def _show_reply(app, reply: str) -> None:
    text = app.claude_reply_text
    text.configure(state="normal")
    text.delete("1.0", "end")
    text.insert("end", reply)
    text.configure(state="disabled")
    app.status_var.set("Claude replied")
