"""Modal dialogs launched from tabs, kept separate from tab layout modules."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from revbench.analysis import dyntrace, jumptrace
from revbench.gui.widgets.scrolled import scrolled_tree
from revbench.gui.widgets.tooltip import tip


class JumpTraceDialog(tk.Toplevel):
    """Feature 1b UI: resolve a single computed jump via cache lookup, static
    heuristics, an imported dynamic trace, or manual entry -- see
    analysis/jumptrace.py for the resolution order and cache-key design."""

    def __init__(self, app, jump_index: int):
        super().__init__(app.root)
        self.app = app
        self.jump_index = jump_index
        self.dynamic_targets: dict[int, list[int]] = {}

        insn = self._instructions()[jump_index]
        kind = app.image_backend.is_computed_jump(insn)
        self.title(f"Jump Trace -- {insn.mnemonic} @ {insn.address:#x}")
        self.geometry("580x380")

        ttk.Label(self, text=f"{insn.mnemonic} {insn.op_str}   (kind: {kind.value if kind else 'n/a'})"
                  ).pack(anchor="w", padx=8, pady=(8, 4))

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8)
        tip(ttk.Button(bar, text="Resolve", command=self._resolve),
            "Consult the cache first; on a miss, run static heuristics (and any "
            "imported dynamic trace) and save the result back to the cache."
            ).pack(side="left")
        tip(ttk.Button(bar, text="Import dynamic trace...", command=self._import_trace),
            "Load an addr,target execution trace (CSV or JSON). Observed targets "
            "outrank any static guess."
            ).pack(side="left", padx=(6, 0))

        manual_bar = ttk.Frame(self)
        manual_bar.pack(fill="x", padx=8, pady=(6, 0))
        ttk.Label(manual_bar, text="Manual target(s), comma-separated hex:").pack(side="left")
        self.manual_var = tk.StringVar()
        tip(ttk.Entry(manual_bar, textvariable=self.manual_var, width=32),
            "e.g. 0x1a300, 0x1a320 -- saved straight to the cache as source=manual."
            ).pack(side="left", padx=(4, 4))
        tip(ttk.Button(manual_bar, text="Add manual", command=self._add_manual),
            "Use these addresses as the resolution for this jump."
            ).pack(side="left")

        columns = ("addr", "confidence", "source")
        tree_frame, tree = scrolled_tree(self, columns, height=10)
        for col, width in zip(columns, (100, 80, 160)):
            tree.column(col, width=width, anchor="w")
        tree_frame.pack(fill="both", expand=True, padx=8, pady=8)
        self.result_tree = tree

        self.status_label = ttk.Label(self, text="Not yet resolved.", foreground="#888")
        self.status_label.pack(anchor="w", padx=8, pady=(0, 8))

    def _instructions(self):
        return self.app.current_block_result.block.instructions

    def _resolve(self) -> None:
        try:
            cj = jumptrace.resolve(
                self.app.image_backend, self.app.image_blob, self._instructions(), self.jump_index,
                self.app.jump_cache, dynamic_targets=self.dynamic_targets or None,
                image_name=self.app.image_name,
            )
        except ValueError as exc:
            messagebox.showerror("Not a computed jump", str(exc))
            return
        self.app.jump_cache.save()
        self._show_result(cj)

    def _import_trace(self) -> None:
        path = filedialog.askopenfilename(title="Import dynamic trace (CSV or JSON)")
        if not path:
            return
        try:
            self.dynamic_targets = dyntrace.load_trace(path)
        except Exception as exc:  # noqa: BLE001 -- surface any parse error to the user
            messagebox.showerror("Failed to load trace", str(exc))
            return
        self.status_label.configure(text=f"Loaded trace: {len(self.dynamic_targets)} jump address(es).")

    def _add_manual(self) -> None:
        text = self.manual_var.get().strip()
        if not text:
            return
        try:
            targets = [int(t.strip(), 0) for t in text.split(",") if t.strip()]
        except ValueError:
            messagebox.showerror("Invalid input", "Enter comma-separated addresses, e.g. 0x1a300, 0x1a320")
            return
        cj = jumptrace.resolve_manual(
            self.app.image_backend, self._instructions(), self.jump_index, self.app.jump_cache,
            targets, image_name=self.app.image_name,
        )
        self.app.jump_cache.save()
        self._show_result(cj)

    def _show_result(self, cj) -> None:
        for row in self.result_tree.get_children():
            self.result_tree.delete(row)
        for t in cj.targets:
            self.result_tree.insert("", "end", values=(hex(t.addr), f"{t.confidence:.2f}", t.source))

        cache_hit = "(from cache)" in cj.resolution_source
        status = f"resolved={cj.resolved}  source={cj.resolution_source or '(none)'}"
        if cj.notes:
            status += f"  -- {cj.notes}"
        self.status_label.configure(text=status, foreground="#1a4a7a" if cache_hit else "#111")

        self.app.status_var.set(
            f"Jump @ {cj.address:#x}: {len(cj.targets)} target(s), {cj.resolution_source or 'unresolved'}")
        self.app._update_live_info()
