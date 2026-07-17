"""revbench GUI shell: one ttk.Notebook, one App class, a single background
worker thread fed by queue.Queue jobs, and the standard lab tooltip/INI
conventions (see _claude/UI.md, _claude/tooltips.md).

Must run standalone via --smoke (build the GUI, self-destruct after 2s, no
image loaded)."""

from __future__ import annotations

import argparse
import os
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from revbench.analysis import blockeval, patterns
from revbench.core import formats
from revbench.core.cache import KeyedCache
from revbench.core.isa import InsnFlags
from revbench.core import registry
from revbench.gui import config as cfgmod
from revbench.gui import session as sessionmod
from revbench.gui.context import Context
from revbench.gui.dialogs import JumpTraceDialog, ResumeSessionDialog
from revbench.gui.tabs import (
    block_tab, claude_tab, hexview_tab, image_tab, jumps_tab, labels_tab, listing_tab,
    maintenance_tab, patterns_tab, settings_tab, subroutines_tab, values_tab,
)
from revbench.gui.widgets.scrolled import wheel_everywhere
from revbench.gui.widgets.tooltip import RowToolTip, _tips_on, tip
from revbench.io import listing as listingmod


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("revbench")

        self.settings_cfg = cfgmod.load()
        _tips_on["v"] = self.settings_cfg.getboolean("options", "tooltips", fallback=True)

        # --- analysis state: multiple contexts (binary/listing sessions), ---
        # one active at a time. No context exists until an image is loaded.
        self.contexts: list[Context] = []
        self.active_ctx_index: int = -1
        self.last_goto_addr: int | None = None

        # settings.ini stores cache paths relative to the project root (e.g.
        # "data/jump_cache.json"), so resolve against DATA_DIR's parent.
        project_root = cfgmod.DATA_DIR.parent
        self.jump_cache = KeyedCache(project_root / self.settings_cfg.get(
            "paths", "jump_cache", fallback="data/jump_cache.json"))
        self.pattern_cache = KeyedCache(project_root / self.settings_cfg.get(
            "paths", "patterns", fallback="data/patterns.json"))

        # --- single worker thread + job queue --------------------------------
        self._job_q: "queue.Queue" = queue.Queue()
        self._decode_q: "queue.Queue" = queue.Queue()
        self._trace_q: "queue.Queue" = queue.Queue()
        self._pattern_q: "queue.Queue" = queue.Queue()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker.start()

        self._build_context_bar(root)

        notebook = ttk.Notebook(root)
        notebook.pack(side="top", fill="both", expand=True)

        self.tabs = {}
        for name, mod in (
            ("Image", image_tab),
            ("Block", block_tab),
            ("Values", values_tab),
            ("Patterns", patterns_tab),
            ("Listing", listing_tab),
            ("Hex", hexview_tab),
            ("Labels", labels_tab),
            ("Subroutines", subroutines_tab),
            ("Jumps", jumps_tab),
            ("Claude", claude_tab),
            ("Maintenance", maintenance_tab),
            ("Settings", settings_tab),
        ):
            frame = mod.build(notebook, self)
            notebook.add(frame, text=name)
            self.tabs[name] = frame
        self.notebook = notebook

        RowToolTip(self.block_tree, self._explain_block_row)

        self._build_bottom_bar(root)
        wheel_everywhere(root)

        root.after(150, self._poll_decode_q)
        root.after(150, self._poll_trace_q)
        root.after(150, self._poll_pattern_q)

    # --- context (multi-image session) management ------------------------------

    @property
    def ctx(self) -> Context | None:
        if self.active_ctx_index < 0:
            return None
        return self.contexts[self.active_ctx_index]

    def _build_context_bar(self, root: tk.Tk) -> None:
        bar = ttk.Frame(root)
        bar.pack(side="top", fill="x", padx=6, pady=(6, 0))

        ttk.Label(bar, text="Context:").pack(side="left")
        self.ctx_var = tk.StringVar()
        combo = ttk.Combobox(bar, textvariable=self.ctx_var, state="readonly", width=32)
        combo.pack(side="left", padx=(2, 12))
        combo.bind("<<ComboboxSelected>>", lambda e: self._on_ctx_combo_selected())
        self.ctx_combo = combo

        tip(ttk.Button(bar, text="New Session...", command=self.new_session_dialog),
            "Start a new session: pick a firmware binary, name the project, "
            "and it becomes a new context. Every session starts from a binary "
            "-- a listing can be attached to it afterward."
            ).pack(side="left")
        tip(ttk.Button(bar, text="Attach listing...", command=self.attach_listing_dialog),
            "Attach an existing .lst disassembly listing to the ACTIVE "
            "session: brings in its labels, comments, and cross-references "
            "for the Listing/Labels/Subroutines/Jumps tabs. Analysis still "
            "runs off the real binary, not the listing text."
            ).pack(side="left", padx=(6, 0))
        tip(ttk.Button(bar, text="Close", command=self.close_context),
            "Close the active context."
            ).pack(side="left", padx=(6, 0))

    def _refresh_ctx_combo(self) -> None:
        self.ctx_combo.configure(values=[c.name for c in self.contexts])
        if self.active_ctx_index >= 0:
            self.ctx_var.set(self.contexts[self.active_ctx_index].name)
        else:
            self.ctx_var.set("")

    def _on_ctx_combo_selected(self) -> None:
        try:
            index = self.ctx_combo.current()
        except (tk.TclError, ValueError):
            return
        if index < 0:
            return
        self.switch_context(index)

    def switch_context(self, index: int) -> None:
        self.active_ctx_index = index
        self._refresh_ctx_combo()
        self._refresh_tabs_for_ctx()

    def close_context(self) -> None:
        if self.ctx is None:
            return
        del self.contexts[self.active_ctx_index]
        self.active_ctx_index = min(self.active_ctx_index, len(self.contexts) - 1)
        self._refresh_ctx_combo()
        self._refresh_tabs_for_ctx()

    def _refresh_tabs_for_ctx(self) -> None:
        ctx = self.ctx
        for tree in (self.block_tree, self.values_tree, self.patterns_tree):
            for row in tree.get_children():
                tree.delete(row)

        if ctx is None:
            self.image_info_label.configure(
                text="No image loaded. Use Open image... to open a firmware binary.")
            self.block_verdict_label.configure(text="Load an image on the Image tab first.")
            self.status_var.set("Ready")
        else:
            self.image_info_label.configure(
                text=f"{ctx.name}: {len(ctx.image_blob)} bytes, "
                     f"backend={ctx.image_backend.name}, {len(ctx.image_seeds)} vector-table seed(s), "
                     f"{len(ctx.bookmarks)} bookmark(s)")
            if ctx.current_block_result is not None:
                self._on_block_evaluated(ctx.current_block_result)
            else:
                self.block_verdict_label.configure(text="No block evaluated yet in this context.")
            self.status_var.set(f"Switched to {ctx.name}")

        self._refresh_bookmarks_combo()
        self._update_live_info()
        listing_tab.refresh(self)
        hexview_tab.refresh(self)
        labels_tab.refresh(self)
        subroutines_tab.refresh(self)
        jumps_tab.refresh(self)

    def goto_address(self, addr: int) -> None:
        """Selecting an entry in Labels/Subroutines/Jumps moves both the
        Listing and Hex view tabs to that address and switches to Listing."""
        self.last_goto_addr = addr
        self.notebook.select(self.tabs["Listing"])
        self.goto_listing_address(addr)
        self.goto_hex_address(addr)

    def goto_listing_address(self, addr: int) -> None:
        listing_tab.goto(self, addr)

    def goto_hex_address(self, addr: int) -> None:
        hexview_tab.goto(self, addr)

    def _refresh_bookmarks_combo(self) -> None:
        combo = getattr(self, "bookmark_combo", None)
        if combo is None:
            return
        ctx = self.ctx
        if ctx is None or not ctx.bookmarks:
            combo.configure(values=[])
            self.bookmark_var.set("")
            return
        combo.configure(values=[f"{addr:#x}  {label}" for addr, label in ctx.bookmarks])

    def _on_bookmark_selected(self) -> None:
        ctx = self.ctx
        if ctx is None:
            return
        index = self.bookmark_combo.current()
        if index < 0 or index >= len(ctx.bookmarks):
            return
        addr, _label = ctx.bookmarks[index]
        self.block_start_var.set(hex(addr))

    # --- bottom bar -----------------------------------------------------------

    def _build_bottom_bar(self, root: tk.Tk) -> None:
        bar = ttk.Frame(root)
        bar.pack(side="bottom", fill="x")

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.status_var, relief="sunken", anchor="w").pack(
            side="left", fill="x", expand=True, padx=(2, 4), pady=2)

        self.live_info_var = tk.StringVar(value="0 instrs | 0 unresolved jumps | cache: 0 entries")
        ttk.Label(bar, textvariable=self.live_info_var, relief="sunken", anchor="e").pack(
            side="left", fill="x", expand=True, padx=(4, 4), pady=2)

        self.tips_var = tk.BooleanVar(value=_tips_on["v"])
        tip(ttk.Checkbutton(bar, text="Tips", variable=self.tips_var, command=self._toggle_tips),
            "Hover-help tooltips on the controls. Uncheck to silence them."
            ).pack(side="right", padx=4)

    def _toggle_tips(self) -> None:
        _tips_on["v"] = self.tips_var.get()
        self.settings_cfg.set("options", "tooltips", "true" if _tips_on["v"] else "false")
        cfgmod.save(self.settings_cfg)

    def _update_live_info(self) -> None:
        block_result = self.ctx.current_block_result if self.ctx else None
        instr_count = len(block_result.block.instructions) if block_result else 0
        unresolved = 0
        if block_result:
            for insn in block_result.block.instructions:
                if insn.flags & InsnFlags.COMPUTED:
                    unresolved += 1
        self.live_info_var.set(f"{instr_count} instrs | {unresolved} computed jump(s) | "
                                f"cache: {len(self.jump_cache)} entries")

    # --- worker thread plumbing -------------------------------------------

    def _worker_loop(self) -> None:
        while True:
            fn, args, on_ok, on_err, busy = self._job_q.get()
            try:
                result = fn(*args)
            except Exception as exc:  # noqa: BLE001 -- report to UI thread, never crash worker
                self.root.after(0, on_err, exc)
            else:
                self.root.after(0, on_ok, result)

    def _submit(self, fn, args=(), on_ok=lambda r: None, on_err=lambda e: None, busy=""):
        if busy:
            self.status_var.set(busy)
        self._job_q.put((fn, args, on_ok, on_err, busy))

    def _poll_decode_q(self) -> None:
        self._drain(self._decode_q)
        self.root.after(150, self._poll_decode_q)

    def _poll_trace_q(self) -> None:
        self._drain(self._trace_q)
        self.root.after(150, self._poll_trace_q)

    def _poll_pattern_q(self) -> None:
        self._drain(self._pattern_q)
        self.root.after(150, self._poll_pattern_q)

    def _drain(self, q: "queue.Queue") -> None:
        while True:
            try:
                q.get_nowait()
            except queue.Empty:
                return

    def _on_job_error(self, exc: Exception) -> None:
        self.status_var.set(f"Error: {exc}")
        messagebox.showerror("Error", str(exc))

    # --- Image tab / session management ----------------------------------------

    def new_session_dialog(self) -> None:
        path = filedialog.askopenfilename(title="New session: choose a firmware binary")
        if not path:
            return
        project_name = simpledialog.askstring(
            "New session", "Project name:", initialvalue=Path(path).stem, parent=self.root)
        if not project_name:
            return
        backend_name = self.backend_var.get()
        entry = sessionmod.create_or_reuse_project(Path(path), project_name, backend=backend_name)
        binary_path = entry.dir / entry.binary
        self._submit(self._load_image_job, (str(binary_path), entry.backend),
                     on_ok=lambda result: self._on_new_session_loaded(result, entry),
                     on_err=self._on_job_error,
                     busy=f"Loading {entry.binary}...")

    def _load_image_job(self, path: str, backend_name: str) -> dict:
        with open(path, "rb") as f:
            blob = f.read()
        backend = registry.create(backend_name)
        seeds = backend.vector_table_seeds(blob)
        return {"path": path, "blob": blob, "backend": backend, "seeds": seeds}

    def _on_new_session_loaded(self, result: dict, entry: sessionmod.ProjectEntry) -> None:
        ctx = self._add_context_from_load(result, project_entry=entry)
        if entry.listing:
            self._attach_listing_to_ctx(ctx, entry.dir / entry.listing)

    def _add_context_from_load(
        self, result: dict, bookmarks: list[tuple[int, str]] | None = None,
        project_entry: sessionmod.ProjectEntry | None = None,
    ) -> Context:
        name = os.path.basename(result["path"])
        ctx = Context(
            name=name,
            image_blob=result["blob"],
            image_backend=result["backend"],
            image_seeds=result["seeds"],
            bookmarks=bookmarks or [],
            project_entry=project_entry,
        )
        self.contexts.append(ctx)
        self.active_ctx_index = len(self.contexts) - 1
        self._refresh_ctx_combo()
        self._refresh_tabs_for_ctx()
        self.status_var.set(f"Loaded {name}")
        return ctx

    def attach_listing_dialog(self) -> None:
        if self.ctx is None:
            messagebox.showinfo("No session", "Start a New Session (a binary) first.")
            return
        path = filedialog.askopenfilename(title="Attach disassembly listing",
                                           filetypes=[("Listing files", "*.lst"), ("All files", "*.*")])
        if not path:
            return
        self._attach_listing_to_ctx(self.ctx, Path(path))

    def _attach_listing_to_ctx(self, ctx: Context, listing_path: Path) -> None:
        try:
            full = listingmod.parse_full_listing(listing_path)
        except OSError as exc:
            messagebox.showerror("Failed to read listing", str(exc))
            return

        if ctx.project_entry is not None:
            listing_path = sessionmod.attach_listing(ctx.project_entry, listing_path).dir / ctx.project_entry.listing

        ctx.bookmarks = full.bookmarks
        ctx.image_seeds = sorted(set(ctx.image_seeds) | set(full.seeds))
        ctx.listing_lines = full.lines
        ctx.addr_to_line = full.addr_to_line
        ctx.subroutines = full.subroutines
        ctx.jump_refs = full.jump_refs

        if ctx is self.ctx:
            self._refresh_tabs_for_ctx()
        self.status_var.set(f"Attached listing: {len(full.bookmarks)} label(s), "
                             f"{len(full.jump_refs)} jump ref(s)")

    # --- Block tab (Feature 1) -------------------------------------------------

    def evaluate_block(self) -> None:
        if self.ctx is None:
            messagebox.showinfo("No image", "Load an image on the Image tab first.")
            return
        try:
            addr = int(self.block_start_var.get(), 0)
            length = int(self.block_len_var.get(), 0)
        except ValueError:
            messagebox.showerror("Invalid input", "Start addr and Length must be numbers "
                                                    "(e.g. 0x1000 or 4096).")
            return
        self._submit(self._evaluate_block_job, (addr, length),
                     on_ok=self._on_block_evaluated, on_err=self._on_job_error,
                     busy=f"Evaluating {length} bytes at {addr:#x}...")

    def _evaluate_block_job(self, addr: int, length: int):
        return blockeval.evaluate(self.ctx.image_backend, self.ctx.image_blob, addr, length)

    def _on_block_evaluated(self, result) -> None:
        self.ctx.current_block_result = result
        self.block_verdict_label.configure(text=result.summary)

        tree = self.block_tree
        for row in tree.get_children():
            tree.delete(row)
        self.ctx.block_row_info = {}
        bookmark_by_addr = dict(self.ctx.bookmarks)
        backend = self.ctx.image_backend
        blob_len = len(self.ctx.image_blob)
        for idx, insn in enumerate(result.block.instructions):
            label = bookmark_by_addr.get(insn.address)
            if label:
                tree.insert("", "end", values=(hex(insn.address), "", f"{label}:", "", ""), tags=("label",))
            row_id = tree.insert("", "end", values=(
                hex(insn.address), backend.format_hex_bytes(insn), insn.mnemonic,
                backend.annotate_op_str(insn, blob_len), self._flags_text(insn.flags)))
            self.ctx.block_row_info[row_id] = (insn, idx)
            self.ctx.evaluated_instructions[insn.address] = insn
        tree.tag_configure("label", foreground="#888")

        self.status_var.set(result.summary)
        self._update_live_info()

    @staticmethod
    def _flags_text(flags: InsnFlags) -> str:
        names = [f.name for f in InsnFlags if f != InsnFlags.NONE and flags & f]
        return ",".join(names)

    def _explain_block_row(self, row_id: str):
        if self.ctx is None or self.ctx.image_backend is None:
            return None
        entry = self.ctx.block_row_info.get(row_id)
        if entry is None:
            return None
        insn, _idx = entry
        return self.ctx.image_backend.explain(insn)

    def trace_selected_jump(self) -> None:
        if self.ctx is None or self.ctx.current_block_result is None:
            messagebox.showinfo("No block", "Evaluate a block on the Block tab first.")
            return
        selection = self.block_tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select an instruction row first.")
            return
        entry = self.ctx.block_row_info.get(selection[0])
        if entry is None:
            return
        insn, idx = entry
        if self.ctx.image_backend.is_computed_jump(insn) is None:
            messagebox.showinfo("Not a computed jump", "The selected instruction is not a computed jump.")
            return
        JumpTraceDialog(self, idx)

    def send_block_selection_to_values(self) -> None:
        if self.ctx is None:
            return
        selection = self.block_tree.selection()
        if not selection:
            return
        entry = self.ctx.block_row_info.get(selection[0])
        if entry is None:
            return
        insn, _idx = entry
        self.values_addr_var.set(hex(insn.address))
        self.inspect_values()

    # --- Values tab (Feature 2a) -----------------------------------------------

    def inspect_values(self) -> None:
        if self.ctx is None:
            messagebox.showinfo("No image", "Load an image on the Image tab first.")
            return
        try:
            addr = int(self.values_addr_var.get(), 0)
            width = int(self.values_width_var.get())
        except (ValueError, AttributeError):
            messagebox.showerror("Invalid input", "Enter a valid address and width.")
            return
        endian = self.values_endian_var.get()
        chunk = self.ctx.image_blob[addr:]
        views = formats.inspect(chunk, width, endian)
        guess = formats.best_guess(chunk, width, endian)

        tree = self.values_tree
        for row in tree.get_children():
            tree.delete(row)
        if not views:
            self.status_var.set(f"Not enough bytes at {addr:#x} for width {width}")
            return
        for v in views:
            note = v.note
            if guess == v.interpretation:
                note = (note + " " if note else "") + "[best guess]"
            tree.insert("", "end", values=(v.interpretation, v.value, note))
        self.status_var.set(f"Inspecting {width} byte(s) at {addr:#x}")

    def values_step(self, delta: int) -> None:
        try:
            addr = int(self.values_addr_var.get(), 0)
        except (ValueError, AttributeError):
            addr = 0
        self.values_addr_var.set(hex(max(0, addr + delta)))
        self.inspect_values()

    # --- Patterns tab (Feature 2b) ---------------------------------------------

    def collect_pattern(self) -> None:
        if self.ctx is None or self.ctx.current_block_result is None:
            messagebox.showinfo("No block", "Evaluate a block on the Block tab first.")
            return
        label = simpledialog.askstring("Collect pattern", "Label for this pattern:", parent=self.root)
        if not label:
            return
        strictness = self.settings_cfg.get("options", "pattern_strictness", fallback="structural")
        record = patterns.collect(
            self.pattern_cache, self.ctx.image_backend, self.ctx.current_block_result.block.instructions,
            label, strictness=strictness, image_name=self.ctx.name)
        self.pattern_cache.save()
        self.status_var.set(f"Collected pattern '{label}' ({record.instr_count} instrs, {strictness})")

    def compare_pattern(self) -> None:
        if self.ctx is None or self.ctx.current_block_result is None:
            messagebox.showinfo("No block", "Evaluate a block on the Block tab first.")
            return
        strictness = self.settings_cfg.get("options", "pattern_strictness", fallback="structural")
        results = patterns.compare(
            self.pattern_cache, self.ctx.image_backend, self.ctx.current_block_result.block.instructions,
            strictness=strictness)

        tree = self.patterns_tree
        for row in tree.get_children():
            tree.delete(row)
        for r in results:
            tree.insert("", "end", values=(
                r.label, f"{r.score:.2f}", self.ctx.image_backend.name, r.instr_count,
                f"{r.source_image} @ {r.source_addr}"))
        self.status_var.set(f"{len(results)} pattern match(es) ({strictness})")

    # --- session resume (startup) -----------------------------------------------

    def resume_project(self, entry: sessionmod.ProjectEntry) -> None:
        binary_path = entry.dir / entry.binary
        result = self._load_image_job(str(binary_path), entry.backend)
        ctx = self._add_context_from_load(result, project_entry=entry)
        if entry.listing:
            self._attach_listing_to_ctx(ctx, entry.dir / entry.listing)
        sessionmod.touch_last_opened(entry.name)

    # --- Settings tab -----------------------------------------------------------

    def apply_settings(self) -> None:
        for row in self.settings_tree.get_children():
            section, key, value = self.settings_tree.item(row, "values")
            if not self.settings_cfg.has_section(section):
                self.settings_cfg.add_section(section)
            self.settings_cfg.set(section, key, value)
        cfgmod.save(self.settings_cfg)
        self.status_var.set("Settings saved")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="revbench")
    parser.add_argument("--smoke", action="store_true",
                         help="build the GUI headlessly and self-destruct after 2s")
    args = parser.parse_args(argv)

    root = tk.Tk()

    resume_entry = None
    if not args.smoke and sessionmod.list_projects():
        resume_entry = ResumeSessionDialog.ask(root)

    app = App(root)
    if resume_entry is not None:
        app.resume_project(resume_entry)

    if args.smoke:
        root.after(2000, root.destroy)

    root.mainloop()


if __name__ == "__main__":
    main()
