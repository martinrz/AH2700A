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
from tkinter import filedialog, messagebox, simpledialog, ttk

from revbench.analysis import blockeval, patterns
from revbench.core import formats
from revbench.core.cache import KeyedCache
from revbench.core.isa import InsnFlags
from revbench.core import registry
from revbench.gui import config as cfgmod
from revbench.gui.dialogs import JumpTraceDialog
from revbench.gui.tabs import block_tab, image_tab, patterns_tab, settings_tab, values_tab
from revbench.gui.widgets.scrolled import wheel_everywhere
from revbench.gui.widgets.tooltip import RowToolTip, _tips_on, tip


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("revbench")

        self.settings_cfg = cfgmod.load()
        _tips_on["v"] = self.settings_cfg.getboolean("options", "tooltips", fallback=True)

        # --- analysis state (no image loaded yet) ------------------------
        self.image_blob: bytes | None = None
        self.image_backend = None
        self.image_name: str = ""
        self.image_seeds: list[int] = []
        self.current_block_result = None       # blockeval.BlockEvalResult
        self._block_row_info: dict[str, tuple] = {}   # tree row id -> (Instruction, index)

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

        notebook = ttk.Notebook(root)
        notebook.pack(side="top", fill="both", expand=True)

        self.tabs = {}
        for name, mod in (
            ("Image", image_tab),
            ("Block", block_tab),
            ("Values", values_tab),
            ("Patterns", patterns_tab),
            ("Settings", settings_tab),
        ):
            frame = mod.build(notebook, self)
            notebook.add(frame, text=name)
            self.tabs[name] = frame

        RowToolTip(self.block_tree, self._explain_block_row)

        self._build_bottom_bar(root)
        wheel_everywhere(root)

        root.after(150, self._poll_decode_q)
        root.after(150, self._poll_trace_q)
        root.after(150, self._poll_pattern_q)

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
        instr_count = len(self.current_block_result.block.instructions) if self.current_block_result else 0
        unresolved = 0
        if self.current_block_result:
            for insn in self.current_block_result.block.instructions:
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

    # --- Image tab ------------------------------------------------------------

    def load_image_dialog(self) -> None:
        path = filedialog.askopenfilename(title="Load firmware image")
        if not path:
            return
        backend_name = self.backend_var.get()
        self._submit(self._load_image_job, (path, backend_name),
                     on_ok=self._on_image_loaded, on_err=self._on_job_error,
                     busy=f"Loading {os.path.basename(path)}...")

    def _load_image_job(self, path: str, backend_name: str) -> dict:
        with open(path, "rb") as f:
            blob = f.read()
        backend = registry.create(backend_name)
        seeds = backend.vector_table_seeds(blob)
        return {"path": path, "blob": blob, "backend": backend, "seeds": seeds}

    def _on_image_loaded(self, result: dict) -> None:
        self.image_blob = result["blob"]
        self.image_backend = result["backend"]
        self.image_name = os.path.basename(result["path"])
        self.image_seeds = result["seeds"]
        self.image_info_label.configure(
            text=f"{self.image_name}: {len(self.image_blob)} bytes, "
                 f"backend={self.image_backend.name}, {len(self.image_seeds)} vector-table seed(s)")
        self.status_var.set(f"Loaded {self.image_name}")
        self._update_live_info()

    # --- Block tab (Feature 1) -------------------------------------------------

    def evaluate_block(self) -> None:
        if self.image_blob is None:
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
        return blockeval.evaluate(self.image_backend, self.image_blob, addr, length)

    def _on_block_evaluated(self, result) -> None:
        self.current_block_result = result
        self.block_verdict_label.configure(text=result.summary)

        tree = self.block_tree
        for row in tree.get_children():
            tree.delete(row)
        self._block_row_info = {}
        for idx, insn in enumerate(result.block.instructions):
            row_id = tree.insert("", "end", values=(
                hex(insn.address), insn.raw_bytes.hex(), insn.mnemonic, insn.op_str,
                self._flags_text(insn.flags)))
            self._block_row_info[row_id] = (insn, idx)

        self.status_var.set(result.summary)
        self._update_live_info()

    @staticmethod
    def _flags_text(flags: InsnFlags) -> str:
        names = [f.name for f in InsnFlags if f != InsnFlags.NONE and flags & f]
        return ",".join(names)

    def _explain_block_row(self, row_id: str):
        if self.image_backend is None:
            return None
        entry = self._block_row_info.get(row_id)
        if entry is None:
            return None
        insn, _idx = entry
        return self.image_backend.explain(insn)

    def trace_selected_jump(self) -> None:
        if self.current_block_result is None:
            messagebox.showinfo("No block", "Evaluate a block on the Block tab first.")
            return
        selection = self.block_tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select an instruction row first.")
            return
        entry = self._block_row_info.get(selection[0])
        if entry is None:
            return
        insn, idx = entry
        if self.image_backend.is_computed_jump(insn) is None:
            messagebox.showinfo("Not a computed jump", "The selected instruction is not a computed jump.")
            return
        JumpTraceDialog(self, idx)

    def send_block_selection_to_values(self) -> None:
        selection = self.block_tree.selection()
        if not selection:
            return
        entry = self._block_row_info.get(selection[0])
        if entry is None:
            return
        insn, _idx = entry
        self.values_addr_var.set(hex(insn.address))
        self.inspect_values()

    # --- Values tab (Feature 2a) -----------------------------------------------

    def inspect_values(self) -> None:
        if self.image_blob is None:
            messagebox.showinfo("No image", "Load an image on the Image tab first.")
            return
        try:
            addr = int(self.values_addr_var.get(), 0)
            width = int(self.values_width_var.get())
        except (ValueError, AttributeError):
            messagebox.showerror("Invalid input", "Enter a valid address and width.")
            return
        endian = self.values_endian_var.get()
        chunk = self.image_blob[addr:]
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
        if self.current_block_result is None:
            messagebox.showinfo("No block", "Evaluate a block on the Block tab first.")
            return
        label = simpledialog.askstring("Collect pattern", "Label for this pattern:", parent=self.root)
        if not label:
            return
        strictness = self.settings_cfg.get("options", "pattern_strictness", fallback="structural")
        record = patterns.collect(
            self.pattern_cache, self.image_backend, self.current_block_result.block.instructions,
            label, strictness=strictness, image_name=self.image_name)
        self.pattern_cache.save()
        self.status_var.set(f"Collected pattern '{label}' ({record.instr_count} instrs, {strictness})")

    def compare_pattern(self) -> None:
        if self.current_block_result is None:
            messagebox.showinfo("No block", "Evaluate a block on the Block tab first.")
            return
        strictness = self.settings_cfg.get("options", "pattern_strictness", fallback="structural")
        results = patterns.compare(
            self.pattern_cache, self.image_backend, self.current_block_result.block.instructions,
            strictness=strictness)

        tree = self.patterns_tree
        for row in tree.get_children():
            tree.delete(row)
        for r in results:
            tree.insert("", "end", values=(
                r.label, f"{r.score:.2f}", self.image_backend.name, r.instr_count,
                f"{r.source_image} @ {r.source_addr}"))
        self.status_var.set(f"{len(results)} pattern match(es) ({strictness})")

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
    App(root)

    if args.smoke:
        root.after(2000, root.destroy)

    root.mainloop()


if __name__ == "__main__":
    main()
