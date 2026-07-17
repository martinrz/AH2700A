"""Maintenance tab: scan for files under the sessions root not accounted for
by any known project (revbench/gui/session.py's scan_stranded_files()),
list them with a checkbox per row, and let the user delete the checked
ones. Destructive -- requires confirmation before deleting. Not
context-scoped (stranded files are global, not tied to the active
context), so this tab has no refresh() hooked into context switching."""

from __future__ import annotations

from pathlib import Path
from tkinter import messagebox, ttk

from revbench.gui import session as sessionmod
from revbench.gui.widgets.scrolled import scrolled_tree
from revbench.gui.widgets.tooltip import tip


def build(notebook: ttk.Notebook, app) -> ttk.Frame:
    frame = ttk.Frame(notebook)

    bar = ttk.Frame(frame)
    bar.pack(side="top", fill="x", padx=6, pady=6)
    tip(ttk.Button(bar, text="Scan for stranded files", command=lambda: _scan(app)),
        "Find files under the sessions directory not accounted for by any "
        "known project, and write them to stranded_files.txt."
        ).pack(side="left")
    tip(ttk.Button(bar, text="All", command=lambda: _set_all(app, True)),
        "Check every listed file."
        ).pack(side="left", padx=(12, 0))
    tip(ttk.Button(bar, text="None", command=lambda: _set_all(app, False)),
        "Uncheck every listed file."
        ).pack(side="left", padx=(4, 0))
    tip(ttk.Button(bar, text="Delete checked", command=lambda: _delete_checked(app)),
        "Permanently delete every checked file/directory. Cannot be undone."
        ).pack(side="left", padx=(12, 0))

    columns = ("checked", "path")
    tree_frame, tree = scrolled_tree(frame, columns, height=20)
    tree.heading("checked", text="")
    tree.column("checked", width=40, anchor="center")
    tree.column("path", width=500, anchor="w")
    tree_frame.pack(side="top", fill="both", expand=True, padx=6, pady=(0, 6))
    tip(tree, "Click the checkbox column to toggle a row for deletion.")
    tree.bind("<Button-1>", lambda e: _toggle_row(app, tree, e))
    app.maintenance_tree = tree
    app.maintenance_checked = {}  # item id -> bool

    status = ttk.Label(frame, text="", foreground="#888")
    status.pack(side="top", anchor="w", padx=6, pady=(0, 6))
    app.maintenance_status_label = status

    return frame


def _scan(app) -> None:
    stranded = sessionmod.scan_stranded_files()
    tree = app.maintenance_tree
    for row in tree.get_children():
        tree.delete(row)
    app.maintenance_checked = {}
    for path in stranded:
        row_id = tree.insert("", "end", values=("[ ]", str(path)))
        app.maintenance_checked[row_id] = False
    app.maintenance_status_label.configure(
        text=f"{len(stranded)} stranded item(s) -- see {sessionmod.STRANDED_FILES_PATH}")


def _toggle_row(app, tree: ttk.Treeview, event) -> None:
    row_id = tree.identify_row(event.y)
    col = tree.identify_column(event.x)
    if not row_id or col != "#1":
        return
    checked = not app.maintenance_checked.get(row_id, False)
    app.maintenance_checked[row_id] = checked
    values = list(tree.item(row_id, "values"))
    values[0] = "[x]" if checked else "[ ]"
    tree.item(row_id, values=values)


def _set_all(app, checked: bool) -> None:
    tree = app.maintenance_tree
    for row_id in tree.get_children():
        app.maintenance_checked[row_id] = checked
        values = list(tree.item(row_id, "values"))
        values[0] = "[x]" if checked else "[ ]"
        tree.item(row_id, values=values)


def _delete_checked(app) -> None:
    tree = app.maintenance_tree
    to_delete = [Path(tree.item(row_id, "values")[1])
                 for row_id, checked in app.maintenance_checked.items() if checked]
    if not to_delete:
        return
    if not messagebox.askyesno("Delete stranded files",
                                f"Permanently delete {len(to_delete)} item(s)? This cannot be undone."):
        return
    sessionmod.delete_stranded_files(to_delete)
    _scan(app)
