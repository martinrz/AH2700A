# revbench -- interactive firmware RE companion

Purpose: interactive companion to the batch listing pipeline (make_listing.py,
disregion.py, etc. -- those live elsewhere, untouched). Instant code/data
evaluation of a byte range, computed-jump resolution with a persistent cache,
multi-format value inspection, pattern collection/comparison, and plain-English
instruction tooltips. ISA-agnostic core; only M68K (capstone) implemented today.

Stack: Python 3, tkinter GUI (follows `_claude/UI.md` + `_claude/tooltips.md`),
capstone for decoding. No GPIB/instrument dependency -- pure offline file tool.

Run: `python -m revbench.gui.app` (or `--smoke` for a headless self-test).
Tests: `python -m pytest tests/` from this directory.

Data: `data/settings.ini`, `data/jump_cache.json`, `data/patterns.json` -- all
project-local, nothing written outside `projects/revbench/`.

Watch-outs:
- Not a refactor of make_listing.py/dump3v9.py -- a separate, standalone
  companion tool. Don't go looking for those scripts in this repo.
- Cache keys are content-hash based (address-normalized instruction+immediate
  signature), NOT raw addresses -- see `core/cache.py` / `analysis/jumptrace.py`.
  Don't "fix" a cache miss by keying on address; that defeats the point (cache
  must survive address drift across firmware revisions).
- Instruction bytes need lookahead (up to `backend.max_insn_len`, 10 for M68K)
  -- always slice `blob[addr:addr+backend.max_insn_len]` before decoding one
  instruction, never a size guessed from the previous instruction.
- ASCII-only strings in code/UI (no unicode symbols) -- Drive-synced
  UTF-8-BOM files elsewhere in this lab; keep this project consistent.
- `core/` and `analysis/` must never import from `backends/` directly -- they
  depend only on the `ISABackend` interface (`core/isa.py`). Capstone-specific
  code stays inside `backends/m68k/`. This is what keeps a future ARM/x86
  backend a pure addition.
