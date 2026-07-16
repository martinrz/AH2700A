"""Feature 1b: computed-jump resolution orchestration + cache glue.

Resolution sources are merged onto one ComputedJump in order of trust:
dynamic trace (ground truth, confidence 1.0) > backend static heuristics
(`ISABackend.static_resolvers()`) > manual entry > unresolved (an explicit,
renderable "needs a live/dynamic trace" state -- see core/isa.py).

The cache key is content-hash based (`core/cache.py`'s KeyedCache), keyed on
an address-normalized signature over a fixed window of instructions ending at
the jump, NOT on the jump's address -- so the same routine at a shifted
address in a later firmware revision still hits the cache. See
`context_signature()` / `cache_key()` below and _claude/68000.md #9.
"""

from __future__ import annotations

from typing import Optional

from revbench.core.cache import KeyedCache
from revbench.core.isa import ComputedJump, ComputedJumpKind, ISABackend, Instruction, ResolvedTarget
from revbench.core.signature import exact_hash, tokenize

DEFAULT_WINDOW = 6


def context_signature(
    backend: ISABackend, instructions: list[Instruction], jump_index: int, window: int = DEFAULT_WINDOW
) -> tuple[str, int, int]:
    """(sha256 hex digest, instr_count_used, total_byte_len) over the K
    instructions ending at jump_index (inclusive), address-normalized via the
    same exact-strictness signature engine used for pattern collection
    (core/signature.py) -- one implementation, two call sites. instr_count/
    byte_len are stored alongside the hash as a corroboration check: a hash
    COLLISION with a different window shape degrades to a safe cache miss,
    never a silently wrong reuse."""
    start = max(0, jump_index - window + 1)
    window_instrs = instructions[start:jump_index + 1]
    tokens = tokenize(backend, window_instrs, strictness="exact")
    byte_len = sum(i.size for i in window_instrs)
    digest = exact_hash(tokens)
    return digest, len(window_instrs), byte_len


def cache_key(arch: str, kind: ComputedJumpKind, sig_hash: str) -> str:
    return f"{arch}:{kind.value}:{sig_hash}"


def resolve(
    backend: ISABackend,
    blob: bytes,
    instructions: list[Instruction],
    jump_index: int,
    cache: KeyedCache,
    *,
    window: int = DEFAULT_WINDOW,
    dynamic_targets: Optional[dict[int, list[int]]] = None,
    image_name: str = "",
) -> ComputedJump:
    """Resolve the computed jump at instructions[jump_index], consulting the
    cache first, then dynamic-trace data, then backend static heuristics."""
    insn = instructions[jump_index]
    kind = backend.is_computed_jump(insn)
    if kind is None:
        raise ValueError(f"instruction at {insn.address:#x} is not a computed jump")

    sig_hash, instr_count, byte_len = context_signature(backend, instructions, jump_index, window)
    key = cache_key(backend.name, kind, sig_hash)

    cached = cache.get(key)
    if cached is not None and _corroborates(cached, instr_count, byte_len):
        targets = _targets_from_cached_offsets(cached.get("target_offsets", []), insn.address)
        cj = ComputedJump(
            address=insn.address, kind=kind, context_sig=sig_hash,
            resolved=cached.get("resolved", False), targets=targets,
            resolution_source=(cached.get("resolution_source") or "") + " (from cache)",
            notes=cached.get("notes", ""),
        )
        _record_provenance(cache, key, cached, insn.address, image_name)
        return cj

    targets: list[ResolvedTarget] = []
    resolution_source = ""

    if dynamic_targets and insn.address in dynamic_targets:
        targets = [ResolvedTarget(addr=t, confidence=1.0, source="dynamic_trace")
                   for t in dynamic_targets[insn.address]]
        resolution_source = "dynamic_trace"

    if not targets:
        for resolver in backend.static_resolvers():
            result = resolver(blob, backend, instructions, jump_index)
            if result:
                targets = result
                resolution_source = result[0].source
                break

    resolved = bool(targets)
    notes = "" if resolved else "base computed at runtime; needs a live/dynamic trace"

    cj = ComputedJump(address=insn.address, kind=kind, context_sig=sig_hash,
                       resolved=resolved, targets=targets,
                       resolution_source=resolution_source, notes=notes)

    entry = {
        "arch": backend.name, "kind": kind.value,
        "context_window_instrs": instr_count, "context_window_bytes": byte_len,
        "resolved": resolved, "resolution_source": resolution_source,
        "target_offsets": _offsets_from_targets(targets, insn.address),
        "notes": notes,
        "first_seen": {"image": image_name, "addr": hex(insn.address)},
        "seen_addrs": [hex(insn.address)],
    }
    cache.put(key, entry)
    return cj


def resolve_manual(
    backend: ISABackend,
    instructions: list[Instruction],
    jump_index: int,
    cache: KeyedCache,
    target_addrs: list[int],
    *,
    window: int = DEFAULT_WINDOW,
    image_name: str = "",
) -> ComputedJump:
    """User-supplied targets take precedence and are written straight to the
    cache with source="manual"."""
    insn = instructions[jump_index]
    kind = backend.is_computed_jump(insn)
    if kind is None:
        raise ValueError(f"instruction at {insn.address:#x} is not a computed jump")

    sig_hash, instr_count, byte_len = context_signature(backend, instructions, jump_index, window)
    key = cache_key(backend.name, kind, sig_hash)
    targets = [ResolvedTarget(addr=t, confidence=1.0, source="manual") for t in target_addrs]

    cj = ComputedJump(address=insn.address, kind=kind, context_sig=sig_hash,
                       resolved=True, targets=targets, resolution_source="manual", notes="")

    entry = cache.get(key) or {"first_seen": {"image": image_name, "addr": hex(insn.address)},
                                "seen_addrs": []}
    entry.update({
        "arch": backend.name, "kind": kind.value,
        "context_window_instrs": instr_count, "context_window_bytes": byte_len,
        "resolved": True, "resolution_source": "manual",
        "target_offsets": _offsets_from_targets(targets, insn.address),
        "notes": "",
    })
    _record_provenance(cache, key, entry, insn.address, image_name, put=False)
    cache.put(key, entry)
    return cj


def _offsets_from_targets(targets: list[ResolvedTarget], jump_addr: int) -> list[dict]:
    """Cache entries store targets as offsets RELATIVE to the jump instruction,
    not absolute addresses -- the whole point of a content-hash cache key is
    that the same routine can appear at a different absolute address in a
    later firmware revision, so an absolute address stored in the entry would
    be wrong as soon as it's reused there."""
    return [{"offset": t.addr - jump_addr, "confidence": t.confidence, "source": t.source} for t in targets]


def _targets_from_cached_offsets(offsets: list[dict], jump_addr: int) -> list[ResolvedTarget]:
    return [ResolvedTarget(addr=jump_addr + o["offset"], confidence=o["confidence"], source=o["source"])
            for o in offsets]


def _corroborates(cached: dict, instr_count: int, byte_len: int) -> bool:
    return (cached.get("context_window_instrs") == instr_count
            and cached.get("context_window_bytes") == byte_len)


def _record_provenance(cache: KeyedCache, key: str, entry: dict, addr: int, image_name: str,
                        put: bool = True) -> None:
    seen = entry.setdefault("seen_addrs", [])
    addr_hex = hex(addr)
    if addr_hex not in seen:
        seen.append(addr_hex)
        if put:
            cache.put(key, entry)
