"""Arch-agnostic address-normalized instruction signatures (Feature 2b core),
also reused by analysis/jumptrace.py's computed-jump cache key (one
implementation, two call sites) -- see _claude/68000.md #9 for the underlying
technique: hash mnemonics + immediates while ignoring absolute
addresses/branch targets, so the same routine matches across firmware
revisions.

Three strictness levels, since cross-revision immediates (version strings,
addresses baked in as data) can legitimately differ while a routine is "the
same":
- exact:      mnemonic + immediates (from ISABackend.normalize_for_signature)
- structural: mnemonic + operand kinds, immediates ignored
- loose:      mnemonic sequence only (control-flow shape)
"""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Sequence

from revbench.core.isa import ISABackend, Instruction

STRICTNESS_LEVELS = ("exact", "structural", "loose")


def _normalize_exact(backend: ISABackend, insn: Instruction) -> tuple:
    mnemonic, immediates = backend.normalize_for_signature(insn)
    return (mnemonic, immediates)


def _normalize_structural(backend: ISABackend, insn: Instruction) -> tuple:
    mnemonic, _ = backend.normalize_for_signature(insn)
    return (mnemonic, tuple(op.kind.value for op in insn.operands))


def _normalize_loose(backend: ISABackend, insn: Instruction) -> tuple:
    mnemonic, _ = backend.normalize_for_signature(insn)
    return (mnemonic,)


_NORMALIZERS = {
    "exact": _normalize_exact,
    "structural": _normalize_structural,
    "loose": _normalize_loose,
}


def tokenize(backend: ISABackend, instructions: Sequence[Instruction], strictness: str = "structural") -> tuple:
    if strictness not in _NORMALIZERS:
        raise ValueError(f"unknown strictness {strictness!r}; must be one of {STRICTNESS_LEVELS}")
    normalizer = _NORMALIZERS[strictness]
    return tuple(normalizer(backend, insn) for insn in instructions)


def exact_hash(tokens: tuple) -> str:
    """Stable content hash of a token tuple -- plain repr() of tuples/str/int/
    None is deterministic across runs (no memory addresses involved)."""
    return hashlib.sha256(repr(tokens).encode("utf-8")).hexdigest()


def ngram_bag(tokens: tuple, n: int = 2) -> Counter:
    if not tokens:
        return Counter()
    if len(tokens) < n:
        return Counter([tokens])
    return Counter(tokens[i:i + n] for i in range(len(tokens) - n + 1))


def bag_similarity(bag_a: Counter, bag_b: Counter) -> float:
    """Jaccard similarity over the two n-gram bags' distinct keys, 0.0-1.0."""
    keys_a, keys_b = set(bag_a), set(bag_b)
    if not keys_a and not keys_b:
        return 1.0
    union = keys_a | keys_b
    if not union:
        return 0.0
    return len(keys_a & keys_b) / len(union)


def tokens_from_json(raw) -> tuple:
    """JSON round-trips tuples as lists, which breaks hashing (a tuple
    containing a list is unhashable) -- recursively restore tuples after
    loading a stored pattern record back from disk."""
    if isinstance(raw, list):
        return tuple(tokens_from_json(item) for item in raw)
    return raw
