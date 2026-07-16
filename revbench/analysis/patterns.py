"""Feature 2b: pattern collection/comparison orchestration on top of
core/signature.py (the signature engine) and core/cache.py (the same generic
JSON KeyedCache used by the jump-resolution cache -- one storage abstraction,
two uses).
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from difflib import SequenceMatcher

from revbench.core.cache import KeyedCache
from revbench.core.isa import ISABackend, Instruction
from revbench.core.signature import bag_similarity, exact_hash, ngram_bag, tokenize, tokens_from_json


@dataclass
class PatternRecord:
    id: str
    label: str
    arch: str
    strictness: str
    exact_hash: str
    tokens: tuple
    instr_count: int
    byte_len: int
    source_image: str = ""
    source_addr: str = ""
    notes: str = ""


@dataclass
class MatchResult:
    record_id: str
    label: str
    score: float
    exact: bool
    instr_count: int = 0
    source_image: str = ""
    source_addr: str = ""


def collect(
    cache: KeyedCache,
    backend: ISABackend,
    instructions: list[Instruction],
    label: str,
    strictness: str = "structural",
    image_name: str = "",
) -> PatternRecord:
    """Store the current block's signature into the pattern collection."""
    tokens = tokenize(backend, instructions, strictness)
    record = PatternRecord(
        id=uuid.uuid4().hex[:16],
        label=label,
        arch=backend.name,
        strictness=strictness,
        exact_hash=exact_hash(tokens),
        tokens=tokens,
        instr_count=len(instructions),
        byte_len=sum(i.size for i in instructions),
        source_image=image_name,
        source_addr=hex(instructions[0].address) if instructions else "",
    )
    cache.put(record.id, _to_entry(record))
    return record


def compare(
    cache: KeyedCache,
    backend: ISABackend,
    instructions: list[Instruction],
    strictness: str = "structural",
    n: int = 2,
    same_arch_only: bool = True,
) -> list[MatchResult]:
    """Rank every stored pattern (of the same strictness, same arch by
    default) by similarity to the current block. Exact-hash matches score
    1.0; otherwise a Jaccard score over mnemonic n-grams."""
    tokens = tokenize(backend, instructions, strictness)
    this_hash = exact_hash(tokens)
    this_bag = ngram_bag(tokens, n)

    results: list[MatchResult] = []
    for key in cache.keys():
        entry = cache.get(key)
        if entry is None or entry.get("strictness") != strictness:
            continue
        if same_arch_only and entry.get("arch") != backend.name:
            continue

        if entry.get("exact_hash") == this_hash:
            results.append(MatchResult(record_id=entry["id"], label=entry["label"], score=1.0,
                                        exact=True, instr_count=entry.get("instr_count", 0),
                                        source_image=entry.get("source_image", ""),
                                        source_addr=entry.get("source_addr", "")))
            continue

        other_tokens = tokens_from_json(entry.get("tokens", []))
        other_bag = ngram_bag(other_tokens, n)
        score = bag_similarity(this_bag, other_bag)
        results.append(MatchResult(record_id=entry["id"], label=entry["label"], score=score,
                                    exact=False, instr_count=entry.get("instr_count", 0),
                                    source_image=entry.get("source_image", ""),
                                    source_addr=entry.get("source_addr", "")))

    results.sort(key=lambda r: r.score, reverse=True)
    return results


def diff_against(cache: KeyedCache, record_id: str, tokens: tuple):
    """Side-by-side diff opcodes (difflib) between `tokens` and a stored
    record's tokens, for the Patterns tab's drill-down view."""
    entry = cache.get(record_id)
    if entry is None:
        raise KeyError(f"no pattern record {record_id!r}")
    other_tokens = tokens_from_json(entry.get("tokens", []))
    return SequenceMatcher(a=tokens, b=other_tokens, autojunk=False).get_opcodes()


def _to_entry(record: PatternRecord) -> dict:
    # asdict()'s tuple fields serialize fine as JSON arrays (json.dumps treats
    # tuples like lists); tokens_from_json() restores tuples on the way back
    # in, since that direction actually needs hashable n-gram keys.
    return asdict(record)
