"""Arch-agnostic multi-format value conversion (Feature 2a).

`printable_ascii_density` is shared with `analysis/blockeval.py`'s
code/data plausibility scoring -- one implementation, two call sites, per the
project's "reuse, don't duplicate" rule.
"""

from __future__ import annotations

import string
import struct
from dataclasses import dataclass
from typing import Optional

_PRINTABLE = set(bytes(string.printable, "ascii")) - set(bytes("\x0b\x0c", "ascii"))

# A small curated table of recognized IEEE-754 constants, matched within a
# tolerance -- mirrors the "dc.d $<hex> ; <value> ; <name>" annotation
# convention already used in _claude/68000.md / 5520A-decode-findings.md.
_RECOGNIZED_CONSTANTS = {
    "pi": 3.14159265358979323846,
    "2pi": 2 * 3.14159265358979323846,
    "e": 2.71828182845904523536,
    "ln2": 0.69314718055994530942,
    "sqrt2": 1.4142135623730951,
}
for _n in range(-32, 33):
    _RECOGNIZED_CONSTANTS[f"2^{_n}"] = 2.0 ** _n


def printable_ascii_density(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (or common whitespace).
    0.0 for empty input."""
    if not data:
        return 0.0
    return sum(1 for b in data if b in _PRINTABLE) / len(data)


def recognize_float_constant(value: float, rel_tol: float = 1e-9) -> Optional[str]:
    if value != value or value in (float("inf"), float("-inf")):  # NaN / Inf
        return None
    for name, const in _RECOGNIZED_CONSTANTS.items():
        if const == 0:
            continue
        if abs(value - const) <= rel_tol * abs(const):
            return name
    return None


@dataclass(frozen=True)
class BcdResult:
    digits: str
    valid: bool          # False if any nibble > 9


def decode_bcd(data: bytes) -> BcdResult:
    digits = []
    valid = True
    for b in data:
        hi, lo = (b >> 4) & 0xF, b & 0xF
        for nibble in (hi, lo):
            if nibble > 9:
                valid = False
            digits.append(str(nibble))
    return BcdResult(digits="".join(digits), valid=valid)


@dataclass(frozen=True)
class FormatView:
    interpretation: str   # e.g. "uint32", "float64", "ascii", "bcd", "hex"
    value: str             # rendered text
    note: str = ""         # e.g. "NaN", "recognized: pi", "invalid nibble present"


def inspect(data: bytes, width: int, endian: str = "big") -> list[FormatView]:
    """Every applicable interpretation of data[:width]. Non-authoritative --
    the caller shows all of these side by side, never picking one as "the"
    answer. Empty list if `data` has fewer than `width` bytes available."""
    if width not in (1, 2, 4, 8):
        raise ValueError(f"unsupported width {width}; must be 1, 2, 4, or 8")
    chunk = data[:width]
    if len(chunk) < width:
        return []

    byteorder = "big" if endian == "big" else "little"
    views: list[FormatView] = []

    views.append(FormatView("hex", " ".join(f"{b:02x}" for b in chunk)))

    uval = int.from_bytes(chunk, byteorder, signed=False)
    sval = int.from_bytes(chunk, byteorder, signed=True)
    views.append(FormatView(f"uint{width * 8}", str(uval)))
    views.append(FormatView(f"int{width * 8}", str(sval)))

    if width in (4, 8):
        fmt = (">" if byteorder == "big" else "<") + ("f" if width == 4 else "d")
        (fval,) = struct.unpack(fmt, chunk)
        if fval != fval:
            views.append(FormatView(f"float{width * 8}", "NaN", "NaN"))
        elif fval in (float("inf"), float("-inf")):
            views.append(FormatView(f"float{width * 8}", str(fval), "Inf"))
        else:
            recognized = recognize_float_constant(fval)
            note = f"recognized: {recognized}" if recognized else ""
            views.append(FormatView(f"float{width * 8}", f"{fval:.10g}", note))

    density = printable_ascii_density(chunk)
    ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    views.append(FormatView("ascii", ascii_text, f"{density:.0%} printable"))

    bcd = decode_bcd(chunk)
    views.append(FormatView("bcd", bcd.digits, "valid" if bcd.valid else "invalid nibble present"))

    return views


def best_guess(data: bytes, width: int, endian: str = "big") -> Optional[str]:
    """A hint badge naming the most-plausible interpretation of data[:width] --
    always advisory, never hides the alternatives (the caller still shows
    every row from inspect()). None if there aren't enough bytes."""
    chunk = data[:width]
    if len(chunk) < width:
        return None

    scores: dict[str, float] = {
        f"uint{width * 8}": 0.3,
        f"int{width * 8}": 0.3,
        "hex": 0.1,
    }
    scores["ascii"] = printable_ascii_density(chunk)

    bcd = decode_bcd(chunk)
    scores["bcd"] = 0.55 if bcd.valid else 0.0

    if width in (4, 8):
        fmt = (">" if endian == "big" else "<") + ("f" if width == 4 else "d")
        (fval,) = struct.unpack(fmt, chunk)
        key = f"float{width * 8}"
        if fval != fval or fval in (float("inf"), float("-inf")):
            scores[key] = 0.0
        elif recognize_float_constant(fval):
            scores[key] = 0.9
        else:
            scores[key] = 0.45

    return max(scores, key=scores.get)
