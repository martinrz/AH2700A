from __future__ import annotations

import math
import struct

import pytest

from revbench.core import formats


def test_printable_ascii_density():
    assert formats.printable_ascii_density(b"") == 0.0
    assert formats.printable_ascii_density(b"ABCD") == 1.0
    assert formats.printable_ascii_density(b"\x00\x01AB") == 0.5


def test_recognize_float_constant_finds_pi():
    assert formats.recognize_float_constant(math.pi) == "pi"


def test_recognize_float_constant_finds_power_of_two():
    assert formats.recognize_float_constant(0.5) == "2^-1"


def test_recognize_float_constant_none_for_garbage():
    assert formats.recognize_float_constant(1.2345678) is None


def test_recognize_float_constant_none_for_nan_inf():
    assert formats.recognize_float_constant(float("nan")) is None
    assert formats.recognize_float_constant(float("inf")) is None


def test_decode_bcd_valid():
    result = formats.decode_bcd(bytes.fromhex("1234"))
    assert result.digits == "1234"
    assert result.valid


def test_decode_bcd_invalid_nibble():
    result = formats.decode_bcd(bytes.fromhex("1A34"))  # 'A' nibble > 9
    assert not result.valid


def test_inspect_worked_listing_example():
    # 68000.md worked example: 0C79 BE55 23FFFE -> cmpi.w #$be55, $23fffe.l
    # $be55 as a plain uint16 big-endian value:
    data = bytes.fromhex("be55")
    views = {v.interpretation: v for v in formats.inspect(data, width=2)}
    assert views["hex"].value == "be 55"
    assert views["uint16"].value == str(0xBE55)


def test_inspect_returns_empty_for_insufficient_bytes():
    assert formats.inspect(b"\x01\x02", width=4) == []


def test_inspect_recognizes_float_constant():
    data = struct.pack(">d", math.pi)
    views = {v.interpretation: v for v in formats.inspect(data, width=8)}
    assert "recognized: pi" == views["float64"].note


def test_inspect_flags_nan():
    data = bytes.fromhex("7FF8000000000000")  # a quiet NaN
    views = {v.interpretation: v for v in formats.inspect(data, width=8)}
    assert views["float64"].note == "NaN"


def test_best_guess_prefers_ascii_for_text():
    data = b"ABCD"
    assert formats.best_guess(data, width=4) == "ascii"


def test_best_guess_prefers_recognized_float():
    data = struct.pack(">d", math.pi)
    assert formats.best_guess(data, width=8) == "float64"


def test_best_guess_none_for_insufficient_bytes():
    assert formats.best_guess(b"\x01", width=4) is None


def test_inspect_rejects_bad_width():
    with pytest.raises(ValueError):
        formats.inspect(b"\x00\x00\x00", width=3)
