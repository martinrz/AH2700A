from __future__ import annotations

import pytest

from revbench.core import signature

cs = pytest.importorskip("capstone")

from revbench.backends.m68k.backend import M68KBackend  # noqa: E402


@pytest.fixture(scope="module")
def backend():
    return M68KBackend()


def decode_seq(backend, hexstr, addr=0x1000):
    blob = bytearray(addr + len(bytes.fromhex(hexstr)) + 16)
    body = bytes.fromhex(hexstr)
    blob[addr:addr + len(body)] = body
    instrs = []
    pos = addr
    end = addr + len(body)
    while pos < end:
        insn = backend.disassemble_one(bytes(blob), pos)
        assert insn is not None
        instrs.append(insn)
        pos += insn.size
    return instrs


def test_exact_hash_identical_for_same_bytes(backend):
    a = decode_seq(backend, "7005" + "4E75", addr=0x1000)  # moveq #5,d0 ; rts
    b = decode_seq(backend, "7005" + "4E75", addr=0x9000)  # same bytes, different base
    tokens_a = signature.tokenize(backend, a, "exact")
    tokens_b = signature.tokenize(backend, b, "exact")
    assert signature.exact_hash(tokens_a) == signature.exact_hash(tokens_b)


def test_exact_hash_differs_for_different_immediate(backend):
    a = decode_seq(backend, "7005", addr=0x1000)  # moveq #5,d0
    b = decode_seq(backend, "7009", addr=0x1000)  # moveq #9,d0
    tokens_a = signature.tokenize(backend, a, "exact")
    tokens_b = signature.tokenize(backend, b, "exact")
    assert signature.exact_hash(tokens_a) != signature.exact_hash(tokens_b)


def test_structural_hash_same_for_different_immediate(backend):
    a = decode_seq(backend, "7005", addr=0x1000)  # moveq #5,d0
    b = decode_seq(backend, "7009", addr=0x1000)  # moveq #9,d0
    tokens_a = signature.tokenize(backend, a, "structural")
    tokens_b = signature.tokenize(backend, b, "structural")
    # structural strictness ignores immediates -- only mnemonic + operand kinds
    assert tokens_a == tokens_b


def test_loose_ignores_immediates_and_operand_kinds(backend):
    a = decode_seq(backend, "7005", addr=0x1000)  # moveq #5,d0
    b = decode_seq(backend, "7009", addr=0x1000)  # moveq #9,d0 -- same mnemonic, different immediate
    assert signature.tokenize(backend, a, "loose") == signature.tokenize(backend, b, "loose")


def test_loose_still_distinguishes_different_mnemonics(backend):
    a = decode_seq(backend, "7005", addr=0x1000)  # moveq
    b = decode_seq(backend, "4E75", addr=0x1000)  # rts
    assert signature.tokenize(backend, a, "loose") != signature.tokenize(backend, b, "loose")


def test_ngram_bag_similarity_exact_match():
    tokens = (("moveq", ()), ("rts", ()))
    bag_a = signature.ngram_bag(tokens, n=1)
    bag_b = signature.ngram_bag(tokens, n=1)
    assert signature.bag_similarity(bag_a, bag_b) == 1.0


def test_ngram_bag_similarity_partial_overlap():
    tokens_a = (("moveq", ()), ("bra", ()), ("rts", ()))
    tokens_b = (("moveq", ()), ("nop", ()), ("rts", ()))
    bag_a = signature.ngram_bag(tokens_a, n=1)
    bag_b = signature.ngram_bag(tokens_b, n=1)
    score = signature.bag_similarity(bag_a, bag_b)
    assert 0.0 < score < 1.0


def test_ngram_bag_similarity_no_overlap():
    tokens_a = (("moveq", ()),)
    tokens_b = (("rts", ()),)
    score = signature.bag_similarity(signature.ngram_bag(tokens_a), signature.ngram_bag(tokens_b))
    assert score == 0.0


def test_tokens_from_json_restores_hashable_tuples():
    raw = [["moveq", [5]], ["rts", []]]
    restored = signature.tokens_from_json(raw)
    assert restored == (("moveq", (5,)), ("rts", ()))
    assert hash(restored)  # must not raise -- tuples of tuples are hashable


def test_tokenize_rejects_unknown_strictness(backend):
    a = decode_seq(backend, "4E75", addr=0x1000)
    with pytest.raises(ValueError):
        signature.tokenize(backend, a, "bogus")
