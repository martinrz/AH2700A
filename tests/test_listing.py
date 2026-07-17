from __future__ import annotations

from revbench.io import listing

SAMPLE_LST = """\
; AH2700A_fw_v15.lst
; big-endian Motorola MC68332 -- header comment, skip entirely.

; --- Exception vector table (0x000000-0x0003FF) ---

  000000  dc.l $FFFFFD50                                      ; vector   0  SSP
  000004  dc.l $00000500                                      ; vector   1  ResetPC       -> 0x000500

; --- DATA 0x00055C-0x000560 (4 bytes) ---

  00055C  11 FC 00 55                                      |...U|

sub_000720:
  000720  4238 FA13                 clr.b $fa13.w
  000724  363C 01F4                 move.w #$1f4, d3
loc_000728:  ; loop target
  000728  49FA 0006                 lea.l $730(pc), a4
  00072C  4EFA 00D4                 jmp $802(pc)
"""


def test_parse_listing_extracts_bookmarks(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(SAMPLE_LST, encoding="utf-8")

    info = listing.parse_listing(lst_path)

    assert (0x000720, "sub_000720") in info.bookmarks
    assert (0x000728, "loc_000728") in info.bookmarks
    assert len(info.bookmarks) == 2


def test_parse_listing_skips_headers_data_and_vectors(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(SAMPLE_LST, encoding="utf-8")

    info = listing.parse_listing(lst_path)

    # Vector-table dc.l entries and the DATA dump line must not be seeds.
    assert 0x000000 not in info.seeds
    assert 0x000004 not in info.seeds
    assert 0x00055C not in info.seeds


def test_parse_listing_collects_real_instruction_seeds(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(SAMPLE_LST, encoding="utf-8")

    info = listing.parse_listing(lst_path)

    assert info.seeds == [0x000720, 0x000724, 0x000728, 0x00072C]


def test_find_binary_hint_matches_single_sibling_bin(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(SAMPLE_LST, encoding="utf-8")
    bin_path = tmp_path / "sample_fw.bin"
    bin_path.write_bytes(b"\x00" * 16)

    assert listing.find_binary_hint(lst_path) == bin_path


def test_find_binary_hint_none_when_ambiguous(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(SAMPLE_LST, encoding="utf-8")
    (tmp_path / "a.bin").write_bytes(b"\x00")
    (tmp_path / "b.bin").write_bytes(b"\x00")

    assert listing.find_binary_hint(lst_path) is None


def test_find_binary_hint_none_when_no_sibling(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(SAMPLE_LST, encoding="utf-8")

    assert listing.find_binary_hint(lst_path) is None


# --- parse_full_listing() ----------------------------------------------------

FULL_SAMPLE_LST = """\
; header comment -- skip

helper_1000:
  001000  4E75                      rts

sub_000720:
  000720  4238 FA13                 clr.b $fa13.w
  000724  6100 08D8                 bsr.w $1000
  000728  4EB9 00101000             jsr $101000.l                        ; biased call to helper_1000
  00072C  4EFA 00D4                 jmp $802(pc)
"""


def test_parse_full_listing_preserves_raw_text_verbatim(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FULL_SAMPLE_LST, encoding="utf-8")

    full = listing.parse_full_listing(lst_path)

    original_lines = FULL_SAMPLE_LST.splitlines()
    assert [line.raw_text for line in full.lines] == original_lines


def test_parse_full_listing_addr_to_line_points_at_instruction_line(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FULL_SAMPLE_LST, encoding="utf-8")

    full = listing.parse_full_listing(lst_path)

    idx = full.addr_to_line[0x000720]
    assert full.lines[idx].kind == "instr"
    assert full.lines[idx].address == 0x000720
    assert full.lines[idx].mnemonic == "clr.b"


def test_parse_full_listing_extracts_pc_relative_jump_ref(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FULL_SAMPLE_LST, encoding="utf-8")

    full = listing.parse_full_listing(lst_path)

    jmp_refs = [r for r in full.jump_refs if r.address == 0x00072C]
    assert len(jmp_refs) == 1
    assert jmp_refs[0].mnemonic == "jmp"
    assert jmp_refs[0].raw_target_text == "$802"


def test_parse_full_listing_resolves_bias_for_call_target(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FULL_SAMPLE_LST, encoding="utf-8")

    full = listing.parse_full_listing(lst_path)

    # jsr $101000.l is +0x100000-biased -- physical target is helper_1000 @ 0x1000.
    jsr_ref = next(r for r in full.jump_refs if r.address == 0x000728)
    assert jsr_ref.resolved_label == "helper_1000"


def test_parse_full_listing_subroutines_includes_sub_prefixed_label(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FULL_SAMPLE_LST, encoding="utf-8")

    full = listing.parse_full_listing(lst_path)

    assert (0x000720, "sub_000720") in full.subroutines


def test_parse_full_listing_subroutines_includes_non_sub_named_call_target(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FULL_SAMPLE_LST, encoding="utf-8")

    full = listing.parse_full_listing(lst_path)

    # helper_1000 isn't sub_*-named but IS a bsr/jsr target -- still counts.
    assert (0x001000, "helper_1000") in full.subroutines


def test_parse_full_listing_bookmarks_and_seeds_match_thin_wrapper(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FULL_SAMPLE_LST, encoding="utf-8")

    full = listing.parse_full_listing(lst_path)
    thin = listing.parse_listing(lst_path)

    assert full.bookmarks == thin.bookmarks
    assert full.seeds == thin.seeds


# --- filter predicates (Listing/Labels tabs) ---------------------------------

def test_is_generic_label_matches_sub_and_loc_prefixes():
    assert listing.is_generic_label("sub_000720")
    assert listing.is_generic_label("loc_0012BC")


def test_is_generic_label_false_for_hand_or_string_named():
    assert not listing.is_generic_label("helper_1000")
    assert not listing.is_generic_label("ResetPC")
    assert not listing.is_generic_label("INTERUPT")


FILTER_SAMPLE_LST = """\
; header

sub_002000:
  002000  4ED0                      jmp (a0)                              ; computed jump
  002004  4E90                      jsr (a0)                              ; computed call
  002008  31FC 0001 FA27            move.w #$1, $fa27.w                   ; flash JEDEC unlock
  00200E  4E75                      rts

; --- DATA 0x003000-0x003010 (16 bytes) ---

data_label:
  003000  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |................|
"""


def test_is_known_variable_line_true_for_label_pointing_at_data(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FILTER_SAMPLE_LST, encoding="utf-8")
    full = listing.parse_full_listing(lst_path)

    data_label_line = next(l for l in full.lines if l.kind == "label" and l.label == "data_label")
    assert listing.is_known_variable_line(data_label_line, full.addr_to_line, full.lines)


def test_is_known_variable_line_true_for_commented_absolute_operand(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FILTER_SAMPLE_LST, encoding="utf-8")
    full = listing.parse_full_listing(lst_path)

    fa27_line = next(l for l in full.lines if l.address == 0x002008)
    assert listing.is_known_variable_line(fa27_line, full.addr_to_line, full.lines)


def test_is_known_variable_line_false_for_plain_instruction(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FILTER_SAMPLE_LST, encoding="utf-8")
    full = listing.parse_full_listing(lst_path)

    rts_line = next(l for l in full.lines if l.address == 0x00200E)
    assert not listing.is_known_variable_line(rts_line, full.addr_to_line, full.lines)


def test_is_computed_jump_line_true_for_register_indirect_jmp(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FILTER_SAMPLE_LST, encoding="utf-8")
    full = listing.parse_full_listing(lst_path)

    resolved_addrs = {ref.address for ref in full.jump_refs}
    jmp_line = next(l for l in full.lines if l.address == 0x002000 and l.kind == "instr")
    assert listing.is_computed_jump_line(jmp_line, resolved_addrs)
    assert not listing.is_computed_call_line(jmp_line, resolved_addrs)


def test_is_computed_call_line_true_for_register_indirect_jsr(tmp_path):
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FILTER_SAMPLE_LST, encoding="utf-8")
    full = listing.parse_full_listing(lst_path)

    resolved_addrs = {ref.address for ref in full.jump_refs}
    jsr_line = next(l for l in full.lines if l.address == 0x002004)
    assert listing.is_computed_call_line(jsr_line, resolved_addrs)
    assert not listing.is_computed_jump_line(jsr_line, resolved_addrs)


def test_is_computed_jump_line_false_when_target_is_resolvable(tmp_path):
    # The original FULL_SAMPLE_LST's "jmp $802(pc)" line HAS a resolvable
    # target, so it must not count as "computed".
    lst_path = tmp_path / "sample.lst"
    lst_path.write_text(FULL_SAMPLE_LST, encoding="utf-8")
    full = listing.parse_full_listing(lst_path)

    resolved_addrs = {ref.address for ref in full.jump_refs}
    jmp_line = next(l for l in full.lines if l.address == 0x00072C)
    assert not listing.is_computed_jump_line(jmp_line, resolved_addrs)
