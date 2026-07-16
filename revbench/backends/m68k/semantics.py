"""Feature 3: plain-English instruction explanations for M68K.

SEMANTICS is seeded from the _claude/68000.md opcode cheat-sheet (link/unlk/
rts/rte/rtr/jsr/jmp/bsr/bra/the bcc family/moveq/pea/lea/movea/tst/clr/btst/
cmpi, plus common ALU ops). Templates use "{op1}"/"{op2}"/... (1-indexed,
filled from each decoded Operand.text) and "{size_note}" for a "(w-sized)"
style suffix. ADDR_MODE_NOTES gives the per-operand-kind addressing-mode
detail used by explain_operand()'s longer-hover/right-click view.

Any mnemonic not in SEMANTICS falls back to a safe generic message via
core.isa.compose_explanation() -- gaps here are visible (a plain, honest
"no description yet"), never a crash.
"""

from __future__ import annotations

from revbench.core.isa import OperandKind

SEMANTICS: dict[str, str] = {
    "MOVE": "Copies {op1} into {op2}{size_note}. Sets N/Z from the result; clears V and C. X unaffected.",
    "MOVEA": "Copies {op1} into address register {op2}{size_note}. Does not affect condition codes.",
    "MOVEQ": "Loads the sign-extended 8-bit immediate {op1} into {op2}. Sets N/Z from the result; clears V and C.",
    "LINK": "Pushes {op1} (frame pointer) onto the stack, points it at the new stack top, "
            "then reserves {op2} bytes of locals -- function-entry prologue.",
    "UNLK": "Restores the stack pointer from {op1} and pops the saved frame pointer -- "
            "function-exit epilogue (pairs with LINK).",
    "JSR": "Calls {op1}: pushes the return address, then jumps there. "
           "Does not save/restore any registers itself.",
    "JMP": "Jumps directly to {op1}. No return address is saved.",
    "BSR": "Calls {op1} (PC-relative): pushes the return address, then branches there.",
    "BRA": "Branches unconditionally to {op1}.",
    "RTS": "Pops the return address from the stack and resumes execution there -- function exit.",
    "RTE": "Restores the status register and program counter from the stack -- "
           "exception/interrupt return.",
    "RTR": "Restores the condition codes and program counter from the stack -- "
           "lightweight subroutine return.",
    "PEA": "Pushes the effective address {op1} onto the stack (without dereferencing it).",
    "LEA": "Loads the effective address {op1} into address register {op2} (without dereferencing it).",
    "TST": "Compares {op1} to zero and sets N/Z accordingly; clears V and C. Does not modify {op1}.",
    "CLR": "Sets {op1} to zero. Clears N/V/C, sets Z.",
    "BTST": "Tests bit {op1} of {op2} and sets Z from it (1=bit was clear, 0=bit was set). "
            "Does not modify {op2}.",
    "BSET": "Tests bit {op1} of {op2} (sets Z accordingly), then sets that bit in {op2}.",
    "BCLR": "Tests bit {op1} of {op2} (sets Z accordingly), then clears that bit in {op2}.",
    "CMPI": "Compares {op2} against the immediate {op1} and sets N/Z/V/C from the "
            "(discarded) subtraction result.",
    "CMP": "Compares {op2} against {op1} and sets N/Z/V/C from the (discarded) subtraction result.",
    "ADD": "Adds {op1} to {op2}, storing the result in {op2}. Sets N/Z/V/C/X.",
    "ADDQ": "Adds the small immediate {op1} to {op2}. Sets N/Z/V/C/X "
            "(condition codes unaffected when {op2} is an address register).",
    "ADDI": "Adds the immediate {op1} to {op2}, storing the result in {op2}. Sets N/Z/V/C/X.",
    "SUB": "Subtracts {op1} from {op2}, storing the result in {op2}. Sets N/Z/V/C/X.",
    "SUBQ": "Subtracts the small immediate {op1} from {op2}. Sets N/Z/V/C/X "
            "(condition codes unaffected when {op2} is an address register).",
    "SUBI": "Subtracts the immediate {op1} from {op2}, storing the result in {op2}. Sets N/Z/V/C/X.",
    "AND": "Bitwise-ANDs {op1} into {op2}. Sets N/Z, clears V/C.",
    "OR": "Bitwise-ORs {op1} into {op2}. Sets N/Z, clears V/C.",
    "EOR": "Bitwise-XORs {op1} into {op2}. Sets N/Z, clears V/C.",
    "NOT": "Bitwise-inverts {op1} in place. Sets N/Z, clears V/C.",
    "NEG": "Negates {op1} (two's complement) in place. Sets N/Z/V/C/X.",
    "SWAP": "Swaps the high and low 16-bit words of {op1}. Sets N/Z, clears V/C.",
    "EXT": "Sign-extends {op1} to the next larger size. Sets N/Z, clears V/C.",
    "NOP": "Does nothing for one cycle -- often a timing pad or a patched-out instruction.",
}

_BCC_CONDITIONS = {
    "BEQ": "equal (Z=1)",
    "BNE": "not equal (Z=0)",
    "BGE": "signed greater-or-equal",
    "BLT": "signed less-than",
    "BGT": "signed greater-than",
    "BLE": "signed less-or-equal",
    "BHI": "unsigned greater-than",
    "BLS": "unsigned less-or-equal",
    "BCC": "carry clear (unsigned greater-or-equal)",
    "BCS": "carry set (unsigned less-than)",
    "BPL": "plus (N=0)",
    "BMI": "minus (N=1)",
    "BVC": "overflow clear",
    "BVS": "overflow set",
}
for _mnemonic, _condition in _BCC_CONDITIONS.items():
    SEMANTICS[_mnemonic] = f"Branches to {{op1}} if {_condition}."


ADDR_MODE_NOTES: dict[OperandKind, str] = {
    OperandKind.REG: "a register, used directly",
    OperandKind.IMMEDIATE: "an immediate literal encoded in the instruction, not a memory reference",
    OperandKind.ABSOLUTE: "a fixed memory address baked into the instruction",
    OperandKind.DISPLACEMENT: "an address register plus a fixed signed offset",
    OperandKind.INDEXED: "an address register plus an index register (and possibly a fixed offset)",
    OperandKind.PC_RELATIVE: "an address relative to the program counter -- moves with the code if it's copied elsewhere",
    OperandKind.REGISTER_INDIRECT: "the memory location an address register currently points to",
    OperandKind.OTHER: "an addressing mode not yet described for this backend",
}
