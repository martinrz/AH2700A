"""Hand work back and forth with Claude from inside revbench by shelling
out to the `claude` CLI (Claude Code) in one-shot/print mode -- no API key,
no separate billing surface, reuses whatever account is already logged in.
Pure Python, no tkinter dependency, so it's testable without a display; the
GUI side lives in gui/tabs/claude_tab.py.

Each call is a fresh exchange (no multi-turn memory) -- fine for a
send-a-question/get-an-answer handoff, not a running conversation.
"""

from __future__ import annotations

import subprocess

MAX_CONTEXT_CHARS = 20_000

_FULL_PASS_INSTRUCTIONS = (
    "Review this disassembly excerpt from an ongoing firmware reverse-"
    "engineering project. Flag anything worth a second look: unresolved "
    "computed jumps/calls, subroutines that still have only a generic "
    "sub_/loc_ name, and any pattern that looks suspicious or "
    "out of place. Be concise -- a short list of findings, not a full "
    "restatement of the input."
)


def build_question_prompt(context_text: str, question: str) -> str:
    parts = []
    if context_text.strip():
        parts.append(f"Context:\n{context_text.strip()}")
    parts.append(f"Question: {question.strip()}")
    return "\n\n".join(parts)


def build_full_pass_prompt(context_text: str) -> str:
    return f"{_FULL_PASS_INSTRUCTIONS}\n\n{context_text.strip()}"


def run_prompt(prompt: str, timeout: int) -> str:
    """Runs `claude -p <prompt>` and returns its stdout. `--permission-mode
    dontAsk` auto-declines any tool-permission request instead of hanging --
    there's no TTY to answer it from a background subprocess -- the timeout
    is still a backstop against a call that never returns."""
    try:
        result = subprocess.run(
            ["claude", "-p", prompt, "--permission-mode", "dontAsk"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "The 'claude' CLI wasn't found on PATH. Install/log in to Claude "
            "Code, or make sure it's on the same PATH revbench runs with."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"claude did not respond within {timeout}s.") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "(no output)"
        raise RuntimeError(f"claude exited with code {result.returncode}: {detail}")

    return result.stdout.strip()
