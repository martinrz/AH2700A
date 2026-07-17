from __future__ import annotations

import subprocess

import pytest

from revbench.gui import claude_bridge


def test_build_question_prompt_includes_context_and_question():
    prompt = claude_bridge.build_question_prompt("sub_001280: jsr $108144.l", "what does this call do?")
    assert "Context:" in prompt
    assert "sub_001280: jsr $108144.l" in prompt
    assert "Question: what does this call do?" in prompt


def test_build_question_prompt_omits_context_section_when_empty():
    prompt = claude_bridge.build_question_prompt("   ", "why is this a computed jump?")
    assert "Context:" not in prompt
    assert "Question: why is this a computed jump?" in prompt


def test_build_full_pass_prompt_includes_instructions_and_listing():
    prompt = claude_bridge.build_full_pass_prompt("  001296  4EB9 108144  jsr $108144.l")
    assert "computed jumps" in prompt.lower()
    assert "jsr $108144.l" in prompt


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_prompt_returns_stripped_stdout_on_success(monkeypatch):
    captured_argv = {}

    def fake_run(argv, capture_output, text, timeout, check):
        captured_argv["argv"] = argv
        captured_argv["timeout"] = timeout
        return _FakeCompletedProcess(returncode=0, stdout="  the reply  \n", stderr="")

    monkeypatch.setattr(claude_bridge.subprocess, "run", fake_run)

    reply = claude_bridge.run_prompt("some prompt", timeout=60)

    assert reply == "the reply"
    assert captured_argv["argv"] == ["claude", "-p", "some prompt", "--permission-mode", "dontAsk"]
    assert captured_argv["timeout"] == 60


def test_run_prompt_raises_with_stderr_on_nonzero_exit(monkeypatch):
    def fake_run(*args, **kwargs):
        return _FakeCompletedProcess(returncode=1, stdout="", stderr="something went wrong")

    monkeypatch.setattr(claude_bridge.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="something went wrong"):
        claude_bridge.run_prompt("some prompt", timeout=60)


def test_run_prompt_raises_clear_message_when_claude_not_found(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("no such file")

    monkeypatch.setattr(claude_bridge.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="claude.*PATH"):
        claude_bridge.run_prompt("some prompt", timeout=60)


def test_run_prompt_raises_clear_message_on_timeout(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="claude", timeout=60)

    monkeypatch.setattr(claude_bridge.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="did not respond within 60s"):
        claude_bridge.run_prompt("some prompt", timeout=60)
