"""Answer the prompts of ``ash config wizard`` from a script.

Three test files each carried a copy of this: the wizard's prompts replaced by a
list of answers, every yes/no question answered no, the toggle tables skipped.
When the wizard's questions changed, the copies had to change together, and one
test file kept asserting the old behavior. One helper is the one place to change.
"""

from __future__ import annotations

from typing import Iterable

import pytest


def script_wizard(monkeypatch: pytest.MonkeyPatch, answers: Iterable[str]) -> None:
    """Answer the wizard's prompts with ``answers``, in order.

    The project name comes first, then module names, a blank answer ending the
    list. Every yes/no question is answered no, and the toggle tables are skipped.
    A prompt asked after the answers run out raises ``StopIteration``, which a test
    that expects no prompt at all relies on (it passes an empty list).
    """
    # Not at the top: the module imports the CLI, which a collection of this
    # helper alone does not need.
    from automated_security_helper.cli import config as config_cli

    replies = iter(answers)
    monkeypatch.setattr(config_cli, "prompt", lambda *_a, **_k: next(replies))
    monkeypatch.setattr(config_cli, "confirm", lambda *_a, **_k: False)
    monkeypatch.setattr(config_cli, "_prompt_toggle_items", lambda *_a, **_k: {})
