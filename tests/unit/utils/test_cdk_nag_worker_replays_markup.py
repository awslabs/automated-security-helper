# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A record the cdk-nag worker logged with markup is replayed with markup.

The worker child keeps each record the wrapper logs and hands it back with its
template's answer, and the parent replays it into ASH's logger, so it reaches
ash.log and the console. The child kept only the message's text. One the wrapper
logged with MARKUP (a template's own suppression reason, styled yellow) came back
as plain text: its values, which escape_markup had shown and escaped for Rich,
were shown a second time, and ash.log got the tags, Rich's "\\[" escapes and a
doubled backslash in each escape:
'AwsSolutions-IAM5\\\\x1b]0;t\\\\x07\\[/x]' ... [yellow]...[/yellow].
"""

from __future__ import annotations

import json
import logging

import pytest

from automated_security_helper.utils.cdk_nag_worker import (
    _RecordCollector,
    _replay_logs,
)
from automated_security_helper.utils.log import (
    ASH_LOGGER,
    MARKUP,
    escape_markup,
    get_logger,
)

pytestmark = pytest.mark.unit

#: A rule id a template chose: an OSC title write, BEL, and a closing Rich tag.
_RULE = "AwsSolutions-IAM5\x1b]0;t\x07[/x]"


def _child_records(log) -> list:
    """What the worker child hands back for the records *log* makes."""
    collector = _RecordCollector()
    child = logging.getLogger("ash-cdk-nag-worker-child-test")
    child.propagate = False
    child.setLevel(1)
    child.handlers = [collector]
    try:
        log(child)
    finally:
        child.handlers = []
    # Across the process boundary, as the worker writes it.
    return json.loads(json.dumps({"logs": collector.take()}))["logs"]


def _replayed_into_ash_log(tmp_path, monkeypatch, logs) -> str:
    monkeypatch.delenv("ASH_LOG_TO_STDERR", raising=False)
    monkeypatch.setattr(ASH_LOGGER, "handlers", [])
    get_logger(
        name="ash",
        level=logging.INFO,
        output_dir=tmp_path,
        show_progress=True,
        use_color=False,
    )
    try:
        _replay_logs({"logs": logs})
        for handler in ASH_LOGGER.handlers:
            handler.flush()
    finally:
        for handler in ASH_LOGGER.handlers:
            handler.close()
    return (tmp_path / "ash.log").read_bytes().decode("utf-8")


def test_a_markup_record_is_replayed_as_markup(tmp_path, monkeypatch):
    logs = _child_records(
        lambda logger: logger.warning(
            f"Suppressing rule '{escape_markup(_RULE)}' based on the template's own "
            f"cdk_nag metadata: [yellow]{escape_markup('accepted [here]')}[/yellow]",
            extra=MARKUP,
        )
    )

    written = _replayed_into_ash_log(tmp_path, monkeypatch, logs)

    assert "Suppressing rule 'AwsSolutions-IAM5\\x1b]0;t\\x07[/x]'" in written, written
    assert "metadata: accepted [here]" in written, written
    assert "[yellow]" not in written and "\\[" not in written, written
    assert "\\\\x" not in written, written


def test_a_text_record_is_replayed_as_text(tmp_path, monkeypatch):
    """Without MARKUP the brackets are the text's, and its controls are shown once."""
    logs = _child_records(lambda logger: logger.warning(f"Rule {_RULE} [bold]x"))

    written = _replayed_into_ash_log(tmp_path, monkeypatch, logs)

    assert "Rule AwsSolutions-IAM5\\x1b]0;t\\x07[/x] [bold]x" in written, written
    assert "\\\\x" not in written, written
