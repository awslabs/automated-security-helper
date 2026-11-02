# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``validate_plugin`` shows a recorded unavailable reason redacted.

A scanner that recorded why it cannot run (``dependency_unavailable_reason``)
has the reason logged by ``validate_plugin`` at ERROR, and the line is kept in
``errors``, which the failure message and the results file quote. The reason
can name a path or option the config read from the environment. Every other
place that shows the text redacts it with the plugin's values; this one logged
it as it was. It now goes through the same guarded read, and a values hook that
raises leaves a note without the reason's text.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.config.config_validator import REDACTED
from tests.unit.base.test_a_rejected_runs_notification_excerpt_is_redacted import (
    CANARY,
    _context,
)
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


def _refusing_scanner(tmp_path):
    scanner = _scanner(_context(tmp_path, [CANARY]))
    scanner.dependency_unavailable_reason = (
        f"the rules file {CANARY} is outside the scanned tree"
    )
    scanner.errors = []
    return scanner


def test_a_configured_value_in_the_reason_is_redacted_where_it_is_logged(tmp_path):
    scanner = _refusing_scanner(tmp_path)

    assert scanner.validate_plugin() is False

    kept = "\n".join(scanner.errors)
    assert CANARY not in kept, kept
    assert "ENVCANARY" not in kept, kept
    assert REDACTED in kept, kept
    assert "is outside the scanned tree" in kept, kept
    assert scanner.dependencies_satisfied is False


def test_a_reason_with_no_configured_value_is_logged_as_it_is(tmp_path):
    scanner = _scanner(_context(tmp_path, [CANARY]))
    scanner.dependency_unavailable_reason = "the tool is not installed"
    scanner.errors = []

    assert scanner.validate_plugin() is False

    assert "the tool is not installed" in "\n".join(scanner.errors)


def test_a_raising_values_hook_leaves_a_note_without_the_reasons_text(tmp_path):
    scanner = _refusing_scanner(tmp_path)

    def _raising_hook(*_args, **_kwargs):
        raise RuntimeError("hook broke")

    with patch.object(scanner, "_values_to_redact", side_effect=_raising_hook):
        assert scanner.validate_plugin() is False

    kept = "\n".join(scanner.errors)
    assert CANARY not in kept, kept
    assert "outside the scanned tree" not in kept, kept
    assert "text not shown" in kept, kept
    assert scanner.dependencies_satisfied is False
