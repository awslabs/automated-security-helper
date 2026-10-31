# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refusal before the scan for an enabled reporter that is "unsupported".

A reporter can land in that set two ways: it declares ``UNSUPPORTED``, which is a
claim that it cannot produce a correct workspace report, or its
``workspace_behaviour`` is a typo or a wrong type, which ASH reads as unsupported
and which claims nothing. The manifest entry already words the second as a
declaration to fix (``test_workspace_reporting_manifest_fidelity``); the refusal
that stops the run before any project is scanned has to say the same thing, or the
operator is told a reporter "declares that it cannot" when it declares nothing.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.core.exceptions import WorkspaceDefinitionError
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from tests.unit.workspace.test_workspace_reporting import (
    FakeMergedReporter,
    FakeUnsupportedReporter,
    _plan,
)
from tests.unit.workspace.test_workspace_reporting_manifest_fidelity import (
    FakeBadBehaviourReporter,
)

pytestmark = pytest.mark.unit


def _refusal(tmp_path, *reporter_classes) -> str:
    root = tmp_path / "ws"
    for key in ("api", "web"):
        (root / key / "src").mkdir(parents=True, exist_ok=True)
    (root / "fixture.code-workspace").write_text(
        json.dumps({"folders": [{"path": "api"}, {"path": "web"}]}),
        encoding="utf-8",
    )

    def never_built(**kwargs):  # pragma: no cover - the refusal precedes the scan
        raise AssertionError("a project was scanned after the pre-scan refusal")

    with pytest.raises(WorkspaceDefinitionError) as caught:
        execute_workspace(
            _plan(root, "api", "web"),
            ProjectScanSettings(
                output_dir=tmp_path / "out",
                phases=("scan", "report"),
                max_parallel_projects=1,
            ),
            orchestrator_factory=never_built,
            reporter_classes=list(reporter_classes),
        )
    return str(caught.value)


def test_a_declaration_that_cannot_be_read_is_worded_as_one_to_fix(tmp_path):
    text = _refusal(tmp_path, FakeBadBehaviourReporter, FakeMergedReporter)

    assert "fake-bad-behaviour" in text, text
    assert "'sideways'" in text, text
    assert "Fix the declaration" in text, text
    assert "declare that they cannot produce" not in text, text
    assert "Nothing was scanned" in text, text


def test_a_reporter_that_declares_itself_unsupported_keeps_its_wording(tmp_path):
    """The control: a real UNSUPPORTED declaration is still a claim."""
    text = _refusal(tmp_path, FakeUnsupportedReporter, FakeMergedReporter)

    assert "fake-unsupported" in text, text
    assert "declare that they cannot produce a correct report" in text, text
    assert "workspace_behaviour" not in text, text
    assert "Disable them, narrow --output-format" in text, text


def test_both_kinds_in_one_run_are_each_worded_as_what_they_are(tmp_path):
    text = _refusal(tmp_path, FakeBadBehaviourReporter, FakeUnsupportedReporter)

    assert "fake-unsupported declare that they cannot produce" in text, text
    assert "fake-bad-behaviour ('sideways')" in text, text
