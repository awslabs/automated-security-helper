# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reporter confinement replays the operator's overrides folded onto the trusted base.

``confine_reporter_destinations`` replays the ``reporters`` overrides onto the
trusted base to read the operator's destinations. The scan's own apply resolves
an override against the resolved configuration, whose section spellings the
repository controls; when the repository's in-tree config spells an undeclared
reporter section one way and the operator's file another, the operator has to
type the repository's spelling, and a raw replay refused it against the trusted
base's own key, so no spelling passed both applications and the scan could not
run. The replay folds that one case (``resolve_config._folded_onto_trusted``),
as the operator view's replay already did.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _resolution(tmp_path: Path, repo_text: str, operator_text: str, override: str):
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / ".ash.yaml").write_text(repo_text, encoding="utf-8")
    operator = tmp_path / "operator.yaml"
    operator.write_text(operator_text, encoding="utf-8")
    return resolve_config(
        source_dir=checkout, trusted_config_path=operator, config_overrides=[override]
    )


def test_the_repositorys_spelling_of_a_plugin_reporter_section_replays(tmp_path):
    """The scan's own apply lands the override on the repository's key (the
    control); the confinement's replay folds it onto the operator's key in the
    trusted base it records (``_trusted_reporter_base``), which is what the fold
    changes: a raw replay refused the repository's spelling there."""
    config = _resolution(
        tmp_path,
        "project_name: repo\nreporters:\n  MyPluginReporter:\n    enabled: true\n",
        "project_name: op\nreporters:\n  my-plugin-reporter:\n    enabled: true\n",
        "reporters.MyPluginReporter.enabled=false",
    )

    extra = config.reporters.model_extra or {}
    assert extra["MyPluginReporter"]["enabled"] is False
    trusted = config._trusted_reporter_base.reporters.model_extra or {}
    assert trusted["my-plugin-reporter"]["enabled"] is False, trusted
    assert "MyPluginReporter" not in trusted, trusted
