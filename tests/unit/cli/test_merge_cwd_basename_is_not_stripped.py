# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` run from a directory named like a top-level directory of the tree.

Why this file exists
--------------------
The merge builds its suppression pass's context with the collector's working
directory as the source directory: the collector job need not have the tree
checked out, and the merged URIs are already relative to each shard's scanned
tree. The pass's URI normalizer carries a reading written for offline opengrep,
which prefixes its URIs with the scanned directory's name: a relative URI whose
first component equals the source directory's basename loses that component,
unless the source directory holds a child of the same name. On the merge every
URI is shard-relative, so a collector run from a directory named ``src`` (or
``app``, or the repository's own name) read ``src/bandit_0.py`` as
``bandit_0.py`` before matching: a suppression written for ``src/bandit_0.py``
did not apply, an ignore path ``bandit_0.py`` dropped a finding it was not
written for, and the finding id changed with the path. The merge now asks the
pass to leave the basename alone; a scan's reading is unchanged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.cli.merge import apply_aggregated_suppressions
from automated_security_helper.config.ash_config import (
    AshConfig,
    AshConfigGlobalSettingsSection,
)
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from tests.unit.cli.merge_shard_support import SCANNERS, build_shard

pytestmark = pytest.mark.unit

RULE = "bandit-RULE-0"
#: The shard fixture locates RULE at this URI, relative to the shard's tree.
URI = "src/bandit_0.py"


def _result(model, rule_id: str):
    return next(
        (
            result
            for run in model.sarif.runs
            for result in run.results or []
            if result.ruleId == rule_id
        ),
        None,
    )


def _merged_from_a_directory_named_src(
    tmp_path, monkeypatch, *, suppressions=(), ignore_paths=()
):
    """The merge's suppression pass, run by a collector whose cwd is ``.../src``."""
    cwd = tmp_path / "src"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    model = build_shard(0, 1, SCANNERS)
    model.ash_config = AshConfig(
        project_name="test-merge",
        global_settings=AshConfigGlobalSettingsSection(
            severity_threshold="MEDIUM",
            suppressions=list(suppressions),
            ignore_paths=list(ignore_paths),
        ),
    )
    context = PluginContext(
        source_dir=Path.cwd(),
        output_dir=tmp_path / "out",
        config=model.ash_config,
        ignore_suppressions=False,
    )
    return apply_aggregated_suppressions(model, context)


def test_a_suppression_for_the_shard_relative_path_applies(tmp_path, monkeypatch):
    merged = _merged_from_a_directory_named_src(
        tmp_path,
        monkeypatch,
        suppressions=[AshSuppression(rule_id=RULE, path=URI, reason="fixture")],
    )

    result = _result(merged, RULE)
    assert result is not None
    assert result.suppressions, f"the suppression written for {URI} did not apply"


def test_an_ignore_path_for_the_bare_name_keeps_the_file_under_src(
    tmp_path, monkeypatch
):
    merged = _merged_from_a_directory_named_src(
        tmp_path,
        monkeypatch,
        ignore_paths=[IgnorePathWithReason(path="bandit_0.py", reason="fixture")],
    )

    assert _result(merged, RULE) is not None


def test_an_ignore_path_for_the_shard_relative_path_drops_it(tmp_path, monkeypatch):
    merged = _merged_from_a_directory_named_src(
        tmp_path,
        monkeypatch,
        ignore_paths=[IgnorePathWithReason(path=URI, reason="fixture")],
    )

    assert _result(merged, RULE) is None
