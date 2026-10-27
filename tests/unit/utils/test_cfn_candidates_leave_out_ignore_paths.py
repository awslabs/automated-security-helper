# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-nag and cdk-nag leave the global ignore paths out of the scan set they read.

ASH drops the findings under ``global_settings.ignore_paths`` after the scan, but
the two scanners read every template in the scan set, the ignored ones included, and
their own results held them. ``cloudformation_candidate_files`` is the selection both
scan, and the one their ``nothing_to_scan_reason`` answers from, so it leaves out
the files the entries that still apply ignore, matched as ASH matches them when it
drops findings.
"""

from __future__ import annotations

import json
from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils.cfn_template_model import (
    NO_CLOUDFORMATION_TEMPLATE,
    cloudformation_candidate_files,
    cloudformation_nothing_to_scan_reason,
)

TEMPLATE = json.dumps(
    {"Resources": {"Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}}}}
)


def _context(tmp_path: Path, files: list[str], ignores: list[dict]) -> PluginContext:
    source = tmp_path / "source"
    for rel in files:
        (source / rel).parent.mkdir(parents=True, exist_ok=True)
        (source / rel).write_text(TEMPLATE, encoding="utf-8")
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir()
    config = get_default_config()
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(reason="vendored", **entry) for entry in ignores
    ]
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config,
    )


def _candidates(context: PluginContext) -> list[str]:
    return sorted(
        Path(p).relative_to(context.source_dir).as_posix()
        for p in cloudformation_candidate_files(context, "source")
    )


def test_an_ignored_template_is_not_a_candidate(tmp_path):
    context = _context(
        tmp_path,
        ["app.template.json", "thirdparty/bad.template.json", "gen/a.template.json"],
        [{"path": "thirdparty/**"}, {"path": "gen/a.template.json"}],
    )

    assert _candidates(context) == ["app.template.json"]


def test_an_expired_ignore_path_no_longer_applies(tmp_path):
    context = _context(
        tmp_path,
        ["app.template.json", "thirdparty/bad.template.json"],
        [{"path": "thirdparty/**", "expiration": "2000-01-01"}],
    )

    assert _candidates(context) == ["app.template.json", "thirdparty/bad.template.json"]


def test_a_tree_whose_only_template_is_ignored_has_nothing_to_scan(tmp_path):
    context = _context(
        tmp_path, ["thirdparty/bad.template.json"], [{"path": "thirdparty/**"}]
    )

    assert cloudformation_nothing_to_scan_reason(context) == NO_CLOUDFORMATION_TEMPLATE


def test_control_with_no_ignore_path_every_template_is_a_candidate(tmp_path):
    context = _context(
        tmp_path, ["app.template.json", "thirdparty/bad.template.json"], []
    )

    assert _candidates(context) == ["app.template.json", "thirdparty/bad.template.json"]
    assert cloudformation_nothing_to_scan_reason(context) is None
