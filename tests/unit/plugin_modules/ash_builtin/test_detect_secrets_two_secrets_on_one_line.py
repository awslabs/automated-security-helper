# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two secrets of one type on one line are two findings with two ids.

detect-secrets reports a line number and no column, and ASH's message for a
detect-secrets finding names only the type, the file and the line, so two AWS keys
on one line would be one rule, one location and one message: everything a finding's
identity is made of. The flattened findings would then tell them apart by the order
detect-secrets lists them, which is the order of a set of objects hashed on
strings, and so changes with the interpreter's hash seed.

The scanner gives each finding the column its secret starts at. The worker
that runs detect-secrets holds the secret's value, finds it in its line, and passes
the column back; the value itself never leaves the worker. Not the secret's hash as
a fingerprint: ASH's reports have never carried it, and a SHA-1 of a weak secret is
a dictionary lookup away from the secret.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)
from automated_security_helper.utils.finding_identity import finding_id, identity_keys

# Assembled at runtime in that module, so this file holds no key-shaped literal for
# ASH's own self-scan to report.
from tests.unit.plugin_modules.ash_builtin.test_detect_secrets_scanner_behavior import (
    PLANTED_KEY,
)

# The scanner's dependency check asked uv for detect-secrets' version (``uv tool run
# detect-secrets --version``), so every scan here started the tool wherever uv could
# reach it. The scan itself runs in ASH's worker, so the probes answer without a
# process (tests/unit/conftest.py).
pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("no_tool_probes")]

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()
PluginContext.model_rebuild()

#: A second key of the same shape: the same prefix, the rest reversed.
SECOND_KEY = PLANTED_KEY[:4] + PLANTED_KEY[:3:-1]
LINE = f"KEYS = ['{PLANTED_KEY}', '{SECOND_KEY}']\n"


def _scan(tmp_path: Path):
    source = tmp_path / "proj"
    source.mkdir(parents=True)
    (source / "settings.py").write_text(f"x = 1\n{LINE}", encoding="utf-8")
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.output_dir.mkdir(parents=True, exist_ok=True)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    return scanner.scan(target=source, target_type="source")


def _aws_results(report):
    return [
        result
        for result in report.runs[0].results
        if result.ruleId == "SECRET-AWS-ACCESS-KEY"
    ]


def test_each_secret_reports_the_column_it_starts_at(tmp_path):
    results = _aws_results(_scan(tmp_path))

    regions = sorted(
        (
            r.locations[0].physicalLocation.root.region.startLine,
            r.locations[0].physicalLocation.root.region.startColumn,
        )
        for r in results
    )
    assert regions == [
        (2, LINE.index(PLANTED_KEY) + 1),
        (2, LINE.index(SECOND_KEY) + 1),
    ], regions


def test_two_keys_on_one_line_get_two_ids(tmp_path):
    report = _scan(tmp_path)
    model = AshAggregatedResults()
    model.sarif = report
    vulns = model.to_flat_vulnerabilities()
    # The run's keys, built from the same identities the ids were.
    keyed = [vuln for vuln in vulns if vuln.identity is not None]
    keys = identity_keys([vuln.identity for vuln in keyed])
    aws = [
        (vuln, key)
        for vuln, key in zip(keyed, keys)
        if vuln.rule_id == "SECRET-AWS-ACCESS-KEY"
    ]

    ids = [vuln.id for vuln, _ in aws]
    assert len(ids) == 2 and len(set(ids)) == 2, ids
    assert [finding_id(key) for _, key in aws] == ids
    # Two ids are not enough: an ordinal also tells them apart, by the order
    # detect-secrets listed them in. Each key has to differ by where its secret
    # starts.
    assert [key for _, key in aws if "ordinal" in key] == [], keys
    assert sorted(vuln.identity.column for vuln, _ in aws) == [
        LINE.index(PLANTED_KEY) + 1,
        LINE.index(SECOND_KEY) + 1,
    ]
    first, second = (key["occurrence"] for _, key in aws)
    assert first != second, keys


def test_the_secret_value_is_not_in_the_results(tmp_path):
    dumped = _scan(tmp_path).model_dump_json()

    assert PLANTED_KEY not in dumped
    assert SECOND_KEY not in dumped
