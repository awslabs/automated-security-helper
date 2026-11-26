# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The warn-once notice for a rule-less suppression covering npm-audit findings.

npm-audit findings moved from ``node_modules/<package>/package.json`` into the
audited lockfile, so a suppression that names no rule and whose path matches a
lockfile can newly cover advisories it never covered when it was written. The
docs promise a warning, once per entry per run, so the first scan after an
upgrade points at the entries to audit. These tests pin that promise and its
edges: one warning however many findings the entry covers, none for a direct
caller that passes no warn-once set, none for an entry scoped by
``package_name`` (the acknowledgment the warning's remedy asks for), and none
for a finding still at the pre-move install location (a report converted on
its own), where nothing is newly widened.
"""

import logging

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    PropertyBag,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    _apply_config_suppression,
    apply_suppressions_to_sarif,
)

pytestmark = pytest.mark.unit

LOCKFILE = "deploy/cdk/package-lock.json"


def npm_audit_result(rule_id: str, uri: str = LOCKFILE, **properties) -> Result:
    return Result(
        ruleId=rule_id,
        message=Message(text=f"{rule_id} advisory"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri=uri)
                )
            )
        ],
        properties=PropertyBag(**properties) if properties else None,
    )


def npm_audit_report(*results: Result) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="npm-audit", version="1.0.0")),
                results=list(results),
            )
        ],
    )


def apply(report, source_dir, output_dir, *suppressions):
    config = AshConfig(
        project_name="p", global_settings={"suppressions": list(suppressions)}
    )
    context = PluginContext(source_dir=source_dir, output_dir=output_dir, config=config)
    return apply_suppressions_to_sarif(report, context)


def rule_less_warnings(caplog) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if "names no rule_id" in record.getMessage()
    ]


def test_one_warning_across_two_findings_one_entry_covers(
    test_source_dir, test_output_dir, caplog
):
    """The planted positive: the entry covers two lockfile-located findings and
    is warned about exactly once, naming its path."""
    report = npm_audit_report(
        npm_audit_result("GHSA-vfj7-8cjw-p6xm"),
        npm_audit_result("GHSA-0000-pico-0000"),
    )
    with caplog.at_level(logging.WARNING):
        out = apply(
            report,
            test_source_dir,
            test_output_dir,
            AshSuppression(path=LOCKFILE, reason="written before the move"),
        )
    assert all(r.suppressions for r in out.runs[0].results)
    warnings = rule_less_warnings(caplog)
    assert len(warnings) == 1
    assert LOCKFILE in warnings[0]


def test_direct_caller_with_no_warn_once_set_warns_nothing(caplog):
    """``warned_rule_less=None`` is a direct caller: the suppression applies,
    the warning does not fire."""
    result = npm_audit_result("GHSA-vfj7-8cjw-p6xm")
    flat_finding = FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="MEDIUM",
        scanner="npm-audit",
        scanner_type="SCA",
        rule_id="GHSA-vfj7-8cjw-p6xm",
        file_path=LOCKFILE,
    )
    suppression = AshSuppression(path=LOCKFILE, reason="written before the move")
    with caplog.at_level(logging.WARNING):
        applied = _apply_config_suppression(
            result, [suppression], flat_finding, None, warned_rule_less=None
        )
    assert applied
    assert result.suppressions
    assert rule_less_warnings(caplog) == []


def test_entry_scoped_by_package_name_is_not_warned_about(
    test_source_dir, test_output_dir, caplog
):
    """A rule-less entry that names a package_name is scoped on purpose: it is
    exactly what the warning's remedy asks for, so it is not warned about."""
    report = npm_audit_report(
        npm_audit_result(
            "GHSA-vfj7-8cjw-p6xm",
            package_name="braces",
            package_version="3.0.3",
            package_path="deploy/cdk/node_modules/braces",
        )
    )
    with caplog.at_level(logging.WARNING):
        out = apply(
            report,
            test_source_dir,
            test_output_dir,
            AshSuppression(
                path=LOCKFILE, package_name="braces", reason="scoped on purpose"
            ),
        )
    assert out.runs[0].results[0].suppressions
    assert rule_less_warnings(caplog) == []


def test_pre_move_install_location_is_not_warned_about(
    test_source_dir, test_output_dir, caplog
):
    """A finding still at node_modules/<package>/package.json (a report
    converted on its own) kept the pre-move shape, which a rule-less entry
    covered before the move too: nothing is newly widened, so no warning."""
    uri = "node_modules/braces/package.json"
    report = npm_audit_report(npm_audit_result("GHSA-vfj7-8cjw-p6xm", uri=uri))
    with caplog.at_level(logging.WARNING):
        out = apply(
            report,
            test_source_dir,
            test_output_dir,
            AshSuppression(path=uri, reason="written against the old shape"),
        )
    assert out.runs[0].results[0].suppressions
    assert rule_less_warnings(caplog) == []
