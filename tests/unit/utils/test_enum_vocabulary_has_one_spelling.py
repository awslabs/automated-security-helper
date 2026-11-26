# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The vocabularies the enum wave's scope lists missed are spelled once.

Each test names a copy site that used to re-spell a vocabulary and pins it to
its single source, so a rename or an added member reaches every consumer.
"""

import re
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.error_types import McpErrorType
from automated_security_helper.core import constants
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.resource_management import (
    result_filters,
    scan_tracking,
)
from automated_security_helper.express import runtime
from automated_security_helper.models import asharp_model, flat_vulnerability
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    _junitxml_frame,
    html_reporter,
    junitxml_reporter,
    report_content_emitter,
)
from automated_security_helper.utils import sarif_utils, severity_ladder, ui_theme

pytestmark = pytest.mark.unit

PACKAGE = Path(severity_ladder.__file__).resolve().parent.parent


def test_ladder_tables_are_derived_from_the_one_ladder():
    assert severity_ladder.SEVERITIES == ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert severity_ladder._SEVERITY_RANK == {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0,
    }
    assert severity_ladder._THRESHOLD_MIN_RANK == {
        "ALL": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    assert severity_ladder.SEVERITY_COUNT_KEYS == (
        "critical",
        "high",
        "medium",
        "low",
        "info",
    )
    assert severity_ladder.SEVERITY_DISPLAY_ORDER == {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }


def test_no_two_modules_define_a_same_named_severity_bucket_constant():
    """``SEVERITY_BUCKETS`` is the ladder's five buckets and is defined once.

    A second module that defined a tuple of the same name with different members
    (scan_tracking's six-member tally used to) lets an auto-import from the wrong
    module silently add or drop ``suppressed``.
    """
    import ast

    definers = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            targets = []
            if isinstance(node, ast.Assign):
                targets = [t for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets = [node.target]
            if any(t.id == "SEVERITY_BUCKETS" for t in targets):
                definers.append(path.relative_to(PACKAGE).as_posix())
    assert definers == ["models/vocab.py"]
    assert not hasattr(scan_tracking, "SEVERITY_BUCKETS")


def test_count_field_sites_read_the_ladders_keys():
    keys = severity_ladder.SEVERITY_COUNT_KEYS
    suppressed = severity_ladder.SUPPRESSED_COUNT_KEY
    assert scanner_executor._SEVERITY_COUNT_FIELDS == (suppressed, *keys)
    assert result_filters._SEVERITY_KEYS == (*keys, suppressed)
    assert result_filters._COUNTED_SEVERITY_KEYS == keys
    assert scan_tracking.SEVERITY_TALLY_BUCKETS == (*keys, suppressed)
    assert asharp_model._SEVERITY_ORDER == keys
    assert asharp_model._SUMMARY_SEVERITY_FIELDS == frozenset((*keys, suppressed))
    assert ui_theme.SEVERITY_LEVELS == keys


def test_severity_name_sites_read_the_ladders_names():
    names = severity_ladder.SEVERITIES
    assert flat_vulnerability._SEVERITY_ORDER == names
    assert sarif_utils._CANONICAL_SEVERITIES == names
    assert constants.VALID_SEVERITY_VALUES == frozenset(names)
    # The emitter derives its places from the vocabulary the severity column's
    # EnumColumn marker records, so it is the ladder's table by value, not by identity.
    assert (
        report_content_emitter._SEVERITY_ORDER == severity_ladder.SEVERITY_DISPLAY_ORDER
    )
    assert html_reporter._SEVERITY_ORDER == severity_ladder.SEVERITY_DISPLAY_ORDER


def test_ghas_security_severity_table_is_keyed_by_the_whole_ladder():
    from automated_security_helper.plugin_modules.ash_builtin.reporters import (
        github_ghas_reporter,
    )

    assert set(github_ghas_reporter._SEVERITY_TO_SECURITY_SEVERITY) == set(
        severity_ladder.SEVERITIES
    )


@pytest.mark.parametrize("outcome", list(_junitxml_frame.CaseOutcome))
def test_junit_outcome_is_the_frames_value_and_the_skip_type(outcome):
    assert outcome == outcome.value
    assert outcome.value == outcome.value.lower()


def test_policy_not_gating_skip_type_is_the_outcome_value():
    assert (
        junitxml_reporter.POLICY_NOT_GATING_SKIP_TYPE
        == _junitxml_frame.CaseOutcome.POLICY_NOT_GATING.value
        == "policy-not-gating"
    )


def test_below_threshold_names_are_one_spelling_each():
    assert flat_vulnerability.BELOW_THRESHOLD_PROPERTY == "below_threshold"
    assert report_content_emitter.SUMMARY_BELOW_THRESHOLD == "below_threshold"
    assert report_content_emitter.SUMMARY_POLICY_NOT_GATING == "policy_not_gating"


def test_html_template_placeholders_are_all_supplied():
    template = (
        PACKAGE
        / "plugin_modules"
        / "ash_builtin"
        / "reporters"
        / "assets"
        / "ash-report.html"
    ).read_text(encoding="utf-8")
    assert "$below_threshold" in template
    source = (
        PACKAGE / "plugin_modules" / "ash_builtin" / "reporters" / "html_reporter.py"
    ).read_text(encoding="utf-8")
    assert re.search(r'"below_threshold":\s*summary\[SUMMARY_BELOW_THRESHOLD\]', source)


def test_express_frames_come_from_the_runtime_builders():
    assert runtime.status_frame() == {"op": "status"}
    assert runtime.stop_frame() == {"op": "stop"}
    assert runtime.go_frame() == {"op": "go"}
    assert runtime.signal_frame(2) == {"op": "signal", "signum": 2}
    assert tuple(op.value for op in runtime.ExpressOp) == (
        "scan",
        "status",
        "stop",
        "go",
        "signal",
    )


@pytest.mark.parametrize(
    "relative",
    ["cli/express.py", "express/client.py", "express/daemon.py"],
)
def test_no_hand_built_express_op_frame_outside_the_runtime(relative):
    source = (PACKAGE / relative).read_text(encoding="utf-8")
    assert not re.search(r'\{\s*"op"\s*:\s*"', source), relative
    assert not re.search(r'\.get\("op"\)\s*[!=]=\s*"', source), relative


def test_mcp_server_uses_the_shared_config_refusal_member():
    source = (PACKAGE / "cli" / "mcp_server.py").read_text(encoding="utf-8")
    assert '"config_input_not_permitted"' not in source
    assert McpErrorType.CONFIG_INPUT_NOT_PERMITTED.value == "config_input_not_permitted"


@pytest.mark.parametrize(
    "relative",
    ["core/unified_metrics.py", "core/resource_management/scan_tracking.py"],
)
def test_scanner_status_words_are_not_bare_literals(relative):
    source = (PACKAGE / relative).read_text(encoding="utf-8")
    literals = [f'"{member.value}"' for member in ScannerStatus]
    for number, line in enumerate(source.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        for literal in literals:
            assert literal not in line, f"{relative}:{number}: {line.strip()}"
