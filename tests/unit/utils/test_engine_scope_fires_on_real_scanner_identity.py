# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Engine-scoped suppressions fire on the scanner identities production carries.

``scope.engines`` entries and the scoped base-rule-id fallback
(``AshSuppression.matches``) are keyed by the REGISTERED scanner name
("cdk-nag"). The existing unit tests hand-construct findings with
``scanner="cdk-nag"``, but no production pass ever carried that value before
the fix these tests pin:

- at the two per-scanner passes (scanner_executor, scan_result_processor) the
  finding's scanner was the run's SARIF driver name, the tool's own
  ("ash-cdk-nag-wrapper"), because ``attach_scanner_details`` renames the
  driver only after suppressions were applied;
- at the merged pass (execution_engine) it was the aggregator's driver name
  ("AWS Labs - Automated Security Helper").

So an engines block, and the scoped base-rule-id fallback, matched nothing on
any real path, silently: the membership check short-circuits before the
warn-once receipt. These tests go SARIF-in through
``apply_suppressions_to_sarif`` and through ``ScanResultProcessor``'s real
pass, with the driver names production carries.
"""

import pytest

from automated_security_helper.base.plugin_context import PluginContext

# Imported for its side effect too: the module registers cdk-nag's
# suppression-scope hooks when it loads, as a real run does.
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (  # noqa: F401
    CdkNagScanner,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

pytestmark = pytest.mark.unit

RULE_ID = "AwsSolutions-IAM5[Action::logs:*]"
TEMPLATE = "cdk.out/stack.template.json"


@pytest.fixture()
def config(tmp_path):
    """A run's config with one engines-scoped suppression, keyed "cdk-nag".

    The entry's rule_id is the unqualified base, so a match also exercises the
    scoped base-rule-id fallback (``split_rule_qualifier_for``), which reads
    the same scanner identity the engines membership check does.
    """
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    profile = tmp_path / "suppressions.ash.yaml"
    profile.write_text(
        "project_name: engine-scope-identity\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: cdk.out/*.template.json\n"
        "      rule_id: AwsSolutions-IAM5\n"
        "      reason: scoped wildcard accepted\n"
        "      scope:\n"
        "        engines:\n"
        "          cdk-nag:\n"
        "            applies_to: 'Action::logs:*'\n",
        encoding="utf-8",
    )
    return load_config_file_for_run(profile)[1]


def _context(tmp_path, config) -> PluginContext:
    for name in ("source", "output", "work"):
        (tmp_path / name).mkdir(exist_ok=True)
    return PluginContext(
        source_dir=tmp_path / "source",
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=config,
    )


def _sarif(driver_name: str, result_properties: dict | None = None) -> SarifReport:
    result = {
        "ruleId": RULE_ID,
        "level": "error",
        "message": {"text": "wildcard action"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": TEMPLATE}}}],
    }
    if result_properties is not None:
        result["properties"] = result_properties
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": driver_name, "rules": []}},
                    "results": [result],
                }
            ],
        }
    )


def _suppression_count(report: SarifReport) -> int:
    return len(report.runs[0].results[0].suppressions or [])


def test_per_scanner_pass_matches_through_the_callers_scanner_name(tmp_path, config):
    """The per-scanner passes: the caller's registered name wins the match.

    Red on the unfixed base by construction, two ways: the base's
    ``apply_suppressions_to_sarif`` has no ``scanner_name`` parameter, so this
    call raises TypeError there; and the same input without the parameter
    leaves the finding unsuppressed on the base, because the finding's scanner
    is then the driver name "ash-cdk-nag-wrapper", which is not a key of
    ``scope.engines`` and has no registered scope hooks, so both the engines
    membership check and the base-rule-id fallback fail closed.
    """
    out = apply_suppressions_to_sarif(
        _sarif("ash-cdk-nag-wrapper"),
        _context(tmp_path, config),
        used_suppressions=set(),
        scanner_name="cdk-nag",
    )
    assert _suppression_count(out) == 1, out.runs[0].results[0]


def test_merged_pass_matches_through_the_attached_result_scanner_name(
    tmp_path, config
):
    """The merged pass: each result's identity is what attach_scanner_details
    wrote on it, not the aggregator's driver name.

    Red on the unfixed base by construction: the base reads only
    ``run.tool.driver.name``, which at the merged pass is
    "AWS Labs - Automated Security Helper", never an engines key, so the entry
    matched nothing there whatever the result's properties said.
    """
    out = apply_suppressions_to_sarif(
        _sarif(
            "AWS Labs - Automated Security Helper",
            result_properties={"scanner_name": "cdk-nag", "tags": ["cdk-nag"]},
        ),
        _context(tmp_path, config),
        used_suppressions=set(),
    )
    assert _suppression_count(out) == 1, out.runs[0].results[0]


def test_external_sarif_keeps_failing_closed_on_the_driver_name(tmp_path, config):
    """The must-not-flag control: with no caller name and no attached
    property, the identity is still the driver name, so external SARIF from an
    unregistered tool matches no engines block (today's fail-closed path,
    unchanged by the fix)."""
    out = apply_suppressions_to_sarif(
        _sarif("ash-cdk-nag-wrapper"),
        _context(tmp_path, config),
        used_suppressions=set(),
    )
    assert _suppression_count(out) == 0, out.runs[0].results[0]


def test_an_attached_identity_outside_the_scope_does_not_match(tmp_path, config):
    """The other must-not-flag control: an attached identity that is not an
    engines key matches nothing, so the fix widens the entry to no other
    scanner's findings."""
    out = apply_suppressions_to_sarif(
        _sarif(
            "AWS Labs - Automated Security Helper",
            result_properties={"scanner_name": "checkov"},
        ),
        _context(tmp_path, config),
        used_suppressions=set(),
    )
    assert _suppression_count(out) == 0, out.runs[0].results[0]


def test_scan_result_processor_pass_suppresses_through_the_registered_name(
    tmp_path, config
):
    """The real per-scanner pass: ScanResultProcessor.process_container applies
    suppressions to a report whose driver still carries the tool's own name,
    and passes the container's registered scanner name.

    Red on the unfixed base by construction: the base's processor passes no
    scanner name, the driver is "ash-cdk-nag-wrapper", and the merged result
    reaches the aggregate unsuppressed.
    """
    from automated_security_helper.core.phases.scan_result_processor import (
        ScanResultProcessor,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )

    context = _context(tmp_path, config)
    container = ScanResultsContainer(
        scanner_name="cdk-nag",
        target_type="source",
        raw_results=_sarif("ash-cdk-nag-wrapper"),
    )
    aggregated = AshAggregatedResults()

    ScanResultProcessor(context).process_container(container, aggregated)

    merged = [r for r in aggregated.sarif.runs[0].results if r.ruleId == RULE_ID]
    assert len(merged) == 1, aggregated.sarif.runs[0].results
    assert len(merged[0].suppressions or []) == 1, merged[0]
