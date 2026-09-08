"""cdk-nag must report SKIPPED, not PASSED, when it evaluated nothing.

Three routes reach zero evaluated templates, and all three used to end the same way: an empty
SARIF report, zero findings, PASSED, green.

  1. The scan set holds no JSON or YAML file at all, so the scan body returns before the loop.
  2. Files were found but every one turned out not to be a CloudFormation template, so the
     per-file skip decremented the attempt count back to zero.
  3. Every nag pack is disabled, so the wrapper registers no plugin and returns None for every
     template -- which lands in the same skip branch as route 2.

Route 3 is worth stating explicitly because it is the one the PR #514 reviewer named ("empty
packs"), and because reading the scanner alone suggests it produces a validation report with no
plugin reports and therefore an ERROR. It does not:
``cdk_nag_wrapper.run_cdk_nag_against_cfn_template`` checks ``if not nag_packs`` before synthesis
and returns None, so no report is written and no ``failure`` is set. It is a green case, and it
is fixed by the same counter that fixes route 2.

Asserted on the counters here and on the container's status in
``tests/unit/models/test_scan_results_container_nothing_scanned.py``, because the scanner's job
is to record what it attempted and the container's job is to turn that into a status.
"""

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.models.scan_results_container import ScanResultsContainer
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagPacks,
    CdkNagScanner,
    CdkNagScannerConfig,
    CdkNagScannerConfigOptions,
)
from automated_security_helper.utils import cdk_nag_wrapper as wrapper_module
from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse

CFN_TEMPLATE = """Resources:
  MyDataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: placeholder-bucket
"""


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return context


@pytest.fixture
def scanner(plugin_context):
    return CdkNagScanner(context=plugin_context, config=CdkNagScannerConfig())


@pytest.fixture
def cdk_available(monkeypatch, tmp_path):
    """Present the CDK dependencies and node without installing either."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    fake_node = tmp_path / "bin" / "node"
    fake_node.parent.mkdir(parents=True, exist_ok=True)
    fake_node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(cdk_nag_scanner, "find_executable", lambda name: str(fake_node))
    return fake_node


@pytest.fixture
def wrapper_double(monkeypatch):
    from unittest.mock import create_autospec

    double = create_autospec(
        wrapper_module.run_cdk_nag_against_cfn_template, spec_set=True
    )
    double.return_value = CdkNagWrapperResponse(results={})
    monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", double)
    return double


def _status_for(scanner_plugin) -> ScannerStatus:
    """Run the two executor lines that copy the counters, then compute status.

    Reproduces the join rather than the whole executor: the counters are read off the plugin
    with the same helpers ScannerExecutor uses, so a change that flattens the tri-state at that
    boundary fails here.
    """
    from automated_security_helper.core.phases.scanner_executor import (
        _non_negative_int_attr,
        _target_count_attr,
    )

    container = ScanResultsContainer(scanner_name="cdk-nag")
    container.targets_attempted = _target_count_attr(
        scanner_plugin, "targets_attempted"
    )
    container.targets_failed = _non_negative_int_attr(scanner_plugin, "targets_failed")
    return container.determine_status("MEDIUM")


# ---------------------------------------------------------------------------
# Route 1: nothing in the scan set could be a CloudFormation template
# ---------------------------------------------------------------------------


def test_an_empty_scan_set_records_a_zero_attempt(
    scanner, cdk_available, wrapper_double
):
    """The counters must exist on this path, and they did not before.

    This branch returns before the loop. The counters were initialized just above the loop, so
    on this path the attributes were never set at all -- and an absent attribute is how a
    scanner says "I do not track targets", which is a different claim from "I tracked and
    attempted none". The executor read no claim and the empty report resolved to PASSED.
    """
    (scanner.context.work_dir / "notes.txt").write_text("nothing here")
    (scanner.context.work_dir / "main.py").write_text("print('hi')\n")

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 0, (
        "the scanner must record that it tracked targets and attempted none; leaving the "
        "attribute unset reads as 'does not track targets' and reports PASSED"
    )
    assert scanner.targets_failed == 0
    wrapper_double.assert_not_called()


def test_an_empty_scan_set_reports_skipped(scanner, cdk_available, wrapper_double):
    (scanner.context.work_dir / "notes.txt").write_text("nothing here")

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert _status_for(scanner) == ScannerStatus.SKIPPED


# ---------------------------------------------------------------------------
# Route 2: every candidate file turned out not to be a CloudFormation template
# ---------------------------------------------------------------------------


def test_all_files_skipped_reports_skipped(scanner, cdk_available, wrapper_double):
    """Ordinary JSON in the repository is not a clean CloudFormation scan."""
    (scanner.context.work_dir / "package.json").write_text('{"name": "x"}\n')
    (scanner.context.work_dir / "tsconfig.json").write_text("{}\n")
    wrapper_double.return_value = None

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 0
    assert scanner.targets_failed == 0
    assert _status_for(scanner) == ScannerStatus.SKIPPED


def test_one_real_template_among_skipped_files_is_not_skipped(
    scanner, cdk_available, wrapper_double, monkeypatch
):
    """The negative control for route 2, and the reason the count is not a boolean.

    A single evaluated template means the scan produced real information. Reporting SKIPPED here
    would hide a genuine result behind a status that says nothing was checked.
    """
    (scanner.context.work_dir / "package.json").write_text('{"name": "x"}\n')
    (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)

    def _by_name(template_path, **kwargs):
        if template_path.name == "bucket.yaml":
            return CdkNagWrapperResponse(results={"AwsSolutions": []}, failure=None)
        return None

    wrapper_double.side_effect = _by_name

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 0
    assert _status_for(scanner) == ScannerStatus.PASSED


# ---------------------------------------------------------------------------
# Route 3: every nag pack disabled -- the case the reviewer named
# ---------------------------------------------------------------------------


def test_the_wrapper_asks_for_no_packs_when_all_are_disabled(
    scanner, cdk_available, wrapper_double, plugin_context
):
    """Pins the input side: a config with every pack off produces an empty pack list.

    Without this, the next test would prove only that a mocked None yields SKIPPED, and the
    claim that disabling every pack reaches that branch would rest on reading the config code.
    """
    scanner.config = CdkNagScannerConfig(
        options=CdkNagScannerConfigOptions(
            nag_packs=CdkNagPacks(
                AwsSolutionsChecks=False,
                HIPAASecurityChecks=False,
                NIST80053R4Checks=False,
                NIST80053R5Checks=False,
                PCIDSS321Checks=False,
            )
        )
    )
    (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)
    wrapper_double.return_value = None

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert wrapper_double.call_args_list, "the wrapper was never called"
    for call in wrapper_double.call_args_list:
        assert call.kwargs["nag_packs"] == [], (
            f"expected no packs to be requested; got {call.kwargs['nag_packs']}"
        )


def test_the_wrapper_returns_none_when_no_pack_is_registered():
    """Pins the wrapper side: an empty pack list is None, not a report with no plugin reports.

    Checked against the source rather than by calling the wrapper, because a call needs cdk-nag
    and NodeJS and this is a unit test. The reading matters: if this branch instead synthesized
    and wrote a report, ``_violations_from_validation_report`` would return a ``failure``, the
    scanner would count a failed target, and every-pack-disabled would already report ERROR
    rather than green. It returns None, so it does not.
    """
    import inspect

    source = inspect.getsource(wrapper_module.run_cdk_nag_against_cfn_template)
    guard = source.split("if not nag_packs:", 1)
    assert len(guard) == 2, (
        "run_cdk_nag_against_cfn_template no longer guards on an empty pack list; the "
        "every-pack-disabled route may now take a different path"
    )
    after_guard = guard[1]
    assert "return None" in after_guard.split("app.synth()", 1)[0], (
        "the empty-pack guard must return None before synthesis; if it now synthesizes, this "
        "route produces a validation report and needs its own handling"
    )


def test_every_pack_disabled_reports_skipped(scanner, cdk_available, wrapper_double):
    """The reviewer's case, end to end through the scanner.

    Every template returns None because no pack was registered, the attempt count returns to
    zero, and the status says nothing was evaluated instead of rendering green.
    """
    scanner.config = CdkNagScannerConfig(
        options=CdkNagScannerConfigOptions(
            nag_packs=CdkNagPacks(
                AwsSolutionsChecks=False,
                HIPAASecurityChecks=False,
                NIST80053R4Checks=False,
                NIST80053R5Checks=False,
                PCIDSS321Checks=False,
            )
        )
    )
    (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(CFN_TEMPLATE)
    wrapper_double.return_value = None

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 0
    assert _status_for(scanner) == ScannerStatus.SKIPPED
    # The run itself completed; it simply had no rule to apply. executionSuccessful describes
    # the run, and the "nothing evaluated" fact is carried by the status above.
    assert report.runs[0].invocations[0].executionSuccessful is True


# ---------------------------------------------------------------------------
# A scan that did work is untouched
# ---------------------------------------------------------------------------


def test_a_real_scan_with_findings_still_fails(scanner, cdk_available, wrapper_double):
    from tests.unit.plugin_modules.ash_builtin.test_cdk_nag_scanner_behavior import (
        nag_result,
    )

    (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={"AwsSolutions": [nag_result()]}, failure=None
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 0
    assert _status_for(scanner) != ScannerStatus.SKIPPED


def test_a_scan_that_failed_every_template_still_errors(
    scanner, cdk_available, wrapper_double
):
    """SKIPPED must not swallow the ERROR case PR #514 added."""
    (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={}, failure="no validation report"
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1
    assert _status_for(scanner) == ScannerStatus.ERROR
