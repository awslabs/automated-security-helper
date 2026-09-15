"""cdk-nag must report SKIPPED, not PASSED, when there was nothing to evaluate.

Two routes reach zero evaluated templates without anything having gone wrong, and both used to
end the same way: an empty SARIF report, zero findings, PASSED, green.

  1. The scan set holds no JSON or YAML file at all, so the scan body returns before the loop.
  2. Files were found but every one turned out not to be a CloudFormation template, so the
     per-file skip decremented the attempt count back to zero.

A third route used to be covered here: every nag pack disabled, which made the wrapper register
no plugin and return None for every template, landing in the same skip branch as route 2. It has
moved to ``test_cdk_nag_unevaluated_is_not_skipped.py`` and its expected status has changed from
SKIPPED to ERROR, because a real CloudFormation template that no rule ran against is not the same
claim as a repository with no CloudFormation in it. The reasoning for overturning it is in that
file's docstring. What stays here is route 3's *input* side --
``test_the_wrapper_asks_for_no_packs_when_all_are_disabled`` -- which pins that a config with
every pack off really does ask the wrapper for an empty pack list, and is unaffected by what the
wrapper then does with it.

Worth knowing before adding a route-3 test back to this file: the two tests that were removed
alongside the docstring change did not both fail when the wrapper's behavior changed. One of them
set ``wrapper_double.return_value = None`` and asserted SKIPPED, which is still true of a doubled
None and always will be -- it pinned the scanner's skip branch while its name claimed to pin the
every-pack-disabled route. Only the test that read the wrapper's source noticed. A route-3
assertion driven through a double of the wrapper cannot detect a change in the wrapper.

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
# Route 3, input side only. What the wrapper does with an empty pack list, and
# what status that produces, is in test_cdk_nag_unevaluated_is_not_skipped.py.
# ---------------------------------------------------------------------------


def test_the_wrapper_asks_for_no_packs_when_all_are_disabled(
    scanner, cdk_available, wrapper_double, plugin_context
):
    """Pins the input side: a config with every pack off produces an empty pack list.

    Without this, any claim about the every-pack-disabled route rests on reading the config
    code rather than on running it -- and the filter this pins is not trivial. ``CdkNagPacks``
    allows extra keys, so ``nag_packs.items()`` can hold names that are not packs at all, and
    the comprehension in ``scan()`` decides which of them reach the wrapper.
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


# ---------------------------------------------------------------------------
# The production shape: one plugin instance, two targets, two scan() calls
# ---------------------------------------------------------------------------


def _outcome(scanner_plugin):
    """What the executor would record for the target that just finished."""
    return (
        scanner_plugin.targets_attempted,
        scanner_plugin.targets_failed,
        _status_for(scanner_plugin),
    )


class TestCountersDoNotLeakBetweenTargets:
    """Every test above calls ``scan()`` once on a fresh fixture. Production never does.

    ``ScanPhase`` appends one task per scanner carrying ``[source, converted]``, and
    ``ScannerExecutor._execute_scanner`` loops that list against the *same* ``scanner_plugin``
    object. So ``scan()`` runs twice on one instance, and the counters are instance attributes
    that the executor reads after each call. Anything left over from the first target is read as
    the second target's own claim.

    The empty-or-absent-target return sits above the point where the counters are set, so a
    target that returns there keeps whatever the previous target left behind. That is not an
    exotic path: ``_pre_scan`` calls ``work_dir.mkdir(parents=True, exist_ok=True)`` during the
    source pass, so by the time the converted pass runs the directory exists, and it is empty
    for any project with nothing to convert.

    The first leaked shape is precisely the defect this whole change exists to prevent -- a
    PASSED that means "nothing was evaluated" -- except now backed by a positive attempt count
    it did not earn, which is worse than the original because the count looks like evidence.

    Only the empty-directory half of that branch is covered here. ``not target.exists()`` shares
    the same ``if``, but it is unreachable two ways over: ``ScannerExecutor._execute_scanner``
    drops targets whose path does not exist before calling ``scan()``, and a direct call with a
    missing path raises earlier still, while building the SARIF skeleton above the check.
    """

    @pytest.fixture
    def empty_target(self, tmp_path):
        """A target directory that exists and is empty, like an unused work_dir."""
        target = tmp_path / "empty-target"
        target.mkdir()
        return target

    def test_a_clean_first_target_does_not_lend_its_attempts_to_an_empty_second(
        self, scanner, cdk_available, wrapper_double, empty_target
    ):
        (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)
        (scanner.context.work_dir / "queue.yaml").write_text(CFN_TEMPLATE)
        wrapper_double.return_value = CdkNagWrapperResponse(
            results={"AwsSolutions": []}, failure=None
        )

        scanner.scan(target=scanner.context.work_dir, target_type="converted")
        assert _outcome(scanner) == (2, 0, ScannerStatus.PASSED)

        scanner.scan(target=empty_target, target_type="converted")

        assert _outcome(scanner) == (0, 0, ScannerStatus.SKIPPED), (
            "the second target evaluated nothing and must say so; inheriting the first "
            "target's attempt count reports PASSED off two attempts it never made"
        )

    def test_a_failed_first_target_does_not_lend_its_failures_to_an_empty_second(
        self, scanner, cdk_available, wrapper_double, empty_target
    ):
        """The mirror image, and the one that invents a failure rather than hiding one.

        A stale ``targets_failed`` makes the second target report ERROR -- "cdk-nag failed on
        every template" -- for a target where cdk-nag never opened a file.
        """
        (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)
        wrapper_double.return_value = CdkNagWrapperResponse(
            results={}, failure="no validation report"
        )

        scanner.scan(target=scanner.context.work_dir, target_type="converted")
        assert _outcome(scanner) == (1, 1, ScannerStatus.ERROR)

        scanner.scan(target=empty_target, target_type="converted")

        assert _outcome(scanner) == (0, 0, ScannerStatus.SKIPPED), (
            "the second target evaluated nothing and must not inherit a failure; a false "
            "ERROR names a broken scanner where nothing ran"
        )

    def test_the_real_source_then_converted_ordering_leaks_the_same_way(
        self, scanner, cdk_available, wrapper_double
    ):
        """The same leak in the exact order ``ScanPhase`` builds the task list.

        Stated separately from the two tests above so the defect cannot be dismissed as an
        artifact of scanning the same target type twice. Source templates are evaluated, then the
        converted pass finds an empty work_dir and returns early.
        """
        (scanner.context.source_dir / "bucket.yaml").write_text(CFN_TEMPLATE)
        wrapper_double.return_value = CdkNagWrapperResponse(
            results={"AwsSolutions": []}, failure=None
        )

        scanner.scan(target=scanner.context.source_dir, target_type="source")
        source_outcome = _outcome(scanner)
        assert source_outcome[0] == 1, (
            f"fixture check: the source pass must evaluate the template; got {source_outcome}"
        )

        assert not any(scanner.context.work_dir.iterdir()), (
            "fixture check: the converted target must be empty to reach the early return"
        )
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

        assert _outcome(scanner) == (0, 0, ScannerStatus.SKIPPED)

    def test_an_empty_target_makes_a_claim_on_the_very_first_call(
        self, scanner, cdk_available, wrapper_double, empty_target
    ):
        """The leak's other face: with nothing to inherit, the counters stay unset entirely.

        Not a leak at all on a first call, but the same missing initialization, and it defeats
        the guard rather than corrupting it. An unset attribute is how a scanner says "I do not
        track targets", the executor records no claim, and the empty report resolves to PASSED --
        the exact outcome the SKIPPED status exists to replace.

        The route-1 tests above miss this because their work_dir holds ``notes.txt``, so the
        directory is not empty and execution reaches the initialization further down. Only a
        genuinely empty target returns above it.
        """
        wrapper_double.return_value = CdkNagWrapperResponse(
            results={"AwsSolutions": []}, failure=None
        )

        scanner.scan(target=empty_target, target_type="converted")

        assert scanner.targets_attempted == 0, (
            "an empty target directory must record a tracked-zero claim; leaving the attribute "
            "unset reads as 'does not track targets' and reports PASSED"
        )
        assert _outcome(scanner) == (0, 0, ScannerStatus.SKIPPED)

    def test_a_second_target_that_does_scan_is_still_counted(
        self, scanner, cdk_available, wrapper_double, empty_target
    ):
        """The negative control: resetting must not erase the second target's own work.

        Without this, zeroing the counters unconditionally at the top of every call would pass
        the tests above while destroying the counts for any target that really did scan.
        """
        wrapper_double.return_value = CdkNagWrapperResponse(
            results={"AwsSolutions": []}, failure=None
        )

        scanner.scan(target=empty_target, target_type="converted")
        assert _outcome(scanner) == (0, 0, ScannerStatus.SKIPPED)

        (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)
        (scanner.context.work_dir / "queue.yaml").write_text(CFN_TEMPLATE)
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

        assert _outcome(scanner) == (2, 0, ScannerStatus.PASSED)
