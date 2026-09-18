"""``None`` from the wrapper means one thing, and it used to mean three.

``run_cdk_nag_against_cfn_template`` returned a bare ``None`` from three places, and
``cdk_nag_scanner`` has exactly one branch for it -- the per-file skip, which decrements the
attempt count back down. Only one of the three is a skip:

  site                          meaning                          logged as
  ----------------------------  -------------------------------  ---------
  no valid template model       not a CloudFormation file        debug     <- a real skip
  ``import cdk_nag`` failed     nothing was evaluated            WARNING   <- a failure
  zero nag packs registered     nothing was evaluated            ERROR     <- a failure

For the two failures the file *was* a real template and no rule ran against it. Returning the
skip value made each one un-count itself, so a scan where every template hit one of them ended
at zero attempts, which the container reads as "tracked, attempted none" and reports SKIPPED --
on the completeness allowlist in both gates, so the run exited 0 and printed "none incomplete".

``CdkNagWrapperResponse.failure`` already existed for "ran but produced no readable report", and
``cdk_nag_scanner`` already counts a response carrying it as a failed target. Both failures now
return that instead, so both reach ERROR.

The regression this file guards against is the opposite direction. A repository with no
CloudFormation in it must still be SKIPPED with exit code 0 -- that is the case the SKIPPED
status was designed for, and making the two failures loud is only correct if it leaves that one
alone. ``test_a_repository_with_no_templates_is_still_a_clean_skip`` is that control.

On the zero-packs case being reclassified
----------------------------------------
It was previously pinned as intended, asserting SKIPPED and ``executionSuccessful is True``
(``test_cdk_nag_nothing_scanned.py``). Overturned, for reasons that are not "ERROR is stricter":

  * SKIPPED's place on the completeness allowlist is justified by a specific meaning -- "the
    scanner was not selected" -- which is what ``core.sharding`` and ``--exclude-scanners``
    produce, and why failing on SKIPPED would break every shard of a sharded scan. cdk-nag with
    zero packs was selected and did run. It was riding on a justification written for something
    else.
  * Nothing is taken away from an operator who wants cdk-nag quiet. ``enabled: false`` and
    ``--exclude-scanners cdk-nag`` both still record SKIPPED. What is removed is only the
    ability to silence cdk-nag while it still reports as a completed scan.
  * ``CdkNagPacks`` sets ``extra="allow"``, so an unrecognized pack name is accepted rather than
    rejected, and only ``AwsSolutionsChecks`` defaults on. Turning that one off in the belief
    that another is on -- or naming a pack that no longer exists -- reaches zero packs by
    accident and rendered identically to reaching it deliberately. Under SKIPPED an operator
    could not tell those two apart. Under ``failure`` both are named out loud.
  * The wrapper has always logged this at ERROR with the words "nothing was evaluated". A status
    of SKIPPED with ``executionSuccessful=True`` and exit 0 contradicted the code's own reading
    of its own state.
"""

import inspect
import sys

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.interactions.run_ash_scan import (
    _COMPLETE_SCANNER_STATUSES,
)
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

ALL_PACKS_OFF = CdkNagScannerConfig(
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


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
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
    monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", double)
    return double


def _status_for(scanner_plugin) -> ScannerStatus:
    """Run the two executor lines that copy the counters, then compute status."""
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


def _gate_accepts(status: ScannerStatus) -> bool:
    return status.value in _COMPLETE_SCANNER_STATUSES


# ---------------------------------------------------------------------------
# Site 1: no valid template model -- the one legitimate skip, and the control
# ---------------------------------------------------------------------------


def test_a_repository_with_no_templates_is_still_a_clean_skip(
    scanner, cdk_available, wrapper_double
):
    """The regression to guard against, and the reason this change is delicate.

    Ordinary JSON in a repository with no CloudFormation in it is not a failure. If this ever
    reports ERROR, every repository without a template starts failing its scan, which is a far
    louder break than the hole being closed.
    """
    (scanner.context.work_dir / "package.json").write_text('{"name": "x"}\n')
    (scanner.context.work_dir / "tsconfig.json").write_text("{}\n")
    wrapper_double.return_value = None

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    status = _status_for(scanner)
    assert (scanner.targets_attempted, scanner.targets_failed) == (0, 0)
    assert status == ScannerStatus.SKIPPED
    assert _gate_accepts(status), (
        "a repository with no CloudFormation must still exit 0"
    )
    assert report.runs[0].invocations[0].exitCode == 0


def test_only_the_not_a_template_case_still_returns_none():
    """Pins that the wrapper has exactly one bare-None return left.

    Read off the source rather than by calling, because reaching the other two sites needs
    cdk-nag and NodeJS installed. Counting them is what catches a future site being added back:
    the assertions below name the two that were converted, but a third one added later would
    slip past a test that only checked those two.
    """
    source = inspect.getsource(wrapper_module.run_cdk_nag_against_cfn_template)
    bare_returns = [
        line.strip() for line in source.splitlines() if line.strip() == "return None"
    ]
    assert len(bare_returns) == 1, (
        f"expected exactly one bare `return None` -- the not-a-CloudFormation-template skip -- "
        f"found {len(bare_returns)}. A `return None` for a template that went unevaluated "
        f"reaches the scanner's skip branch and un-counts the attempt."
    )


# ---------------------------------------------------------------------------
# Site 2: cdk-nag could not be imported
# ---------------------------------------------------------------------------


def test_a_failed_import_returns_a_failure_not_a_skip(tmp_path, monkeypatch):
    """Drives the real wrapper, with a real ImportError.

    ``sys.modules["cdk_nag"] = None`` makes ``import cdk_nag`` raise
    ``ImportError: import of cdk_nag halted; None in sys.modules``, so this exercises the
    production guard rather than a double of it -- and it works whether or not the ``cdk``
    extra is installed, which matters because CI does not install it.
    """
    template = tmp_path / "bucket.yaml"
    template.write_text(CFN_TEMPLATE)
    monkeypatch.setitem(sys.modules, "cdk_nag", None)

    response = wrapper_module.run_cdk_nag_against_cfn_template(
        template_path=template,
        nag_packs=["AwsSolutionsChecks"],
        outdir=tmp_path / "out",
    )

    assert response is not None, (
        "a failed import must not return the not-a-template skip value; the scanner "
        "un-counts that branch and the run reports SKIPPED with exit code 0"
    )
    assert response.failure is not None
    assert "could not be imported" in response.failure


def test_the_failed_import_message_names_the_module_not_nodejs(
    tmp_path, monkeypatch, caplog
):
    """The diagnosis was wrong, not merely unhelpful.

    Measured on a host with NodeJS 22 on PATH and cdk-nag installed without its dependencies:
    the import failed on a Python module and the log said "NodeJS is missing", sending the
    operator to install something they already had.
    """
    template = tmp_path / "bucket.yaml"
    template.write_text(CFN_TEMPLATE)
    monkeypatch.setitem(sys.modules, "cdk_nag", None)

    with caplog.at_level("WARNING"):
        wrapper_module.run_cdk_nag_against_cfn_template(
            template_path=template,
            nag_packs=["AwsSolutionsChecks"],
            outdir=tmp_path / "out",
        )

    logged = " ".join(caplog.messages)
    assert "cdk_nag" in logged, "the message must name the module that failed to load"
    assert "NodeJS is missing" not in logged, (
        "an ImportError is a Python module problem; blaming NodeJS for it was the wrong "
        f"diagnosis and it was reported as fact: {logged!r}"
    )


def test_a_failed_import_on_every_template_reports_error(
    scanner, cdk_available, wrapper_double
):
    """Through the scanner: the status a broken install now reaches."""
    (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(CFN_TEMPLATE)
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={}, failure="cdk-nag could not be imported (ImportError: nope)"
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    status = _status_for(scanner)
    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 2)
    assert status == ScannerStatus.ERROR
    assert not _gate_accepts(status), (
        "two real templates and no rule evaluated against either must not exit 0"
    )
    assert report.runs[0].invocations[0].executionSuccessful is False
    assert report.runs[0].invocations[0].exitCode == 1


# ---------------------------------------------------------------------------
# Site 3: zero nag packs registered
# ---------------------------------------------------------------------------


def test_the_empty_pack_guard_returns_a_failure_before_synthesis():
    """Pins the wrapper side of route 3, replacing the assertion that pinned ``return None``.

    Checked against the source rather than by calling, because a call needs cdk-nag and NodeJS.
    Still asserts the guard fires before ``app.synth()``: if it ever synthesized instead, the
    validation report would drive the outcome and this branch would need different handling.
    """
    source = inspect.getsource(wrapper_module.run_cdk_nag_against_cfn_template)
    guard = source.split("if not nag_packs:", 1)
    assert len(guard) == 2, (
        "run_cdk_nag_against_cfn_template no longer guards on an empty pack list; the "
        "every-pack-disabled route may now take a different path"
    )
    before_synth = guard[1].split("app.synth()", 1)[0]
    assert "CdkNagWrapperResponse(" in before_synth, (
        "the empty-pack guard must return a response carrying `failure`; a bare None lands in "
        "the scanner's skip branch, un-counts the attempt, and reports SKIPPED with exit 0"
    )
    assert "failure=" in before_synth
    assert "return None" not in before_synth


def test_the_empty_pack_guard_sits_after_the_template_model_check():
    """The ordering that keeps the control above true.

    A repository of ordinary JSON scanned with every pack disabled must still be a skip, and it
    is only a skip because the not-a-template return comes first. Hoisting the pack guard to the
    top of the function -- an obvious-looking tidy-up, since it needs no template -- would turn
    every non-template file into a failed target.
    """
    source = inspect.getsource(wrapper_module.run_cdk_nag_against_cfn_template)

    assert source.index("get_model_from_template(") < source.index(
        "if not nag_packs:"
    ), (
        "the template model check must precede the empty-pack guard, or a repository with no "
        "CloudFormation in it reports ERROR instead of SKIPPED"
    )


def test_every_pack_disabled_reports_error(scanner, cdk_available, wrapper_double):
    """Route 3 end to end, and the assertion that was previously inverted.

    Two real CloudFormation templates, zero rules evaluated against either. The previous pin
    asserted SKIPPED here and ``executionSuccessful is True``; see the module docstring for why
    that was overturned rather than kept.
    """
    scanner.config = ALL_PACKS_OFF
    (scanner.context.work_dir / "bucket.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(CFN_TEMPLATE)
    wrapper_double.return_value = CdkNagWrapperResponse(
        results={}, failure="no cdk-nag pack was registered, so no rule was evaluated"
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    status = _status_for(scanner)
    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 2)
    assert status == ScannerStatus.ERROR
    assert not _gate_accepts(status)
    assert report.runs[0].invocations[0].executionSuccessful is False


def test_the_empty_pack_failure_names_the_way_to_turn_the_scanner_off(
    scanner, cdk_available, wrapper_double
):
    """The operator has to be told which of the two states they are in.

    A config that reached zero packs deliberately and one that reached it by a typo produce the
    same state, and ``extra="allow"`` means pydantic rejects neither. The remedy for each is
    different -- fix the config, or disable the scanner -- so the message names both.
    """
    source = inspect.getsource(wrapper_module.run_cdk_nag_against_cfn_template)
    guard = source.split("if not nag_packs:", 1)[1].split("app.synth()", 1)[0]

    assert "nag_packs" in guard and "enabled: false" in guard, (
        "the failure message must point at both remedies; an operator who wanted cdk-nag off "
        "needs to be told that disabling every pack is not how to say so"
    )


# ---------------------------------------------------------------------------
# A partial failure is still a pass -- unchanged, and deliberately so
# ---------------------------------------------------------------------------


def test_one_template_evaluated_among_failures_is_still_a_pass(
    scanner, cdk_available, wrapper_double
):
    """Records the classification this change did NOT touch.

    ``targets_failed < targets_attempted`` is a pass, so one template out of three evaluating
    cleanly masks two that were never evaluated at all. That is arguable in both directions and
    changing it is an operator-facing semantics decision nobody has made, so it is pinned here
    as the current behavior rather than altered.
    """
    (scanner.context.work_dir / "good.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "bad1.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "bad2.yaml").write_text(CFN_TEMPLATE)

    def _by_name(template_path, **kwargs):
        if template_path.name == "good.yaml":
            return CdkNagWrapperResponse(results={"AwsSolutions": []}, failure=None)
        return CdkNagWrapperResponse(results={}, failure="no validation report")

    wrapper_double.side_effect = _by_name

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert (scanner.targets_attempted, scanner.targets_failed) == (3, 2)
    assert _status_for(scanner) == ScannerStatus.PASSED
