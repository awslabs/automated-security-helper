"""``self.errors`` is per-call state too, and it was the field the counters' fix missed.

``TestCountersDoNotLeakBetweenTargets`` in ``test_cdk_nag_nothing_scanned.py`` establishes the
shape: ``ScanPhase`` appends one task per scanner carrying ``[source, converted]``, and
``ScannerExecutor._execute_scanner`` loops that list against the *same* plugin object, so
``scan()`` runs twice on one instance and whatever a target leaves behind is what the next target
starts with. That fix reset ``targets_attempted`` and ``targets_failed`` and stopped there.

``errors`` is declared on ``PluginBase`` and nothing resets it -- not ``_pre_scan``, not the
executor, not ``scan()``. Two consequences, both observable:

  * ``scan()`` serializes the list into ``exitCodeDescription`` on the invocation it returns. So
    a source pass that failed on ``a.yaml`` followed by a converted pass that succeeded produced
    a SARIF run carrying ``executionSuccessful=True``, ``exitCode=0`` and
    ``exitCodeDescription="a.yaml: RuntimeError: ..."`` -- a failure message on a run that did
    not fail.
  * ``ScannerExecutor`` splices ``*scanner_plugin.errors`` into the second target's error list on
    its exception path, re-reporting the first target's errors against the second.

The field has more writers than the two ``self.errors.append`` calls in ``scan()``:
``PluginBase._plugin_log`` appends for anything logged at ERROR or with
``append_to_stream="stderr"``, which includes the "target directory is empty" notice. Resetting
at the top of ``scan()`` covers every writer, and it has to sit above the first ``_plugin_log``
call in the method rather than merely above the loop, or that notice is cleared after being
recorded.
"""

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
    CdkNagScannerConfig,
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
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    return context


@pytest.fixture
def scanner(plugin_context):
    return CdkNagScanner(context=plugin_context, config=CdkNagScannerConfig())


@pytest.fixture
def cdk_available(monkeypatch, tmp_path):
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


def _description(report) -> str:
    return report.runs[0].invocations[0].exitCodeDescription


def test_a_failed_first_target_does_not_pollute_a_clean_second(
    scanner, cdk_available, wrapper_double
):
    """The concrete leak: a failure message on a run that reports success.

    Source fails on ``a.yaml``, converted succeeds. The converted pass's own invocation must not
    describe the source pass's failure -- a consumer reading ``exitCodeDescription`` alongside
    ``exitCode=0`` has no way to tell the message is stale.
    """
    (scanner.context.source_dir / "a.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "b.yaml").write_text(CFN_TEMPLATE)

    def _by_name(template_path, **kwargs):
        if template_path.name == "a.yaml":
            raise RuntimeError("synth blew up")
        return CdkNagWrapperResponse(results={"AwsSolutions": []}, failure=None)

    wrapper_double.side_effect = _by_name

    source_report = scanner.scan(
        target=scanner.context.source_dir, target_type="source"
    )
    assert "a.yaml" in _description(source_report), (
        "fixture check: the source pass must actually record its own failure, or this test "
        "proves nothing about the second pass"
    )

    converted_report = scanner.scan(
        target=scanner.context.work_dir, target_type="converted"
    )

    invocation = converted_report.runs[0].invocations[0]
    assert invocation.executionSuccessful is True
    assert invocation.exitCode == 0
    assert invocation.exitCodeDescription == "", (
        "the converted pass succeeded; carrying the source pass's error message describes a "
        f"failure that did not happen: {invocation.exitCodeDescription!r}"
    )
    assert scanner.errors == [], (
        "ScannerExecutor splices *scanner_plugin.errors into the next target's error list on "
        "its exception path, so a leftover entry is re-reported against a target it did not "
        "come from"
    )


def test_a_second_target_that_fails_still_reports_its_own_error(
    scanner, cdk_available, wrapper_double
):
    """The negative control.

    Without it, clearing ``errors`` at the wrong moment -- after the loop rather than before it,
    or in ``_post_scan`` -- would satisfy the test above while erasing every genuine message.
    """
    (scanner.context.source_dir / "a.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "b.yaml").write_text(CFN_TEMPLATE)
    wrapper_double.side_effect = lambda template_path, **kwargs: (_ for _ in ()).throw(
        RuntimeError(f"synth blew up on {template_path.name}")
    )

    scanner.scan(target=scanner.context.source_dir, target_type="source")
    converted_report = scanner.scan(
        target=scanner.context.work_dir, target_type="converted"
    )

    description = _description(converted_report)
    assert "b.yaml" in description, (
        "the failing target must still describe its own failure"
    )
    assert "a.yaml" not in description, f"and only its own: {description!r}"
    assert converted_report.runs[0].invocations[0].exitCode == 1


def test_an_empty_second_target_does_not_inherit_the_first_targets_errors(
    scanner, cdk_available, wrapper_double, tmp_path
):
    """The path that returns before the loop, which is the common one in production.

    ``_pre_scan`` creates ``work_dir`` during the source pass, so by the converted pass the
    directory exists and is empty for any project with nothing to convert. That return is above
    every ``self.errors.append`` in the method, so nothing on this path could ever clear what
    the previous target left.
    """
    (scanner.context.source_dir / "a.yaml").write_text(CFN_TEMPLATE)
    wrapper_double.side_effect = RuntimeError("synth blew up")

    scanner.scan(target=scanner.context.source_dir, target_type="source")
    assert scanner.errors, "fixture check: the source pass must record an error"

    empty_target = tmp_path / "empty-target"
    empty_target.mkdir()
    scanner.scan(target=empty_target, target_type="converted")

    assert not any("a.yaml" in entry for entry in scanner.errors), (
        f"the empty target inherited the source pass's errors: {scanner.errors}"
    )


def test_the_reset_is_above_the_first_plugin_log_call(scanner, cdk_available):
    """``_plugin_log`` is a writer too, and the reset must not land after it.

    An empty target logs "Target directory ... is empty" with
    ``append_to_stream="stderr"``, which ``PluginBase._plugin_log`` appends to ``errors``.
    Placing the reset below that -- next to the loop, where the counters used to be
    initialized -- would clear the notice on the very call that produced it.
    """
    empty_target = scanner.context.work_dir / "empty-target"
    empty_target.mkdir()

    scanner.scan(target=empty_target, target_type="converted")

    assert any("empty" in entry for entry in scanner.errors), (
        f"the empty-target notice must survive its own call: {scanner.errors}"
    )
