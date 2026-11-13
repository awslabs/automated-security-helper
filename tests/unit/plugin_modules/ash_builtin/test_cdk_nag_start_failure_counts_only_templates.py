# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A cdk-nag run that cannot start fails a template only for a template.

cdk-nag's scan set is every JSON and YAML file in the tree, and the scanner counts
each one as attempted before it knows whether the file is a CloudFormation template.
When the worker answers for a file, a file that is not a template is un-counted: the
wrapper answers "not a template". When the worker cannot answer at all, nothing says
what the file is, and every candidate used to count as a failed template. A
repository with no CloudFormation in it then exited non-zero, and named its
package.json as a template that was not evaluated.

The four ways the worker cannot answer are covered here:

  import failure   the wrapper reports that cdk-nag could not be imported, as a
                   response carrying ``failure``;
  node refusal     the wrapper raises while it looks up node;
  child exit       the worker child ends before it answers anything;
  child timeout    the worker child is stopped at ``scan_timeout``.

The scanner asks the question the tool-absent check asks,
``holds_cloudformation_template``, where it counts a failure. A candidate that is
not a template stops counting. A template, a damaged template and a template the
model cannot represent keep counting, so a broken install still fails a repository
that has something to scan.
"""

from pathlib import Path
from unittest.mock import create_autospec

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
    CdkNagScanner,
    CdkNagScannerConfig,
)
from automated_security_helper.utils import cdk_nag_worker
from automated_security_helper.utils import cdk_nag_wrapper as wrapper_module
from automated_security_helper.utils.cdk_nag_wrapper import CdkNagWrapperResponse
from automated_security_helper.utils.cfn_template_model import (
    NO_CLOUDFORMATION_TEMPLATE,
)

pytestmark = pytest.mark.unit

SUBPROCESS_UTILS = "automated_security_helper.utils.subprocess_utils"

CFN_TEMPLATE = """Resources:
  MyDataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: placeholder-bucket
"""

#: A template no parser can read that still reads as one: the format version and a
#: resource type survive the damage.
DAMAGED_TEMPLATE = (
    "AWSTemplateFormatVersion: '2010-09-09'\n"
    "Resources:\n"
    "  Bucket:\n"
    "    Type: AWS::S3::Bucket\n"
    "   Properties: [\n"
)

#: A document the template model rejects although it carries a Resources mapping:
#: the resource type has a space in it.
UNMODELABLE_TEMPLATE = 'Resources:\n  Bad:\n    Type: "has a space"\n'

#: Files an ordinary repository holds that are not CloudFormation.
PLAIN_FILES = {
    "package.json": '{"name": "example", "version": "1.0.0"}\n',
    "settings.yaml": "retries: 3\nendpoints:\n  - primary\n  - secondary\n",
}

START_FAILURES = ["import-failure", "node-refusal", "child-exit", "child-timeout"]


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
def cdk_available(monkeypatch, tmp_path):
    """Present the CDK dependencies and node without installing either."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)
    fake_node = tmp_path / "bin" / "node"
    fake_node.parent.mkdir(parents=True, exist_ok=True)
    fake_node.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(cdk_nag_scanner, "find_executable", lambda name: str(fake_node))
    return fake_node


@pytest.fixture(params=START_FAILURES)
def cdk_nag_cannot_answer(request, monkeypatch, cdk_available):
    """cdk-nag with its tool present and a worker that cannot answer for any file.

    The first two shapes replace the wrapper the scanner calls. The last two run the
    real worker seam with the spawn replaced, so the error a child that exited or
    timed out leaves reaches the scanner as the worker raises it.
    """
    shape = request.param
    if shape in ("import-failure", "node-refusal"):
        double = create_autospec(
            wrapper_module.run_cdk_nag_against_cfn_template, spec_set=True
        )
        if shape == "import-failure":
            double.return_value = CdkNagWrapperResponse(
                results={},
                failure=(
                    "cdk-nag could not be imported (ImportError: No module named "
                    "'cdk_nag'), so no rule was evaluated"
                ),
            )
        else:
            double.side_effect = RuntimeError(
                "node is not on PATH, and the copy found through the working "
                "directory is not run"
            )
        monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", double)
    else:
        outcome = (
            {"returncode": 1, "stderr": "Traceback\nImportError: boom"}
            if shape == "child-exit"
            else {"returncode": 124, "stderr": "", "timed_out": True}
        )
        monkeypatch.setattr(
            cdk_nag_scanner,
            "run_cdk_nag_against_cfn_template",
            cdk_nag_worker.run_cdk_nag_against_cfn_template,
        )
        monkeypatch.setattr(
            f"{SUBPROCESS_UTILS}.run_command_with_output_handling",
            lambda command, **kwargs: outcome,
        )
    return shape


def _scan(plugin_context):
    scanner = CdkNagScanner(context=plugin_context, config=CdkNagScannerConfig())
    report = scanner.scan(target=plugin_context.work_dir, target_type="converted")
    return scanner, report


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


def _write(plugin_context, files):
    for name, body in files.items():
        (plugin_context.work_dir / name).write_text(body, encoding="utf-8")


def test_files_that_are_not_templates_do_not_count_when_the_worker_cannot_answer(
    plugin_context, cdk_nag_cannot_answer
):
    """A tree with no CloudFormation is skipped, whatever stops cdk-nag from running.

    The control for it is the same tree with a working cdk-nag, below. Both end with
    no attempted target, which the container grades SKIPPED and the completeness
    gate accepts.
    """
    from automated_security_helper.core.phases.scanner_executor import (
        _skipped_reason_after_scan,
    )

    _write(plugin_context, PLAIN_FILES)

    scanner, report = _scan(plugin_context)

    assert (scanner.targets_attempted, scanner.targets_failed) == (0, 0), (
        f"{sorted(PLAIN_FILES)} hold no CloudFormation, so none of them is a template "
        f"that was lost; got attempted={scanner.targets_attempted} "
        f"failed={scanner.targets_failed}"
    )
    status = _status_for(scanner)
    assert status == ScannerStatus.SKIPPED
    assert status.value in _COMPLETE_SCANNER_STATUSES
    assert scanner.unevaluated_targets == []
    assert not [
        error for error in scanner.errors for name in PLAIN_FILES if name in error
    ], scanner.errors
    assert report.runs[0].invocations[0].exitCode == 0
    assert (
        _skipped_reason_after_scan(scanner, "cdk-nag", "converted")
        == NO_CLOUDFORMATION_TEMPLATE
    )


def test_a_template_among_other_files_is_the_one_failed_target(
    plugin_context, cdk_nag_cannot_answer
):
    """The run still fails, and it names the template and nothing else."""
    _write(plugin_context, {"bucket.yaml": CFN_TEMPLATE, **PLAIN_FILES})

    scanner, report = _scan(plugin_context)

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1), (
        f"only bucket.yaml is a template; got attempted={scanner.targets_attempted} "
        f"failed={scanner.targets_failed}"
    )
    assert _status_for(scanner) == ScannerStatus.ERROR
    assert [Path(name).name for name in scanner.unevaluated_targets] == ["bucket.yaml"]
    description = report.runs[0].invocations[0].exitCodeDescription or ""
    assert "bucket.yaml" in description
    assert not [name for name in PLAIN_FILES if name in description], description
    assert report.runs[0].invocations[0].executionSuccessful is False
    assert report.runs[0].invocations[0].exitCode == 1


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(CFN_TEMPLATE, id="template"),
        pytest.param(DAMAGED_TEMPLATE, id="damaged-template"),
        pytest.param(UNMODELABLE_TEMPLATE, id="template-the-model-rejects"),
    ],
)
def test_a_file_that_may_be_a_template_still_fails_when_the_worker_cannot_answer(
    plugin_context, cdk_nag_cannot_answer, body
):
    """Control: every doubt counts as a template, as the tool-absent check reads it.

    Without this, the test above could be satisfied by un-counting every file when
    the worker cannot answer, which is the silent pass the failure counting exists to
    prevent.
    """
    _write(plugin_context, {"stack.yaml": body})

    scanner, _report = _scan(plugin_context)

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1)
    assert _status_for(scanner) == ScannerStatus.ERROR
    assert [Path(name).name for name in scanner.unevaluated_targets] == ["stack.yaml"]


def test_files_that_are_not_templates_are_still_skipped_when_the_worker_answers(
    plugin_context, cdk_available, monkeypatch
):
    """Control: with a cdk-nag that runs, the same tree is the same skip."""
    double = create_autospec(
        wrapper_module.run_cdk_nag_against_cfn_template, spec_set=True
    )
    double.return_value = None
    monkeypatch.setattr(cdk_nag_scanner, "run_cdk_nag_against_cfn_template", double)
    _write(plugin_context, PLAIN_FILES)

    scanner, report = _scan(plugin_context)

    assert (scanner.targets_attempted, scanner.targets_failed) == (0, 0)
    status = _status_for(scanner)
    assert status == ScannerStatus.SKIPPED
    assert status.value in _COMPLETE_SCANNER_STATUSES
    assert report.runs[0].invocations[0].exitCode == 0
