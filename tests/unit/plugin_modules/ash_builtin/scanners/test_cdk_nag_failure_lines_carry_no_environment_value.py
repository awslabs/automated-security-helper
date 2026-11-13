# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cdk-nag's per-template failure records carry no value the config read from the environment.

A config option can come from the environment (``${VAR}``), and the two
records the scanner makes of a template it could not evaluate interpolate
text that can carry such a value:

- the wrapper's reported failure (``nag_result_dict.failure``), which is the
  worker's own reason text (its timeout reason names the configured
  ``scan_timeout``);
- the exception a template's evaluation raised, logged at ERROR and appended
  to ``self.errors``, which the SARIF ``exitCodeDescription`` keeps.
"""

import logging
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    CdkNagScanner,
    CdkNagScannerConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

_MOD = "automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner"

CANARY = "/nonexistent/ENVCANARY-settings/settings.yaml"

#: Where the value sits: a value under the home directory no longer matches
#: once a line writes it with ~, so it has to be redacted first.
WHERE = ["elsewhere", "under HOME"]


def _value(where: str) -> str:
    if where == "elsewhere":
        return CANARY
    from pathlib import Path

    return (Path.home() / "ENVCANARY-settings" / "settings.yaml").as_posix()


@pytest.fixture
def logged():
    lines = []

    class _Collect(logging.Handler):
        def emit(self, record):
            lines.append(logging.Formatter("%(message)s").format(record))

    handler = _Collect(level=logging.DEBUG)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        yield lines
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _scanner_and_template(test_plugin_context, value=CANARY):
    scanner = CdkNagScanner(context=test_plugin_context, config=CdkNagScannerConfig())
    scanner.context.config._environment_values = [value]
    scanner.dependencies_satisfied = True
    # The template lives inside the context's source tree: a file outside it
    # is refused before it is evaluated, and the SARIF tail shortens paths
    # against this directory.
    target = scanner.context.source_dir
    target.mkdir(parents=True, exist_ok=True)
    scanner.context.output_dir.mkdir(parents=True, exist_ok=True)
    template = target / "template.yaml"
    template.write_text("Resources: {}\n")
    return scanner, target, template


def _scan(scanner, target, template, per_template):
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch(
            f"{_MOD}.cloudformation_candidate_files",
            return_value=[str(template)],
        ),
        # The batch's two records, empty: the scanner reads them directly after the
        # loop, and a bare ``nullcontext()`` yields None.
        patch(
            f"{_MOD}.cdk_nag_worker_batch",
            return_value=nullcontext(
                SimpleNamespace(failed_child_responses=[], could_not_stop_response=None)
            ),
        ),
        patch(f"{_MOD}.run_cdk_nag_against_cfn_template", **per_template),
    ):
        scanner.scan(target=target, target_type="source")


def _scan_with_a_crashing_worker_child(scanner, target, template, stderr_text):
    """A scan through the REAL batch and worker, whose child exits before
    answering: only the spawned run is replaced, so the reason the scanner
    records is the one the worker builds from the child's stderr. The
    scanner's module-level name for the worker entry is its availability
    gate (None without the CDK installed), so the real function is patched
    in by name rather than stubbed out as the other cells do."""
    from automated_security_helper.utils.cdk_nag_worker import (
        run_cdk_nag_against_cfn_template,
    )

    outcome = {"returncode": 2, "stdout": "", "stderr": stderr_text}
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch(
            f"{_MOD}.cloudformation_candidate_files",
            return_value=[str(template)],
        ),
        patch(
            f"{_MOD}.run_cdk_nag_against_cfn_template",
            run_cdk_nag_against_cfn_template,
        ),
        patch(
            "automated_security_helper.utils.subprocess_utils"
            ".run_command_with_output_handling",
            return_value=outcome,
        ),
    ):
        scanner.scan(target=target, target_type="source")


def test_the_workers_stderr_tail_hides_a_value_spanning_lines(test_plugin_context):
    """The worker's exited-before-answering reason joins the child's last
    stderr lines with " | ": a split before any redaction rewrites a
    value's line break as the joiner, so the downstream whole-spelling
    redaction (the scanner's error_text over its environment values) matched
    nothing and both halves printed. The worker redacts the whole stderr
    with the scan's values before it splits."""
    value = "Zq7Kx9LmLeak\nPw4Nv2RtTail"
    scanner, target, template = _scanner_and_template(test_plugin_context, value)

    _scan_with_a_crashing_worker_child(
        scanner, target, template, f"node crashed reading {value} here"
    )

    recorded = next(error for error in scanner.errors if "before answering" in error)
    # The controls: the child's exit and its own words are reported.
    assert "exited 2" in recorded, recorded
    assert "node crashed" in recorded, recorded
    assert "Zq7Kx9LmLeak" not in recorded, recorded
    assert "Pw4Nv2RtTail" not in recorded, recorded


def test_the_workers_stderr_tail_hides_a_value_split_by_a_non_color_escape(
    test_plugin_context,
):
    """A terminal code inside the value's printed spelling: the strip before
    the redaction covers every escape the package strips (ESCAPE_CODES), not
    only colors. An erase-line code left in place splits the match, and both
    halves print joined by the literal code."""
    value = "Zq7Kx9LmLeakPw4Nv2RtTail"
    scanner, target, template = _scanner_and_template(test_plugin_context, value)

    _scan_with_a_crashing_worker_child(
        scanner,
        target,
        template,
        "node crashed reading Zq7Kx9LmLeak\x1b[KPw4Nv2RtTail here",
    )

    recorded = next(error for error in scanner.errors if "before answering" in error)
    assert "node crashed" in recorded, recorded
    assert "Zq7Kx9LmLeak" not in recorded, recorded
    assert "Pw4Nv2RtTail" not in recorded, recorded


def test_the_workers_stderr_tail_hides_a_single_line_value(test_plugin_context):
    """The control for the spanning cell: a value on one line is hidden from
    the recorded reason whether the worker or the scanner's own redaction
    hides it."""
    value = "Zq7Kx9LmLeakPw4Nv2RtTail"
    scanner, target, template = _scanner_and_template(test_plugin_context, value)

    _scan_with_a_crashing_worker_child(
        scanner, target, template, f"node crashed reading {value} here"
    )

    recorded = next(error for error in scanner.errors if "before answering" in error)
    assert "node crashed" in recorded, recorded
    assert value not in recorded, recorded


@pytest.mark.parametrize("where", WHERE)
def test_an_evaluation_failure_carries_no_environment_value(
    test_plugin_context, logged, where
):
    value = _value(where)
    scanner, target, template = _scanner_and_template(test_plugin_context, value)

    _scan(
        scanner,
        target,
        template,
        {"side_effect": RuntimeError(f"could not read {value}")},
    )

    line = next(line for line in logged if "failed to scan" in line)
    assert "could not read" in line, line
    assert "ENVCANARY-settings" not in line, line
    recorded = next(error for error in scanner.errors if "could not read" in error)
    assert "ENVCANARY-settings" not in recorded, recorded


@pytest.mark.parametrize("where", WHERE)
def test_a_wrapper_reported_failure_carries_no_environment_value(
    test_plugin_context, logged, where
):
    value = _value(where)
    scanner, target, template = _scanner_and_template(test_plugin_context, value)

    _scan(
        scanner,
        target,
        template,
        {
            "return_value": SimpleNamespace(
                failure=f"the worker could not read {value}", results={}
            )
        },
    )

    line = next(line for line in logged if "did not evaluate" in line)
    assert "could not read" in line, line
    assert "ENVCANARY-settings" not in line, line
    recorded = next(error for error in scanner.errors if "could not read" in error)
    assert "ENVCANARY-settings" not in recorded, recorded
