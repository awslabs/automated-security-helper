# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A target the scanner's tool never evaluated refuses a PASSED verdict.

A scanner that names unevaluated targets keeps the evaluated targets' findings,
and PASSED would read as "evaluated and clean" for a target nothing evaluated.
The executor reads ``unevaluated_targets`` off the plugin after the scan: each
named target goes on the results row as "no rule was evaluated against <name>",
whatever the status is, and a PASSED verdict becomes ERROR. A row that already
says FAILED keeps it, since its findings are real.

Every way a template ends up unevaluated feeds that refusal, so no failure type
gets a kinder grade than another: the tool wrote no output for it, the tool
reported a failure it could not render (a non-zero exit with an empty result
set), its output does not parse as a report, the template's model was rejected,
the template could not be evaluated (a value in it could not be built), or its
invocation timed out. A timed-out run also keeps the timeout as its recorded
cause; rewriting it as missing output hides why the template has no verdict.

The cells drive :class:`CfnNagScanner` through the executor with the tool's
subprocess call replaced underneath the plugin's own bookkeeping, so the exit
code, a timeout and any spawn failure are recorded as production records them.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
)
from automated_security_helper.utils.normalizers import get_normalized_filename

pytestmark = pytest.mark.unit

RENDERS_TEMPLATE = """Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: placeholder-role
"""

OTHER_TEMPLATE = """Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: placeholder-queue
"""

#: A Resources mapping the template model rejects: a failed target, decided
#: before the tool is invoked.
UNMODELABLE_TEMPLATE = "Resources:\n  Bad:\n    Type: 'invalid type with spaces'\n"

#: A template whose structure is one (a top-level Resources mapping) with a value
#: the YAML loader cannot build, so ASH could not evaluate it.
UNEVALUABLE_TEMPLATE = "Resources:\n  Bad: !!int forty-two\n"


def _cfn_sarif(results) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "cfn_nag", "rules": []}},
                    "results": results,
                }
            ],
        }
    )


_FINDING = {
    "ruleId": "F38",
    "level": "error",
    "message": {"text": "IAM policy allows *"},
    "locations": [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "aaa.yaml"},
                "region": {"startLine": 3},
            }
        }
    ],
}

#: A rendered, clean invocation: a complete document, zero results, exit 0.
CLEAN = {"stdout": _cfn_sarif([]), "stderr": "", "returncode": 0}

#: The subprocess response for a run its tool's timeout killed.
TIMED_OUT = {
    "stdout": "",
    "stderr": "Command timed out after 1 seconds: cfn_nag_scan",
    "returncode": 124,
    "timed_out": True,
    "error": "Command timed out after 1 seconds: cfn_nag_scan",
}

#: The ways one template of several ends up unevaluated: its content, and the
#: subprocess response its invocation gets, or None where the failure is decided
#: before the tool is invoked.
FAILURES = {
    "returned-no-output": (
        OTHER_TEMPLATE,
        {"stdout": "", "stderr": "", "returncode": 1},
    ),
    "reported-but-not-rendered": (
        OTHER_TEMPLATE,
        {"stdout": _cfn_sarif([]), "stderr": "", "returncode": 1},
    ),
    "output-not-a-report": (
        OTHER_TEMPLATE,
        {"stdout": "a line that is not a document", "stderr": "", "returncode": 0},
    ),
    "model-rejected": (UNMODELABLE_TEMPLATE, None),
    "unevaluable-template": (UNEVALUABLE_TEMPLATE, None),
    "timed-out": (OTHER_TEMPLATE, TIMED_OUT),
}


def _context(tmp_path, files) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    for name, text in files.items():
        (source / name).write_text(text, encoding="utf-8")
    output = tmp_path / "out"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=get_default_config(),
    )


def _row(
    context,
    responses,
    monkeypatch,
    names_after_scan=None,
    plain_value=None,
    timeout_after_scan=None,
    raise_after_scan=False,
    plugin_values=(),
):
    """One executor row for a cfn-nag run whose tool answers from *responses*.

    *responses* maps a template's file name to the subprocess response its
    invocation gets. The ``--input-path`` argument names a copy of the template
    under a fixed name (``template`` plus the template's extension) in a results
    directory named after the template, so the template is read off that
    directory's name, as the scanner's own behavior tests read it. The stand-in
    replaces
    ``subprocess_utils.run_command_with_output_handling``, the call under the
    real ``_run_subprocess``, so the plugin's own bookkeeping of a response (the
    exit code, a timeout, a spawn failure, a post-run error) runs as production
    runs it. A command the stand-in cannot match is collected and failed on
    after the run: an assertion raised inside ``scan()`` would be wrapped into
    an ERROR row and read as the refusal under test.

    With *names_after_scan*, the scanner reports those as its unevaluated
    targets once the scan returns, standing in for any scanner that sets the
    attribute. With *plain_value*, the ``unevaluated_targets`` property is
    replaced on the class with that value as it is, standing in for a plugin
    that exposes the attribute in another shape. With *timeout_after_scan*,
    the scanner reports that recorded timeout once the scan returns, with no
    kept flag, standing in for a scanner that cleared its flag or a plugin
    recording the attribute alone - the one shape that reaches the grading
    block's own timeout line instead of the acceptance step's raise. With
    *raise_after_scan*, the scan raises once it has named its targets, so the
    row is the executor's failure path's. *plugin_values* are what the plugin's
    own ``_environment_values()`` gives.
    """
    scanner = CfnNagScanner(context=context, config=CfnNagScannerConfig())
    if plugin_values:
        monkeypatch.setattr(
            CfnNagScanner, "_environment_values", lambda self: tuple(plugin_values)
        )
    if plain_value is not None:
        monkeypatch.setattr(
            CfnNagScanner, "unevaluated_targets", plain_value, raising=False
        )

    unmatched = []
    served = set()

    def template_of(staged: str):
        """The template a staged cfn_nag input was copied from: the copy sits in
        ``<results dir>/<normalized template path>/.ash-cfn-nag-input/``, so its
        directory's name ends with the template's normalized name, after the
        ``_s`` that stands for the separator before it."""
        results_dir = Path(staged).parent.parent.name
        for name in responses:
            normalized = get_normalized_filename(name)
            if results_dir == normalized or results_dir.endswith(f"_s{normalized}"):
                return name
        return None

    def tool(command=None, **kwargs):
        parts = [str(part) for part in command or []]
        if "--input-path" in parts:
            template = template_of(parts[parts.index("--input-path") + 1])
            if template is not None:
                served.add(template)
                return dict(responses[template])
        unmatched.append(" ".join(parts))
        return {"stdout": "", "stderr": "no stand-in response", "returncode": 86}

    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils."
        "run_command_with_output_handling",
        tool,
    )
    with patch.object(
        CfnNagScanner, "validate_plugin_dependencies", autospec=True, return_value=True
    ):
        if names_after_scan is not None or timeout_after_scan is not None:
            original = scanner.scan

            def scan_and_mark(*args, **kwargs):
                report = original(*args, **kwargs)
                if names_after_scan is not None:
                    record = getattr(scanner, "record_unevaluated_target", None)
                    if callable(record):
                        for name in names_after_scan:
                            record(name)
                    else:
                        scanner.unevaluated_targets = list(names_after_scan)
                if timeout_after_scan is not None:
                    scanner._scan_timed_out_after = float(timeout_after_scan)
                    scanner.clear_scan_kept_flag()
                if raise_after_scan:
                    raise RuntimeError("the scan failed after naming its targets")
                return report

            monkeypatch.setattr(scanner, "scan", scan_and_mark)
        executor = ScannerExecutor(
            plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
        )
        (row,) = executor._execute_scanner(
            "cfn-nag", scanner, [{"path": context.source_dir, "type": "source"}]
        )
    assert unmatched == [], unmatched
    # Every prepared response was asked for: a template dropped before its
    # invocation would otherwise pass its cell without exercising the response.
    assert served == set(responses), (served, set(responses))
    return row


def _row_errors(row):
    """Every error the row's readers see: raw_results holds a failed run's
    reasons (unified_metrics.recorded_error reads the first one), and the
    container's own list holds what the grading recorded on a run that
    returned. A cell that pins a recorded cause reads both channels."""
    raw = row.raw_results if isinstance(row.raw_results, dict) else {}
    return [str(error) for error in [*(raw.get("errors") or []), *(row.errors or [])]]


def _unevaluated_errors(row):
    return [
        error for error in _row_errors(row) if "no rule was evaluated against" in error
    ]


def test_a_clean_run_with_no_unevaluated_target_is_passed(tmp_path, monkeypatch):
    """Positive control: without the attribute, a clean run keeps PASSED."""
    context = _context(tmp_path, {"aaa.yaml": RENDERS_TEMPLATE})

    row = _row(context, {"aaa.yaml": CLEAN}, monkeypatch)

    assert row.status == ScannerStatus.PASSED, (row.status, row.errors)
    assert _unevaluated_errors(row) == []


def test_an_unevaluated_target_turns_a_passed_verdict_into_error(tmp_path, monkeypatch):
    """Any scanner that names an unevaluated target after its scan: the row says
    which file has no verdict, and the clean verdict is refused."""
    context = _context(tmp_path, {"aaa.yaml": RENDERS_TEMPLATE})

    row = _row(
        context, {"aaa.yaml": CLEAN}, monkeypatch, names_after_scan=["second.yaml"]
    )

    assert row.status == ScannerStatus.ERROR, (row.status, row.errors)
    assert any("second.yaml" in error for error in _unevaluated_errors(row)), row.errors


def test_unevaluated_targets_given_as_one_string_is_one_name(tmp_path, monkeypatch):
    """A plugin is an arbitrary object: one that exposes its unevaluated targets
    as a plain string, with no recording method behind it, names one target.
    Iterating the string would put one row error per character."""
    context = _context(tmp_path, {"aaa.yaml": RENDERS_TEMPLATE})

    row = _row(context, {"aaa.yaml": CLEAN}, monkeypatch, plain_value="one-name")

    assert row.status != ScannerStatus.PASSED, (row.status, row.errors)
    assert _unevaluated_errors(row) == ["no rule was evaluated against one-name"], (
        row.errors
    )


def test_a_failed_row_keeps_its_status_and_still_names_the_target(
    tmp_path, monkeypatch
):
    """The refusal only replaces PASSED. Real findings keep FAILED, and the
    unevaluated target is still named on the row, whatever the status is."""
    context = _context(tmp_path, {"aaa.yaml": RENDERS_TEMPLATE})
    found = {"stdout": _cfn_sarif([_FINDING]), "stderr": "", "returncode": 1}

    row = _row(
        context, {"aaa.yaml": found}, monkeypatch, names_after_scan=["second.yaml"]
    )

    assert row.status == ScannerStatus.FAILED, (row.status, row.errors)
    assert any("second.yaml" in error for error in _unevaluated_errors(row)), row.errors


@pytest.mark.parametrize("failure", sorted(FAILURES))
def test_an_unevaluated_template_of_any_failure_type_refuses_passed(
    tmp_path, monkeypatch, failure
):
    """One template of two is unevaluated, whatever made it so: the rendered
    template's clean result cannot read PASSED, and the unevaluated one is named
    on the row."""
    template, response = FAILURES[failure]
    context = _context(tmp_path, {"aaa.yaml": RENDERS_TEMPLATE, "bbb.yaml": template})
    responses = {"aaa.yaml": CLEAN}
    if response is not None:
        responses["bbb.yaml"] = response

    row = _row(context, responses, monkeypatch)

    assert row.status != ScannerStatus.PASSED, (row.status, row.errors)
    assert any("bbb.yaml" in error for error in _unevaluated_errors(row)), row.errors


def test_a_timed_out_templates_cause_survives_another_rendering(tmp_path, monkeypatch):
    """The timed-out run's recorded cause is the timeout, also when another
    template rendered: a tool its timeout killed has no verdict that can be
    graded, so the row is ERROR, carries the cause, and still names the template
    nothing was evaluated against."""
    context = _context(
        tmp_path, {"aaa.yaml": RENDERS_TEMPLATE, "bbb.yaml": OTHER_TEMPLATE}
    )

    row = _row(context, {"aaa.yaml": CLEAN, "bbb.yaml": TIMED_OUT}, monkeypatch)

    assert row.status == ScannerStatus.ERROR, (row.status, _row_errors(row))
    assert any(
        "timed out after" in error and "and was killed" in error
        for error in _row_errors(row)
    ), _row_errors(row)
    assert any("bbb.yaml" in error for error in _unevaluated_errors(row)), _row_errors(
        row
    )
    # The recorded cause stays the timeout: a killed tool's empty stdout is not
    # rewritten as the tool having produced no output for the template.
    assert not any(
        "produced no output" in error and "bbb.yaml" in error
        for error in _row_errors(row)
    ), _row_errors(row)


def test_a_recorded_timeout_without_a_kept_flag_carries_the_quoted_limit(
    tmp_path, monkeypatch
):
    """The grading block's own timeout line: it runs when scan() returns
    normally with a recorded timeout and no kept flag (a scanner that cleared
    its flag, or a third-party plugin recording the attribute alone; for a
    PluginBase scanner that keeps its flag, the acceptance step's raise runs
    first and the exception path words the cause instead). The limit goes
    through the one token every timeout message prints its limit with
    (timeout_limit_token; the redaction reasoning is its docstring). The
    exception path writes a line with the same "on {target} and was killed"
    words, so what tells the two apart is asserted, not assumed: the block
    writes the container's own error channel, where the exception path
    records its line in raw_results, and the block's line ENDS at "and was
    killed", where the exception path's continues with the exception text."""
    context = _context(tmp_path, {"aaa.yaml": RENDERS_TEMPLATE})

    row = _row(context, {"aaa.yaml": CLEAN}, monkeypatch, timeout_after_scan=67)

    assert row.status == ScannerStatus.ERROR, (row.status, _row_errors(row))
    # The container channel only: row.errors is container.add_error's list,
    # which the grading block writes; the exception path's raw_results stream
    # is deliberately not read here.
    killed = [
        str(error) for error in row.errors if "on source and was killed" in str(error)
    ]
    assert killed, _row_errors(row)
    for line in killed:
        assert line.endswith("on source and was killed"), line
        assert "timed out after '67' s on source and was killed" in line, line
        assert "67.0" not in line, line
    raw = row.raw_results if isinstance(row.raw_results, dict) else {}
    assert not any(
        "on source and was killed" in str(error) for error in raw.get("errors") or []
    ), raw.get("errors")


def test_an_unevaluated_target_with_no_attempts_refuses_a_skipped_verdict(
    tmp_path, monkeypatch
):
    """A plugin that names an unevaluated target while it attempted nothing:
    SKIPPED would read as "nothing here to scan" (and the completeness gate
    counts a SKIPPED row complete) while the same row names a file with no
    verdict. The refusal covers SKIPPED as it covers PASSED, and the
    skipped_reason that would contradict the error is never written."""
    context = _context(tmp_path, {})

    row = _row(context, {}, monkeypatch, names_after_scan=["second.yaml"])

    assert row.status == ScannerStatus.ERROR, (row.status, _row_errors(row))
    assert any("second.yaml" in error for error in _unevaluated_errors(row)), (
        _row_errors(row)
    )
    assert row.skipped_reason is None, row.skipped_reason


#: A value the plugin's own ``_environment_values()`` names, in a target's path.
_CANARY = "ENVCANARY-unevaluated-0123456789"


@pytest.mark.parametrize("ending", ["returns", "raises"])
def test_an_unevaluated_target_s_name_is_redacted_on_the_row(
    tmp_path, monkeypatch, ending
):
    """The target's name is the plugin's own text, and a path in it can hold a
    value the config read from the environment. Both lines that name it, on the
    row of a scan that returned and in the failed run's errors, are redacted
    with the plugin's values as the timeout line beside them is, before the
    home directory is written as a tilde. The control: the line still names the
    target, with the value replaced."""
    context = _context(tmp_path, {"aaa.yaml": RENDERS_TEMPLATE})

    row = _row(
        context,
        {"aaa.yaml": CLEAN},
        monkeypatch,
        names_after_scan=[f"/srv/{_CANARY}/second.yaml"],
        raise_after_scan=ending == "raises",
        plugin_values=(_CANARY,),
    )

    lines = _unevaluated_errors(row)
    assert lines, _row_errors(row)
    assert all("second.yaml" in line for line in lines), lines
    assert not any(_CANARY in error for error in _row_errors(row)), _row_errors(row)
