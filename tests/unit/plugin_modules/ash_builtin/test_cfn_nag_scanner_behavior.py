"""Behavior tests for :class:`CfnNagScanner`.

cfn_nag is a Ruby tool and is not installed here, so
``validate_plugin_dependencies()`` returns False and the scanner short-circuits
before it ever walks the scan set. Every test below patches exactly two seams
-- the dependency probe and ``_run_subprocess`` -- and drives the real scan
body over real files on disk.

``_run_subprocess`` is patched with ``autospec=True`` so a call that passes an
argument the real method does not accept fails the test instead of being
absorbed by a permissive double.

The central risk in this module is a scan that completes having parsed nothing:
cfn_nag writing no stdout, or a SARIF parse failure, both leave the report with
zero results and read as a clean template. ``test_findings_from_stdout_are_
merged_into_the_report`` pins the positive direction (non-empty tool output ->
non-empty findings) and the empty/garbage-stdout tests pin the negative one
without letting it masquerade as a pass.
"""

import json
import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import exit_status

pytestmark = pytest.mark.unit

CFN_TEMPLATE = """Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: placeholder-role
"""

SECOND_CFN_TEMPLATE = """Resources:
  MyQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: placeholder-queue
"""

NON_CFN_YAML = "services:\n  web:\n    image: nginx\n"

MALFORMED_YAML = "Resources:\n  - this: [is\n   not: valid yaml\n"

# A Resources mapping this repository's pydantic model cannot represent. It is
# CloudFormation -- the Resources key holds a mapping -- so it is a failed target
# rather than the not-a-template skip.
UNMODELABLE_CFN = "Resources:\n  Bad:\n    Type: 'invalid type with spaces'\n"


def cfn_nag_sarif(rule_id="F38", uri="MyRole.yaml", start_line=3):
    """A SARIF document shaped the way cfn_nag emits one."""
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "cfn_nag",
                            "rules": [
                                {
                                    "id": rule_id,
                                    "shortDescription": {
                                        "text": "IAM policy should not allow *"
                                    },
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": "error",
                            "message": {"text": f"{rule_id} triggered on {uri}"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": start_line},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


def cfn_nag_sarif_no_results():
    """A SARIF document shaped the way cfn_nag emits one for an unevaluated template.

    This is the exact shape measured from ``cfn_nag_scan --output-format sarif`` on a
    template carrying a ``!Ref`` to an undeclared logical id: a complete document, a
    fully populated rule driver, and an empty result array. It is byte-for-byte the
    same size as the document a genuinely clean template produces, which is why the
    exit code is the only thing that can tell them apart. Reproduce with::

        cfn_nag_scan --print-suppression --output-format sarif --input-path <template>
    """
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "cfn_nag",
                            "rules": [
                                {"id": "F38", "shortDescription": {"text": "a rule"}},
                                {"id": "W48", "shortDescription": {"text": "another"}},
                            ],
                        }
                    },
                    "results": [],
                }
            ],
        }
    )


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
    return CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig())


@pytest.fixture
def deps_available():
    """Report the Ruby cfn_nag binary as present without installing it."""
    with patch.object(
        CfnNagScanner, "validate_plugin_dependencies", autospec=True, return_value=True
    ) as probe:
        yield probe


@pytest.fixture
def subprocess_double():
    """Patch the subprocess boundary, preserving the real signature."""
    with patch.object(CfnNagScanner, "_run_subprocess", autospec=True) as double:
        double.return_value = {"stdout": "", "stderr": "", "returncode": 0}
        yield double


def stdout_sequence(*payloads):
    """Return a side_effect that yields one payload per subprocess call."""
    remaining = list(payloads)

    def _side_effect(self, **kwargs):
        return {
            "stdout": remaining.pop(0) if remaining else "",
            "stderr": "",
            "returncode": 0,
        }

    return _side_effect


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_scanner_configures_its_command_and_tool_type(scanner):
    """model_post_init wires the Ruby entrypoint and the IAC tool type."""
    assert scanner.command == "cfn_nag_scan"
    assert scanner.tool_type == ScannerToolType.IAC
    assert scanner.args.format_arg == "--output-format"
    assert scanner.args.format_arg_value == "sarif"
    assert scanner.args.scan_path_arg == "--input-path"

    keys = [arg.key for arg in scanner.args.extra_args]
    assert "--print-suppression" in keys
    assert "--rule-directory" in keys
    rule_dir = next(a for a in scanner.args.extra_args if a.key == "--rule-directory")
    assert rule_dir.value.endswith("appsec_cfn_rules")


def test_ignore_fatal_is_not_passed(scanner):
    """``--ignore-fatal`` must be absent, and its absence is the whole signal.

    The inverse of this assertion used to stand here. cfn_nag's exit status is its
    failing-violation count, and a FATAL violation -- what cfn-model raises for an
    unresolved Ref or GetAtt -- carries no logical resource ids, so SARIF renders
    it as nothing at all. ``--ignore-fatal`` additionally prunes it from the
    failure count, which drops the exit status to 0 and leaves a document
    indistinguishable from a clean template. Measured on both shapes with::

        cfn_nag_scan --print-suppression [--ignore-fatal] \
            --output-format sarif --input-path <template>

    With the flag, an unresolved-Ref template and a clean template both give exit 0
    and zero results. Without it, the unresolved-Ref template gives exit 1 and zero
    results while the clean one gives exit 0, so the pair is separable.
    """
    keys = [arg.key for arg in scanner.args.extra_args]
    assert "--ignore-fatal" not in keys, (
        "passing --ignore-fatal erases the only signal that distinguishes a "
        f"template cfn_nag could not parse from a clean one; keys were {keys}"
    )


def test_custom_rule_exceptions_are_isolated(scanner):
    """A raising custom rule must cost that rule, not the template's whole scan.

    cfn_nag's CustomRuleLoader re-raises a rule's exception unless this flag is
    passed, and the exception escapes every rescue clause above it, so the process
    dies before rendering any output. The blast radius is every rule's verdict on
    that template, not just the broken rule's.
    """
    keys = [arg.key for arg in scanner.args.extra_args]
    assert "--isolate-custom-rule-exceptions" in keys, (
        f"a defect in one shipped rule must not destroy the scan; keys were {keys}"
    )


@pytest.mark.parametrize("level", [logging.DEBUG, logging.INFO, logging.WARNING])
def test_no_log_level_flag_is_passed_to_cfn_nag(plugin_context, monkeypatch, level):
    """No ``--verbose`` (or ``--debug``) at any ASH log level, DEBUG included.

    cfn_nag_scan defines no ``--verbose`` option, so passing it at DEBUG made
    every invocation exit 255 with no stdout and the whole scan fail as "no
    output". Its ``--debug`` writes to stdout, which is parsed as SARIF, so it
    is not passed either.
    """
    monkeypatch.setattr(ASH_LOGGER, "level", level)

    scanner = CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig())
    keys = [arg.key for arg in scanner.args.extra_args]

    assert "--verbose" not in keys, (
        f"at level {logging.getLevelName(level)} cfn_nag_scan would be given "
        f"--verbose, which it does not define; extra_args keys were {keys}"
    )
    assert "--debug" not in keys, keys


def test_config_defaults_are_applied_when_config_is_none(plugin_context):
    """A scanner built without a config gets the cfn-nag default config."""
    scanner = CfnNagScanner(context=plugin_context)

    assert scanner.config is not None
    assert scanner.config.name == "cfn-nag"
    assert scanner.config.enabled is True


def test_execute_scan_stub_raises_not_implemented(scanner):
    """The abstract hook is unreachable because scan() is overridden."""
    with pytest.raises(NotImplementedError, match="overrides scan"):
        scanner._execute_scan(
            target=scanner.context.source_dir,
            target_type="source",
            global_ignore_paths=[],
        )


# ---------------------------------------------------------------------------
# Early exits
# ---------------------------------------------------------------------------


def test_missing_target_directory_returns_an_empty_report(
    scanner, deps_available, subprocess_double, tmp_path
):
    """A target that does not exist yields an empty report, not an exception.

    The report skeleton is built first and passes the target through
    get_shortest_name; a missing path now comes back as text, so
    ArtifactLocation.uri validates and scan() reaches its own "target is empty
    or doesn't exist" branch. This was an expected failure while
    get_shortest_name handed a missing Path back unchanged.
    """
    report = scanner.scan(target=tmp_path / "does-not-exist", target_type="converted")

    assert report.runs[0].results == []
    subprocess_double.assert_not_called()


def test_get_shortest_name_answers_in_text_for_a_missing_path():
    """The early return for a missing path is text, like the resolved return.

    Callers feed the result into pydantic str fields (ArtifactLocation.uri), so
    a missing path that came back as a Path failed validation where an existing
    one passed; both are str now.
    """
    from automated_security_helper.utils.get_shortest_name import get_shortest_name

    existing = get_shortest_name(input=Path.cwd())
    assert isinstance(existing, str)

    missing = get_shortest_name(input=Path.cwd() / "no-such-file-exists-here")
    assert isinstance(missing, str)


def test_empty_target_directory_returns_an_empty_report(
    scanner, deps_available, subprocess_double
):
    """An existing but empty target directory is skipped before _pre_scan."""
    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert report.runs[0].tool.driver.name == "cfn_nag"
    subprocess_double.assert_not_called()
    # The skip is announced on stderr so the run summary can show it.
    assert any("empty or doesn't exist" in err for err in scanner.errors)


def test_unsatisfied_dependencies_returns_false(scanner, subprocess_double):
    """With the Ruby binary absent the scanner reports False, not a report.

    False is how the executor distinguishes "skipped" from "scanned clean";
    returning an empty report here would publish a clean result for a scanner
    that never ran.
    """
    (scanner.context.work_dir / "template.yaml").write_text(CFN_TEMPLATE)

    with patch.object(
        CfnNagScanner,
        "validate_plugin_dependencies",
        autospec=True,
        return_value=False,
    ):
        result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is False
    subprocess_double.assert_not_called()


def test_dependency_flag_is_rechecked_after_pre_scan(scanner, subprocess_double):
    """The post-_pre_scan dependency guard also returns False.

    _pre_scan normally returns False when dependencies are missing; this
    covers the independent second check, which is what protects against a
    _pre_scan override that forgets to set the flag.
    """
    (scanner.context.work_dir / "template.yaml").write_text(CFN_TEMPLATE)

    with patch.object(CfnNagScanner, "_pre_scan", autospec=True, return_value=True):
        scanner.dependencies_satisfied = False
        result = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert result is False
    subprocess_double.assert_not_called()


def test_target_with_no_yaml_or_json_files_returns_an_empty_report(
    scanner, deps_available, subprocess_double
):
    """Files that cannot be CloudFormation are filtered before any subprocess."""
    (scanner.context.work_dir / "notes.txt").write_text("nothing to scan here")
    (scanner.context.work_dir / "script.py").write_text("print('hello')\n")

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    subprocess_double.assert_not_called()
    assert any("No JSON/YAML files found" in err for err in scanner.errors)


# ---------------------------------------------------------------------------
# The scan body
# ---------------------------------------------------------------------------


def test_findings_from_stdout_are_merged_into_the_report(
    scanner, deps_available, subprocess_double
):
    """Non-empty cfn_nag output produces non-empty findings.

    This is the assertion that separates "scanned and found nothing" from
    "parsed nothing and reported clean".
    """
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif(rule_id="F38"))

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert subprocess_double.call_count == 1
    results = report.runs[0].results
    assert len(results) == 1, (
        f"expected the one cfn_nag result to survive the merge, got {len(results)}"
    )
    assert results[0].ruleId == "F38"
    assert "F38 triggered on" in results[0].message.root.text


def test_every_template_is_scanned_and_all_findings_survive(
    scanner, deps_available, subprocess_double
):
    """Two templates mean two subprocess calls and two merged findings."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.json").write_text(
        json.dumps({"Resources": {"MyQueue": {"Type": "AWS::SQS::Queue"}}})
    )
    subprocess_double.side_effect = stdout_sequence(
        cfn_nag_sarif(rule_id="F38", uri="role.yaml"),
        cfn_nag_sarif(rule_id="W48", uri="queue.json"),
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert subprocess_double.call_count == 2
    rule_ids = sorted(r.ruleId for r in report.runs[0].results)
    assert rule_ids == ["F38", "W48"], (
        f"a finding was dropped during the merge; got {rule_ids}"
    )


def test_each_template_is_passed_to_the_subprocess_as_the_input_path(
    scanner, deps_available, subprocess_double
):
    """The resolved argv names one template, not the containing directory.

    The path is a copy of the text ASH read and checked, kept under the template's
    results directory under a fixed name with the template's extension, and removed
    afterwards; see ``_stage_cfn_nag_input``.
    """
    template = scanner.context.work_dir / "role.yaml"
    template.write_text(CFN_TEMPLATE)
    given = []

    def run(self, **kwargs):
        command = kwargs["command"]
        staged = Path(command[command.index("--input-path") + 1])
        given.append((staged, staged.read_text()))
        return {"stdout": cfn_nag_sarif(), "stderr": "", "returncode": 0}

    subprocess_double.side_effect = run

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    command = subprocess_double.call_args.kwargs["command"]
    assert command[0] == "cfn_nag_scan"
    assert "--input-path" in command
    ((staged, text),) = given
    assert staged.name == "template.yaml"
    assert staged != template
    assert text == CFN_TEMPLATE
    assert not staged.exists(), "the copy is removed once cfn_nag_scan has run"
    assert "--output-format" in command
    assert command[command.index("--output-format") + 1] == "sarif"


def test_non_cloudformation_yaml_is_not_sent_to_the_scanner(
    scanner, deps_available, subprocess_double
):
    """A YAML file with no Resources block is filtered out, not scanned."""
    (scanner.context.work_dir / "compose.yaml").write_text(NON_CFN_YAML)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    subprocess_double.assert_not_called()
    assert report.runs[0].results == []


def test_unparseable_yaml_is_skipped_without_failing_the_scan(
    scanner, deps_available, subprocess_double
):
    """A YAML syntax error in one candidate file does not abort the others."""
    (scanner.context.work_dir / "broken.yaml").write_text(MALFORMED_YAML)
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif(rule_id="F38"))

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    # Only the valid template reached the scanner.
    assert subprocess_double.call_count == 1
    assert [r.ruleId for r in report.runs[0].results] == ["F38"]


def test_empty_stdout_is_a_hard_scanner_failure(
    scanner, deps_available, subprocess_double, caplog
):
    """cfn_nag writing nothing for the only template fails the scan itself.

    This test's predecessor asserted the opposite -- that the scan returned a report
    and raised nothing -- and that is the behavior being corrected: an invocation
    that renders zero bytes did not find nothing, it failed to run. With the only
    attempted template unrendered, nothing at all was evaluated, so the scan raises
    as a whole-run failure. One unrendered template among rendered ones is the
    partial case: the scan returns, the rendered findings are kept, and the
    executor refuses a PASSED verdict over the recorded name
    (test_one_empty_stdout_among_two_templates_is_named_unevaluated below).

    The subprocess is still invoked -- the emptiness is in its output, which is
    exactly the case that must not silently become a passing scan.
    """
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {"stdout": "   ", "stderr": "", "returncode": 0}

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert subprocess_double.call_count == 1
    assert "role.yaml" in str(excinfo.value)
    assert any("returned no stdout" in record.message for record in caplog.records), (
        "an empty-stdout scan must leave a trace in the log"
    )


def test_non_sarif_stdout_is_warned_about_and_skipped(
    scanner, deps_available, subprocess_double, caplog
):
    """Output that is not SARIF is logged as a parse failure."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": "Fatal error: could not load rule directory",
        "stderr": "",
        "returncode": 1,
    }

    with caplog.at_level(logging.WARNING):
        report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert any(
        "Failed to parse CFN Nag results as SARIF" in record.message
        for record in caplog.records
    ), f"expected a parse warning; got {[r.message for r in caplog.records]}"


def test_partial_failure_keeps_the_findings_that_did_parse(
    scanner, deps_available, subprocess_double
):
    """One unparseable template does not discard another's findings."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(SECOND_CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(
        "not json at all", cfn_nag_sarif(rule_id="W48", uri="queue.yaml")
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["W48"]


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------


def test_sarif_output_file_is_written_next_to_the_results(
    scanner, deps_available, subprocess_double
):
    """The merged report is persisted to ``cfn_nag.sarif`` under results_dir."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif(rule_id="F38"))

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    output_file = Path(scanner.results_dir) / "converted" / "cfn_nag.sarif"
    assert output_file.is_file(), f"{output_file} was not written"
    written = json.loads(output_file.read_text(encoding="utf-8"))
    rule_ids = [r["ruleId"] for r in written["runs"][0]["results"]]
    assert rule_ids == ["F38"], (
        f"the persisted file must contain the findings, not an empty run; got {written}"
    )


def test_invocation_replaces_the_placeholder_and_records_the_exit_code(
    scanner, deps_available, subprocess_double
):
    """The final report carries exactly one invocation describing the ASH run."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif())

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    invocations = report.runs[0].invocations
    assert len(invocations) == 1
    invocation = invocations[0]
    assert invocation.commandLine == "ash-CFN Nag-scanner"
    assert "--target" in invocation.arguments
    assert invocation.exitCode == scanner.exit_code
    assert invocation.executionSuccessful is True
    assert invocation.startTimeUtc is not None
    assert invocation.endTimeUtc is not None


@pytest.mark.parametrize(
    "exit_code, successful",
    [
        (0, True),
        (1, True),
        (2, True),
        (137, True),
        (127, True),
        pytest.param(
            -9,
            False,
            marks=pytest.mark.skipif(
                os.name == "nt",
                reason="Windows has no signal deaths: signal_ending reads a negative "
                "code as a signal on POSIX only",
            ),
        ),
    ],
)
def test_execution_successful_treats_zero_and_one_as_success(
    scanner, deps_available, subprocess_double, exit_code, successful
):
    """cfn_nag's exit status is its count of failing violations, so any
    non-negative count from a run that rendered results is a success. This
    cell previously pinned (2, False) and (137, False) from the base
    {0, 1} set; both runs here rendered results and evaluated their target,
    so the count is findings, not failure -- 137 included, because through
    ``_run_subprocess`` a signal death arrives as a NEGATIVE code, never as
    128+N, and 127 included, because cfn_nag returns that number for 127
    (mod 256) failing violations: whether the tool ran at all is read from the
    recorded spawn failure, not from the code (see
    ``test_a_clean_run_whose_code_counts_violations_is_successful``). A negative
    code is no count: the plugin keeps a signal death as the run's cause, which
    is read before any count, and records its code as the shell reports it
    (``exit_status``, 128+N), so the recorded 137 of a SIGKILL is never a count
    either.

    The code arrives the way the real ``_run_subprocess`` delivers it, through
    ``_process_command_response``: scan() starts each target with no exit code, so
    one set on the plugin beforehand is not cfn_nag's.
    """
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)

    def run(self, **kwargs):
        # The code is recorded as the real _run_subprocess records it.
        response = {"stdout": cfn_nag_sarif(), "stderr": "", "returncode": exit_code}
        self._process_command_response(response)
        return response

    subprocess_double.side_effect = run

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    invocation = report.runs[0].invocations[0]
    assert invocation.executionSuccessful is successful
    # A signal death is recorded as the shell reports it; every other code as given.
    recorded = exit_status(exit_code) if exit_code < 0 else exit_code
    assert invocation.exitCode == recorded


# ---------------------------------------------------------------------------
# Failure wrapping
# ---------------------------------------------------------------------------


def test_subprocess_failure_is_wrapped_in_scanner_error(
    scanner, deps_available, subprocess_double
):
    """An unexpected error inside the scan body surfaces as ScannerError."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = OSError("cfn_nag_scan died")

    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert "CfnNagScanner failed" in str(excinfo.value)
    assert "cfn_nag_scan died" in str(excinfo.value)


# ---------------------------------------------------------------------------
# source vs converted target selection
# ---------------------------------------------------------------------------


def test_source_target_type_scans_the_source_tree(
    scanner, deps_available, subprocess_double
):
    """A ``source`` scan enumerates the source dir, not the work dir.

    The two branches build the candidate list differently, so a template that
    exists only in work_dir must not be picked up by a source scan.
    """
    (scanner.context.source_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "should-not-be-scanned.yaml").write_text(
        SECOND_CFN_TEMPLATE
    )
    subprocess_double.side_effect = stdout_sequence(
        cfn_nag_sarif(rule_id="F38", uri="role.yaml")
    )

    report = scanner.scan(target=scanner.context.source_dir, target_type="source")

    scanned = [
        call.kwargs["command"][call.kwargs["command"].index("--input-path") + 1]
        for call in subprocess_double.call_args_list
    ]
    # The copy cfn_nag reads has a fixed name; the directory it sits in is named
    # after the template.
    assert any("role__yaml" in path for path in scanned), (
        f"the source template was never scanned; scanned={scanned}"
    )
    assert not any("should-not-be-scanned" in path for path in scanned), (
        f"a work_dir template leaked into a source scan; scanned={scanned}"
    )
    assert [r.ruleId for r in report.runs[0].results] == ["F38"]


# ---------------------------------------------------------------------------
# Failed targets
#
# cfn_nag failing on a template produces the same empty report as a template with
# nothing wrong in it. The only thing that separates them is the target counters the
# executor reads off the plugin, so these assert the counters rather than the report.
# ---------------------------------------------------------------------------


def _status_for(scanner_plugin):
    """Run the two executor lines that copy the counters, then compute status."""
    from automated_security_helper.core.phases.scanner_executor import (
        _non_negative_int_attr,
        _target_count_attr,
    )
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )

    container = ScanResultsContainer(scanner_name="cfn-nag")
    container.targets_attempted = _target_count_attr(
        scanner_plugin, "targets_attempted"
    )
    container.targets_failed = _non_negative_int_attr(scanner_plugin, "targets_failed")
    return container.determine_status("MEDIUM"), container


def test_empty_stdout_is_recorded_as_a_failed_target_and_then_raises(
    scanner, deps_available, subprocess_double, caplog
):
    """cfn_nag producing nothing must not resolve to a passing scan.

    The counter assertions are the ones this test always made and they still hold.
    What changed is the tail: with its only template unrendered, every attempted
    template is in this state, so the scan raises as a whole-run failure. The
    counters are still set so the failure is also visible to
    ``--fail-on-incomplete-scanners``, which reads ``targets_failed``. A partial
    run returns instead and is refused through ``unevaluated_targets``.
    """
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {"stdout": "   ", "stderr": "", "returncode": 1}

    with caplog.at_level(logging.ERROR):
        with pytest.raises(ScannerError):
            scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1
    assert any("role.yaml" in err for err in scanner.errors), scanner.errors
    assert any("NOT a clean scan" in record.message for record in caplog.records), (
        f"a run that evaluated no rule must say so; got {[r.message for r in caplog.records]}"
    )

    status, container = _status_for(scanner)
    assert not container.scan_succeeded
    assert status == ScannerStatus.ERROR


def test_one_empty_stdout_among_two_templates_is_named_unevaluated(
    scanner, deps_available, subprocess_double
):
    """The case the counters alone cannot reach.

    One unrendered template of two is a property of that template, not of the
    tool, so the scan returns rather than raising, and the rendered template's
    findings are kept; raising here threw them away with the verdict. The run is
    still not a clean one: the unrendered template is recorded on
    ``unevaluated_targets`` and in ``errors``, which the executor reads off the
    plugin to name the template on the results row and to refuse a PASSED
    verdict over it (test_scanners_name_a_file_that_is_not_utf8.py's
    test_cfn_nag_keeps_the_other_templates_findings drives that path end to
    end). The counters now read the run fail-closed too -- one failed target
    of two is not a succeeded scan -- and the executor's refusal is still what
    NAMES the unevaluated template, which a counter cannot.
    """
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(SECOND_CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(
        cfn_nag_sarif(rule_id="F38", uri="role.yaml"), ""
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    # The rendered template's findings survive the other template's failure.
    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    # Both templates were attempted; only the unrendered one failed, which is
    # precisely the ratio that used to read as a successful scan.
    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 1)
    # Exactly one of the two is unevaluated (whichever the walk reached second),
    # and it is named in the errors the results row carries.
    (unrendered,) = scanner.unevaluated_targets
    assert Path(unrendered).name in {"role.yaml", "queue.yaml"}, unrendered
    assert any(unrendered in err for err in scanner.errors), scanner.errors
    assert not _status_for(scanner)[1].scan_succeeded, (
        "the counters read a partial failure fail-closed; the executor's refusal "
        "over unevaluated_targets still names the template the counters cannot"
    )


def test_a_template_the_model_rejects_is_counted_as_a_failed_target(
    scanner, deps_available, subprocess_double, caplog
):
    """A Resources mapping ASH cannot model is a failure, not an un-counted skip.

    Before the sentinel was split, ``get_model_from_template`` answered None for
    this file just as it does for a file that is not CloudFormation, and the
    ``continue`` sat above ``targets_attempted += 1``. A scan set in which every
    template tripped the model therefore ended at zero attempts, which the
    container reports as SKIPPED with exit code 0 -- and SKIPPED is on the
    completeness allowlist on the grounds that the scanner was not selected, which
    is not what happened.
    """
    (scanner.context.work_dir / "unmodelable.yaml").write_text(UNMODELABLE_CFN)

    with caplog.at_level(logging.ERROR):
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    subprocess_double.assert_not_called()
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1)
    assert any("unmodelable.yaml" in err for err in scanner.errors), scanner.errors
    assert _status_for(scanner)[0] == ScannerStatus.ERROR


@pytest.mark.skipif(not hasattr(os, "link"), reason="no hard links")
def test_a_hard_linked_template_is_scanned(
    scanner, deps_available, subprocess_double, tmp_path
):
    """A template whose other name is outside the tree is still the tree's bytes.

    The scanned-tree rule refused a file with a second hard link, and this scanner
    took the refusal as the not-CloudFormation skip: no finding, no error, no
    failed target, so a repository that hard-links its templates was reported
    clean. The template read now admits a hard-linked regular file (a symlink
    stays refused), and the template is checked and scanned like any other.
    """
    elsewhere = tmp_path / "elsewhere" / "role.yaml"
    elsewhere.parent.mkdir()
    elsewhere.write_text(CFN_TEMPLATE)
    try:
        os.link(elsewhere, scanner.context.work_dir / "role.yaml")
    except OSError as exc:  # pragma: no cover - filesystem without hard links
        pytest.skip(f"cannot create a hard link here: {exc}")
    subprocess_double.side_effect = stdout_sequence(
        cfn_nag_sarif(rule_id="F38", uri="role.yaml")
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert subprocess_double.call_count == 1, "the hard-linked template was skipped"
    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0)
    assert not any("Skipped" in err for err in scanner.errors), scanner.errors


def test_a_non_zero_exit_with_no_results_is_a_failed_target(
    scanner, deps_available, subprocess_double, caplog
):
    """The pruned-FATAL shape: schema-valid SARIF, zero results, non-zero exit.

    cfn-model raises on a ``!Ref`` or ``!GetAtt`` to a logical id not declared in
    the file, cfn_nag turns that into a FATAL violation, and a FATAL violation
    carries no logical resource ids -- so the SARIF renderer, which iterates those
    ids, emits nothing for it. The document is complete and its rule driver is fully
    populated. No rule ran against the template, and without this guard the run is
    indistinguishable from a compliant one.
    """
    (scanner.context.work_dir / "badref.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": cfn_nag_sarif_no_results(),
        "stderr": "",
        "returncode": 1,
    }

    with caplog.at_level(logging.ERROR):
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1)
    assert any("badref.yaml" in err for err in scanner.errors), scanner.errors
    assert _status_for(scanner)[0] == ScannerStatus.ERROR


def test_a_clean_template_with_no_results_is_not_a_failed_target(
    scanner, deps_available, subprocess_double
):
    """Positive control for the guard above: the same empty SARIF at exit 0 passes.

    Without this the guard could be satisfied by rejecting every zero-result run,
    which would fail every compliant template in existence. Measured: a compliant
    template and an unresolved-Ref template produce SARIF documents of identical
    size with zero results each, and differ only in the exit status.
    """
    (scanner.context.work_dir / "clean.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": cfn_nag_sarif_no_results(),
        "stderr": "",
        "returncode": 0,
    }

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0)
    assert _status_for(scanner)[1].scan_succeeded


def test_unparseable_stdout_is_recorded_as_a_failed_target(
    scanner, deps_available, subprocess_double
):
    """Output that is not SARIF leaves the template unevaluated, same as no output."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.return_value = {
        "stdout": "Fatal error: could not load rule directory",
        "stderr": "",
        "returncode": 1,
    }

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1)
    assert _status_for(scanner)[0] == ScannerStatus.ERROR


def test_a_template_that_scanned_is_not_counted_as_failed(
    scanner, deps_available, subprocess_double
):
    """Positive control: the same path with usable output records no failure."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif(rule_id="F38"))

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["F38"]
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 0)
    assert _status_for(scanner)[1].scan_succeeded


def test_one_failure_among_two_templates_fails_the_run(
    scanner, deps_available, subprocess_double
):
    """A partial failure fails the run: the failed template was never
    evaluated, so a clean sibling does not make the scan a success. An earlier
    revision of this cell pinned the opposite as the then-current behavior;
    the fail-closed rule has since been decided."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(SECOND_CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(
        "not json at all", cfn_nag_sarif(rule_id="W48", uri="queue.yaml")
    )

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 1)
    assert not _status_for(scanner)[1].scan_succeeded


def test_non_cloudformation_yaml_is_not_counted_as_a_target(
    scanner, deps_available, subprocess_double
):
    """A YAML file that is not a template is a skip, not an attempt or a failure."""
    (scanner.context.work_dir / "compose.yaml").write_text(NON_CFN_YAML)

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    subprocess_double.assert_not_called()
    assert (scanner.targets_attempted, scanner.targets_failed) == (0, 0)
    assert _status_for(scanner)[1].scan_succeeded


def test_execution_successful_is_false_when_a_template_was_not_evaluated(
    scanner, deps_available, subprocess_double
):
    """SARIF executionSuccessful follows the graded rule, not the exit code:
    one unrendered template beside a clean one grades ERROR, so the report
    cannot claim the execution succeeded about the same run."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(SECOND_CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif(), "")

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 1)
    assert not _status_for(scanner)[1].scan_succeeded
    assert report.runs[0].invocations[0].executionSuccessful is False


def test_execution_successful_is_false_when_no_accepted_run_produced_a_code(
    scanner, deps_available, subprocess_double
):
    """Every template rejected by the model: the tool never ran, the exit
    code is None, and a codeless run with attempted targets is not a
    successful execution."""
    (scanner.context.work_dir / "bad.yaml").write_text(UNMODELABLE_CFN)

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    subprocess_double.assert_not_called()
    assert scanner.exit_code is None
    assert (scanner.targets_attempted, scanner.targets_failed) == (1, 1)
    assert not _status_for(scanner)[1].scan_succeeded
    assert report.runs[0].invocations[0].executionSuccessful is False


def test_execution_successful_keep_sides_clean_run_and_nothing_attempted(
    scanner, deps_available, subprocess_double
):
    """The keep sides of the rule: two clean templates stay True (whatever
    aggregate exit code the run recorded), and attempted-nothing stays True
    (a completed execution with nothing to do). The drop sides directly: a
    failed target marks the run unsuccessful even beside an accepted exit
    code, and a miscounted scan (negative attempted) never says success."""
    (scanner.context.work_dir / "role.yaml").write_text(CFN_TEMPLATE)
    (scanner.context.work_dir / "queue.yaml").write_text(SECOND_CFN_TEMPLATE)
    subprocess_double.side_effect = stdout_sequence(cfn_nag_sarif(), cfn_nag_sarif())

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert (scanner.targets_attempted, scanner.targets_failed) == (2, 0)
    assert report.runs[0].invocations[0].executionSuccessful is True

    scanner.targets_attempted = 1
    scanner.targets_failed = 1
    scanner.exit_code = 0
    assert scanner._sarif_execution_successful() is False
    scanner.targets_attempted = -1
    scanner.targets_failed = 0
    assert scanner._sarif_execution_successful() is False
    scanner.targets_attempted = 0
    assert scanner._sarif_execution_successful() is True


def test_a_clean_run_whose_code_counts_violations_is_successful(scanner):
    """cfn_nag's exit status is its count of failing violations
    (_evaluated_no_rule's rule), so a run that evaluated every attempted
    target and found two is a successful execution -- the count is findings,
    not failure (the base accepted set {0, 1} graded it False).
    A recorded spawn failure and a signal death still are not: neither is
    a count cfn_nag returned. The spawn-failure marker's VALUE alone is a
    count, though: cfn_nag returns the same number for 127 (mod 256) failing
    violations, so whether the tool ran is read from the recorded spawn
    failure, never from the code."""
    from automated_security_helper.utils.subprocess_utils import (
        SPAWN_FAILURE_RETURNCODE,
    )

    scanner.targets_attempted = 2
    scanner.targets_failed = 0
    scanner.exit_code = 2
    assert scanner._sarif_execution_successful() is True
    scanner.exit_code = SPAWN_FAILURE_RETURNCODE
    assert scanner._sarif_execution_successful() is True
    scanner._scan_spawn_failure = "the command never ran"
    assert scanner._sarif_execution_successful() is False
    scanner._scan_spawn_failure = None
    scanner.exit_code = -11
    assert scanner._sarif_execution_successful() is False
    # A failed target outranks any accepted count.
    scanner.exit_code = 2
    scanner.targets_failed = 1
    assert scanner._sarif_execution_successful() is False


@pytest.mark.parametrize("attempted", [None, 0])
def test_a_failure_count_is_unsuccessful_whatever_the_attempt_count_holds(
    scanner, attempted
):
    """A recorded failed target grades the row ERROR even beside an attempt
    count of None or 0, so the SARIF flag must say False for the same run.
    The control: nothing attempted and nothing failed completed successfully,
    and the flag stays True."""
    scanner.exit_code = 0
    scanner.targets_attempted = attempted
    scanner.targets_failed = 1

    status, container = _status_for(scanner)
    assert status == ScannerStatus.ERROR
    assert not container.scan_succeeded
    assert scanner._sarif_execution_successful() is False

    scanner.targets_failed = 0
    assert scanner._sarif_execution_successful() is True
