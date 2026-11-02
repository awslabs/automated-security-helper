"""cfn-guard: how a run's failure is worded, what one scan records, and its budget.

Pinned here against ``CfnGuardScanner`` with its rule selection, dependency probe
and subprocess boundary faked, as ``test_cfn_guard_scanner.py`` fakes the process:

* a response's flags, not its ``error`` key, say what happened: a tool that died
  on a signal, or whose output ASH could not record, read as "could not be
  started", and a timeout ASH could not end read as "was killed";
* SARIF that validates but holds no run (``{}`` does) read as a clean template;
* a result cfn-guard reports with no location reached the merged report with
  nothing naming its template;
* every failure line was recorded twice (the ERROR log already appends it), and
  the unmodelable line carried the host's absolute path;
* ``exit_code`` was reset to 0, so a target on which no cfn-guard ran recorded a
  completed run; ``errors`` was never reset, so a second target's invocation
  carried the first target's failures;
* ``scan_timeout`` bounded each template rather than the scan; a template reached
  with no time left is now named and not started;
* the SARIF text came back on stdout and was also kept, line by line, in
  ``self.output``; each template's stderr log overwrote the previous one's; a
  damaged template was never named;
* a rule set name ending in a newline passed the validator; a hard-linked rules
  file inside the scanned tree was read; an operator's rules file was read whole
  with no bound; the copy of a rules file whose name was within four bytes of
  NAME_MAX could not be written; an empty rules directory was silently unread;
  a rules file outside the source directory was recorded by its absolute path.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cfn_guard_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    _MAX_COPY_NAME_BYTES,
    _NOT_STARTED_AFTER_BUDGET,
    _RULE_SET_NAME,
    _SUCCESS_EXIT_CODES,
    CfnGuardScanner,
    CfnGuardScannerConfig,
    CfnGuardScannerConfigOptions,
    _copy_name,
    _run_failure,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.cfn_template_discovery import TemplateDiscovery
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.rules_bundles import RulesBundleUnavailable
from automated_security_helper.utils.scanned_tree import (
    REASON_HARDLINK,
    TreeInputRefused,
)
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_SUFFIX,
    WAS_KILLED_ENDING,
)

pytestmark = pytest.mark.unit

TEMPLATE = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n"


def _sarif(results=None) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "cfn-guard", "semanticVersion": "3.2.1"}
                    },
                    "results": results or [],
                }
            ],
        }
    )


def _result_without_location() -> dict:
    return {
        "ruleId": "WHOLE_DOCUMENT_RULE",
        "level": "error",
        "message": {"text": "the document fails the rule"},
    }


def _scanner(source: Path, **options) -> CfnGuardScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    context = PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        work_dir=source / ".ash" / "ash_output" / "converted",
        config=config,
    )
    return CfnGuardScanner(
        context=context,
        config=CfnGuardScannerConfig(
            enabled=True, options=CfnGuardScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def source(ash_temp_path) -> Path:
    directory = ash_temp_path / "src"
    directory.mkdir()
    (directory / "one.yaml").write_text(TEMPLATE, encoding="utf-8")
    (directory / "two.yaml").write_text(TEMPLATE, encoding="utf-8")
    return directory


@pytest.fixture
def faked_scan():
    """Rule selection empty, dependencies present; only the process is left."""
    with (
        patch.object(CfnGuardScanner, "_selected_rules", return_value=[]),
        patch.object(
            CfnGuardScanner, "validate_plugin_dependencies", return_value=True
        ),
    ):
        yield


def _discovery(source: Path, **fields) -> TemplateDiscovery:
    found = TemplateDiscovery(
        templates=[source / "one.yaml", source / "two.yaml"], **fields
    )
    return found


class TestRunFailureWording:
    def test_a_bare_error_is_still_could_not_be_started(self):
        assert _run_failure({"error": "No such file"}) == (
            "cfn-guard could not be started: No such file"
        )

    def test_a_spawn_failure_reads_the_same(self):
        text = _run_failure({"error": "[Errno 14] Bad address", "spawn_failed": True})
        assert text == "cfn-guard could not be started: [Errno 14] Bad address"

    def test_a_timeout_ash_ended_says_killed(self):
        text = _run_failure({"returncode": -9, "timed_out": True})
        assert text == f"cfn-guard timed out{WAS_KILLED_ENDING}"

    def test_a_timeout_ash_could_not_end_says_so(self):
        text = _run_failure({"timed_out": True, "returncode": None})
        assert text is not None
        assert text.startswith("cfn-guard timed out")
        assert COULD_NOT_STOP_SUFFIX in text
        assert WAS_KILLED_ENDING not in text

    def test_a_signal_death_is_not_a_start_failure(self):
        text = _run_failure({"error": "died on SIGSEGV", "signaled": True})
        assert text == "cfn-guard did not finish: died on SIGSEGV"

    def test_an_unrecorded_output_is_named_as_such(self):
        text = _run_failure({"error": "disk full", "post_run_error": True})
        assert text == "cfn-guard ran, but ASH could not record its output: disk full"

    def test_a_cancel_and_a_rejection_keep_their_words(self):
        assert _run_failure({"error": "halted", "cancelled": True}) == (
            "cfn-guard was cancelled: halted"
        )
        assert _run_failure({"error": "too big", "result_rejected": True}) == (
            "cfn-guard's result was rejected: too big"
        )

    def test_a_completed_run_has_no_failure(self):
        assert _run_failure({"returncode": 0, "stdout": _sarif()}) is None


class TestParseResponse:
    def test_sarif_with_no_run_is_not_a_clean_template(self):
        failure, report = CfnGuardScanner._parse_response(
            {"returncode": 0, "stdout": "{}", "stderr": ""}, values=()
        )
        assert report is None
        assert failure is not None and "holds no run" in failure

    def test_sarif_with_a_run_is_read(self):
        failure, report = CfnGuardScanner._parse_response(
            {"returncode": 0, "stdout": _sarif(), "stderr": ""}, values=()
        )
        assert failure is None and report is not None


def test_a_result_without_a_location_is_located_at_its_template():
    report = SarifReport.model_validate(
        json.loads(_sarif([_result_without_location()]))
    )
    results = CfnGuardScanner.normalize_results(report, "templates/whole.yaml")
    assert len(results) == 1
    location = results[0].locations[0].physicalLocation.root.artifactLocation
    assert location.uri == "templates/whole.yaml"


class TestOneScansRecords:
    def test_a_target_with_no_run_records_no_exit_code_and_no_old_errors(
        self, source, faked_scan
    ):
        scanner = _scanner(source)
        scanner.errors = ["(cfn-guard) a failure from the source target"]
        scanner.exit_code = 19
        with (
            patch.object(
                cfn_guard_scanner,
                "discover_templates",
                return_value=TemplateDiscovery(),
            ),
            patch.object(CfnGuardScanner, "_run_subprocess", autospec=True) as run,
        ):
            report = scanner.scan(target=source, target_type="source")
        assert run.call_count == 0
        assert scanner.exit_code is None
        assert scanner.errors == []
        assert report.runs[0].invocations[0].exitCode is None

    def test_each_failure_is_recorded_once_with_the_shown_path(
        self, source, faked_scan
    ):
        scanner = _scanner(source)
        found = TemplateDiscovery(
            templates=[source / "one.yaml"],
            unmodelable=[(source / "bad.yaml", "Resources is not a mapping")],
            unparseable=[("broken.yaml", "it could not be parsed")],
        )
        with (
            patch.object(cfn_guard_scanner, "discover_templates", return_value=found),
            patch.object(
                CfnGuardScanner,
                "_run_subprocess",
                autospec=True,
                return_value={"error": "No such file"},
            ),
        ):
            scanner.scan(target=source, target_type="source")
        joined = "\n".join(scanner.errors)
        assert joined.count("did not evaluate bad.yaml") == 1
        assert source.as_posix() not in joined
        assert joined.count("did not evaluate one.yaml") == 1
        assert "Skipped broken.yaml: it could not be parsed" in joined
        assert scanner.targets_attempted == 2 and scanner.targets_failed == 2
        # Both failed targets are recorded by name as targets the tool never
        # evaluated, with the shown path, so the run's error record names them.
        assert sorted(scanner.unevaluated_targets) == ["bad.yaml", "one.yaml"]

    def test_the_sarif_text_is_not_kept_in_output(self, source, faked_scan):
        scanner = _scanner(source)

        def run(self_, **kwargs):
            # What PluginBase._process_command_response does with "return".
            self_.output.extend(_sarif().splitlines())
            return {"returncode": 0, "stdout": _sarif(), "stderr": ""}

        with (
            patch.object(
                cfn_guard_scanner, "discover_templates", return_value=_discovery(source)
            ),
            patch.object(
                CfnGuardScanner, "_run_subprocess", autospec=True, side_effect=run
            ) as double,
        ):
            scanner.scan(target=source, target_type="source")
        assert scanner.output == []
        assert double.call_count == 2
        assert all(
            call.kwargs["stderr_preference"] == "return"
            for call in double.call_args_list
        )

    def test_every_templates_stderr_reaches_one_log(self, source, faked_scan):
        scanner = _scanner(source)

        def run(self_, **kwargs):
            data = next(a for a in kwargs["command"] if a.startswith("--data="))
            return {
                "returncode": 0,
                "stdout": _sarif(),
                "stderr": f"note for {Path(data).name}\n",
            }

        with (
            patch.object(
                cfn_guard_scanner, "discover_templates", return_value=_discovery(source)
            ),
            patch.object(
                CfnGuardScanner, "_run_subprocess", autospec=True, side_effect=run
            ),
        ):
            scanner.scan(target=source, target_type="source")
        log = scanner.results_dir / "source" / "CfnGuardScanner.stderr.log"
        text = log.read_text(encoding="utf-8")
        assert "--- one.yaml\nnote for one.yaml" in text
        assert "--- two.yaml\nnote for two.yaml" in text


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now


def test_the_scan_timeout_bounds_the_whole_scan(source, faked_scan, monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(cfn_guard_scanner, "time", clock)
    scanner = _scanner(source, scan_timeout=10)
    timeouts = []

    def run(self_, **kwargs):
        timeouts.append(kwargs["timeout"])
        clock.now += 11  # the first template spends the whole budget
        return {"returncode": 0, "stdout": _sarif(), "stderr": ""}

    with (
        patch.object(
            cfn_guard_scanner, "discover_templates", return_value=_discovery(source)
        ),
        patch.object(
            CfnGuardScanner, "_run_subprocess", autospec=True, side_effect=run
        ),
    ):
        scanner.scan(target=source, target_type="source")
    assert timeouts == [10.0]
    assert scanner.targets_attempted == 2 and scanner.targets_failed == 1
    assert any(
        "two.yaml" in line and _NOT_STARTED_AFTER_BUDGET in line
        for line in scanner.errors
    ), scanner.errors


def test_with_scan_timeout_null_every_template_runs_unbounded(source, faked_scan):
    # The option defaults to 1800 (ScannerOptionsBase); null is the documented
    # way to leave the scanner unbounded, and then no deadline is computed.
    scanner = _scanner(source, scan_timeout=None)
    with (
        patch.object(
            cfn_guard_scanner, "discover_templates", return_value=_discovery(source)
        ),
        patch.object(
            CfnGuardScanner,
            "_run_subprocess",
            autospec=True,
            return_value={"returncode": 0, "stdout": _sarif(), "stderr": ""},
        ) as double,
    ):
        scanner.scan(target=source, target_type="source")
    assert [call.kwargs["timeout"] for call in double.call_args_list] == [None, None]


def test_the_class_advertises_its_own_accepted_exit_codes():
    # The base class reads success_exit_codes to grade a run's exit code; its
    # default {0, 1} would read cfn-guard's 19 (a rule failed) as a failed run
    # and 1 as a clean one. The class carries the set _parse_response accepts.
    assert CfnGuardScanner.success_exit_codes == set(_SUCCESS_EXIT_CODES)
    assert CfnGuardScanner.success_exit_codes == {0, 19}


class TestRuleFiles:
    def test_a_rule_set_name_ending_in_a_newline_is_refused(self):
        assert _RULE_SET_NAME.match("wa-Security-Pillar") is not None
        assert _RULE_SET_NAME.match("wa-Security-Pillar\n") is None

    def test_copy_name_keeps_the_suffix_within_name_max(self):
        assert _copy_name(3, "mine.guard") == "003-mine.guard"
        long_name = "x" * 252 + ".guard"
        copy = _copy_name(0, long_name)
        assert len(copy.encode("utf-8")) <= _MAX_COPY_NAME_BYTES
        assert copy.startswith("000-x") and copy.endswith(".guard")

    def test_a_hard_linked_rules_file_in_the_tree_is_refused(self, ash_temp_path):
        root = ash_temp_path / "tree"
        root.mkdir()
        rule = root / "mine.guard"
        rule.write_text("rule mine { }\n", encoding="utf-8")
        try:
            os.link(rule, root / "twin.guard")
        except OSError as exc:  # pragma: no cover - a filesystem without links
            pytest.skip(f"hard links unavailable here: {exc}")
        with pytest.raises(TreeInputRefused) as refused:
            CfnGuardScanner._read_rule(rule, root, in_tree=True)
        assert refused.value.reason == REASON_HARDLINK
        # Outside the tree the operator owns the file, links and all.
        assert CfnGuardScanner._read_rule(rule, root).content == "rule mine { }\n"

    def test_a_rules_file_over_the_cap_is_refused(self, ash_temp_path, monkeypatch):
        monkeypatch.setattr(cfn_guard_scanner, "_MAX_OPERATOR_RULE_BYTES", 16)
        rule = ash_temp_path / "big.guard"
        rule.write_bytes(b"r" * 17)
        with pytest.raises(RulesBundleUnavailable, match="larger than"):
            CfnGuardScanner._read_rule(rule, ash_temp_path)
        rule.write_bytes(b"r" * 16)
        assert CfnGuardScanner._read_rule(rule, ash_temp_path).content == "r" * 16

    def test_an_empty_rules_directory_is_named(self, source, ash_temp_path, caplog):
        empty = ash_temp_path / "operator-rules"
        empty.mkdir()
        (empty / "notes.txt").write_text("not a rule\n", encoding="utf-8")
        scanner = _scanner(source, rule_sets=[], rules_paths=[str(empty)])
        # The directory contributes nothing, so with rule_sets empty nothing is
        # selected at all, which _selected_rules refuses by name; the warning
        # about the directory is what tells the operator why.
        with (
            caplog.at_level(logging.WARNING, logger="ash"),
            pytest.raises(RulesBundleUnavailable, match="names no rules file"),
        ):
            scanner.rule_files()
        assert "holds no .guard or .ruleset file" in caplog.text

    def test_a_rules_file_outside_the_source_is_recorded_by_name(
        self, source, ash_temp_path
    ):
        outside = ash_temp_path / "elsewhere" / "mine.guard"
        inside = source / "rules" / "ours.guard"
        recorded = CfnGuardScanner._recorded_rule_args([outside, inside], source)
        assert recorded == ["--rules=mine.guard", "--rules=rules/ours.guard"]


def test_a_rules_root_with_an_expansion_is_warned_about(source, caplog):
    scanner = _scanner(source)
    with (
        patch.object(cfn_guard_scanner, "rules_root", return_value=Path("$X/rules")),
        caplog.at_level(logging.WARNING, logger="ash"),
    ):
        requirements = scanner.sandbox_requirements
    assert requirements.read_paths == ("$X/rules",)
    assert "reads as an expansion" in caplog.text
