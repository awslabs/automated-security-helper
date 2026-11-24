# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The three mechanisms the scanner base owns for the secret scanners.

They were copies in the gitleaks and betterleaks adapters before they moved here:

* dropping the results located under ASH's own output directory from a scanner
  that walks the whole target (``_drop_results_under_output_dir`` and the two
  helpers it builds on);
* the "operator only" option gate with its one warning per option
  (``_operator_gated``);
* keeping a tool's stderr out of ``errors`` and out of the failure text
  (``quote_tool_stderr``).

Each test builds a scanner of the base class itself, so a scanner that adopts
the mechanism is covered by what the base does, not by a copy of it.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import ClassVar, Literal, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils import scan_output_dirs
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()


class WalkerConfig(ScannerPluginConfigBase):
    name: Literal["walker"] = "walker"


class WalkerScanner(ScannerPluginBase):
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "walker-tool"
        self.tool_type = ScannerToolType.SECRETS
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError


class QuietWalkerScanner(WalkerScanner):
    quote_tool_stderr: ClassVar[bool] = False
    unquoted_failure_tool_name: ClassVar[Optional[str]] = "walker-tool"


def _scanner(tmp_path, cls=WalkerScanner, output_inside=True, operator=None):
    source = tmp_path / "source"
    source.mkdir(parents=True, exist_ok=True)
    output = source / "out" if output_inside else tmp_path / "output"
    output.mkdir(parents=True, exist_ok=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    if operator:
        record_provenance(context.config, in_tree=[], trusted=AshConfig())
    return cls(config=WalkerConfig(), context=context)


def _report(*uris: str) -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "walker"}},
                    "results": [
                        {
                            "ruleId": "r",
                            "message": {"text": "m"},
                            "locations": [
                                {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                            ],
                        }
                        for uri in uris
                    ],
                }
            ],
        }
    )


def _kept(report: SarifReport) -> list[str]:
    return [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    ]


# --------------------------------------------------------------------------- #
# The output-directory result drop
# --------------------------------------------------------------------------- #


def test_results_under_this_runs_output_directory_are_dropped(tmp_path):
    scanner = _scanner(tmp_path)
    report = _report("app.py", "out/reports/x.sarif", "out/y.txt")
    scanner._drop_results_under_output_dir(report, Path(scanner.context.source_dir))
    assert _kept(report) == ["app.py"]


def test_an_earlier_runs_default_output_directory_is_dropped_too(tmp_path, monkeypatch):
    # Which directories count is _ash_output_dirs_inside's answer (it reads git, and
    # gitleaks' own tests cover it in a repository); the drop acts on all of them.
    monkeypatch.setattr(
        WalkerScanner,
        "_ash_output_dirs_inside",
        lambda self, target: [Path(".ash/ash_output")],
    )
    scanner = _scanner(tmp_path)
    report = _report("app.py", ".ash/ash_output/reports/old.sarif")
    scanner._drop_results_under_output_dir(report, Path(scanner.context.source_dir))
    assert _kept(report) == ["app.py"]


def test_the_directories_named_are_this_runs_then_the_default_without_repeats(
    tmp_path,
):
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    found = scanner._output_dirs_inside_target(source)
    assert found[0] == Path("out")
    assert len(found) == len(set(found))


def test_nothing_is_dropped_when_the_output_directory_is_outside_the_target(tmp_path):
    scanner = _scanner(tmp_path, output_inside=False)
    report = _report("app.py", "out/x.txt")
    scanner._drop_results_under_output_dir(report, Path(scanner.context.source_dir))
    assert _kept(report) == ["app.py", "out/x.txt"]


def test_a_file_the_repository_committed_under_the_output_directory_is_kept(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    committed = (source / "out" / "kept.txt").resolve()
    asked = []

    def fake_committed(context):
        asked.append(context)
        return {committed}

    monkeypatch.setattr(scan_output_dirs, "committed_output_files", fake_committed)
    report = _report("out/kept.txt", "out/dropped.txt")
    scanner._drop_results_under_output_dir(report, source)
    assert _kept(report) == ["out/kept.txt"]
    # Read once, when first asked, however many results were tested.
    assert len(asked) == 1


def test_a_committed_path_that_cannot_be_resolved_stays_treated_as_ashs(
    tmp_path, monkeypatch
):
    scanner = _scanner(tmp_path)
    monkeypatch.setattr(
        scan_output_dirs, "committed_output_files", lambda context: set()
    )
    is_committed = scanner._committed_file_test()
    assert is_committed(Path("out/\0name")) is False


def test_a_backslash_is_a_separator_only_where_the_platform_writes_it(tmp_path):
    scanner = _scanner(tmp_path)
    report = _report("out\\x.txt")
    scanner._drop_results_under_output_dir(report, Path(scanner.context.source_dir))
    # POSIX: a backslash is a character of the file's name, so it is not under out/.
    import os

    expected = [] if os.sep == "\\" else ["out\\x.txt"]
    assert _kept(report) == expected


def test_the_drop_is_logged_at_debug_with_a_count_and_no_names(tmp_path, caplog):
    scanner = _scanner(tmp_path)
    report = _report("out/secret-name.txt", "app.py")
    with caplog.at_level(logging.DEBUG, logger="ash"):
        scanner._drop_results_under_output_dir(report, Path(scanner.context.source_dir))
    texts = [r.getMessage() for r in caplog.records]
    assert any("Dropped 1 finding(s) under ASH's output directory" in t for t in texts)
    assert not any("secret-name" in t for t in texts)


# --------------------------------------------------------------------------- #
# The operator gate
# --------------------------------------------------------------------------- #

KEY = "scanners.walker.options.widen"


def test_an_operator_set_option_is_granted_without_a_warning(tmp_path, caplog):
    scanner = _scanner(tmp_path, operator=True)
    with caplog.at_level(logging.WARNING, logger="ash"):
        got = scanner._operator_gated(KEY, True, False, "refused: widen")
    assert got is True
    assert not [r for r in caplog.records if "refused: widen" in r.getMessage()]


def test_an_option_from_the_tree_gets_the_default_and_one_warning(tmp_path, caplog):
    # No recorded provenance reads as not the operator's.
    scanner = _scanner(tmp_path, operator=False)
    with caplog.at_level(logging.WARNING, logger="ash"):
        first = scanner._operator_gated(KEY, True, False, "refused: widen")
        second = scanner._operator_gated(KEY, True, False, "refused: widen")
    assert first is False and second is False
    warned = [r for r in caplog.records if "refused: widen" in r.getMessage()]
    assert len(warned) == 1


def test_each_option_is_warned_about_once_on_its_own(tmp_path, caplog):
    scanner = _scanner(tmp_path, operator=False)
    with caplog.at_level(logging.WARNING, logger="ash"):
        scanner._operator_gated(KEY, True, False, "refused: widen")
        scanner._operator_gated(KEY + "2", 5, None, "refused: size")
    texts = [r.getMessage() for r in caplog.records]
    assert sum("refused: widen" in t for t in texts) == 1
    assert sum("refused: size" in t for t in texts) == 1


def test_a_warning_already_given_is_not_shared_between_instances(tmp_path, caplog):
    first = _scanner(tmp_path / "a", operator=False)
    second = _scanner(tmp_path / "b", operator=False)
    with caplog.at_level(logging.WARNING, logger="ash"):
        first._operator_gated(KEY, True, False, "refused: widen")
        second._operator_gated(KEY, True, False, "refused: widen")
    assert len([r for r in caplog.records if "refused: widen" in r.getMessage()]) == 2


def test_a_scanner_with_no_context_gets_the_default(tmp_path):
    scanner = _scanner(tmp_path, operator=True)
    scanner.context = None
    assert scanner._operator_gated(KEY, True, "safe", "refused: widen") == "safe"


# --------------------------------------------------------------------------- #
# Secret-safe stderr
# --------------------------------------------------------------------------- #


def test_a_scanner_that_quotes_stderr_keeps_it_in_errors(tmp_path):
    scanner = _scanner(tmp_path, WalkerScanner)
    scanner._process_command_response({"returncode": 0, "stderr": "TOKEN-IN-STDERR"})
    assert any("TOKEN-IN-STDERR" in str(line) for line in scanner.errors)


def test_a_scanner_that_does_not_quote_stderr_keeps_it_out_of_errors(tmp_path):
    scanner = _scanner(tmp_path, QuietWalkerScanner)
    scanner._process_command_response({"returncode": 0, "stderr": "TOKEN-IN-STDERR"})
    assert not any("TOKEN-IN-STDERR" in str(line) for line in scanner.errors)


def test_the_exit_code_is_still_counted_when_stderr_is_withheld(tmp_path):
    scanner = _scanner(tmp_path, QuietWalkerScanner)
    scanner._process_command_response({"returncode": 3, "stderr": "TOKEN-IN-STDERR"})
    assert scanner.exit_code == 3


def test_the_failure_text_names_the_log_and_never_quotes_it(tmp_path):
    scanner = _scanner(tmp_path, QuietWalkerScanner)
    results_file = tmp_path / "results" / "source" / "walker.sarif"
    results_file.parent.mkdir(parents=True)
    log = results_file.parent / "QuietWalkerScanner.stderr.log"
    log.write_text("TOKEN-IN-STDERR\n")
    scanner.exit_code = 2
    text = scanner._describe_scan_failure(RuntimeError("boom"), results_file)
    assert "TOKEN-IN-STDERR" not in text
    assert "boom" in text
    assert "walker-tool' log is not quoted here" in text
    assert log.as_posix() in text
    assert "exit code 2" in text


def test_the_unquoted_failure_text_before_the_tool_started(tmp_path):
    scanner = _scanner(tmp_path, QuietWalkerScanner)
    text = scanner._describe_scan_failure(
        RuntimeError("boom"), None, tool_started=False
    )
    assert text.endswith("(walker-tool was not started)")


def test_the_unquoted_failure_text_for_a_tool_ash_could_not_stop(tmp_path):
    scanner = _scanner(tmp_path, QuietWalkerScanner)
    scanner._scan_could_not_stop = "the tool outlived its timeout"
    text = scanner._describe_scan_failure(
        RuntimeError("boom"), tmp_path / "results" / "source" / "walker.sarif"
    )
    assert "no exit code: ASH could not stop walker-tool" in text
    assert "exit code " not in text.replace("no exit code", "")
