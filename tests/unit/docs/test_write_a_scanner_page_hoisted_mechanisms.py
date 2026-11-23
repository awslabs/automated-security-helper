# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""plugins/write-a-scanner.md teaches the scanner base class's mechanisms, not copies.

The result drop under ASH's output directory, the operator-only option gate and the
secret-safe stderr contract moved from the gitleaks and betterleaks adapters into
``ScannerPluginBase``. The page tells a plugin author to inherit them. Each test pins
the sentence that says so (``assert_on_page``) and probes the base class that makes it
true, so the page goes red when the base API drifts and the base goes red when the
page promises something it no longer does.

The probes build a scanner of the base class itself, with the fixtures of
tests/unit/base/test_scanner_base_hoisted_mechanisms.py.
"""

from __future__ import annotations

import inspect
import logging
from pathlib import Path

import pytest

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from tests.unit.base.test_scanner_base_hoisted_mechanisms import (
    QuietWalkerScanner,
    WalkerScanner,
    _kept,
    _report,
    _scanner,
)
from tests.unit.docs.test_page_claims import assert_on_page

pytestmark = pytest.mark.unit

PAGE = "plugins/write-a-scanner.md"
KEY = "scanners.walker.options.widen"


def test_the_page_says_to_inherit_and_not_copy() -> None:
    assert_on_page(
        PAGE,
        "Subclass it and use them. A copy keeps the behavior it had on the day it was "
        "made, while the base class's version is fixed for every scanner at once, so "
        "write none of the three yourself.",
    )
    for name in (
        "_drop_results_under_output_dir",
        "_operator_gated",
        "quote_tool_stderr",
        "unquoted_failure_tool_name",
    ):
        assert hasattr(ScannerPluginBase, name), name


def test_the_page_says_the_drop_removes_output_results_and_keeps_committed_ones(
    tmp_path, monkeypatch
) -> None:
    assert_on_page(
        PAGE,
        "It removes the results located under ASH's output directories inside "
        "`target`, this run's and an earlier run's `.ash/ash_output`, and keeps a "
        "result in a file the repository committed there.",
    )
    assert_on_page(
        PAGE,
        "It removes nothing when the output directory is outside `target`, which is "
        "the case for the converted target.",
    )
    from automated_security_helper.utils import scan_output_dirs

    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    committed = (source / "out" / "kept.txt").resolve()
    monkeypatch.setattr(
        scan_output_dirs, "committed_output_files", lambda context: {committed}
    )
    monkeypatch.setattr(
        WalkerScanner,
        "_ash_output_dirs_inside",
        lambda self, target: [Path(".ash/ash_output")],
    )
    report = _report(
        "app.py",
        "out/dropped.txt",
        ".ash/ash_output/reports/old.sarif",
        "out/kept.txt",
    )
    scanner._drop_results_under_output_dir(report, source)
    assert _kept(report) == ["app.py", "out/kept.txt"]

    outside = _scanner(tmp_path / "other", output_inside=False)
    report = _report("app.py", "out/x.txt")
    outside._drop_results_under_output_dir(report, Path(outside.context.source_dir))
    assert _kept(report) == ["app.py", "out/x.txt"]


def test_the_page_names_the_operator_gate_signature() -> None:
    assert_on_page(
        PAGE,
        "Call `self._operator_gated(key, wanted, default, refusal)`, where `key` is "
        "the option's dotted path, `scanners.<name>.options.<option>`, and `wanted` "
        "is the value the scanner is about to use.",
    )
    params = list(inspect.signature(ScannerPluginBase._operator_gated).parameters)
    assert params == ["self", "key", "wanted", "default", "refusal"]


def test_the_page_says_the_gate_returns_the_default_and_warns_once(
    tmp_path, caplog
) -> None:
    assert_on_page(
        PAGE,
        "It returns `wanted` when the operator set the option. Otherwise it returns "
        "`default` and logs `refusal` as a warning once for that option on that "
        "scanner instance.",
    )
    granted = _scanner(tmp_path / "op", operator=True)
    tree = _scanner(tmp_path / "tree", operator=False)
    with caplog.at_level(logging.WARNING, logger="ash"):
        assert granted._operator_gated(KEY, True, False, "refused: widen") is True
        assert tree._operator_gated(KEY, True, False, "refused: widen") is False
        assert tree._operator_gated(KEY, True, False, "refused: widen") is False
    warned = [r for r in caplog.records if "refused: widen" in r.getMessage()]
    assert len(warned) == 1


def test_the_page_says_stderr_is_quoted_by_default() -> None:
    assert_on_page(
        PAGE,
        "By default the failure text and `self.errors` carry the tool's stderr, which "
        "is what an author debugging a plugin wants.",
    )
    assert ScannerPluginBase.quote_tool_stderr is True
    assert ScannerPluginBase.unquoted_failure_tool_name is None


def test_the_page_says_unquoted_stderr_stays_out_and_the_log_is_named(
    tmp_path,
) -> None:
    assert_on_page(
        PAGE,
        "With `quote_tool_stderr` False, ASH drops the `stderr` key from the tool's "
        "response before it records errors, and the failure text names the scanner's "
        "`.stderr.log` file next to the results file and does not quote it. The exit "
        "code is still recorded, and the log file keeps the whole stream.",
    )
    scanner = _scanner(tmp_path, QuietWalkerScanner)
    scanner._process_command_response({"returncode": 3, "stderr": "PLANTED-STDERR"})
    assert not any("PLANTED-STDERR" in str(line) for line in scanner.errors)
    assert scanner.exit_code == 3

    results_file = tmp_path / "results" / "source" / "walker.sarif"
    results_file.parent.mkdir(parents=True)
    log = results_file.parent / "QuietWalkerScanner.stderr.log"
    log.write_text("PLANTED-STDERR\n")
    text = scanner._describe_scan_failure(RuntimeError("boom"), results_file)
    assert "PLANTED-STDERR" not in text
    assert log.name.endswith(".stderr.log")
    assert log.as_posix() in text
    assert "exit code 3" in text


def test_the_page_says_where_the_unquoted_tool_name_comes_from(tmp_path) -> None:
    assert_on_page(
        PAGE,
        "`unquoted_failure_tool_name` is the tool's name in that text. Left as "
        '`None`, it reads the name in the plugin config, and then "its tool".',
    )

    class ConfigNamed(QuietWalkerScanner):
        unquoted_failure_tool_name = None

    scanner = _scanner(tmp_path, ConfigNamed)
    text = scanner._describe_scan_failure(RuntimeError("b"), None, tool_started=False)
    assert text.endswith("(walker was not started)")

    scanner.__dict__["config"] = None
    text = scanner._describe_scan_failure(RuntimeError("b"), None, tool_started=False)
    assert text.endswith("(its tool was not started)")


def test_the_helpers_table_points_at_the_inherited_mechanisms() -> None:
    assert_on_page(
        PAGE,
        "If the tool has no exclude option, call "
        "`self._drop_results_under_output_dir(sarif_report, target)` instead",
    )
    assert_on_page(
        PAGE,
        "For any other option that widens what a scan reads, trusts, or sends, use "
        "`self._operator_gated(...)`",
    )
