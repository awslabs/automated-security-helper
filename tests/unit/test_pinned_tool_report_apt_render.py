# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The tool report and the apt report are rendered apart, so one fault keeps the other.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` built both reports inside one ``try``. When
``render_report`` raised (the bump steps for one outdated pin could not be built), the
handler wrote only the plain tool table, and the apt results, already fetched, were
never printed: an ``unavailable`` apt pin ("the image build fails now") was missing
from the job summary exactly when the run was already going red. The same held the
other way round: a fault in the apt table dropped the whole tool report.

Each report now has its own ``try``. What can be written is written, a report that
could not be built is named on stderr, and the run exits 2.

No network and no child process: the lookups and the file reads ``main`` makes are
replaced with stubs.
"""

from __future__ import annotations

import importlib.util
import socket
import sys
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"

TOOL_REPORT_CLOSING = "Every pin is at its upstream's latest release."
APT_REPORT_HEADING = "Dockerfile apt pins"
APT_UNAVAILABLE_LINE = "the image build fails now"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_check_pinned_tool_report_apt_render", SCRIPT
    )
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a unit test reached the network")

    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", refuse)
    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", refuse)
    monkeypatch.setattr(urllib.request.FTPHandler, "ftp_open", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def _tool_result() -> Any:
    pin = checker.Pin(
        tool="grype",
        version="v1.0.0",
        ecosystem=checker.GITHUB,
        project="example/grype",
        pinned_in=("TOOL_VERSIONS",),
        kind=checker.RELEASE_BINARY,
    )
    return checker.Result(pin, "v1.0.0", "current")


def _wire(monkeypatch, apt_status: str, **replacements: Any) -> None:
    """Replace what main() reads from the checkout and the network."""
    ruby = checker.AptPin("ruby", "1:3.1", (3,))
    curl = checker.AptPin("curl", "7.1-1", (4,))
    apt_results = [
        checker.AptResult(ruby, "amd64", "1:3.1", "current"),
        checker.AptResult(
            curl,
            "amd64",
            None if apt_status == "unavailable" else "7.1-1",
            apt_status,
            "no index lists the package" if apt_status == "unavailable" else "",
        ),
    ]
    stubs: dict[str, Any] = {
        "load_pins_module": lambda *a, **k: SimpleNamespace(),
        "enumerate_pins": lambda *a, **k: [_tool_result().pin],
        "enumerate_apt_pins": lambda *a, **k: [ruby, curl],
        "apt_indexes": lambda *a, **k: [],
        "check": lambda *a, **k: [_tool_result()],
        "check_apt": lambda *a, **k: apt_results,
    }
    stubs.update(replacements)
    for name, value in stubs.items():
        monkeypatch.setattr(checker, name, value)


def _cannot(message: str):
    def raiser(*args, **kwargs):
        raise ValueError(message)

    return raiser


class TestOneReportFailsTheOtherIsWritten:
    def test_a_tool_report_fault_keeps_the_apt_report(self, monkeypatch, capsys):
        # Red before: both renders shared one try, so the apt table, with its
        # "unavailable" pin, was never written once render_report raised.
        _wire(monkeypatch, "unavailable", render_report=_cannot("no bump steps"))
        assert checker.main([]) == checker.EXIT_ERROR
        captured = capsys.readouterr()
        assert "could not render the report: ValueError" in captured.err
        assert captured.out.splitlines()[0].startswith("tool")
        assert APT_REPORT_HEADING in captured.out
        assert APT_UNAVAILABLE_LINE in captured.out

    @pytest.mark.parametrize(
        ("flags", "table_start"), [([], "tool"), (["--markdown"], "| tool |")]
    )
    def test_the_bare_table_is_followed_by_a_notice_in_the_summary(
        self, monkeypatch, capsys, flags, table_start
    ):
        # Red before: stdout held the bare table, with no notes, bump steps or closing
        # line, and nothing said they were missing, while the apt side wrote a notice.
        _wire(monkeypatch, "current", render_report=_cannot("no bump steps"))
        assert checker.main(flags) == checker.EXIT_ERROR
        out = capsys.readouterr().out
        assert out.splitlines()[0].startswith(table_start)
        assert (
            "could not render the notes, bump steps and closing line: "
            "ValueError: no bump steps" in out
        )
        assert TOOL_REPORT_CLOSING not in out

    def test_a_report_that_renders_has_no_notice(self, monkeypatch, capsys):
        """Control: the notice is for the fallback only."""
        _wire(monkeypatch, "current")
        assert checker.main([]) == checker.EXIT_OK
        out = capsys.readouterr().out
        assert "could not render" not in out
        assert TOOL_REPORT_CLOSING in out

    def test_an_apt_report_fault_keeps_the_tool_report(self, monkeypatch, capsys):
        # Red before: the apt fault was handled as a tool-report fault, and only the
        # plain table was written, without the closing line and the notes.
        _wire(monkeypatch, "current", render_apt_report=_cannot("no apt table"))
        assert checker.main([]) == checker.EXIT_ERROR
        captured = capsys.readouterr()
        assert "could not render the apt report: ValueError" in captured.err
        assert TOOL_REPORT_CLOSING in captured.out

    def test_an_apt_report_fault_leaves_a_notice_in_the_summary(
        self, monkeypatch, capsys
    ):
        # Red before: the apt report became "" and the summary, which is stdout, said
        # nothing about apt while the job exited 2.
        _wire(monkeypatch, "unavailable", render_apt_report=_cannot("no apt table"))
        assert checker.main(["--markdown"]) == checker.EXIT_ERROR
        out = capsys.readouterr().out
        assert "## Dockerfile apt pins" in out
        assert "could not render the apt report: ValueError: no apt table" in out
        assert APT_UNAVAILABLE_LINE not in out

    def test_a_fault_in_the_tool_table_itself_is_still_exit_two(
        self, monkeypatch, capsys
    ):
        # Red before: the fallback render_table raised again inside the handler, the
        # ValueError left main (a traceback is exit 1, "a pin is behind"), and the apt
        # report was never written.
        _wire(
            monkeypatch,
            "unavailable",
            render_report=_cannot("no bump steps"),
            render_table=_cannot("no table"),
        )
        assert checker.main([]) == checker.EXIT_ERROR
        captured = capsys.readouterr()
        assert "could not render the report: ValueError" in captured.err
        assert "could not render the tool table: ValueError" in captured.err
        assert "could not render the tool report: ValueError: no table" in captured.out
        assert APT_UNAVAILABLE_LINE in captured.out

    def test_both_faults_are_both_named_and_the_run_is_exit_two(
        self, monkeypatch, capsys
    ):
        _wire(
            monkeypatch,
            "current",
            render_report=_cannot("no bump steps"),
            render_apt_report=_cannot("no apt table"),
        )
        assert checker.main([]) == checker.EXIT_ERROR
        captured = capsys.readouterr()
        assert "could not render the report: ValueError" in captured.err
        assert "could not render the apt report: ValueError" in captured.err
        assert captured.out.splitlines()[0].startswith("tool")


class TestNeitherReportFails:
    def test_both_reports_are_written_and_the_status_is_the_worse_of_the_two(
        self, monkeypatch, capsys
    ):
        """Control: an unavailable apt pin is exit 1 with both reports printed."""
        _wire(monkeypatch, "unavailable")
        assert checker.main([]) == checker.EXIT_OUTDATED
        captured = capsys.readouterr()
        assert captured.err == ""
        assert TOOL_REPORT_CLOSING in captured.out
        assert APT_UNAVAILABLE_LINE in captured.out

    def test_a_clean_run_is_exit_zero(self, monkeypatch, capsys):
        """Control: nothing off, nothing named on stderr."""
        _wire(monkeypatch, "current")
        assert checker.main(["--fail-on-outdated"]) == checker.EXIT_OK
        assert capsys.readouterr().err == ""
