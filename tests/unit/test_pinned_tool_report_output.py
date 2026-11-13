# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pin checker's report text and exit status stay true when something is off.

Why this file exists
--------------------
The weekly job writes ``scripts/check_pinned_tool_versions.py --markdown`` to the job
summary and treats exit status 1 as "a pin is behind". Several outputs broke that:

* The summary escaped only ``_``, so text shaped like a tag (the ``<new commit>``
  placeholder of a license-file step, the ``<urlopen error timed out>`` of a failed
  lookup) was read as HTML and vanished, leaving ``lookup failed (URLError: )``.
* ``render_table`` and ``render_apt_report`` called ``max`` on one number when given
  no rows, which raises.
* The apt bullets were de-duplicated by package and candidate across architectures,
  so an architecture whose pin is gone was described only by another architecture's
  "a newer version is published".
* The closing line said every pin is at its upstream's latest release while a pin
  was ahead of it or a gem had a newer release the image cannot use.
* ``main`` caught only ``PinEnumerationError``. A pins module that does not import,
  a missing Dockerfile or a bump step that cannot be built ended as a traceback with
  exit status 1, the code for a pin that is behind, and the report was lost. Run with
  ``python -OO`` there is no module docstring, and building the argument parser
  raised.

No network and no child process: the lookups and the file reads ``main`` makes are
replaced with stubs where a test needs them.
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


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_check_pinned_tool_report_output", SCRIPT
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


def _pin(tool: str = "grype", version: str = "v1.0.0") -> Any:
    return checker.Pin(
        tool=tool,
        version=version,
        ecosystem=checker.GITHUB,
        project=f"example/{tool}",
        pinned_in=("TOOL_VERSIONS",),
        kind=checker.RELEASE_BINARY,
    )


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


class TestMarkdownEscaping:
    def test_text_shaped_like_a_tag_is_not_left_to_be_read_as_html(self):
        # Red at the base: only "_" was escaped, so "<new commit>" went out raw and
        # the job summary dropped it.
        escaped = checker._escape_markdown("sha256 of https://host/o/r/<new commit>/f")
        assert "&lt;new commit>" in escaped
        assert "<new commit>" not in escaped

    def test_a_code_span_is_left_as_written(self):
        escaped = checker._escape_markdown("`<a> _b` and <c> _d")
        assert escaped == "`<a> _b` and &lt;c> \\_d"

    def test_an_ampersand_is_escaped_so_an_entity_in_a_message_prints_as_written(self):
        assert checker._escape_markdown("a &lt; b") == "a &amp;lt; b"

    def test_an_underscore_is_still_escaped(self):
        """Control: the original escape."""
        assert checker._escape_markdown("_DIGESTS: 3") == "\\_DIGESTS: 3"

    def test_the_license_file_step_reaches_the_summary_with_its_placeholder(
        self, monkeypatch
    ):
        pins = checker.load_pins_module()
        monkeypatch.setattr(checker, "_copy_steps", lambda *args, **kwargs: [])
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}["semgrep"]
        results = [checker.Result(pin, "9.9.9", "outdated")]
        markdown = checker.render_report(pins, results, markdown=True)
        assert "&lt;new commit>" in markdown
        assert "<new commit>" not in markdown
        # Plain text is not Markdown: it keeps the placeholder as it is.
        assert "<new commit>" in checker.render_report(pins, results, markdown=False)

    def test_a_tool_lookup_failure_keeps_its_detail_in_the_summary(self):
        detail = "URLError: <urlopen error timed out>"
        results = [checker.Result(_pin(), None, "error", detail)]
        markdown = checker.render_report(SimpleNamespace(), results, markdown=True)
        assert "lookup failed (URLError: &lt;urlopen error timed out>)" in markdown
        text = checker.render_report(SimpleNamespace(), results, markdown=False)
        assert f"lookup failed ({detail})" in text

    def test_an_apt_lookup_failure_keeps_its_detail_in_the_summary(self):
        pin = checker.AptPin("curl", "7.1-1", (3,))
        detail = "OSError: <urlopen error timed out>"
        result = checker.AptResult(pin, "amd64", None, "error", detail)
        markdown = checker.render_apt_report([result], markdown=True)
        assert "lookup failed (OSError: &lt;urlopen error timed out>)" in markdown
        assert f"lookup failed ({detail})" in checker.render_apt_report([result])


# ---------------------------------------------------------------------------
# No rows
# ---------------------------------------------------------------------------


class TestAnEmptyTable:
    def test_a_tool_table_with_no_rows_is_its_header(self):
        # Red at the base: max(len(title)) was called on one int and raised.
        table = checker.render_table([])
        assert table.splitlines()[0].split() == [
            "tool",
            "pinned",
            "latest",
            "status",
            "upstream",
            "pinned",
            "in",
        ]

    def test_an_apt_report_with_no_rows_is_its_header(self):
        report = checker.render_apt_report([])
        assert "Dockerfile apt pins" in report
        assert "package" in report

    def test_markdown_tables_with_no_rows_are_their_headers(self):
        """Control: the Markdown branch never called max."""
        assert checker.render_table([], markdown=True).startswith("| tool |")
        assert "| package |" in checker.render_apt_report([], markdown=True)

    def test_widths_follow_the_longest_entry(self):
        """Control: a table with rows is as wide as its widest entry."""
        wide = checker.Result(_pin("a-long-tool-name"), "v1.0.0", "current")
        header = checker.render_table([wide]).splitlines()[0]
        assert header.startswith("tool" + " " * (len("a-long-tool-name") - 4 + 2))


# ---------------------------------------------------------------------------
# The apt bullets
# ---------------------------------------------------------------------------


class TestAptBullets:
    PIN = checker.AptPin("curl", "7.1-1", (3, 9))

    def _report(self, *rows: tuple[str, str]) -> str:
        results = [
            checker.AptResult(self.PIN, arch, "7.2-1", status) for arch, status in rows
        ]
        return checker.render_apt_report(results)

    def test_an_architecture_where_the_pin_is_gone_is_not_hidden_by_another(self):
        # Red at the base: the arm64 bullet had the key of the amd64 one and was
        # skipped, so only "a newer version is published" was said.
        report = self._report(("amd64", "outdated"), ("arm64", "unavailable"))
        assert "a newer version is published" in report
        assert "no longer in any index, so the image build fails now" in report

    def test_one_bullet_when_every_architecture_says_the_same(self):
        """Control: the de-duplication that stays."""
        report = self._report(("amd64", "outdated"), ("arm64", "outdated"))
        assert report.count("a newer version is published") == 1


# ---------------------------------------------------------------------------
# The closing line
# ---------------------------------------------------------------------------

EVERY = "Every pin is at its upstream's latest release."


class TestClosingLine:
    def _report(self, *results: Any) -> str:
        return checker.render_report(SimpleNamespace(), list(results))

    def test_a_pin_ahead_of_upstream_is_not_at_its_latest_release(self):
        # Red at the base: nothing outdated and no error printed the claim.
        report = self._report(checker.Result(_pin(), "v0.9.0", "ahead"))
        assert EVERY not in report
        assert "not every pin is at its upstream's latest release" in report

    def test_a_gem_with_a_newer_release_it_cannot_run_is_not_at_its_latest(self):
        note = "9.0 is the newest release, but it needs Ruby 9.0"
        report = self._report(checker.Result(_pin(), "v1.0.0", "current", note=note))
        assert EVERY not in report
        assert note in report

    @staticmethod
    def _bundled(tool: str = "lib") -> Any:
        return checker.Pin(
            tool=tool,
            version="1.0.0",
            ecosystem=checker.BUNDLED,
            project="wheel",
            pinned_in=("THIRD_PARTY_LICENSES (bundled)",),
            kind=checker.BUNDLED_LIBRARY,
        )

    def test_current_and_held_pins_keep_the_claim(self):
        # Red before: the held row check() builds carries its reason in ``note``, which
        # the closing line read as a caveat, so every real run with a bundled library
        # printed "not every pin is at its upstream's latest release". The control built
        # its held row with the reason as ``detail``, a shape check() no longer makes.
        results = checker.check(
            [_pin(), self._bundled()],
            fetchers={checker.GITHUB: lambda project: "v1.0.0"},
        )
        assert [r.status for r in results] == ["current", "held"]
        assert results[1].note == "version set by wheel"
        report = self._report(*results)
        assert EVERY in report
        assert "not every pin" not in report
        assert "lib: version set by wheel" in report

    def test_a_caveat_beside_a_held_pin_still_withholds_the_claim(self):
        """Control: only the held row's own note is left out of the condition."""
        note = "9.0 is the newest release, but it needs Ruby 9.0"
        gem = checker.Result(_pin(), "v1.0.0", "current", note=note)
        held = checker.check([self._bundled()])[0]
        report = self._report(gem, held)
        assert EVERY not in report
        assert "not every pin is at its upstream's latest release" in report

    def test_an_outdated_pin_has_neither_closing_line(self, monkeypatch):
        """Control: a pin that is behind gets its steps and no summary sentence."""
        monkeypatch.setattr(checker, "bump_steps", lambda *args, **kwargs: ["edit it"])
        report = self._report(checker.Result(_pin(), "v2.0.0", "outdated"))
        assert "edit it" in report
        assert EVERY not in report
        assert "not every pin" not in report


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def _wire(monkeypatch, **replacements: Any) -> None:
    """Replace what main() reads from the checkout and the network."""
    apt_pin = checker.AptPin("ruby", "1:3.1", (3,))
    stubs: dict[str, Any] = {
        "load_pins_module": lambda *a, **k: SimpleNamespace(),
        "enumerate_pins": lambda *a, **k: [_pin()],
        "enumerate_apt_pins": lambda *a, **k: [apt_pin],
        "apt_indexes": lambda *a, **k: [],
        "check": lambda *a, **k: [checker.Result(_pin(), "v1.0.0", "current")],
        "check_apt": lambda *a, **k: [
            checker.AptResult(apt_pin, "amd64", "1:3.1", "current")
        ],
    }
    stubs.update(replacements)
    for name, value in stubs.items():
        monkeypatch.setattr(checker, name, value)


class TestMain:
    def test_the_wired_run_is_clean(self, monkeypatch, capsys):
        """Control: with every stub answering, the run is a pass."""
        _wire(monkeypatch)
        assert checker.main(["--fail-on-outdated"]) == checker.EXIT_OK
        assert EVERY in capsys.readouterr().out

    def test_a_pins_module_that_does_not_import_is_exit_two_not_one(
        self, monkeypatch, capsys
    ):
        # Red at the base: the SyntaxError left main, and Python exits 1 for it.
        def broken(*args, **kwargs):
            raise SyntaxError("invalid syntax in the half-edited pins module")

        _wire(monkeypatch, load_pins_module=broken)
        assert checker.main([]) == checker.EXIT_ERROR
        assert "SyntaxError" in capsys.readouterr().err

    def test_a_missing_dockerfile_is_exit_two_not_one(self, monkeypatch, capsys):
        def missing(*args, **kwargs):
            raise FileNotFoundError("no Dockerfile here")

        _wire(monkeypatch, enumerate_apt_pins=missing)
        assert checker.main([]) == checker.EXIT_ERROR
        assert "FileNotFoundError" in capsys.readouterr().err

    def test_a_refusal_is_still_exit_two(self, monkeypatch, capsys):
        """Control: the case that was already handled."""

        def refuse(*args, **kwargs):
            raise checker.PinEnumerationError("a pin this script cannot read")

        _wire(monkeypatch, enumerate_pins=refuse)
        assert checker.main([]) == checker.EXIT_ERROR
        assert "a pin this script cannot read" in capsys.readouterr().err

    def test_a_report_that_cannot_be_built_still_gives_the_table_and_exit_two(
        self, monkeypatch, capsys
    ):
        # Red at the base: the ValueError left main after the lookups, the table was
        # never written, and the exit status was 1.
        def cannot(*args, **kwargs):
            raise ValueError("no bump steps for this kind of pin")

        _wire(monkeypatch, render_report=cannot)
        assert checker.main([]) == checker.EXIT_ERROR
        captured = capsys.readouterr()
        assert "could not render the report: ValueError" in captured.err
        assert captured.out.splitlines()[0].startswith("tool")

    def test_help_works_without_a_module_docstring(self, monkeypatch, capsys):
        # Red at the base: __doc__.split raised AttributeError under python -OO.
        monkeypatch.setattr(checker, "__doc__", None)
        with pytest.raises(SystemExit) as raised:
            checker.main(["--help"])
        assert raised.value.code == 0
        assert "--fail-on-outdated" in capsys.readouterr().out
