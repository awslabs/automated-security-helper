# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Held pins: ``HELD_PINS`` in ``tool_downloads.py`` and what the checker does with it.

A pin that cannot move yet (pygit2, capped by GuardDog) made the weekly
``--fail-on-outdated`` run permanently red, so nobody read it. A hold acknowledges one
specific upstream release. These tests pin the properties that keep that from turning
into a way to hide pins:

* an acknowledged row passes ``--fail-on-outdated``;
* a release newer than the acknowledged one fails it again;
* every held row is listed, with its reason and release condition, in both renderings;
* a hold that names no pinned tool, or has no reason, is refused rather than ignored.

No test here touches the network; every lookup is a stub.
"""

from __future__ import annotations

import importlib.util
import socket
import sys
import urllib.request
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("_check_pinned_held_rows", SCRIPT)
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


@pytest.fixture(autouse=True)
def _recorded_apt_indexes(monkeypatch):
    fixtures = REPO_ROOT / "tests" / "test_data" / "apt_indices"
    monkeypatch.setattr(
        checker,
        "APT_INDEX_FETCHER",
        lambda url: (
            fixtures / url.removeprefix("https://").removesuffix(".xz")
        ).read_text(encoding="utf-8"),
    )


@pytest.fixture
def pins():
    return checker.load_pins_module()


def _pin(tool: str = "held-tool", version: str = "1.0.0") -> Any:
    return checker.Pin(
        tool=tool,
        version=version,
        ecosystem=checker.PYPI,
        project=tool,
        pinned_in=("THIRD_PARTY_LICENSES (uv-tool pin)",),
        kind=checker.UV_TOOL,
    )


def _hold(pins: Any, acknowledged: str = "2.0.0", **overrides: str) -> Any:
    fields = {
        "acknowledged": acknowledged,
        "reason": "the cap in another tool keeps this one at 1.0.0.",
        "until": "the other tool lifts its cap.",
    }
    fields.update(overrides)
    return pins.HeldPin(**fields)


def _latest(version: str):
    return {checker.PYPI: lambda project: version}


@pytest.mark.unit
class TestTheDeclaration:
    def test_pygit2_is_held_with_a_reason_and_a_release_condition(self, pins):
        entry = pins.HELD_PINS["pygit2"]
        assert entry.acknowledged == "1.21.0"
        assert "GuardDog" in entry.reason and "<1.19" in entry.reason
        assert "GuardDog" in entry.until and "1.19" in entry.until

    def test_opengrep_is_not_held(self, pins):
        # Its adoption is in flight on another branch; a hold would hide it.
        assert "opengrep" not in pins.HELD_PINS

    def test_every_real_hold_names_a_pinned_tool(self, pins):
        tools = {p.tool for p in checker.enumerate_pins(pins)}
        assert set(pins.HELD_PINS) <= tools

    def test_the_held_global_is_not_taken_for_a_version_pin(self, pins):
        import re

        name = "HELD_PINS"
        assert not re.search(r"(^|_)VERSIONS?$", name)
        assert name in vars(pins)


@pytest.mark.unit
class TestCheck:
    def test_outdated_at_the_acknowledged_version_is_acknowledged(self, pins):
        entry = _hold(pins)
        (result,) = checker.check([_pin()], _latest("2.0.0"), held={"held-tool": entry})
        assert result.status == "acknowledged"
        assert result.latest == "2.0.0"
        assert result.held is entry

    def test_a_v_prefix_does_not_defeat_the_match(self, pins):
        (result,) = checker.check(
            [_pin()], _latest("v2.0.0"), held={"held-tool": _hold(pins, "2.0.0")}
        )
        assert result.status == "acknowledged"

    def test_a_newer_release_than_the_acknowledged_one_is_outdated_again(self, pins):
        (result,) = checker.check(
            [_pin()], _latest("2.0.1"), held={"held-tool": _hold(pins)}
        )
        assert result.status == "outdated"
        assert result.held is None
        assert "2.0.1" in result.note and "2.0.0" in result.note

    def test_the_same_pin_without_a_hold_is_outdated(self):
        (result,) = checker.check([_pin()], _latest("2.0.0"))
        assert result.status == "outdated"

    def test_a_hold_on_a_current_pin_is_named_as_no_longer_needed(self, pins):
        (result,) = checker.check(
            [_pin()], _latest("1.0.0"), held={"held-tool": _hold(pins)}
        )
        assert result.status == "current"
        assert "remove the hold" in result.note

    def test_a_hold_does_not_hide_a_failed_lookup(self, pins):
        def down(project: str) -> str:
            raise OSError("rate limited")

        (result,) = checker.check(
            [_pin()], {checker.PYPI: down}, held={"held-tool": _hold(pins)}
        )
        assert result.status == "error"

    def test_a_hold_for_one_tool_does_not_excuse_another(self, pins):
        results = checker.check(
            [_pin("held-tool"), _pin("other-tool")],
            _latest("2.0.0"),
            held={"held-tool": _hold(pins)},
        )
        assert {r.pin.tool: r.status for r in results} == {
            "held-tool": "acknowledged",
            "other-tool": "outdated",
        }


@pytest.mark.unit
class TestExitCode:
    def test_acknowledged_rows_alone_pass_with_the_flag(self, pins):
        results = checker.check(
            [_pin()], _latest("2.0.0"), held={"held-tool": _hold(pins)}
        )
        assert checker.exit_code(results, fail_on_outdated=True) == checker.EXIT_OK

    def test_a_newer_release_fails_with_the_flag(self, pins):
        results = checker.check(
            [_pin()], _latest("2.1.0"), held={"held-tool": _hold(pins)}
        )
        assert (
            checker.exit_code(results, fail_on_outdated=True) == checker.EXIT_OUTDATED
        )

    def test_an_unheld_outdated_row_beside_an_acknowledged_one_fails(self, pins):
        results = checker.check(
            [_pin("held-tool"), _pin("other-tool")],
            _latest("2.0.0"),
            held={"held-tool": _hold(pins)},
        )
        assert (
            checker.exit_code(results, fail_on_outdated=True) == checker.EXIT_OUTDATED
        )


@pytest.mark.unit
class TestListing:
    def _results(self, pins):
        return checker.check(
            [_pin()], _latest("2.0.0"), held={"held-tool": _hold(pins)}
        )

    @pytest.mark.parametrize("markdown", [False, True])
    def test_a_held_row_is_listed_with_its_reason_and_release_condition(
        self, pins, markdown
    ):
        out = checker.render_report(pins, self._results(pins), markdown=markdown)
        assert "Held pins" in out
        assert "held-tool" in out and "held below 2.0.0" in out
        assert "Reason:" in out and "cap in another tool" in out
        assert "Until:" in out and "lifts its cap" in out

    def test_the_table_row_says_acknowledged(self, pins):
        out = checker.render_report(pins, self._results(pins))
        assert any(
            line.split()[:1] == ["held-tool"] and "acknowledged" in line
            for line in out.splitlines()
        )

    def test_an_acknowledged_row_gets_no_bump_steps(self, pins):
        out = checker.render_report(pins, self._results(pins))
        assert "-> 2.0.0" not in out

    def test_the_closing_line_does_not_claim_every_pin_is_current(self, pins):
        out = checker.render_report(pins, self._results(pins))
        assert "Every pin is at its upstream's latest release." not in out
        assert "deliberately behind" in out

    def test_a_newer_release_is_not_listed_as_held(self, pins):
        results = checker.check(
            [_pin()], _latest("2.0.1"), held={"held-tool": _hold(pins)}
        )
        out = checker.render_report(pins, results)
        assert "Held pins" not in out
        assert "held-tool: 1.0.0 -> 2.0.1" in out
        assert "the hold covers only the acknowledged release" in out


@pytest.mark.unit
class TestEnumerationRefusals:
    def test_a_hold_for_a_tool_nothing_pins_is_refused(self, pins, monkeypatch):
        monkeypatch.setitem(pins.HELD_PINS, "not-a-pinned-tool", _hold(pins))
        with pytest.raises(checker.PinEnumerationError, match="not-a-pinned-tool"):
            checker.enumerate_pins(pins)

    @pytest.mark.parametrize("field", ["reason", "until"])
    def test_a_hold_with_no_reason_or_release_condition_is_refused(
        self, pins, monkeypatch, field
    ):
        monkeypatch.setitem(pins.HELD_PINS, "pygit2", _hold(pins, **{field: "  "}))
        with pytest.raises(checker.PinEnumerationError, match=field):
            checker.enumerate_pins(pins)

    def test_an_acknowledged_version_that_is_not_a_version_is_refused(
        self, pins, monkeypatch
    ):
        monkeypatch.setitem(pins.HELD_PINS, "pygit2", _hold(pins, "latest"))
        with pytest.raises(checker.PinEnumerationError, match="acknowledged"):
            checker.enumerate_pins(pins)

    def test_a_module_with_no_holds_enumerates_as_before(self, pins, monkeypatch):
        before = checker.enumerate_pins(pins)
        monkeypatch.delattr(pins, "HELD_PINS")
        assert checker.enumerate_pins(pins) == before


@pytest.mark.unit
class TestMainOverTheRealPins:
    def _run(self, monkeypatch, capsys, latest_for, argv):
        def lookup(project: str) -> str:
            return latest_for(project)

        # Every upstream kind the checker looks up is stubbed, not only GitHub, PyPI
        # and RubyGems: main() also checks the repository's own pins (REPO_PINS), and
        # on v4 those include image digests, dated snapshots and a pyproject floor.
        monkeypatch.setattr(
            checker,
            "DEFAULT_FETCHERS",
            {
                **dict.fromkeys(checker.DEFAULT_FETCHERS, lookup),
                checker.RUBYGEMS: lambda project: [
                    {
                        "number": lookup(project),
                        "prerelease": False,
                        "platform": "ruby",
                        "ruby_version": ">= 0",
                    }
                ],
            },
        )
        code = checker.main(argv)
        return code, capsys.readouterr().out

    def _versions(self) -> dict[str, str]:
        """project -> pinned value over the module's pins and REPO_PINS, so a stub that
        answers with these reports every pin current. A bundled library is never looked
        up; a project pinned twice keeps its first spelling (the version check test
        asserts the two name one release)."""
        versions: dict[str, str] = {}
        every = (
            checker.enumerate_pins(checker.load_pins_module())
            + checker.enumerate_repo_pins()
        )
        for p in every:
            if p.kind != checker.BUNDLED_LIBRARY:
                versions.setdefault(p.project, p.version)
        return versions

    def test_pygit2_at_its_acknowledged_release_passes_and_is_listed(
        self, monkeypatch, capsys
    ):
        versions = dict(self._versions(), **{"libgit2/pygit2": "v1.21.0"})
        code, out = self._run(
            monkeypatch, capsys, versions.__getitem__, ["--fail-on-outdated"]
        )
        assert code == 0, out
        assert "Held pins" in out and "pygit2" in out
        assert "GuardDog" in out

    def test_a_pygit2_release_after_the_acknowledged_one_fails(
        self, monkeypatch, capsys
    ):
        versions = dict(self._versions(), **{"libgit2/pygit2": "v1.21.1"})
        code, out = self._run(
            monkeypatch, capsys, versions.__getitem__, ["--fail-on-outdated"]
        )
        assert code == 1, out
        assert "Held pins" not in out
