# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/check_pinned_tool_versions.py`` and the weekly workflow that runs it.

Why this file exists
--------------------
The script is the only thing that reports a pin in ``tool_downloads.py`` falling
behind its upstream. A check like that fails quietly in one direction: a pin it does
not enumerate is a pin it never reports, and the run stays green. So the tests here
are built around the enumeration first, and each coverage assertion carries a
negative control showing that the same assertion goes red when a pin is missed.

No test here touches the network. Every lookup is a stub, and the HTTP and HTTPS
transports are replaced with one that fails the test if anything reaches it.
"""

from __future__ import annotations

import base64
import dataclasses
import functools
import importlib.util
import re
import socket
import subprocess  # nosec B404 - git ls-files over this checkout only
import sys
import urllib.request
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-pinned-tool-versions.yml"
PINS_FILE = REPO_ROOT / "automated_security_helper" / "utils" / "tool_downloads.py"
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _load_script():
    spec = importlib.util.spec_from_file_location("_check_pinned_tool_versions", SCRIPT)
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

    # At the transport, which every opener goes through, urlopen's and the script's
    # own redirect-checking opener alike.
    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", refuse)
    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", refuse)
    monkeypatch.setattr(urllib.request.FTPHandler, "ftp_open", refuse)
    # A backstop beneath every transport, the ones not patched above included.
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


@pytest.fixture(autouse=True)
def _recorded_apt_indexes(monkeypatch):
    """main() also checks the Dockerfile's apt pins; answer from the recorded indexes.

    tests/unit/test_apt_pin_check.py is where that check is tested. Here it only has
    to be current, so the exit codes below are the tool pins' alone.
    """
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
    """A fresh copy of tool_downloads per test, so monkeypatching it is local."""
    return checker.load_pins_module()


def _expected_pins(pins: Any) -> dict[str, tuple[str, str]]:
    """Every pin the module carries, as tool -> (version, ecosystem).

    Built straight from the module's tables, independently of the script, so the
    coverage test compares two readings rather than the script against itself.
    """
    expected: dict[str, tuple[str, str]] = {}
    for tool, version in pins.TOOL_VERSIONS.items():
        expected[tool] = (version, checker.GITHUB)
    for tool, entry in pins.THIRD_PARTY_LICENSES.items():
        if entry.distribution:
            ecosystem = checker.PYPI
        elif getattr(entry, "bundled_in", None):
            ecosystem = checker.BUNDLED
        else:
            ecosystem = checker.GITHUB
        expected[tool] = (entry.version, ecosystem)
    for gem, name in _GEM_PINS.items():
        expected[gem] = (getattr(pins, name), checker.RUBYGEMS)
    return expected


#: The gems tool_downloads.py pins, and the module global that holds each version.
_GEM_PINS = {"cfn-nag": "CFN_NAG_GEM_VERSION", "bundler": "BUNDLER_VERSION"}


def _uncovered(pins: Any, enumerated: list[Any]) -> list[str]:
    """What the module pins that ``enumerated`` does not report, or reports wrong."""
    got = {p.tool: (p.version, p.ecosystem) for p in enumerated}
    return sorted(
        f"{tool} {want}"
        for tool, want in _expected_pins(pins).items()
        if got.get(tool) != want
    )


def _pin_shaped_globals(module: Any) -> set[str]:
    return {
        name
        for name in vars(module)
        if name.isupper() and re.search(r"(^|_)VERSIONS?$", name)
    }


def _fake_uv_tool_entry(pins: Any, tool: str) -> Any:
    template = pins.THIRD_PARTY_LICENSES["bandit"]
    return dataclasses.replace(template, tool=tool, version="2.0.0", distribution=tool)


@pytest.mark.unit
class TestEnumerationCoversEveryPin:
    def test_every_pin_in_the_module_is_enumerated(self, pins):
        enumerated = checker.enumerate_pins(pins)
        assert not _uncovered(pins, enumerated), _uncovered(pins, enumerated)

        tools = {p.tool for p in enumerated}
        assert set(pins.TOOL_VERSIONS) <= tools
        assert set(pins.THIRD_PARTY_LICENSES) <= tools
        assert set(_GEM_PINS) <= tools

    def test_the_population_is_not_vacuous(self, pins):
        """Positive control: an empty module would satisfy the test above."""
        uv_tool_pins = {
            t for t, e in pins.THIRD_PARTY_LICENSES.items() if e.distribution
        }
        assert {"grype", "opengrep", "syft", "trivy", "uv"} <= set(pins.TOOL_VERSIONS)
        assert {"bandit", "checkov", "semgrep"} <= uv_tool_pins
        assert len(checker.enumerate_pins(pins)) >= 9

    def test_uv_tool_pins_are_looked_up_on_pypi_by_distribution(self, pins):
        by_tool = {p.tool: p for p in checker.enumerate_pins(pins)}
        for tool, entry in pins.THIRD_PARTY_LICENSES.items():
            if entry.distribution:
                assert by_tool[tool].ecosystem == checker.PYPI
                assert by_tool[tool].project == entry.distribution
                assert by_tool[tool].version == entry.version

    def test_release_pins_are_looked_up_where_they_are_downloaded_from(self, pins):
        by_tool = {p.tool: p for p in checker.enumerate_pins(pins)}
        for tool in pins.TOOL_VERSIONS:
            owner_repo = by_tool[tool].project
            assert pins._RELEASE_BASE_URLS[tool].startswith(
                f"https://github.com/{owner_repo}/"
            )

    def test_a_pin_the_enumeration_missed_is_caught(self, pins, monkeypatch):
        """Negative control on the coverage assertion itself.

        The enumeration is taken, then a pin is added to the module behind its back.
        The coverage check must name the new pin; if it did not, the test above
        could pass over an enumeration that skips tools.
        """
        stale = checker.enumerate_pins(pins)
        monkeypatch.setitem(pins.TOOL_VERSIONS, "fakepin", "v9.9.9")
        monkeypatch.setitem(
            pins.THIRD_PARTY_LICENSES,
            "fakeuvtool",
            _fake_uv_tool_entry(pins, "fakeuvtool"),
        )

        missing = _uncovered(pins, stale)
        assert any(m.startswith("fakepin ") for m in missing), missing
        assert any(m.startswith("fakeuvtool ") for m in missing), missing

    def test_an_enumeration_that_drops_the_uv_tool_pins_is_caught(self, pins):
        """The same control against the subtler miss: a whole category skipped."""
        without_pypi = [
            p for p in checker.enumerate_pins(pins) if p.ecosystem != checker.PYPI
        ]
        missing = _uncovered(pins, without_pypi)
        assert {m.split()[0] for m in missing} == {
            t for t, e in pins.THIRD_PARTY_LICENSES.items() if e.distribution
        }

    def test_a_newly_pinned_tool_is_enumerated_without_editing_the_script(
        self, pins, monkeypatch
    ):
        monkeypatch.setitem(pins.TOOL_VERSIONS, "fakepin", "v9.9.9")
        monkeypatch.setitem(
            pins._RELEASE_BASE_URLS,
            "fakepin",
            "https://github.com/example/fakepin/releases/download",
        )
        monkeypatch.setitem(
            pins.THIRD_PARTY_LICENSES,
            "fakeuvtool",
            _fake_uv_tool_entry(pins, "fakeuvtool"),
        )

        enumerated = checker.enumerate_pins(pins)
        assert not _uncovered(pins, enumerated)
        by_tool = {p.tool: p for p in enumerated}
        assert by_tool["fakepin"].project == "example/fakepin"
        assert by_tool["fakeuvtool"].ecosystem == checker.PYPI

    def test_a_pin_with_no_known_upstream_is_refused_not_skipped(
        self, pins, monkeypatch
    ):
        monkeypatch.setitem(pins.TOOL_VERSIONS, "fakepin", "v9.9.9")
        with pytest.raises(checker.PinEnumerationError, match="fakepin"):
            checker.enumerate_pins(pins)

    def test_a_half_applied_bump_is_refused(self, pins, monkeypatch):
        monkeypatch.setitem(pins.TOOL_VERSIONS, "grype", "v0.999.0")
        with pytest.raises(checker.PinEnumerationError, match="half-applied"):
            checker.enumerate_pins(pins)

    def test_every_pin_shaped_module_global_is_a_pin_source(self, pins):
        """A pin kept under a new module-level name must be read, not missed."""
        unread = _pin_shaped_globals(pins) - set(checker.PIN_SOURCES)
        assert not unread, (
            f"tool_downloads.py has {sorted(unread)}, which look like version pins "
            "that scripts/check_pinned_tool_versions.py does not read. Teach "
            "enumerate_pins about them and add them to PIN_SOURCES."
        )
        assert set(checker.PIN_SOURCES) <= set(vars(pins)), "a PIN_SOURCES name is gone"

    def test_a_new_pin_shaped_global_is_caught(self, pins, monkeypatch):
        monkeypatch.setattr(pins, "HADOLINT_VERSION", "v2.14.0", raising=False)
        assert "HADOLINT_VERSION" in _pin_shaped_globals(pins) - set(
            checker.PIN_SOURCES
        )


@pytest.mark.unit
class TestVersionComparison:
    @pytest.mark.parametrize(
        ("pinned", "latest", "status"),
        [
            ("v0.111.0", "v0.111.0", "current"),
            ("v1.179.0", "1.179.0", "current"),  # tag vs PyPI spelling
            ("1.2", "1.2.0", "current"),
            ("v0.69.3", "v0.75.0", "outdated"),
            ("1.9.4", "1.10.0", "outdated"),
            ("v0.69.9", "v0.69.10", "outdated"),
            ("1.2.0rc1", "1.2.0", "outdated"),
            ("3.3.26", "3.3.25", "ahead"),
            ("v0.69.10", "v0.69.9", "ahead"),
            ("libssh2-1.11.1", "libssh2-1.11.1", "current"),  # project-prefixed tag
            ("openssl-3.3.3", "openssl-3.6.0", "outdated"),
        ],
    )
    def test_compare(self, pinned, latest, status):
        assert checker.compare(pinned, latest) == status

    def test_numeric_comparison_disagrees_with_string_comparison(self):
        """The cases above that would be wrong as string comparisons, asserted so."""
        assert "1.10.0" < "1.9.4" and "v0.69.10" < "v0.69.9"
        assert checker.compare("1.9.4", "1.10.0") == "outdated"
        assert checker.compare("v0.69.9", "v0.69.10") == "outdated"

    def test_an_unparseable_version_raises(self):
        with pytest.raises(ValueError):
            checker.parse_version("latest")


def _pin(tool="grype", version="v1.0.0", ecosystem=None):
    return checker.Pin(
        tool=tool,
        version=version,
        ecosystem=ecosystem or checker.GITHUB,
        project=f"example/{tool}",
        pinned_in=("TOOL_VERSIONS",),
        kind=checker.RELEASE_BINARY,
    )


def _releases(
    *entries: "tuple[str, str | None] | dict[str, Any]",
) -> list[dict[str, Any]]:
    """A RubyGems versions answer: (number, required Ruby) pairs, or whole entries."""
    releases: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, dict):
            releases.append(entry)
        else:
            number, ruby_version = entry
            releases.append(
                {
                    "number": number,
                    "prerelease": False,
                    "platform": "ruby",
                    "ruby_version": ruby_version,
                }
            )
    return releases


def _as_gem_answer(lookup: Any) -> Any:
    """``lookup``'s version as the one release a RubyGems versions answer lists."""
    return lambda project: _releases((lookup(project), ">= 0"))


def _fetchers(latest: dict[str, str]):
    def lookup(project: str) -> str:
        value = latest[project.rsplit("/", 1)[-1]]
        if isinstance(value, Exception):
            raise value
        return value

    return {
        checker.GITHUB: lookup,
        checker.PYPI: lookup,
        checker.RUBYGEMS: _as_gem_answer(lookup),
    }


@pytest.mark.unit
class TestCheckWithMockedFetchers:
    def test_equal_behind_and_ahead(self):
        pins = [
            _pin("equal", "v1.0.0"),
            _pin("behind", "v1.9.0"),
            _pin("ahead", "2.0.0", checker.PYPI),
        ]
        results = checker.check(
            pins, _fetchers({"equal": "v1.0.0", "behind": "v1.10.0", "ahead": "1.5.0"})
        )
        assert {r.pin.tool: r.status for r in results} == {
            "equal": "current",
            "behind": "outdated",
            "ahead": "ahead",
        }
        assert {r.pin.tool: r.latest for r in results}["behind"] == "v1.10.0"

    def test_a_failed_lookup_is_an_error_not_current(self):
        results = checker.check(
            [_pin("down")], _fetchers({"down": OSError("rate limited")})
        )
        assert results[0].status == "error"
        assert "rate limited" in results[0].detail


class TestExitCode:
    def _run(self, monkeypatch, capsys, latest_for, argv):
        """Run main() over the real pins with every lookup answered by ``latest_for``."""

        def lookup(project: str) -> str:
            return latest_for(project)

        monkeypatch.setattr(
            checker,
            "DEFAULT_FETCHERS",
            {
                checker.GITHUB: lookup,
                checker.PYPI: lookup,
                checker.RUBYGEMS: _as_gem_answer(lookup),
            },
        )
        code = checker.main(argv)
        return code, capsys.readouterr().out

    def _pinned_versions(self) -> dict[str, str]:
        return {
            p.project: p.version
            for p in checker.enumerate_pins(checker.load_pins_module())
        }

    @pytest.mark.unit
    def test_all_current_exits_zero_with_the_flag(self, monkeypatch, capsys):
        versions = self._pinned_versions()
        code, out = self._run(
            monkeypatch, capsys, versions.__getitem__, ["--fail-on-outdated"]
        )
        assert code == 0, out
        assert "outdated" not in out

    @pytest.mark.integration
    def test_one_outdated_pin_exits_one_with_the_flag(self, monkeypatch, capsys):
        versions = self._pinned_versions()
        bumped = dict(versions, **{"anchore/grype": "v999.0.0"})
        code, out = self._run(
            monkeypatch, capsys, bumped.__getitem__, ["--fail-on-outdated"]
        )
        assert code == 1
        assert re.search(r"grype\s+v\S+\s+v999\.0\.0\s+outdated", out), out

    @pytest.mark.unit
    def test_a_stale_bundler_is_reported_outdated(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """bundler is looked up on RubyGems like cfn-nag; the lookup is a stub."""
        pins = checker.load_pins_module()
        versions = self._pinned_versions()
        asked: list[str] = []

        def latest(project: str) -> str:
            asked.append(project)
            return "99.0.0" if project == "bundler" else versions[project]

        code, out = self._run(monkeypatch, capsys, latest, ["--fail-on-outdated"])
        assert "bundler" in asked, "bundler's latest release was never looked up"
        assert code == 1, out
        pinned = re.escape(pins.BUNDLER_VERSION)
        assert re.search(rf"bundler\s+{pinned}\s+99\.0\.0\s+outdated", out), out
        assert "ARG BUNDLER_VERSION in Dockerfile:" in out
        assert "BUNDLED WITH" in out
        assert "required Ruby version" in out

    @pytest.mark.integration
    def test_outdated_without_the_flag_exits_zero(self, monkeypatch, capsys):
        versions = self._pinned_versions()
        bumped = dict(versions, **{"anchore/grype": "v999.0.0"})
        code, _ = self._run(monkeypatch, capsys, bumped.__getitem__, [])
        assert code == 0

    @pytest.mark.unit
    def test_ahead_does_not_fail(self, monkeypatch, capsys):
        versions = self._pinned_versions()
        older = dict(versions, semgrep="1.0.0")
        code, out = self._run(
            monkeypatch, capsys, older.__getitem__, ["--fail-on-outdated"]
        )
        assert code == 0
        assert "ahead" in out

    @pytest.mark.unit
    def test_a_lookup_error_exits_two_even_without_the_flag(self, monkeypatch, capsys):
        def broken(project: str) -> str:
            raise OSError("no route to host")

        code, out = self._run(monkeypatch, capsys, broken, [])
        assert code == 2
        assert "lookup failed" in out


def _gem_pin(tool: str, version: str) -> Any:
    return checker.Pin(
        tool=tool,
        version=version,
        ecosystem=checker.RUBYGEMS,
        project=tool,
        pinned_in=("x",),
        kind=checker.GEM,
    )


#: bundler's real releases around its pin, as RubyGems lists them (2026-10-12).
_BUNDLER_RELEASES = _releases(
    ("4.0.22", ">= 3.2.0"),
    ("2.7.2", ">= 3.2.0"),
    ("2.6.9", ">= 3.1.0"),
    ("2.5.23", ">= 3.0.0"),
    ("2.4.22", ">= 2.6.0"),
)


def _judged(pin: Any, releases: Any, ruby: "tuple[int, int]" = (3, 1)) -> Any:
    fetchers = {checker.RUBYGEMS: lambda project: releases}
    return checker.check([pin], fetchers, ruby=ruby)[0]


@pytest.mark.unit
class TestGemsAreJudgedByTheImagesRuby:
    """A gem is outdated only when a newer release the image's Ruby can run exists."""

    def test_a_newer_release_this_ruby_can_run_is_the_target(self) -> None:
        result = _judged(_gem_pin("bundler", "2.4.22"), _BUNDLER_RELEASES)
        assert (result.status, result.latest) == ("outdated", "2.6.9"), result
        assert "4.0.22" in result.note and ">= 3.2.0" in result.note, result.note
        assert "3.1" in result.note, result.note

    def test_the_newest_release_this_ruby_can_run_is_current(self) -> None:
        result = _judged(_gem_pin("bundler", "2.6.9"), _BUNDLER_RELEASES)
        assert (result.status, result.latest) == ("current", "2.6.9"), result
        assert "4.0.22" in result.note, "the newest release is still shown"

    def test_with_a_newer_ruby_the_newest_release_is_the_target(self) -> None:
        result = _judged(_gem_pin("bundler", "2.4.22"), _BUNDLER_RELEASES, (3, 3))
        assert (result.status, result.latest, result.note) == ("outdated", "4.0.22", "")

    def test_prereleases_and_other_platforms_are_never_the_target(self) -> None:
        releases = _releases(
            {
                "number": "2.7.0.pre.1",
                "prerelease": True,
                "platform": "ruby",
                "ruby_version": ">= 3.1.0",
            },
            {
                "number": "2.6.10",
                "prerelease": False,
                "platform": "java",
                "ruby_version": ">= 3.1.0",
            },
            ("2.6.9", ">= 3.1.0"),
        )
        result = _judged(_gem_pin("bundler", "2.6.9"), releases)
        assert (result.status, result.latest) == ("current", "2.6.9"), result

    def test_a_pin_newer_than_every_release_is_ahead(self) -> None:
        result = _judged(_gem_pin("bundler", "9.0.0"), _BUNDLER_RELEASES)
        assert result.status == "ahead", result

    @pytest.mark.parametrize(
        "requirement",
        ["between 3 and 4", ">= three", ">= 3.1.0, banana", "=> 3.1"],
    )
    def test_a_required_ruby_it_cannot_read_is_refused(self, requirement: str) -> None:
        releases = _releases(("2.7.0", requirement), ("2.6.9", ">= 3.1.0"))
        result = _judged(_gem_pin("bundler", "2.6.9"), releases)
        assert result.status == "error", result
        assert requirement in result.detail, result.detail

    def test_an_answer_that_is_not_a_versions_list_is_refused(self) -> None:
        result = _judged(_gem_pin("bundler", "2.6.9"), {"version": "4.0.22"})
        assert result.status == "error", result

    def test_the_bundler_pin_is_the_newest_release_the_image_can_run(self) -> None:
        """The real pin, against bundler's real releases: current, 4.0.22 noted."""
        pins = checker.enumerate_pins(checker.load_pins_module())
        pin = {p.tool: p for p in pins}["bundler"]
        ruby = checker.image_ruby(checker.enumerate_apt_pins())
        result = _judged(pin, _BUNDLER_RELEASES, ruby)
        assert (result.status, result.latest) == ("current", "2.6.9"), result
        assert "4.0.22" in result.note, result.note

    def test_cfn_nag_goes_through_the_same_path(self) -> None:
        pin = _gem_pin("cfn-nag", "0.8.10")
        newer_ruby = _judged(pin, _releases(("0.9.0", ">= 3.3"), ("0.8.10", ">= 2.5")))
        assert (newer_ruby.status, newer_ruby.latest) == ("current", "0.8.10")
        assert "0.9.0" in newer_ruby.note
        runnable = _judged(pin, _releases(("0.9.0", ">= 2.5"), ("0.8.10", ">= 2.5")))
        assert (runnable.status, runnable.latest) == ("outdated", "0.9.0")

    @pytest.mark.parametrize(
        ("requirement", "admits"),
        [
            (None, True),
            ("", True),
            (">= 0", True),
            (">= 3.1.0", True),
            (">= 3.1", True),
            (">= 3.2.0", False),
            ("> 3.1", False),
            ("< 3.2", True),
            ("< 3.1", False),
            ("<= 3.1.0", True),
            ("= 3.1", True),
            ("3.1", True),
            ("!= 3.1.0", False),
            ("~> 2.2", False),
            ("~> 3.0", True),
            ("~> 3.1.0", True),
            ("~> 3.0.1", False),
            ("~> 3", True),
            (">= 2.3.0, < 4", True),
            (">= 2.3.0, < 3.1", False),
        ],
    )
    def test_required_ruby_against_ruby_3_1(
        self, requirement: str | None, admits: bool
    ) -> None:
        assert checker.ruby_admits(requirement, (3, 1)) is admits

    def test_the_image_ruby_is_read_from_its_apt_pin(self) -> None:
        pinned = re.search(
            r"\bruby=(?:\d+:)?(\d+)\.(\d+)\b",
            DOCKERFILE.read_text(encoding="utf-8"),
        )
        assert pinned, "the Dockerfile installs no pinned ruby"
        expected = (int(pinned.group(1)), int(pinned.group(2)))
        assert checker.image_ruby(checker.enumerate_apt_pins()) == expected

    @pytest.mark.parametrize(
        "apt_pins",
        [
            [],
            [("ruby-dev", "1:3.1")],
            [("ruby", "1:latest")],
        ],
        ids=["no ruby pin", "only ruby-dev", "no major.minor"],
    )
    def test_a_ruby_pin_it_cannot_read_refuses_the_run(
        self,
        apt_pins: "list[tuple[str, str]]",
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        fake = [checker.AptPin(name, version, (1,)) for name, version in apt_pins]
        monkeypatch.setattr(checker, "enumerate_apt_pins", lambda *a, **k: fake)
        monkeypatch.setattr(checker, "apt_indexes", lambda *a, **k: [])
        assert checker.main([]) == checker.EXIT_ERROR
        err = capsys.readouterr().err
        assert "ruby" in err and "Dockerfile" in err, err

    def test_fail_on_outdated_fails_only_for_a_release_the_image_can_run(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        pins = checker.enumerate_pins(checker.load_pins_module())
        versions = {p.project: p.version for p in pins}
        bundler = versions["bundler"]

        def run(bundler_releases: "list[dict[str, Any]]") -> "tuple[int, str]":
            def gem(project: str) -> "list[dict[str, Any]]":
                if project == "bundler":
                    return bundler_releases
                return _releases((versions[project], ">= 0"))

            monkeypatch.setattr(
                checker,
                "DEFAULT_FETCHERS",
                {
                    checker.GITHUB: versions.__getitem__,
                    checker.PYPI: versions.__getitem__,
                    checker.RUBYGEMS: gem,
                },
            )
            code = checker.main(["--fail-on-outdated"])
            return code, capsys.readouterr().out

        code, out = run(_releases(("99.0.0", ">= 99.0"), (bundler, ">= 2.6.0")))
        assert code == checker.EXIT_OK, out
        assert re.search(rf"bundler\s+{re.escape(bundler)}\s+\S+\s+current", out), out
        assert "99.0.0" in out and ">= 99.0" in out, "the newest release is shown"

        code, out = run(
            _releases(
                ("99.0.0", ">= 99.0"), ("98.0.0", ">= 3.0"), (bundler, ">= 2.6.0")
            )
        )
        assert code == checker.EXIT_OUTDATED, out
        assert re.search(rf"bundler\s+{re.escape(bundler)}\s+98\.0\.0\s+outdated", out)


@pytest.mark.integration
class TestBumpGuidance:
    def _steps(self, pins, tool: str, latest: str) -> str:
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}[tool]
        return "\n".join(
            checker.bump_steps(pins, checker.Result(pin, latest, "outdated"))
        )

    def test_a_release_binary_names_every_table(self, pins):
        steps = self._steps(pins, "grype", "v9.0.0")
        for needle in (
            'TOOL_VERSIONS["grype"] -> v9.0.0',
            "_DIGESTS:",
            "_EXECUTABLE_DIGESTS:",
            'THIRD_PARTY_LICENSES["grype"].version -> v9.0.0',
            '_THIRD_PARTY_HASHES["grype commit"]',
            "gh api repos/anchore/grype/commits/v9.0.0",
            "ARG GRYPE_VERSION in Dockerfile:",
        ):
            assert needle in steps, f"{needle!r} missing from:\n{steps}"

    def test_an_unversioned_asset_names_digests_taken_at(self, pins):
        assert '_DIGESTS_TAKEN_AT["opengrep"]' in self._steps(
            pins, "opengrep", "v9.0.0"
        )

    def test_a_uv_tool_pin_names_its_url_pinned_license_files(self, pins):
        steps = self._steps(pins, "semgrep", "v9.0.0")
        assert '_THIRD_PARTY_HASHES["semgrep/LICENSE"]' in steps
        assert '_THIRD_PARTY_HASHES["semgrep/COPYRIGHT"]' in steps
        assert "TOOL_VERSIONS" not in steps

    def test_the_report_points_at_guidance_that_exists(self, pins):
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}["trivy"]
        report = checker.render_report(
            pins, [checker.Result(pin, "v9.0.0", "outdated")], markdown=True
        )
        assert '"Bumping a version"' in report and '"Adding a tool"' in report
        source = PINS_FILE.read_text(encoding="utf-8")
        assert "Bumping a version" in source
        assert "# Adding a tool" in source
        assert "check_pinned_tool_versions.py" in source


# ---------------------------------------------------------------------------
# Every value a bump changes is named in its steps
#
# What a bump of one pin changes is read here from the module's tables, the
# Dockerfile and the tracked files, independently of bump_steps. The steps for each
# real pin must name all of it. A table keyed by a tool that is not named in its
# steps, and not listed below with the reason a bump leaves it alone, fails the test,
# so a value added to the module later cannot be left out of the guidance unnoticed.
# ---------------------------------------------------------------------------

#: Module tables keyed by a tool or one of its assets whose entry a version bump
#: leaves as it is.
_TABLES_A_BUMP_LEAVES = {
    "_ASSET_TABLES": "maps the tool to its asset table, which its own step names",
    "_RELEASE_BASE_URLS": "the project's release download prefix, for every version",
    "_BARE_EXECUTABLE_TOOLS": "whether the release asset is the executable itself",
}

#: Dockerfile ``ARG <NAME>_VERSION`` lines that pin a version this script does not
#: track, by design. Each is a version pin all the same, so the reason says how it is
#: bumped instead. Empty: every such ARG belongs to a pin. A new one fails the test
#: below until a pin owns it or its reason is written here.
_UNTRACKED_DOCKERFILE_VERSION_ARGS: dict[str, str] = {}

PINS_REL = PINS_FILE.relative_to(REPO_ROOT).as_posix()
GEMFILE_REL = "automated_security_helper/assets/Gemfile"
GEMFILE_LOCK = REPO_ROOT / f"{GEMFILE_REL}.lock"


def _kind(pins: Any, tool: str) -> str:
    """The kind of pin ``tool`` is, read from the module's tables."""
    if tool in _GEM_PINS:
        return "gem"
    if tool in getattr(pins, "RULES_BUNDLES", {}):
        return "rules-bundle"
    if tool in pins.TOOL_VERSIONS:
        return "release-binary"
    entry = pins.THIRD_PARTY_LICENSES.get(tool)
    if entry is not None and entry.distribution:
        return "uv-tool"
    if entry is not None and getattr(entry, "bundled_in", None):
        return "bundled-library"
    return "unknown"


def _archives(pins: Any, tool: str) -> list[str]:
    """The file names of what a bump of ``tool`` downloads."""
    names = list(pins._ASSET_TABLES.get(tool, {}).values())
    bundle = getattr(pins, "RULES_BUNDLES", {}).get(tool)
    if bundle is not None:
        names.append(bundle.url.rsplit("/", 1)[-1])
    return names


def _pinned_digests(pins: Any, tool: str) -> set[str]:
    """Every digest and commit the module pins for ``tool``; a bump replaces each."""
    values: set[str] = set()
    for archive in _archives(pins, tool):
        for table in ("_DIGESTS", "_EXECUTABLE_DIGESTS", "_BUNDLE_CONTENTS_DIGESTS"):
            value = getattr(pins, table, {}).get(archive)
            if value:
                values.add(value)
    for key, value in pins._THIRD_PARTY_HASHES.items():
        if key == f"{tool} commit" or key.startswith(f"{tool}/"):
            values.add(value)
    return values


def _spellings(digest: str) -> set[str]:
    """``digest`` as hex, and as the SRI string nix writes for a SHA256."""
    spellings = {digest}
    if len(digest) == 64:
        sri = base64.b64encode(bytes.fromhex(digest)).decode("ascii")
        spellings.add(f"sha256-{sri}")
    return spellings


@functools.lru_cache(maxsize=1)
def _tracked_text() -> dict[str, str]:
    """Every tracked text file but the pins module, by repository-relative path."""
    listed = subprocess.run(  # nosec B603 B607 - git over this checkout
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
        timeout=60,
    ).stdout
    text: dict[str, str] = {}
    for raw in listed.split(b"\0"):
        name = raw.decode("utf-8")
        path = REPO_ROOT / name
        if not name or name == PINS_REL or path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" not in data[:8192]:
            text[name] = data.decode("utf-8", "replace")
    return text


def _copies_elsewhere(pins: Any, tool: str) -> list[str]:
    """Tracked files outside the pins module that hold one of ``tool``'s digests."""
    spellings = {s for d in _pinned_digests(pins, tool) for s in _spellings(d)}
    return sorted(
        name
        for name, text in _tracked_text().items()
        if any(s in text for s in spellings)
    )


def _dockerfile_args(tool: str) -> list[str]:
    stem = tool.upper().replace("-", "_")
    return [
        f"Dockerfile:{number}"
        for number, line in enumerate(
            DOCKERFILE.read_text(encoding="utf-8").splitlines(), start=1
        )
        if re.match(rf"\s*ARG\s+{re.escape(stem)}_VERSION=", line)
    ]


def _tables_keyed_by(pins: Any, tool: str) -> list[str]:
    """Module tables with an entry for ``tool`` or one of its downloads."""
    archives = set(_archives(pins, tool))
    names = []
    for name, value in vars(pins).items():
        if name.startswith("__") or not isinstance(value, (dict, set, frozenset)):
            continue
        for key in value:
            if isinstance(key, str) and (
                key == tool
                or key in archives
                or key.startswith((f"{tool} ", f"{tool}/"))
            ):
                names.append(name)
                break
    return sorted(n for n in names if n not in _TABLES_A_BUMP_LEAVES)


def _bundle_version_name(tool: str) -> str | None:
    """The name RULES_BUNDLES[tool]'s ``version=`` is written as, read from the text."""
    source = PINS_FILE.read_text(encoding="utf-8")
    match = re.search(
        rf'"{re.escape(tool)}": RulesBundle\((?:(?!RulesBundle\().)*?'
        r"version=([A-Za-z_][A-Za-z0-9_]*),",
        source,
        re.DOTALL,
    )
    return match.group(1) if match else None


def _gem_copies(tool: str, version: str) -> list[str]:
    """Where assets/Gemfile and its lockfile repeat a gem pin's version."""
    copies = []
    gemfile = (REPO_ROOT / GEMFILE_REL).read_text(encoding="utf-8")
    gem_line = rf'^gem "{re.escape(tool)}", "{re.escape(version)}"'
    if re.search(gem_line, gemfile, re.MULTILINE):
        copies.append(GEMFILE_REL)
    lock = GEMFILE_LOCK.read_text(encoding="utf-8")
    spec_line = rf"^    {re.escape(tool)} \({re.escape(version)}\)$"
    if re.search(spec_line, lock, re.MULTILINE):
        copies.append(f"{GEMFILE_REL}.lock")
    bundled_with = re.search(r"^BUNDLED WITH\n\s+(\S+)", lock, re.MULTILINE)
    if tool == "bundler" and bundled_with and bundled_with.group(1) == version:
        copies += [f"{GEMFILE_REL}.lock", "BUNDLED WITH"]
    return copies


def _needles(pins: Any, tool: str, version: str) -> list[str]:
    """Text a bump of ``tool`` from ``version`` has to name, one per value it changes."""
    bare = version.lstrip("v")
    kind = _kind(pins, tool)
    needles: list[str] = []
    if kind == "gem":
        needles.append(_GEM_PINS[tool])
        needles += _gem_copies(tool, version)
    if kind == "release-binary":
        needles.append(f'TOOL_VERSIONS["{tool}"]')
        table = pins._ASSET_TABLES[tool]
        if all(bare in name for name in table.values()):
            # The module-level name of the tool's asset table: its file names move.
            needles.append(next(n for n, v in vars(pins).items() if v is table))
        if tool in pins._DIGESTS_TAKEN_AT:
            needles.append(f'_DIGESTS_TAKEN_AT["{tool}"]')
    if kind == "rules-bundle":
        needles.append(f'RULES_BUNDLES["{tool}"]')
        constant = _bundle_version_name(tool)
        if constant:
            needles.append(constant)
        needles += ["rules_bundles.extract_bundle", "contents_digest"]
    for archive in _archives(pins, tool):
        for table in ("_DIGESTS", "_EXECUTABLE_DIGESTS", "_BUNDLE_CONTENTS_DIGESTS"):
            if archive in getattr(pins, table, {}):
                needles.append(
                    f'{table}["{archive}"]' if kind == "rules-bundle" else f"{table}:"
                )
    entry = pins.THIRD_PARTY_LICENSES.get(tool)
    if entry is not None:
        needles.append(f'THIRD_PARTY_LICENSES["{tool}"].version')
        needles += [
            f'_THIRD_PARTY_HASHES["{key}"]'
            for key in pins._THIRD_PARTY_HASHES
            if key == f"{tool} commit" or key.startswith(f"{tool}/")
        ]
        needles += [f.name for f in entry.files if not f.url]
    needles += _dockerfile_args(tool)
    needles += _copies_elsewhere(pins, tool)
    needles += _tables_keyed_by(pins, tool)
    needles += [f"git grep -nF {bare}", "ferret-scan line ranges"]
    return list(dict.fromkeys(needles))


def _steps_text(pins: Any, pin: Any) -> str:
    latest = "v9.9.9" if pin.version.startswith("v") else "9.9.9"
    return "\n".join(checker.bump_steps(pins, checker.Result(pin, latest, "outdated")))


def _unnamed(pins: Any, pin: Any, steps: str) -> list[str]:
    needles = _needles(pins, pin.tool, pin.version)
    return [needle for needle in needles if needle not in steps]


# Every pin the module carries, read by this file rather than by the script, so a pin
# the script does not enumerate is still a case below, and fails.
_EXPECTED_PINS = sorted(_expected_pins(checker.load_pins_module()).items())


class TestBumpStepsNameEveryValueABumpChanges:
    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("tool", "version"),
        [(tool, version) for tool, (version, _) in _EXPECTED_PINS],
        ids=[tool for tool, _ in _EXPECTED_PINS],
    )
    def test_every_value_is_named(self, pins: Any, tool: str, version: str) -> None:
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}.get(tool)
        assert pin is not None, (
            f"{tool} {version} ({_kind(pins, tool)}) is pinned, but the script "
            "reports no pin for it, so a bump gets no steps and none of "
            f"{_needles(pins, tool, version)}"
        )
        steps = _steps_text(pins, pin)
        unnamed = _unnamed(pins, pin, steps)
        assert not unnamed, (
            f"{tool} ({_kind(pins, tool)}): the bump steps do not name {unnamed}:\n"
            f"{steps}"
        )

    @pytest.mark.unit
    def test_every_pin_is_a_known_kind_and_every_kind_is_tested(
        self, pins: Any
    ) -> None:
        kinds = {p.tool: _kind(pins, p.tool) for p in checker.enumerate_pins(pins)}
        assert "unknown" not in kinds.values(), kinds
        assert set(kinds.values()) == {
            "gem",
            "release-binary",
            "rules-bundle",
            "uv-tool",
        }
        # The script's own list: each kind it knows has a real pin above, so the
        # parametrized test covers it, and each has its own steps. The one kind with
        # no shipped pin today is the bundled library (its entries left with the
        # GuardDog plugin and return with it); TestBundledLibrariesAreListedButNotLookedUp
        # covers that kind on planted entries until then.
        assert set(checker.PIN_KINDS) == set(kinds.values()) | {checker.BUNDLED_LIBRARY}
        assert set(checker._KIND_STEPS) == set(checker.PIN_KINDS)

    @pytest.mark.unit
    def test_each_pin_reports_the_kind_its_tables_give(self, pins: Any) -> None:
        for pin in checker.enumerate_pins(pins):
            assert pin.kind == _kind(pins, pin.tool), pin

    @pytest.mark.unit
    def test_a_license_entry_no_download_pin_names_is_refused(
        self, pins: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A new kind of pin: refused when read, not given half its steps."""
        entry = dataclasses.replace(
            pins.THIRD_PARTY_LICENSES["actionlint"], tool="fakelicensed"
        )
        monkeypatch.setitem(pins.THIRD_PARTY_LICENSES, "fakelicensed", entry)
        with pytest.raises(checker.PinEnumerationError, match="PIN_KINDS"):
            checker.enumerate_pins(pins)

    @pytest.mark.unit
    def test_a_tool_in_both_download_tables_is_refused(
        self, pins: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bundle = pins.RULES_BUNDLES["aws-guard-rules-registry"]
        monkeypatch.setitem(pins.RULES_BUNDLES, "grype", bundle)
        with pytest.raises(checker.PinEnumerationError, match="pick one"):
            checker.enumerate_pins(pins)

    @pytest.mark.unit
    def test_a_half_applied_rules_bundle_bump_is_refused(
        self, pins: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bundle = pins.RULES_BUNDLES["aws-guard-rules-registry"]
        monkeypatch.setitem(
            pins.RULES_BUNDLES,
            "aws-guard-rules-registry",
            dataclasses.replace(bundle, version="9.9.9"),
        )
        with pytest.raises(checker.PinEnumerationError, match="half-applied"):
            checker.enumerate_pins(pins)

    @pytest.mark.unit
    def test_a_pin_of_another_kind_has_no_steps(self, pins: Any) -> None:
        pin = dataclasses.replace(_pin(), kind="future")
        with pytest.raises(ValueError, match="'future'"):
            checker.bump_steps(pins, checker.Result(pin, "v9.9.9", "outdated"))

    @pytest.mark.integration
    def test_the_rules_registry_names_its_release_and_both_digests(
        self, pins: Any
    ) -> None:
        """The values a bump of the Guard Rules Registry changes, by name."""
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}[
            "aws-guard-rules-registry"
        ]
        steps = _steps_text(pins, pin)
        for needle in (
            "_CFN_GUARD_RULES_RELEASE -> 9.9.9",
            '_DIGESTS["ruleset-build-v1.0.2.zip"]',
            '_BUNDLE_CONTENTS_DIGESTS["ruleset-build-v1.0.2.zip"]',
            "ruleset-build-v9.9.9.zip",
            "rules_bundles.extract_bundle",
            'THIRD_PARTY_LICENSES["aws-guard-rules-registry"].version -> 9.9.9',
            "ferret-scan line ranges",
        ):
            assert needle in steps, f"{needle!r} missing from:\n{steps}"

    @pytest.mark.integration
    def test_the_needles_are_not_vacuous(self, pins: Any) -> None:
        """Positive control: what the test above requires, for three pins."""
        expected = {tool: version for tool, (version, _) in _EXPECTED_PINS}
        registry = _needles(
            pins, "aws-guard-rules-registry", expected["aws-guard-rules-registry"]
        )
        assert "_CFN_GUARD_RULES_RELEASE" in registry
        assert '_BUNDLE_CONTENTS_DIGESTS["ruleset-build-v1.0.2.zip"]' in registry
        assert len(registry) >= 10, registry
        cfn_guard = _needles(pins, "cfn-guard", expected["cfn-guard"])
        assert "nix/cfn-guard.nix" in cfn_guard
        assert any(n.startswith("Dockerfile:") for n in cfn_guard), cfn_guard
        bundler = _needles(pins, "bundler", expected["bundler"])
        assert "BUNDLER_VERSION" in bundler and "BUNDLED WITH" in bundler, bundler
        assert any(n.startswith("Dockerfile:") for n in bundler), bundler

    @pytest.mark.unit
    def test_the_bundler_pin_and_its_copies_agree(self, pins: Any) -> None:
        """The Dockerfile ARG and the lockfile's BUNDLED WITH are the same pin."""
        arg = re.search(
            r'^ARG BUNDLER_VERSION="([^"]+)"$',
            DOCKERFILE.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        bundled_with = re.search(
            r"^BUNDLED WITH\n\s+(\S+)$",
            GEMFILE_LOCK.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        assert arg and bundled_with
        assert arg.group(1) == bundled_with.group(1) == pins.BUNDLER_VERSION, (
            f"BUNDLER_VERSION is {pins.BUNDLER_VERSION}, the Dockerfile ARG "
            f"{arg.group(1)} and Gemfile.lock's BUNDLED WITH {bundled_with.group(1)}; "
            "a bundler bump is half-applied"
        )

    @pytest.mark.integration
    def test_a_step_left_out_is_caught(self, pins: Any) -> None:
        """Negative control: the same steps with one dropped fail the check."""
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}["grype"]
        steps = [
            s
            for s in checker.bump_steps(pins, checker.Result(pin, "v9.9.9", "outdated"))
            if "_EXECUTABLE_DIGESTS" not in s
        ]
        assert "_EXECUTABLE_DIGESTS:" in _unnamed(pins, pin, "\n".join(steps))

    @pytest.mark.integration
    def test_a_new_table_keyed_by_a_tool_is_caught(
        self, pins: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Negative control: a value added to the module later needs a step."""
        monkeypatch.setattr(pins, "_GRYPE_SIGNATURES", {"grype": "sig"}, raising=False)
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}["grype"]
        assert "_GRYPE_SIGNATURES" in _unnamed(pins, pin, _steps_text(pins, pin))

    @pytest.mark.unit
    def test_every_dockerfile_version_arg_belongs_to_a_pin(self, pins: Any) -> None:
        """A version pinned in the Dockerfile that no pin owns would get no step."""
        stems = {p.tool.upper().replace("-", "_") for p in checker.enumerate_pins(pins)}
        args = re.findall(
            r"^\s*ARG\s+([A-Z0-9_]+)_VERSION=",
            DOCKERFILE.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        unowned = sorted(
            {f"{a}_VERSION" for a in args if a not in stems}
            - set(_UNTRACKED_DOCKERFILE_VERSION_ARGS)
        )
        assert not unowned, unowned

    @pytest.mark.unit
    def test_an_apt_pin_names_the_new_version_and_every_line(self) -> None:
        """The Dockerfile's apt pins: the report gives the edit and every line."""
        pin = checker.enumerate_apt_pins()[0]
        report = checker.render_apt_report(
            [checker.AptResult(pin, "amd64", "9.9.9-1", "outdated")]
        )
        assert f"{pin.package}={pin.version} -> {pin.package}=9.9.9-1" in report
        for number in pin.lines:
            assert f"Dockerfile:{number}" in report


@pytest.mark.unit
class TestWorkflow:
    @pytest.fixture(scope="class")
    def workflow(self) -> dict[str, Any]:
        assert WORKFLOW.is_file(), f"{WORKFLOW} is missing"
        return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    def test_it_runs_weekly_and_on_demand(self, workflow):
        # PyYAML reads the bare key `on` as the boolean True.
        triggers = workflow.get("on", workflow.get(True))
        assert set(triggers) == {"schedule", "workflow_dispatch"}
        crons = [entry["cron"] for entry in triggers["schedule"]]
        assert len(crons) == 1
        fields = crons[0].split()
        assert len(fields) == 5
        assert fields[2] == "*" and fields[3] == "*" and fields[4] != "*", (
            f"{crons[0]!r} is not a once-a-week schedule"
        )

    def test_it_calls_the_script_and_fails_on_outdated(self, workflow):
        runs = [
            step.get("run", "")
            for job in workflow["jobs"].values()
            for step in job["steps"]
        ]
        script_runs = [r for r in runs if "scripts/check_pinned_tool_versions.py" in r]
        assert len(script_runs) == 1
        assert "--fail-on-outdated" in script_runs[0]
        assert "GITHUB_STEP_SUMMARY" in script_runs[0]
        assert 'exit "$status"' in script_runs[0]

    def test_permissions_are_read_only(self, workflow):
        assert workflow["permissions"] == {"contents": "read"}
        for job in workflow["jobs"].values():
            assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}

    def test_it_opens_no_issue_or_pull_request(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        for forbidden in ("gh issue", "gh pr", "create-pull-request", "issues: write"):
            assert forbidden not in text

    def test_every_action_is_pinned_by_sha(self, workflow):
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", step["uses"])


@pytest.mark.unit
class TestOnlyAllowlistedHttpsUrlsAreFetched:
    """_get_json refuses anything but https to the three upstream APIs, before opening."""

    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "http://api.github.com/repos/anchore/syft/releases/latest",
            "http://pypi.org/pypi/bandit/json",
            "ftp://pypi.org/pypi/bandit/json",
            "https://example.com/pypi/bandit/json",
            "https://pypi.org.example.com/pypi/bandit/json",
            "https://user:secret@pypi.org/pypi/bandit/json",  # pragma: allowlist secret
            "https://pypi.org:8443/pypi/bandit/json",
        ],
    )
    def test_a_url_outside_the_allowlist_is_refused_unopened(self, url, monkeypatch):
        opened: list[Any] = []
        for handler, method in (
            (urllib.request.HTTPSHandler, "https_open"),
            (urllib.request.HTTPHandler, "http_open"),
        ):
            monkeypatch.setattr(handler, method, lambda *a: opened.append(a) or None)
        with pytest.raises(ValueError, match="refusing to fetch"):
            checker._get_json(url)
        assert opened == [], f"{url} reached the transport"

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.github.com/repos/anchore/syft/releases/latest",
            "https://pypi.org/pypi/bandit/json",
            "https://rubygems.org/api/v1/versions/cfn-nag.json",
        ],
    )
    def test_positive_control_each_upstream_api_is_opened(self, url, monkeypatch):
        import email.message
        import io
        import urllib.response

        opened: list[str] = []

        def fake_https_open(handler, request):
            opened.append(request.full_url)
            response = urllib.response.addinfourl(
                io.BytesIO(b'{"ok": true}'), email.message.Message(), url, 200
            )
            response.msg = "OK"
            return response

        monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", fake_https_open)
        assert checker._get_json(url) == {"ok": True}
        assert opened == [url]


@pytest.mark.unit
class TestBundledLibrariesAreListedButNotLookedUp:
    """A library a wheel bundles cannot be bumped on its own (its version is the
    wheel's), so comparing it with its project's latest release would make the
    scheduled check red with a bump nobody can make. It is listed as held instead.

    The shipped inventory carries no such entry today. The entries this class once
    named by hand (pygit2 and the libraries its wheel bundles: libgit2, libssh2,
    OpenSSL and PCRE) arrived with the GuardDog community plugin and left with it
    when that plugin moved to its own pull request for licensing review (the
    "refactor(plugins): move the hadolint and guarddog scanner plugins to a
    separate PR" step of the #727 squash), while ``ThirdPartyLicense.bundled_in``
    and the checker's held arm stayed. So each test plants an entry of the shape it
    checks into its own copy of the pins module, and reads the shipped table only
    for whatever bundled entries it does carry, so the tests hold whether or not
    those pins are back.
    """

    WHEEL = "planted-wheel"
    LIBRARY = "planted-library"

    @staticmethod
    def _plant(pins: Any, tool: str, **fields: Any) -> Any:
        """Add a license entry for ``tool`` to this test's copy of the module."""
        entry = pins.ThirdPartyLicense(
            tool=tool,
            version=fields.pop("version", "1.2.3"),
            license="MIT",
            repository=f"https://github.com/example/{tool}",
            commit="0" * 40,
            files=(pins.LicenseFile("LICENSE"),),
            **fields,
        )
        pins.THIRD_PARTY_LICENSES[tool] = entry
        return entry

    def test_each_bundled_entry_enumerates_as_bundled(self, pins):
        self._plant(pins, self.LIBRARY, bundled_in=self.WHEEL)
        bundled = {
            tool: entry
            for tool, entry in pins.THIRD_PARTY_LICENSES.items()
            if getattr(entry, "bundled_in", None)
        }
        assert self.LIBRARY in bundled
        by_tool = {p.tool: p for p in checker.enumerate_pins(pins)}
        for tool, entry in bundled.items():
            assert by_tool[tool].ecosystem == checker.BUNDLED, tool
            assert by_tool[tool].project == entry.bundled_in, tool
            assert by_tool[tool].kind == checker.BUNDLED_LIBRARY, tool
            assert by_tool[tool].kind == _kind(pins, tool), tool

    def test_a_bump_of_the_wheel_names_the_library_as_following_it(
        self, pins, monkeypatch
    ):
        """bump_steps has steps for the bundled kind, and they name the wheel."""
        self._plant(pins, self.LIBRARY, bundled_in=self.WHEEL)
        monkeypatch.setattr(checker, "_copy_steps", lambda *a, **k: [])
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}[self.LIBRARY]
        steps = checker.bump_steps(pins, checker.Result(pin, "9.9.9", "outdated"))
        assert steps, "a bundled-library pin has no steps"
        assert (
            self.WHEEL in steps[0]
            and f'THIRD_PARTY_LICENSES["{self.LIBRARY}"]' in steps[0]
        )
        assert "gh api" not in " ".join(steps)

    def test_a_bundled_pin_is_held_and_never_fetched(self, pins):
        self._plant(pins, self.LIBRARY, bundled_in=self.WHEEL)
        bundled = [
            p for p in checker.enumerate_pins(pins) if p.ecosystem == checker.BUNDLED
        ]
        assert [p.tool for p in bundled if p.tool == self.LIBRARY] == [self.LIBRARY]

        def refuse(project):
            raise AssertionError(f"looked up {project}")

        results = checker.check(bundled, {checker.GITHUB: refuse, checker.PYPI: refuse})
        assert {r.status for r in results} == {"held"}
        assert {r.latest for r in results} == {None}
        planted = [r for r in results if r.pin.tool == self.LIBRARY]
        assert planted and self.WHEEL in planted[0].note
        assert checker.exit_code(results, fail_on_outdated=True) == checker.EXIT_OK

    def test_the_wheel_that_bundles_it_is_an_ordinary_pin(self, pins):
        """The wheel that sets the bundled versions is looked up like any uv-tool pin."""
        self._plant(pins, self.WHEEL, distribution=self.WHEEL)
        self._plant(pins, self.LIBRARY, bundled_in=self.WHEEL)
        by_tool = {p.tool: p for p in checker.enumerate_pins(pins)}
        assert by_tool[self.WHEEL].ecosystem == checker.PYPI
        assert by_tool[self.LIBRARY].ecosystem == checker.BUNDLED

        def refuse(project):
            raise AssertionError(f"looked up {project} on GitHub")

        looked_up: list[str] = []

        def newest(project):
            looked_up.append(project)
            return "9.9.9"

        results = checker.check(
            [by_tool[self.WHEEL]], {checker.GITHUB: refuse, checker.PYPI: newest}
        )
        assert looked_up == [self.WHEEL]
        assert [(r.status, r.latest) for r in results] == [("outdated", "9.9.9")]
