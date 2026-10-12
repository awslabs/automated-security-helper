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
        ecosystem = checker.PYPI if entry.distribution else checker.GITHUB
        expected[tool] = (entry.version, ecosystem)
    expected[checker.CFN_NAG_GEM] = (pins.CFN_NAG_GEM_VERSION, checker.RUBYGEMS)
    return expected


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


class TestEnumerationCoversEveryPin:
    def test_every_pin_in_the_module_is_enumerated(self, pins):
        enumerated = checker.enumerate_pins(pins)
        assert not _uncovered(pins, enumerated), _uncovered(pins, enumerated)

        tools = {p.tool for p in enumerated}
        assert set(pins.TOOL_VERSIONS) <= tools
        assert set(pins.THIRD_PARTY_LICENSES) <= tools
        assert checker.CFN_NAG_GEM in tools

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


def _fetchers(latest: dict[str, str]):
    def lookup(project: str) -> str:
        value = latest[project.rsplit("/", 1)[-1]]
        if isinstance(value, Exception):
            raise value
        return value

    return {checker.GITHUB: lookup, checker.PYPI: lookup, checker.RUBYGEMS: lookup}


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
            {checker.GITHUB: lookup, checker.PYPI: lookup, checker.RUBYGEMS: lookup},
        )
        code = checker.main(argv)
        return code, capsys.readouterr().out

    def _pinned_versions(self) -> dict[str, str]:
        return {
            p.project: p.version
            for p in checker.enumerate_pins(checker.load_pins_module())
        }

    def test_all_current_exits_zero_with_the_flag(self, monkeypatch, capsys):
        versions = self._pinned_versions()
        code, out = self._run(
            monkeypatch, capsys, versions.__getitem__, ["--fail-on-outdated"]
        )
        assert code == 0, out
        assert "outdated" not in out

    def test_one_outdated_pin_exits_one_with_the_flag(self, monkeypatch, capsys):
        versions = self._pinned_versions()
        bumped = dict(versions, **{"anchore/grype": "v999.0.0"})
        code, out = self._run(
            monkeypatch, capsys, bumped.__getitem__, ["--fail-on-outdated"]
        )
        assert code == 1
        assert re.search(r"grype\s+v\S+\s+v999\.0\.0\s+outdated", out), out

    def test_outdated_without_the_flag_exits_zero(self, monkeypatch, capsys):
        versions = self._pinned_versions()
        bumped = dict(versions, **{"anchore/grype": "v999.0.0"})
        code, _ = self._run(monkeypatch, capsys, bumped.__getitem__, [])
        assert code == 0

    def test_ahead_does_not_fail(self, monkeypatch, capsys):
        versions = self._pinned_versions()
        older = dict(versions, semgrep="1.0.0")
        code, out = self._run(
            monkeypatch, capsys, older.__getitem__, ["--fail-on-outdated"]
        )
        assert code == 0
        assert "ahead" in out

    def test_a_lookup_error_exits_two_even_without_the_flag(self, monkeypatch, capsys):
        def broken(project: str) -> str:
            raise OSError("no route to host")

        code, out = self._run(monkeypatch, capsys, broken, [])
        assert code == 2
        assert "lookup failed" in out


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
#: bumped instead.
_UNTRACKED_DOCKERFILE_VERSION_ARGS = {
    "BUNDLER_VERSION": (
        "the bundler the image installs the cfn-nag gems with. Not tracked by this "
        "checker, by design: it reads its pins from tool_downloads.py, and this "
        "version is set only in the Dockerfile, so tracking it would need a new kind "
        "of pin read from there. A bundler bump is a manual edit to this ARG."
    ),
}

PINS_REL = PINS_FILE.relative_to(REPO_ROOT).as_posix()
GEMFILE_REL = "automated_security_helper/assets/Gemfile"


def _kind(pins: Any, tool: str) -> str:
    """The kind of pin ``tool`` is, read from the module's tables."""
    if tool == checker.CFN_NAG_GEM:
        return "gem"
    if tool in getattr(pins, "RULES_BUNDLES", {}):
        return "rules-bundle"
    if tool in pins.TOOL_VERSIONS:
        return "release-binary"
    entry = pins.THIRD_PARTY_LICENSES.get(tool)
    if entry is not None and entry.distribution:
        return "uv-tool"
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


def _needles(pins: Any, pin: Any) -> list[str]:
    """Text a bump of ``pin`` has to name, one string per value it changes."""
    tool, bare = pin.tool, pin.version.lstrip("v")
    kind = _kind(pins, tool)
    needles: list[str] = []
    if kind == "gem":
        needles += ["CFN_NAG_GEM_VERSION", GEMFILE_REL, f"{GEMFILE_REL}.lock"]
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
    return [needle for needle in _needles(pins, pin) if needle not in steps]


_REAL_PINS = checker.enumerate_pins(checker.load_pins_module())


class TestBumpStepsNameEveryValueABumpChanges:
    @pytest.mark.parametrize("tool", [p.tool for p in _REAL_PINS])
    def test_every_value_is_named(self, pins: Any, tool: str) -> None:
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}[tool]
        steps = _steps_text(pins, pin)
        unnamed = _unnamed(pins, pin, steps)
        assert not unnamed, (
            f"{tool} ({_kind(pins, tool)}): the bump steps do not name {unnamed}:\n"
            f"{steps}"
        )

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
        # parametrized test covers it, and each has its own steps.
        assert set(checker.PIN_KINDS) == set(kinds.values())
        assert set(checker._KIND_STEPS) == set(checker.PIN_KINDS)

    def test_each_pin_reports_the_kind_its_tables_give(self, pins: Any) -> None:
        for pin in checker.enumerate_pins(pins):
            assert pin.kind == _kind(pins, pin.tool), pin

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

    def test_a_tool_in_both_download_tables_is_refused(
        self, pins: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bundle = pins.RULES_BUNDLES["aws-guard-rules-registry"]
        monkeypatch.setitem(pins.RULES_BUNDLES, "grype", bundle)
        with pytest.raises(checker.PinEnumerationError, match="pick one"):
            checker.enumerate_pins(pins)

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

    def test_a_pin_of_another_kind_has_no_steps(self, pins: Any) -> None:
        pin = dataclasses.replace(_pin(), kind="future")
        with pytest.raises(ValueError, match="'future'"):
            checker.bump_steps(pins, checker.Result(pin, "v9.9.9", "outdated"))

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

    def test_the_needles_are_not_vacuous(self, pins: Any) -> None:
        """Positive control: what the test above requires, for two pins."""
        by_tool = {p.tool: p for p in checker.enumerate_pins(pins)}
        registry = _needles(pins, by_tool["aws-guard-rules-registry"])
        assert "_CFN_GUARD_RULES_RELEASE" in registry
        assert '_BUNDLE_CONTENTS_DIGESTS["ruleset-build-v1.0.2.zip"]' in registry
        assert len(registry) >= 10, registry
        cfn_guard = _needles(pins, by_tool["cfn-guard"])
        assert "nix/cfn-guard.nix" in cfn_guard
        assert any(n.startswith("Dockerfile:") for n in cfn_guard), cfn_guard

    def test_a_step_left_out_is_caught(self, pins: Any) -> None:
        """Negative control: the same steps with one dropped fail the check."""
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}["grype"]
        steps = [
            s
            for s in checker.bump_steps(pins, checker.Result(pin, "v9.9.9", "outdated"))
            if "_EXECUTABLE_DIGESTS" not in s
        ]
        assert "_EXECUTABLE_DIGESTS:" in _unnamed(pins, pin, "\n".join(steps))

    def test_a_new_table_keyed_by_a_tool_is_caught(
        self, pins: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Negative control: a value added to the module later needs a step."""
        monkeypatch.setattr(pins, "_GRYPE_SIGNATURES", {"grype": "sig"}, raising=False)
        pin = {p.tool: p for p in checker.enumerate_pins(pins)}["grype"]
        assert "_GRYPE_SIGNATURES" in _unnamed(pins, pin, _steps_text(pins, pin))

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

    def test_an_apt_pin_names_the_new_version_and_every_line(self) -> None:
        """The Dockerfile's apt pins: the report gives the edit and every line."""
        pin = checker.enumerate_apt_pins()[0]
        report = checker.render_apt_report(
            [checker.AptResult(pin, "amd64", "9.9.9-1", "outdated")]
        )
        assert f"{pin.package}={pin.version} -> {pin.package}=9.9.9-1" in report
        for number in pin.lines:
            assert f"Dockerfile:{number}" in report


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
            "https://rubygems.org/api/v1/versions/cfn-nag/latest.json",
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
