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

No test here touches the network. Every lookup is a stub, and ``urlopen`` is
replaced with one that fails the test if anything reaches it.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import re
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

    monkeypatch.setattr(urllib.request, "urlopen", refuse)


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
    )


def _fetchers(latest: dict[str, str]):
    def lookup(project: str) -> str:
        value = latest[project.rsplit("/", 1)[-1]]
        if isinstance(value, Exception):
            raise value
        return value

    return dict.fromkeys(checker.DEFAULT_FETCHERS, lookup)


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
            dict.fromkeys(checker.DEFAULT_FETCHERS, lookup),
        )
        code = checker.main(argv)
        return code, capsys.readouterr().out

    def _pinned_versions(self) -> dict[str, str]:
        """project -> pinned value, over the module's pins and REPO_PINS both, so a
        stub that answers with these reports every pin current."""
        every = (
            checker.enumerate_pins(checker.load_pins_module())
            + checker.enumerate_repo_pins()
        )
        versions = {p.project: p.version for p in every}
        assert len(versions) == len(every), "two pins share a project key"
        return versions

    def test_main_reports_the_repo_pins_too(self, monkeypatch, capsys):
        versions = self._pinned_versions()
        code, out = self._run(monkeypatch, capsys, versions.__getitem__, [])
        assert code == 0, out
        for tool in ("kind", "winget-cli", "gradle image", "debian snapshot"):
            assert re.search(rf"^{re.escape(tool)}\s", out, re.MULTILINE), out

    def test_an_outdated_repo_pin_exits_one(self, monkeypatch, capsys):
        versions = self._pinned_versions()
        bumped = dict(versions, **{"kubernetes-sigs/kind": "v9.0.0"})
        code, out = self._run(
            monkeypatch, capsys, bumped.__getitem__, ["--fail-on-outdated"]
        )
        assert code == 1, out
        assert ".github/workflows/ash-kubernetes-operator.yml:" in out

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
        monkeypatch.setattr(
            urllib.request, "urlopen", lambda *a, **k: opened.append(a) or None
        )
        with pytest.raises(ValueError, match="refusing to fetch"):
            checker._get_json(url)
        assert opened == [], f"{url} reached urlopen"

    @pytest.mark.parametrize(
        "url",
        [
            "https://api.github.com/repos/anchore/syft/releases/latest",
            "https://pypi.org/pypi/bandit/json",
            "https://rubygems.org/api/v1/versions/cfn-nag/latest.json",
        ],
    )
    def test_positive_control_each_upstream_api_is_opened(self, url, monkeypatch):
        import io

        opened: list[str] = []

        class _Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                return False

        def fake_urlopen(request, timeout=None):
            opened.append(request.full_url)
            return _Response(b'{"ok": true}')

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        assert checker._get_json(url) == {"ok": True}
        assert opened == [url]


# ---------------------------------------------------------------------------
# Pins outside tool_downloads.py
# ---------------------------------------------------------------------------

_REPO_PIN_TOOLS = {
    "kind",
    "kubectl",
    "cfn-guard",
    "winget-cli",
    "vscode",
    "actionlint",
    "shellcheck",
    "uv (packaging harnesses)",
    "gradle image",
    "node image",
    "python image",
    "kind node image",
    "debian snapshot",
    "ubuntu snapshot",
}


def _site_tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return tmp_path


class TestRepoPins:
    def test_every_listed_tool_is_read_from_the_tree(self):
        pins = checker.enumerate_repo_pins()
        assert {p.tool for p in pins} == _REPO_PIN_TOOLS
        for pin in pins:
            assert pin.sites, pin
            assert all(":" in site for site in pin.sites), pin

    def test_values_are_read_not_restated(self):
        """The version comes from the file, so editing the file moves the pin."""
        by_tool = {p.tool: p for p in checker.enumerate_repo_pins()}
        workflow = (
            REPO_ROOT / ".github/workflows/ash-kubernetes-operator.yml"
        ).read_text()
        assert f"KIND_VERSION: {by_tool['kind'].version}" in workflow
        gradle = by_tool["gradle image"]
        assert gradle.project.startswith("gradle:") and gradle.version.startswith(
            "sha256:"
        )

    def test_a_site_that_stopped_matching_is_refused(self, tmp_path):
        """NEGATIVE CONTROL: a moved or reshaped line is an error, not a skip."""
        root = _site_tree(tmp_path, {"w.yml": "env:\n  KIND_VERSION: v0.1.0\n"})
        table = [
            checker.RepoPin(
                "kind",
                checker.GITHUB,
                "kubernetes-sigs/kind",
                (checker.PinSite("w.yml", r"^  KIND_VERSION: (v[0-9.]+)$"),),
            )
        ]
        assert checker.enumerate_repo_pins(root, table)[0].version == "v0.1.0"
        (root / "w.yml").write_text("env:\n  KIND_RELEASE: v0.1.0\n")
        with pytest.raises(checker.PinEnumerationError, match="found 0"):
            checker.enumerate_repo_pins(root, table)

    def test_an_extra_match_is_refused(self, tmp_path):
        root = _site_tree(tmp_path, {"d": "ARG V=1.0.0\nARG V=1.0.0\n"})
        table = [
            checker.RepoPin(
                "t", checker.GITHUB, "o/t", (checker.PinSite("d", r"^ARG V=(\S+)$"),)
            )
        ]
        with pytest.raises(checker.PinEnumerationError, match="found 2"):
            checker.enumerate_repo_pins(root, table)

    def test_sites_that_disagree_are_a_half_applied_bump(self, tmp_path):
        root = _site_tree(tmp_path, {"a": "ARG V=1.0.0\n", "b": "V: 1.1.0\n"})
        table = [
            checker.RepoPin(
                "t",
                checker.GITHUB,
                "o/t",
                (
                    checker.PinSite("a", r"^ARG V=(\S+)$"),
                    checker.PinSite("b", r"^V: (\S+)$"),
                ),
            )
        ]
        with pytest.raises(checker.PinEnumerationError, match="half-applied"):
            checker.enumerate_repo_pins(root, table)

    def test_a_missing_file_is_refused(self, tmp_path):
        table = [
            checker.RepoPin(
                "t", checker.GITHUB, "o/t", (checker.PinSite("gone", r"(x)"),)
            )
        ]
        with pytest.raises(checker.PinEnumerationError, match="does not exist"):
            checker.enumerate_repo_pins(tmp_path, table)

    def test_the_harness_uv_is_the_pyproject_floor(self):
        """The packaging harnesses install the oldest uv ASH supports."""
        pin = {p.tool: p for p in checker.enumerate_repo_pins()}[
            "uv (packaging harnesses)"
        ]
        assert pin.version == checker.pyproject_floor("uv")

    def test_pyproject_floor_reads_one_bound(self, tmp_path):
        good = tmp_path / "good.toml"
        good.write_text(
            'dependencies = [\n  "uv>=0.12.21,<0.13",\n  "uvicorn>=1",\n]\n'
        )
        assert checker.pyproject_floor("uv", good) == "0.12.21"
        bad = tmp_path / "bad.toml"
        bad.write_text('dependencies = ["uvicorn>=1"]\n')
        with pytest.raises(LookupError):
            checker.pyproject_floor("uv", bad)


def _repo_pin(ecosystem: str, version: str, project: str = "x") -> Any:
    return checker.Pin(
        tool="t",
        version=version,
        ecosystem=ecosystem,
        project=project,
        pinned_in=("f",),
        sites=("f:1",),
    )


class TestRepoPinComparison:
    def test_an_image_digest_is_compared_for_equality(self):
        pin = _repo_pin(checker.DOCKER_HUB, "sha256:" + "a" * 64, "gradle:jdk21")
        assert checker.compare_pin(pin, "sha256:" + "a" * 64) == "current"
        assert checker.compare_pin(pin, "sha256:" + "b" * 64) == "outdated"

    def test_a_snapshot_is_compared_by_age(self):
        pin = _repo_pin(checker.SNAPSHOT, "20260101T000000Z")
        assert checker.compare_pin(pin, "20260301T000000Z") == "current"
        late = f"2026{1 + (checker.SNAPSHOT_MAX_AGE_DAYS + 31) // 30:02d}01T000000Z"
        assert checker.compare_pin(pin, late) == "outdated"
        assert checker.compare_pin(pin, "20251201T000000Z") == "ahead"

    def test_a_harness_below_the_floor_is_outdated(self):
        pin = _repo_pin(checker.PYPROJECT_FLOOR, "0.12.19", "uv")
        assert checker.compare_pin(pin, "0.12.21") == "outdated"
        assert checker.compare_pin(pin, "0.12.19") == "current"

    def test_docker_hub_lookup_url(self, monkeypatch):
        seen: list[str] = []
        monkeypatch.setattr(
            checker,
            "_get_json",
            lambda url, headers=None: seen.append(url) or {"digest": "d"},
        )
        assert checker.latest_docker_hub_digest("gradle:jdk21") == "d"
        assert checker.latest_docker_hub_digest("kindest/node:v1.34.0") == "d"
        assert seen == [
            "https://hub.docker.com/v2/namespaces/library/repositories/gradle/tags/jdk21",
            "https://hub.docker.com/v2/namespaces/kindest/repositories/node/tags/v1.34.0",
        ]

    def test_bump_steps_name_every_site(self):
        pin = {p.tool: p for p in checker.enumerate_repo_pins()}["vscode"]
        steps = checker.bump_steps(None, checker.Result(pin, "9.9.9", "outdated"))
        for site in pin.sites:
            assert any(step.startswith(site) for step in steps), steps
        assert len(pin.sites) == 3


# A census of what looks like a version or image pin under the trees CI, the
# packaging harnesses and the editor test images live in. Each hit must be a
# REPO_PINS site or carry a reason here; a new pinned tool with neither fails.
_CENSUS_ROOTS = (
    ".github/workflows",
    ".github/actions",
    "packaging",
    "editors",
    "deploy",
)
_CENSUS_NAMES = re.compile(r"^(Dockerfile.*|.*\.(ya?ml|sh|ps1|py))$")
_ASSIGNMENT = re.compile(
    r"^\s*(?:ARG\s+|export\s+|\$)?([A-Za-z0-9_]*(?:_VERSION|_SNAPSHOT|ReleaseTag))"
    r"\s*[:=]\s*[\"']?v?[0-9]",
    re.MULTILINE,
)
_TAGGED_IMAGE = re.compile(
    r"(?<![\w./-])([a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+)@sha256:[0-9a-f]{64}"
)

# Name -> why it is not a tool pin this check should follow.
_CENSUS_EXEMPT = {
    "PYTHON_VERSION": "a Python minor series for setup-python, not a release pin",
    "ASH_VERSION": "ASH's own version, bumped by commitizen",
    "RUNTIME_VERSION": "the Flatpak runtime branch the manifest targets, not a tool",
    "FIXTURE_VERSION": "a test fixture's made-up version",
    "MANIFEST_VERSION": "the winget manifest schema version",
    "MinimumWingetVersion": "a floor the leg asserts, not a pin it installs",
}


def _census() -> list[tuple[str, str]]:
    hits = []
    for root in _CENSUS_ROOTS:
        for path in sorted((REPO_ROOT / root).rglob("*")):
            rel = path.relative_to(REPO_ROOT).as_posix()
            if (
                not path.is_file()
                or "node_modules" in path.parts
                or "/tests/unit" in f"/{rel}"
                or not _CENSUS_NAMES.match(path.name)
            ):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            hits += [(rel, m.group(1)) for m in _ASSIGNMENT.finditer(text)]
            hits += [(rel, m.group(1)) for m in _TAGGED_IMAGE.finditer(text)]
    return hits


class TestPinCensus:
    def _unaccounted(self, hits: list[tuple[str, str]]) -> list[str]:
        by_path: dict[str, list[Any]] = {}
        for repo_pin in checker.REPO_PINS:
            for site in repo_pin.sites:
                by_path.setdefault(site.path, []).append(site)
        unaccounted = []
        for rel, name in hits:
            if name in _CENSUS_EXEMPT:
                continue
            image = name.split(":", 1)[0]
            line_matches = any(
                name in site.pattern or (":" in name and image in site.pattern)
                for site in by_path.get(rel, [])
            )
            if not line_matches:
                unaccounted.append(f"{rel}: {name}")
        return sorted(set(unaccounted))

    def test_every_pin_shaped_line_is_followed_or_exempt(self):
        hits = _census()
        assert not self._unaccounted(hits), (
            "a version or tagged-image pin is neither in REPO_PINS "
            "(scripts/check_pinned_tool_versions.py) nor exempted with a reason:\n"
            + "\n".join(self._unaccounted(hits))
        )

    def test_the_census_is_not_vacuous(self):
        """Positive control: it sees the pins REPO_PINS follows."""
        names = {name for _, name in _census()}
        assert {"KIND_VERSION", "KUBECTL_VERSION", "CFN_GUARD_VERSION"} <= names
        assert {"WingetReleaseTag", "DEBIAN_SNAPSHOT", "UBUNTU_SNAPSHOT"} <= names
        assert "gradle:jdk21" in names

    def test_a_new_pin_is_caught(self):
        """NEGATIVE CONTROL: an unlisted pin in a censused file is reported."""
        hits = _census() + [
            (".github/workflows/ash-kubernetes-operator.yml", "HELM_VERSION"),
            ("editors/vscode/test/visual/Dockerfile", "alpine:3.20"),
        ]
        assert self._unaccounted(hits) == [
            ".github/workflows/ash-kubernetes-operator.yml: HELM_VERSION",
            "editors/vscode/test/visual/Dockerfile: alpine:3.20",
        ]
