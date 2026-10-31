# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/check_pinned_tool_versions.py`` reads its pins and builds bump steps.

Why this file exists
--------------------
Six readings in the pin checker went wrong without any error at the time:

* A license entry whose repository is not on github.com was accepted when the pins
  were read and raised only when the report was rendered, the week its tool fell
  behind, which lost the whole report.
* A gem pin whose ``tool_downloads.py`` global was renamed or removed was dropped from
  the check without a word, so the weekly job stayed green over a pin it no longer
  looked at.
* A license entry for a gem pin was refused as an orphan, with a message that says
  nothing of gems, although the gem pin already names the tool.
* Any tag that began with a number was accepted as the latest release whatever
  followed it, and was copied into the printed ``gh api`` command.
* The asset-name step was emitted only when every file name carried the full version,
  so one unversioned name dropped it for the rest, and cfn-guard's major-versioned
  names were never named when the major changed.
* ``git grep`` was run for the copies of a digest without ``--no-color``, parsed by
  splitting on ``:`` and decoded as text, so a colored config, a path with a colon or
  one undecodable matched line misreported the copies or stopped the report.

No network and no child process: the pins module is read in process, and the one
``git grep`` call is replaced with a fake that answers the way git answers for the
arguments it is given.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import socket
import subprocess  # nosec B404 - CompletedProcess only; nothing is started
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
        "_check_pinned_tool_enumeration_and_steps", SCRIPT
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


@pytest.fixture
def pins():
    """A fresh copy of tool_downloads per test, so monkeypatching it is local."""
    return checker.load_pins_module()


# ---------------------------------------------------------------------------
# The license entry's repository is checked when the pins are read
# ---------------------------------------------------------------------------


class TestLicenseRepositoryHost:
    @pytest.mark.parametrize(
        "tool",
        ["grype", "bandit", "aws-guard-rules-registry"],
        ids=["release-binary", "uv-tool", "rules-bundle"],
    )
    def test_a_repository_off_github_is_refused_when_the_pins_are_read(
        self, pins, monkeypatch, tool
    ):
        # Red at the base: enumerate_pins returned all three without complaint, and
        # _license_steps raised the same refusal later, out of render_report.
        entry = dataclasses.replace(
            pins.THIRD_PARTY_LICENSES[tool],
            repository="https://gitlab.example.com/group/project",
        )
        monkeypatch.setitem(pins.THIRD_PARTY_LICENSES, tool, entry)
        with pytest.raises(checker.PinEnumerationError, match="not a github.com URL"):
            checker.enumerate_pins(pins)

    def test_the_refusal_names_the_license_entry(self, pins, monkeypatch):
        entry = dataclasses.replace(
            pins.THIRD_PARTY_LICENSES["grype"],
            repository="https://gitlab.example.com/group/project",
        )
        monkeypatch.setitem(pins.THIRD_PARTY_LICENSES, "grype", entry)
        with pytest.raises(checker.PinEnumerationError) as raised:
            checker.enumerate_pins(pins)
        assert "THIRD_PARTY_LICENSES['grype'].repository" in str(raised.value)

    def test_the_real_pins_still_enumerate(self, pins):
        """Control: every real repository is on github.com, so nothing is refused."""
        assert len(checker.enumerate_pins(pins)) >= 9


# ---------------------------------------------------------------------------
# Gem pins
# ---------------------------------------------------------------------------


def _gem_license_entry(pins, version: str, repository: str | None = None) -> Any:
    template = pins.THIRD_PARTY_LICENSES["actionlint"]
    changes: dict[str, Any] = {"tool": "cfn-nag", "version": version}
    if repository is not None:
        changes["repository"] = repository
    return dataclasses.replace(template, **changes)


def _cfn_nag_pin(pins) -> Any:
    return checker.Pin(
        tool="cfn-nag",
        version=pins.CFN_NAG_GEM_VERSION,
        ecosystem=checker.RUBYGEMS,
        project="cfn-nag",
        pinned_in=("CFN_NAG_GEM_VERSION",),
        kind=checker.GEM,
    )


class TestGemPins:
    @pytest.mark.parametrize(
        ("gem", "name"),
        [("cfn-nag", "CFN_NAG_GEM_VERSION"), ("bundler", "BUNDLER_VERSION")],
    )
    def test_a_gem_pin_that_is_gone_from_the_module_is_refused(
        self, pins, monkeypatch, gem, name
    ):
        # Red at the base: getattr(pins, name, None) skipped the gem, so it was never
        # looked up and the weekly job stayed green.
        monkeypatch.delattr(pins, name)
        with pytest.raises(checker.PinEnumerationError, match=name):
            checker.enumerate_pins(pins)

    def test_a_gem_pin_that_is_not_a_version_string_is_refused(self, pins, monkeypatch):
        monkeypatch.setattr(pins, "BUNDLER_VERSION", None)
        with pytest.raises(checker.PinEnumerationError, match="BUNDLER_VERSION"):
            checker.enumerate_pins(pins)

    def test_a_license_entry_for_a_gem_is_read_with_its_gem_pin(
        self, pins, monkeypatch
    ):
        # Red at the base: the entry reached the orphan refusal, "not in TOOL_VERSIONS
        # or RULES_BUNDLES and has no distribution".
        entry = _gem_license_entry(pins, "v" + pins.CFN_NAG_GEM_VERSION)
        monkeypatch.setitem(pins.THIRD_PARTY_LICENSES, "cfn-nag", entry)
        by_tool = {p.tool: p for p in checker.enumerate_pins(pins)}
        pin = by_tool["cfn-nag"]
        assert (pin.kind, pin.ecosystem) == (checker.GEM, checker.RUBYGEMS)
        assert pin.version == pins.CFN_NAG_GEM_VERSION
        assert pin.pinned_in == ("CFN_NAG_GEM_VERSION", "THIRD_PARTY_LICENSES")

    def test_one_pin_per_tool_with_a_gem_license_entry(self, pins, monkeypatch):
        entry = _gem_license_entry(pins, pins.CFN_NAG_GEM_VERSION)
        monkeypatch.setitem(pins.THIRD_PARTY_LICENSES, "cfn-nag", entry)
        tools = [p.tool for p in checker.enumerate_pins(pins)]
        assert tools.count("cfn-nag") == 1

    def test_a_gem_license_entry_at_another_version_is_a_half_applied_bump(
        self, pins, monkeypatch
    ):
        entry = _gem_license_entry(pins, "v0.0.1")
        monkeypatch.setitem(pins.THIRD_PARTY_LICENSES, "cfn-nag", entry)
        with pytest.raises(checker.PinEnumerationError, match="half-applied"):
            checker.enumerate_pins(pins)

    def test_a_gem_license_entry_off_github_is_refused(self, pins, monkeypatch):
        entry = _gem_license_entry(
            pins,
            pins.CFN_NAG_GEM_VERSION,
            repository="https://gitlab.example.com/group/project",
        )
        monkeypatch.setitem(pins.THIRD_PARTY_LICENSES, "cfn-nag", entry)
        with pytest.raises(checker.PinEnumerationError, match="not a github.com URL"):
            checker.enumerate_pins(pins)

    def test_the_gem_steps_name_its_license_entry(self, pins, monkeypatch):
        # Built by hand so that it reaches the steps at the base too, where it fails:
        # _gem_steps never looked at THIRD_PARTY_LICENSES.
        entry = _gem_license_entry(pins, "v" + pins.CFN_NAG_GEM_VERSION)
        monkeypatch.setitem(pins.THIRD_PARTY_LICENSES, "cfn-nag", entry)
        steps = "\n".join(checker._gem_steps(pins, _cfn_nag_pin(pins), "0.99.0"))
        assert 'THIRD_PARTY_LICENSES["cfn-nag"].version -> v0.99.0' in steps
        assert "gh api repos/rhysd/actionlint/commits/v0.99.0" in steps

    def test_a_gem_without_a_license_entry_has_no_license_steps(self, pins):
        """Control: the real gems carry no entry, and their steps are unchanged."""
        steps = "\n".join(checker._gem_steps(pins, _cfn_nag_pin(pins), "0.99.0"))
        assert "THIRD_PARTY_LICENSES" not in steps
        assert 'gem "cfn-nag", "0.99.0"' in steps


# ---------------------------------------------------------------------------
# A latest release is a version, and nothing else
# ---------------------------------------------------------------------------


class TestLatestReleaseIsAVersion:
    @pytest.mark.parametrize(
        "tag",
        [
            "v1.2.3;echo-pwned",
            "1.2.3$(id)",
            "v1.2.3 beta",
            "v1.2.3`id`",
            "1.2.3<b>bold</b>",
            "1.2.3'",
            '1.2.3"',
            "1.2.3|tee",
        ],
    )
    def test_a_tag_with_more_than_a_version_is_not_one(self, tag):
        # Red at the base: (.*) took everything after the numbers as a suffix.
        with pytest.raises(ValueError, match="not a version"):
            checker.parse_version(tag)

    def test_such_a_latest_is_a_lookup_error_not_an_outdated_pin(self):
        pin = checker.Pin(
            tool="tool",
            version="v1.0.0",
            ecosystem=checker.GITHUB,
            project="example/tool",
            pinned_in=("TOOL_VERSIONS",),
            kind=checker.RELEASE_BINARY,
        )
        fetchers = {checker.GITHUB: lambda project: "v9.9.9;echo-pwned"}
        (result,) = checker.check([pin], fetchers)
        assert result.status == "error"
        assert "not a version" in result.detail

    @pytest.mark.parametrize(
        "tag",
        [
            "v1.2.3",
            "1.2.3",
            "v1.2.3-rc.1",
            "1.2.3+build.5",
            "1.2.0rc10",
            "1.2.3.post1",
            "libssh2-1.11.1",
        ],
    )
    def test_every_spelling_a_release_uses_is_still_read(self, tag):
        """Control: the characters real tags use are all admitted."""
        release, _ = checker.parse_version(tag)
        assert release[0] >= 1


# ---------------------------------------------------------------------------
# The asset-name step
# ---------------------------------------------------------------------------


def _release_pins(tool: str, table: dict[Any, str]) -> Any:
    """A pins namespace with one release-binary tool and nothing else a step reads."""
    return SimpleNamespace(
        _ASSET_TABLES={tool: table},
        _ASSETS=table,
        _DIGESTS={},
        _EXECUTABLE_DIGESTS={},
        _DIGESTS_TAKEN_AT={},
        THIRD_PARTY_LICENSES={},
    )


def _release_pin(tool: str, version: str) -> Any:
    return checker.Pin(
        tool=tool,
        version=version,
        ecosystem=checker.GITHUB,
        project=f"example/{tool}",
        pinned_in=("TOOL_VERSIONS",),
        kind=checker.RELEASE_BINARY,
    )


class TestAssetNameStep:
    def _steps(self, tool: str, version: str, names: list[str], latest: str) -> str:
        table = {("linux", str(i)): name for i, name in enumerate(names)}
        pins = _release_pins(tool, table)
        steps = checker._release_binary_steps(pins, _release_pin(tool, version), latest)
        return "\n".join(steps)

    def test_a_name_with_only_the_major_is_renamed_when_the_major_changes(self):
        # Red at the base: cfn-guard's names hold "v3" and never "3.2.1", so the
        # all-names test failed and no rename step was written for a 4.0.0 release.
        names = [
            "cfn-guard-v3-x86_64-linux-latest.tar.gz",
            "cfn-guard-v3-aarch64-linux-latest.tar.gz",
        ]
        steps = self._steps("cfn-guard", "3.2.1", names, "4.0.0")
        assert "the 2 asset file names of cfn-guard that carry only the major" in steps
        assert "v3 -> v4" in steps

    def test_a_name_with_only_the_major_is_left_alone_inside_one_major(self):
        names = ["cfn-guard-v3-x86_64-linux-latest.tar.gz"]
        steps = self._steps("cfn-guard", "3.2.1", names, "3.3.0")
        assert "major" not in steps
        assert "asset file names" not in steps

    def test_one_unversioned_name_does_not_drop_the_step_for_the_others(self):
        # Red at the base: all(...) was False for the tool.exe name, so the two
        # versioned archives got no rename step.
        names = ["tool_1.0.0_linux.tar.gz", "tool_1.0.0_darwin.tar.gz", "tool.exe"]
        steps = self._steps("tool", "v1.0.0", names, "v2.0.0")
        assert (
            "the 2 asset file names of tool that carry the version, 1.0.0 -> 2.0.0"
            in steps
        )

    def test_names_that_all_carry_the_version_read_as_they_always_did(self):
        """Control: the common shape keeps its wording."""
        names = ["tool_1.0.0_linux.tar.gz", "tool_1.0.0_darwin.tar.gz"]
        steps = self._steps("tool", "v1.0.0", names, "v2.0.0")
        assert (
            "_ASSETS: the 2 asset file names of tool, 1.0.0 -> 2.0.0; "
            "check each still exists upstream"
        ) in steps

    def test_a_name_that_merely_contains_a_v_is_not_a_major_name(self):
        names = ["uv-x86_64-unknown-linux-gnu.tar.gz"]
        steps = self._steps("uv", "0.13.4", names, "1.0.0")
        assert "major" not in steps


# ---------------------------------------------------------------------------
# The search for copies of a digest
# ---------------------------------------------------------------------------

_DIGEST = hashlib.sha256(b"a digest this test made up").hexdigest()


def _copy_pins() -> Any:
    return SimpleNamespace(
        _ASSET_TABLES={"tool": {("linux", "amd64"): "tool_1.0.0_linux.tar.gz"}},
        _DIGESTS={"tool_1.0.0_linux.tar.gz": _DIGEST},
        _EXECUTABLE_DIGESTS={},
        _BUNDLE_CONTENTS_DIGESTS={},
        THIRD_PARTY_LICENSES={},
    )


class _FakeGit:
    """``subprocess.run`` for ``git grep``, answering as git does for its arguments.

    With ``-z`` git ends the path and the line number with a NUL; without it, with a
    colon. Text mode decodes the answer, which fails on a byte that is not valid
    UTF-8, as the real call does.
    """

    def __init__(self, hits: list[tuple[str, int, bytes]], returncode: int = 0):
        self.hits = hits
        self.returncode = returncode
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> Any:
        self.calls.append((argv, kwargs))
        separator = b"\0" if "-z" in argv else b":"
        out = b"".join(
            path.encode() + separator + str(number).encode() + separator + text + b"\n"
            for path, number, text in self.hits
        )
        err = b"fatal: simulated failure" if self.returncode not in (0, 1) else b""
        if kwargs.get("text"):
            return subprocess.CompletedProcess(
                argv, self.returncode, out.decode(), err.decode()
            )
        return subprocess.CompletedProcess(argv, self.returncode, out, err)


def _copies(monkeypatch, fake: _FakeGit) -> list[str]:
    # Only the script's own reference to subprocess is replaced.
    monkeypatch.setattr(
        checker,
        "subprocess",
        SimpleNamespace(run=fake, TimeoutExpired=subprocess.TimeoutExpired),
    )
    return checker._copy_steps(_copy_pins(), _release_pin("tool", "v1.0.0"), REPO_ROOT)


class TestCopySteps:
    def test_git_is_asked_for_no_color_and_nul_delimited_paths(self, monkeypatch):
        # Red at the base: neither flag was on the command line.
        fake = _FakeGit([("nix/tool.nix", 4, b"hash")])
        _copies(monkeypatch, fake)
        argv = fake.calls[0][0]
        assert "--no-color" in argv
        assert "-z" in argv

    def test_a_path_with_a_colon_is_named_whole(self, monkeypatch):
        # Red at the base: split(":", 2) read "docs/a" and "b.md".
        fake = _FakeGit([("docs/a:b.md", 12, b"hash"), ("docs/café.md", 3, b"hash")])
        steps = _copies(monkeypatch, fake)
        assert [s.split(": a copy", 1)[0] for s in steps] == [
            "docs/a:b.md:12",
            "docs/café.md:3",
        ]

    def test_every_line_of_one_file_is_listed_once_under_its_path(self, monkeypatch):
        fake = _FakeGit([("ci/check.sh", 9, b"hash"), ("ci/check.sh", 41, b"hash")])
        (step,) = _copies(monkeypatch, fake)
        assert step.startswith("ci/check.sh:9,41: a copy of a digest tool pins")

    def test_a_matched_line_that_is_not_valid_text_does_not_stop_the_report(
        self, monkeypatch
    ):
        # Red at the base: text=True decoded the answer, and the UnicodeDecodeError
        # was not among the exceptions the call caught.
        fake = _FakeGit([("fixtures/latin.txt", 7, b"caf\xe9 hash")])
        (step,) = _copies(monkeypatch, fake)
        assert step.startswith("fixtures/latin.txt:7: a copy of a digest tool pins")

    def test_no_hit_is_no_step(self, monkeypatch):
        assert _copies(monkeypatch, _FakeGit([], returncode=1)) == []

    def test_a_failed_search_is_named_in_a_step(self, monkeypatch):
        """Control: a git failure still produces the search-by-hand step."""
        (step,) = _copies(monkeypatch, _FakeGit([], returncode=2))
        assert "git grep failed: fatal: simulated failure" in step
        assert _DIGEST in step
