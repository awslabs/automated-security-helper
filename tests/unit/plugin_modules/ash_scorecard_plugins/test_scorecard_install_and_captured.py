# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local install pin, and the converter over a real captured Scorecard run.

``tests/test_data/scanners/scorecard/captured/`` holds what ``scorecard`` v5.7.0 wrote
(see its README). The conversion tests read those files, so the severity mapping and
the location are pinned over output the tool produced, not over a hand-built document.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import (
    ScannerError,
    ToolNotProvisionableError,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_scorecard_plugins import (
    scorecard_install as si,
)
from automated_security_helper.plugin_modules.ash_scorecard_plugins.scorecard_scanner import (
    convert_scorecard_result,
)

from .test_scorecard_scanner_behavior import FakeScorecard, _run, _scanner

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "scorecard"
    / "captured"
)
HEX64 = re.compile(r"[0-9a-f]{64}")

#: The repository the committed SARIF was converted for (its README says so).
REPO = "github.com/example-org/example-repo"


# ---------------------------------------------------------------------------
# Install pin
# ---------------------------------------------------------------------------


def test_every_asset_has_an_archive_digest_and_a_member_digest():
    assert set(si.ASSETS.values()) == set(si.ARCHIVE_SHA256) == set(si.MEMBER_SHA256)
    for digest in [*si.ARCHIVE_SHA256.values(), *si.MEMBER_SHA256.values()]:
        assert HEX64.fullmatch(digest), digest
    assert len(set(si.ARCHIVE_SHA256.values())) == len(si.ARCHIVE_SHA256)
    assert len(set(si.MEMBER_SHA256.values())) == len(si.MEMBER_SHA256)


def test_asset_names_carry_the_pinned_version():
    bare = si.SCORECARD_VERSION.lstrip("v")
    for name in si.ASSETS.values():
        assert name.startswith(f"scorecard_{bare}_"), name


@pytest.mark.parametrize(
    "platform,arch,install_as",
    [
        ("linux", "amd64", "scorecard"),
        ("linux", "arm64", "scorecard"),
        ("darwin", "amd64", "scorecard"),
        ("darwin", "arm64", "scorecard"),
        ("windows", "amd64", "scorecard.exe"),
        ("windows", "arm64", "scorecard.exe"),
    ],
)
def test_pinned_asset_resolves_a_published_pair(platform, arch, install_as):
    url, archive, member, name = si.pinned_asset(platform, arch)
    assert url == (
        "https://github.com/ossf/scorecard/releases/download/"
        f"{si.SCORECARD_VERSION}/{si.ASSETS[(platform, arch)]}"
    )
    assert HEX64.fullmatch(archive) and HEX64.fullmatch(member)
    assert name == install_as


@pytest.mark.parametrize("pair", [("linux", "386"), ("freebsd", "amd64")])
def test_an_unpublished_pair_is_refused_by_name(pair):
    with pytest.raises(ToolNotProvisionableError, match=pair[0]):
        si.pinned_asset(*pair)


def test_a_half_applied_bump_is_refused(monkeypatch):
    monkeypatch.setitem(
        si.ASSETS, ("linux", "amd64"), "scorecard_99.0.0_linux_amd64.tar.gz"
    )
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        si.pinned_asset("linux", "amd64")


def test_the_linux_amd64_pin_is_the_archive_the_capture_ran():
    # The same digest the captured README records for the run that produced the fixtures.
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    assert si.ARCHIVE_SHA256["scorecard_5.7.0_linux_amd64.tar.gz"] in readme
    assert si.MEMBER_SHA256["scorecard_5.7.0_linux_amd64.tar.gz"] in readme


def test_the_install_table_builds_without_the_shared_pin_table(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = si.scorecard_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(si.ASSETS)
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert "install_scorecard" in " ".join(command.args)


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    from automated_security_helper.utils import download_utils as du

    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = si.scorecard_install_commands()
    assert table["linux"]["amd64"], "a refusing command stands in"
    assert "install_scorecard" not in " ".join(table["linux"]["amd64"][0].args)


# ---------------------------------------------------------------------------
# Conversion over the captured run
# ---------------------------------------------------------------------------


def _capture(name: str) -> dict:
    return json.loads((CAPTURED / name).read_text(encoding="utf-8"))


@pytest.fixture
def converted():
    return convert_scorecard_result(_capture("positive.json"), repo=REPO)


def _results(report):
    return report.runs[0].results or []


def test_the_capture_is_the_pinned_release(converted):
    capture = _capture("positive.json")
    assert capture["scorecard"]["version"] == si.SCORECARD_VERSION
    assert converted.runs[0].tool.driver.version == si.SCORECARD_VERSION


def test_every_check_below_ten_of_the_capture_becomes_one_result(converted):
    capture = _capture("positive.json")
    below_ten = {c["name"] for c in capture["checks"] if 0 <= c["score"] < 10}
    assert {r.ruleId for r in _results(converted)} == below_ten
    assert len(_results(converted)) == 4


def test_the_bands_over_the_captured_scores(converted):
    got = {
        r.ruleId: (r.properties.issue_severity, getattr(r.level, "value", r.level))
        for r in _results(converted)
    }
    assert got == {
        "Dependency-Update-Tool": ("HIGH", "error"),
        "License": ("HIGH", "error"),
        "Pinned-Dependencies": ("MEDIUM", "warning"),
        "Security-Policy": ("LOW", "note"),
    }


def test_every_result_is_located_at_the_repository_with_no_region(converted):
    for result in _results(converted):
        physical = result.locations[0].physicalLocation.root
        assert physical.artifactLocation.uri == REPO
        assert physical.region is None


def test_the_flat_row_carries_the_repository_as_its_path_and_no_lines(converted):
    run = converted.runs[0]
    for result in _results(converted):
        flat = FlatVulnerability.from_sarif_result(result, "scorecard", "SCA", run)
        assert flat.file_path == REPO
        assert flat.line_start is None and flat.line_end is None
        assert flat.resource_id is None


def test_the_documentation_link_is_the_rule_help_uri(converted):
    rules = {
        getattr(r.id, "root", r.id): r for r in converted.runs[0].tool.driver.rules
    }
    help_uri = str(rules["License"].helpUri)
    assert help_uri.startswith("https://github.com/ossf/scorecard/blob/")
    assert help_uri.endswith("/docs/checks.md#license")


def test_the_committed_sarif_is_what_the_converter_writes(converted):
    committed = json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
    written = json.loads(
        converted.model_dump_json(exclude_none=True, exclude_unset=True, by_alias=True)
    )
    assert committed == written


# ---------------------------------------------------------------------------
# A check that fails at run time: exit 1 with the whole document on stdout
# ---------------------------------------------------------------------------


def test_the_check_error_capture_holds_the_failed_check_at_minus_one():
    capture = _capture("check-error.json")
    failed = [c for c in capture["checks"] if c["score"] == -1]
    assert {c["name"] for c in failed} >= {"Fuzzing"}
    fuzzing = next(c for c in failed if c["name"] == "Fuzzing")
    assert fuzzing["reason"].startswith("internal error:")


def test_a_run_that_exits_one_with_a_complete_document_fails_the_scan(
    tmp_path, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_scorecard_plugins import (
        scorecard_scanner as ss,
    )

    for name in ss.TOKEN_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "not-a-real-token")
    monkeypatch.setattr(ss, "find_executable", lambda cmd: f"/fake/bin/{cmd}")
    source = tmp_path / "src"
    (source / ".git").mkdir(parents=True)
    (source / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://github.com/example-org/example-repo.git\n'
    )
    stdout = (CAPTURED / "check-error.json").read_text(encoding="utf-8")
    fake = FakeScorecard(stdout=stdout, exit_code=1)
    with pytest.raises(ScannerError, match="exited 1"):
        _run(_scanner(source, tmp_path), fake, monkeypatch)
    assert len(fake.calls) == 1
