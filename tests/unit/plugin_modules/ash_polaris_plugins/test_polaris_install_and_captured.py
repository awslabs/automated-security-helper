# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local install pin, and the converter over a real captured Polaris run.

``tests/test_data/scanners/polaris/captured/`` holds what ``polaris audit`` v10.2.6
wrote (see its README). The conversion tests read those files, so the severity mapping
is pinned over output the tool produced, not over a hand-built document.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_polaris_plugins import (
    polaris_install as pi,
)
from automated_security_helper.plugin_modules.ash_polaris_plugins.polaris_scanner import (
    POLARIS_SEVERITY_MAP,
    PolarisScanner,
)

from .test_polaris_scanner_behavior import _scanner

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "polaris"
    / "captured"
)
HEX64 = re.compile(r"[0-9a-f]{64}")


# ---------------------------------------------------------------------------
# Install pin
# ---------------------------------------------------------------------------


def test_every_asset_has_an_archive_digest_and_a_member_digest():
    assert set(pi.ASSETS.values()) == set(pi.ARCHIVE_SHA256) == set(pi.MEMBER_SHA256)
    for digest in [*pi.ARCHIVE_SHA256.values(), *pi.MEMBER_SHA256.values()]:
        assert HEX64.fullmatch(digest), digest
    assert len(set(pi.ARCHIVE_SHA256.values())) == len(pi.ARCHIVE_SHA256)
    assert len(set(pi.MEMBER_SHA256.values())) == len(pi.MEMBER_SHA256)


def test_asset_names_carry_the_pinned_version():
    bare = pi.POLARIS_VERSION.lstrip("v")
    for name in pi.ASSETS.values():
        assert name.startswith(f"polaris_{bare}_"), name


@pytest.mark.parametrize(
    "platform,arch,install_as",
    [
        ("linux", "amd64", "polaris"),
        ("linux", "arm64", "polaris"),
        ("darwin", "amd64", "polaris"),
        ("darwin", "arm64", "polaris"),
        ("windows", "amd64", "polaris.exe"),
    ],
)
def test_pinned_asset_resolves_a_published_pair(platform, arch, install_as):
    url, archive, member, name = pi.pinned_asset(platform, arch)
    assert url.startswith(
        "https://github.com/FairwindsOps/polaris/releases/download/"
        f"{pi.POLARIS_VERSION}/polaris_"
    )
    assert HEX64.fullmatch(archive) and HEX64.fullmatch(member)
    assert name == install_as


@pytest.mark.parametrize("pair", [("windows", "arm64"), ("freebsd", "amd64")])
def test_an_unpublished_pair_is_refused_by_name(pair):
    with pytest.raises(ToolNotProvisionableError, match=pair[0]):
        pi.pinned_asset(*pair)


def test_a_half_applied_bump_is_refused(monkeypatch):
    monkeypatch.setitem(
        pi.ASSETS, ("linux", "amd64"), "polaris_99.0.0_linux_amd64.tar.gz"
    )
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        pi.pinned_asset("linux", "amd64")


def test_the_linux_amd64_pin_is_the_archive_that_was_hashed_when_it_was_captured():
    # The same digest the captured README records for the run that produced the fixtures.
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    assert pi.ARCHIVE_SHA256["polaris_10.2.6_linux_amd64.tar.gz"] in readme


def test_the_install_table_builds_without_the_shared_pin_table(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = pi.polaris_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(pi.ASSETS)
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert "install_polaris" in " ".join(command.args)


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    from automated_security_helper.utils import download_utils as du

    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = pi.polaris_install_commands()
    assert table["linux"]["amd64"], "a refusing command stands in"
    assert "install_polaris" not in " ".join(table["linux"]["amd64"][0].args)


# ---------------------------------------------------------------------------
# Conversion over the captured run
# ---------------------------------------------------------------------------


def _positive():
    return json.loads((CAPTURED / "positive.json").read_text(encoding="utf-8"))


@pytest.fixture
def converted(tmp_path):
    # The scanner indexes the tree it audited; the capture's input is committed.
    source = CAPTURED / "in" / "pos"
    index = _scanner(source, tmp_path)._index_target(source)
    return PolarisScanner.convert_polaris_output(_positive(), index)


def _results(sarif):
    return sarif["runs"][0]["results"]


def test_the_negative_capture_is_a_clean_scan():
    negative = json.loads((CAPTURED / "negative.json").read_text(encoding="utf-8"))
    sarif = PolarisScanner.convert_polaris_output(negative, {})
    assert _results(sarif) == []


def test_every_failed_check_of_the_capture_becomes_one_result(converted):
    # 3 controller checks + 4 pod checks + 14 container checks, all Success false.
    assert len(_results(converted)) == 21
    assert {r["ruleId"] for r in _results(converted)} >= {
        "runAsPrivileged",
        "deploymentMissingReplicas",
        "automountServiceAccountToken",
    }


def test_danger_is_high_and_error_and_warning_is_medium_and_warning(converted):
    by_rule = {r["ruleId"]: r for r in _results(converted)}
    danger = {
        "privilegeEscalationAllowed",
        "runAsPrivileged",
        "runAsRootAllowed",
        "tagNotSpecified",
    }
    for rule, result in by_rule.items():
        expected = ("HIGH", "error") if rule in danger else ("MEDIUM", "warning")
        assert (result["properties"]["issue_severity"], result["level"]) == expected, (
            rule
        )
    assert POLARIS_SEVERITY_MAP == {
        "danger": ("HIGH", "error"),
        "warning": ("MEDIUM", "warning"),
    }


def test_results_point_at_the_name_line_of_the_manifest(converted):
    locations = {
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in _results(converted)
    }
    assert locations == {("deploy.yaml", 4)}


def test_a_container_check_names_its_container(converted):
    run_as = next(r for r in _results(converted) if r["ruleId"] == "runAsPrivileged")
    assert run_as["message"]["text"].startswith(
        "Deployment/web container nginx: Should not be running as privileged"
    )
    assert run_as["properties"]["tags"] == ["kubernetes", "security"]


def test_the_committed_sarif_is_what_the_converter_writes(converted):
    committed = json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
    assert committed == converted
