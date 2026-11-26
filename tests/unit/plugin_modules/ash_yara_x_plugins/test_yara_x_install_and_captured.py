# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local install pin, and the converter over a real captured YARA-X run.

``tests/test_data/scanners/yara_x/captured/`` holds what ``yr scan`` v1.23.0 wrote (see
its README). The conversion tests read those files, so the committed SARIF is pinned
over output the tool produced, not over a hand-built document.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_yara_x_plugins import (
    yara_x_install as yi,
)
from automated_security_helper.plugin_modules.ash_yara_x_plugins.yara_x_scanner import (
    convert_ndjson,
    parse_ndjson,
)

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "yara_x"
    / "captured"
)
HEX64 = re.compile(r"[0-9a-f]{64}")


# ---------------------------------------------------------------------------
# Install pin
# ---------------------------------------------------------------------------


def test_every_asset_has_an_archive_digest_and_a_member_digest():
    assert set(yi.ASSETS.values()) == set(yi.ARCHIVE_SHA256) == set(yi.MEMBER_SHA256)
    for digest in [*yi.ARCHIVE_SHA256.values(), *yi.MEMBER_SHA256.values()]:
        assert HEX64.fullmatch(digest), digest
    assert len(set(yi.ARCHIVE_SHA256.values())) == len(yi.ARCHIVE_SHA256)
    assert len(set(yi.MEMBER_SHA256.values())) == len(yi.MEMBER_SHA256)


def test_asset_names_carry_the_pinned_version():
    for name in yi.ASSETS.values():
        assert name.startswith(f"yara-x-{yi.YARA_X_VERSION}-"), name


def test_the_release_publishes_no_windows_arm64_build():
    assert set(yi.ASSETS) == {
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("windows", "amd64"),
    }


@pytest.mark.parametrize(
    "platform,arch,install_as",
    [
        ("linux", "amd64", "yr"),
        ("linux", "arm64", "yr"),
        ("darwin", "amd64", "yr"),
        ("darwin", "arm64", "yr"),
        ("windows", "amd64", "yr.exe"),
    ],
)
def test_pinned_asset_resolves_a_published_pair(platform, arch, install_as):
    url, archive, member, name = yi.pinned_asset(platform, arch)
    assert url.startswith(
        "https://github.com/VirusTotal/yara-x/releases/download/"
        f"{yi.YARA_X_VERSION}/yara-x-{yi.YARA_X_VERSION}-"
    )
    assert HEX64.fullmatch(archive) and HEX64.fullmatch(member)
    assert name == install_as


@pytest.mark.parametrize("pair", [("windows", "arm64"), ("freebsd", "amd64")])
def test_an_unpublished_pair_is_refused_by_name(pair):
    with pytest.raises(ToolNotProvisionableError, match=pair[0]):
        yi.pinned_asset(*pair)


def test_a_half_applied_bump_is_refused(monkeypatch):
    monkeypatch.setitem(
        yi.ASSETS,
        ("linux", "amd64"),
        "yara-x-v99.0.0-x86_64-unknown-linux-gnu.tar.gz",
    )
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        yi.pinned_asset("linux", "amd64")


def test_the_linux_amd64_pin_is_the_archive_that_was_hashed_when_it_was_captured():
    # The same digest the captured README records for the run that produced the fixtures.
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    assert yi.ARCHIVE_SHA256["yara-x-v1.23.0-x86_64-unknown-linux-gnu.tar.gz"] in readme


def test_the_install_table_builds_without_the_shared_pin_table(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = yi.yara_x_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(yi.ASSETS)
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert "install_yara_x" in " ".join(command.args)


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    from automated_security_helper.utils import download_utils as du

    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = yi.yara_x_install_commands()
    assert table["linux"]["amd64"], "a refusing command stands in"
    assert "install_yara_x" not in " ".join(table["linux"]["amd64"][0].args)


# ---------------------------------------------------------------------------
# Conversion over the captured run
# ---------------------------------------------------------------------------


def _converted():
    positive = (CAPTURED / "positive.ndjson").read_text(encoding="utf-8")
    return convert_ndjson(
        parse_ndjson(positive), source_dir=CAPTURED, tool_version=None
    )


def test_the_negative_capture_is_a_clean_scan():
    negative = (CAPTURED / "negative.ndjson").read_text(encoding="utf-8")
    sarif = convert_ndjson(
        parse_ndjson(negative), source_dir=CAPTURED, tool_version=None
    )
    assert sarif["runs"][0]["results"] == []


def test_each_rule_that_matched_becomes_one_result():
    results = _converted()["runs"][0]["results"]
    assert [(r["ruleId"], r["level"]) for r in results] == [
        ("demo_marker", "error"),
        ("no_sev", "none"),
    ]


def test_the_committed_sarif_is_what_the_converter_writes():
    committed = json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
    assert committed == _converted()
