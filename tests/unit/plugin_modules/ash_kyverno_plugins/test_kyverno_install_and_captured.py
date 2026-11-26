# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local install pin, and the adapter over the real captured Kyverno run.

``tests/test_data/scanners/kyverno/captured/`` holds what ``kyverno apply`` v1.19.2
printed (see its README) and the manifest it was run over. The conversion tests here
locate results through that manifest, so the committed SARIF is pinned over output the
tool produced and a line the manifest really declares, not over a hand-built index.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError
from automated_security_helper.plugin_modules.ash_kyverno_plugins import (
    kyverno_install as ki,
)
from automated_security_helper.plugin_modules.ash_kyverno_plugins.kyverno_scanner import (
    ManifestIndex,
    convert_report_results,
    load_manifest,
    parse_policy_report_output,
)

from .test_kyverno_scanner_behavior import _scanner

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "kyverno"
    / "captured"
)
HEX64 = re.compile(r"[0-9a-f]{64}")

#: Every (platform, arch) ASH installs for, with the name the executable lands as.
PUBLISHED = [
    ("darwin", "amd64", "kyverno"),
    ("darwin", "arm64", "kyverno"),
    ("linux", "amd64", "kyverno"),
    ("linux", "arm64", "kyverno"),
    ("windows", "amd64", "kyverno.exe"),
    ("windows", "arm64", "kyverno.exe"),
]


# ---------------------------------------------------------------------------
# Install pin
# ---------------------------------------------------------------------------


def test_every_asset_has_an_archive_digest_and_a_member_digest():
    assert set(ki.ASSETS.values()) == set(ki.ARCHIVE_SHA256) == set(ki.MEMBER_SHA256)
    for digest in [*ki.ARCHIVE_SHA256.values(), *ki.MEMBER_SHA256.values()]:
        assert HEX64.fullmatch(digest), digest
    assert len(set(ki.ARCHIVE_SHA256.values())) == len(ki.ARCHIVE_SHA256)
    assert len(set(ki.MEMBER_SHA256.values())) == len(ki.MEMBER_SHA256)


def test_asset_names_carry_the_pinned_version():
    for name in ki.ASSETS.values():
        assert name.startswith(f"kyverno-cli_{ki.KYVERNO_VERSION}_"), name


def test_the_table_covers_exactly_the_pairs_ash_installs_for():
    assert sorted(ki.ASSETS) == [(p, a) for p, a, _ in PUBLISHED]


@pytest.mark.parametrize("platform,arch,install_as", PUBLISHED)
def test_pinned_asset_resolves_a_published_pair(platform, arch, install_as):
    url, archive, member, name = ki.pinned_asset(platform, arch)
    assert url.startswith(
        "https://github.com/kyverno/kyverno/releases/download/"
        f"{ki.KYVERNO_VERSION}/kyverno-cli_"
    )
    assert url.endswith(".zip" if platform == "windows" else ".tar.gz")
    assert HEX64.fullmatch(archive) and HEX64.fullmatch(member)
    assert name == install_as


@pytest.mark.parametrize("pair", [("linux", "s390x"), ("freebsd", "amd64")])
def test_an_unpublished_pair_is_refused_by_name(pair):
    with pytest.raises(ToolNotProvisionableError, match=pair[0]):
        ki.pinned_asset(*pair)


def test_a_half_applied_bump_is_refused(monkeypatch):
    monkeypatch.setitem(
        ki.ASSETS, ("linux", "amd64"), "kyverno-cli_v9.9.9_linux_x86_64.tar.gz"
    )
    with pytest.raises(ToolNotProvisionableError, match="half-applied"):
        ki.pinned_asset("linux", "amd64")


def test_the_linux_amd64_pin_is_the_archive_that_was_hashed_when_it_was_captured():
    # The same digest the captured README records for the run that produced the fixtures.
    readme = (CAPTURED / "README.md").read_text(encoding="utf-8")
    assert ki.ARCHIVE_SHA256["kyverno-cli_v1.19.2_linux_x86_64.tar.gz"] in readme


def test_the_install_table_builds_without_the_shared_pin_table(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = ki.kyverno_install_commands()
    assert {(p, a) for p, arches in table.items() for a in arches} == set(ki.ASSETS)
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert "install_kyverno" in " ".join(command.args)


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    from automated_security_helper.utils import download_utils as du

    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = ki.kyverno_install_commands()
    assert table["linux"]["amd64"], "a refusing command stands in"
    assert "install_kyverno" not in " ".join(table["linux"]["amd64"][0].args)


def test_the_scanner_installs_through_the_module_local_table(tmp_path, monkeypatch):
    # The scanner carries the module's commands for every pair, so
    # `ash dependencies install --tool kyverno` has an install path on each.
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    source = tmp_path / "src"
    source.mkdir()
    scanner = _scanner(source, tmp_path)
    table = scanner.custom_install_commands
    assert {(p, a) for p, arches in table.items() for a in arches} == set(ki.ASSETS)
    (command,) = table["linux"]["amd64"]
    assert "install_kyverno" in " ".join(command.args)
    assert command.args[-3:-1] == ["linux", "amd64"]


# ---------------------------------------------------------------------------
# Conversion over the captured run, located through the captured manifest
# ---------------------------------------------------------------------------


def _manifest_index() -> ManifestIndex:
    # The capture ran in a directory holding k8s/bad.yaml (see the README).
    index = ManifestIndex()
    objects = load_manifest((CAPTURED / "bad.yaml").read_text(encoding="utf-8"))
    assert objects is not None
    for doc, line in objects:
        index.add(doc, "k8s/bad.yaml", line)
    return index


def _captured_entries():
    return parse_policy_report_output(
        (CAPTURED / "kyverno-1.19.2-high.report.yaml").read_text(encoding="utf-8")
    )


def test_the_captured_manifest_declares_the_failed_pod_on_its_first_line():
    objects = load_manifest((CAPTURED / "bad.yaml").read_text(encoding="utf-8"))
    assert [
        (d["kind"], d["metadata"]["namespace"], d["metadata"]["name"], line)
        for d, line in objects
    ] == [("Pod", "default", "bad-pod", 1)]


def test_the_good_pod_of_the_capture_passed_and_is_not_a_finding():
    results, _, failed = convert_report_results(_captured_entries(), _manifest_index())
    assert failed == []
    assert [r.properties.kyverno_resource for r in results] == ["Pod/default/bad-pod"]


def test_the_committed_sarif_is_what_the_adapter_makes_of_the_capture_and_manifest():
    results, rules, _ = convert_report_results(_captured_entries(), _manifest_index())
    committed = json.loads(
        (CAPTURED / "kyverno-1.19.2-high.sarif").read_text(encoding="utf-8")
    )
    run = committed["runs"][0]
    made = [
        json.loads(r.model_dump_json(exclude_none=True, by_alias=True)) for r in results
    ]
    assert made == run["results"]
    assert [r.id for r in rules] == [
        rule["id"] for rule in run["tool"]["driver"]["rules"]
    ]
    assert run["tool"]["driver"]["version"] == ki.KYVERNO_VERSION.lstrip("v")
