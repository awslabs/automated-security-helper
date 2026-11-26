# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Kyverno plugin page says what the plugin's code does.

docs/plugins/alpha/kyverno-plugin.md states the pinned release and why it is not the
next one, the platforms the pin covers, what a policy directory contributes and which
of its files are skipped, the size limit on a manifest, the severity mapping, and that
Kyverno's stderr stays out of the scan's errors. Each test pins one of those sentences
with ``assert_on_page`` and reads the code that makes it true: the install module's
tables, the hold in ``tool_downloads.HELD_PINS``, the scanner's constants and its
policy directory walk. A reworded sentence or a changed constant fails here, naming
which.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_kyverno_plugins import (
    kyverno_install,
)
from automated_security_helper.plugin_modules.ash_kyverno_plugins.kyverno_scanner import (
    KYVERNO_SEVERITY_MAP,
    MANIFEST_SUFFIXES,
    MAX_MANIFEST_BYTES,
    KyvernoScanner,
    KyvernoScannerConfig,
    severity_for,
)
from automated_security_helper.utils.tool_downloads import HELD_PINS
from tests.unit.docs.test_page_claims import assert_on_page

pytestmark = pytest.mark.unit

KYVERNO_PAGE = "docs/plugins/alpha/kyverno-plugin.md"


def test_the_page_names_the_pinned_release() -> None:
    assert_on_page(KYVERNO_PAGE, "ASH pins v1.19.2.")
    assert_on_page(
        KYVERNO_PAGE,
        "ASH pins the Kyverno CLI v1.19.2 in the plugin's own install module",
    )
    assert kyverno_install.KYVERNO_VERSION == "v1.19.2"
    # Every asset is of that release, so the page's version is the one installed.
    assert all("_v1.19.2_" in name for name in kyverno_install.ASSETS.values())


def test_the_page_says_why_the_pin_is_not_the_next_release() -> None:
    assert_on_page(
        KYVERNO_PAGE,
        "The pin is v1.19.2 and not v1.20.0 because v1.20.0 no longer loads the legacy "
        "`kyverno.io/v1` `ClusterPolicy` and `Policy` kinds.",
    )
    hold = HELD_PINS["kyverno"]
    # The weekly pin check holds the pin at the release the page names.
    assert hold.acknowledged == "v1.20.0"
    assert "legacy kyverno.io/v1 ClusterPolicy and Policy kinds" in hold.reason


def test_the_page_names_the_platforms_the_pin_covers() -> None:
    assert_on_page(
        KYVERNO_PAGE,
        "The pinned assets cover Linux, macOS and Windows on amd64 and arm64",
    )
    assert set(kyverno_install.ASSETS) == {
        (platform, arch)
        for platform in ("linux", "darwin", "windows")
        for arch in ("amd64", "arm64")
    }


def test_the_page_says_kyvernos_stderr_is_not_quoted() -> None:
    assert_on_page(
        KYVERNO_PAGE,
        "Kyverno's stderr is written to the scanner's log file and not quoted in the "
        "scan's errors, because it can contain text from a scanned file.",
    )
    assert KyvernoScanner.quote_tool_stderr is False


def test_the_page_names_the_files_a_policy_directory_contributes() -> None:
    assert_on_page(
        KYVERNO_PAGE,
        "A directory contributes every `.yaml`, `.yml` and `.json` file under it that "
        "holds a Kyverno policy document; other files in it are not passed to Kyverno.",
    )
    assert MANIFEST_SUFFIXES == (".yaml", ".yml", ".json")


def test_the_page_names_the_manifest_size_limit() -> None:
    assert_on_page(KYVERNO_PAGE, "files over 5 MiB")
    assert MAX_MANIFEST_BYTES == 5 * 1024 * 1024


@pytest.mark.parametrize("kyverno", sorted(KYVERNO_SEVERITY_MAP))
def test_the_severity_table_is_the_scanners_map(kyverno: str) -> None:
    severity, level = KYVERNO_SEVERITY_MAP[kyverno]
    assert_on_page(KYVERNO_PAGE, f"| `{kyverno}` | {severity} | `{level.value}` |")


def test_the_page_says_what_a_policy_with_no_known_severity_gets() -> None:
    assert_on_page(
        KYVERNO_PAGE,
        "A policy with no severity gets MEDIUM for a `fail` and LOW for a `warn`. A "
        "severity outside the five is HIGH",
    )
    assert severity_for({"result": "fail"})[0] == "MEDIUM"
    assert severity_for({"result": "warn"})[0] == "LOW"
    assert severity_for({"result": "fail", "severity": "urgent"})[0] == "HIGH"
    # Control: a declared severity is the one used.
    assert severity_for({"result": "fail", "severity": "low"})[0] == "LOW"


_POLICY = """\
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: {name}
spec:
  rules:
    - name: check
      match:
        any:
          - resources:
              kinds: [Pod]
      validate:
        message: a label is required
        pattern:
          metadata:
            labels:
              team: "?*"
"""


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_the_page_says_a_policy_file_reached_through_a_link_leaving_is_skipped(
    tmp_path: Path,
) -> None:
    assert_on_page(
        KYVERNO_PAGE,
        "A file under the directory that resolves outside it, through a link to a file "
        "elsewhere or under a linked directory, is skipped with a warning and not read; "
        "to apply the policies such a link leads to, add their directory to "
        "`policy_paths`.",
    )
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "nested").mkdir(parents=True)
    (elsewhere / "outside.yaml").write_text(_POLICY.format(name="outside"))
    (elsewhere / "nested" / "deep.yaml").write_text(_POLICY.format(name="deep"))
    policies = tmp_path / "src" / "policies"
    policies.mkdir(parents=True)
    (policies / "kept.yaml").write_text(_POLICY.format(name="kept"))
    (policies / "linked.yaml").symlink_to(elsewhere / "outside.yaml")
    (policies / "linked-dir").symlink_to(elsewhere / "nested", target_is_directory=True)
    # Control: a link that stays inside the directory is kept.
    (policies / "alias.yaml").symlink_to(policies / "kept.yaml")
    scanner = KyvernoScanner(
        context=PluginContext(
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=AshConfig(),
        ),
        config=KyvernoScannerConfig(),
    )

    kept = scanner._policy_dir_files(policies)

    assert sorted(path.name for path in kept) == ["alias.yaml", "kept.yaml"]
