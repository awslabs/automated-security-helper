# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""detect-secrets result paths are relative to the source directory, wherever ASH runs.

On a source directory ``proj`` holding one file and no ASH config, with ASH run
from the parent or from ``proj``, every detect-secrets URI reads ``settings.py``,
which the path sanitizer takes as relative to the source directory, so in a
workspace the ``workspace_uri`` never doubles the directory. With two files in
the scan set both runs read the same, and an ASH config in ``.ash/`` is a second
file.

detect-secrets' ``SecretsCollection.scan_files`` keys one file by the name it was
handed, which is absolute, and two or more by the path relative to ``root``; the
URI is made relative to the source directory in either case. The message carries
the key too, absolute for one file and relative for two.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)

# Assembled at runtime in that module, so this file holds no key-shaped literal for
# ASH's own self-scan to report.
from tests.unit.plugin_modules.ash_builtin.test_detect_secrets_scanner_behavior import (
    PLANTED_KEY,
)

# The scanner's dependency check asked uv for detect-secrets' version (``uv tool run
# detect-secrets --version``), so every scan here started the tool wherever uv could
# reach it. The scan itself runs in ASH's worker, so the probes answer without a
# process (tests/unit/conftest.py).
pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("no_tool_probes")]


def _scanner(tmp_path: Path, files: dict[str, str]) -> DetectSecretsScanner:
    source = tmp_path / "proj"
    for name, text in files.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.output_dir.mkdir(parents=True, exist_ok=True)
    return DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())


def _locations(report) -> list[tuple[str, str]]:
    return sorted(
        (
            result.locations[0].physicalLocation.root.artifactLocation.uri,
            result.message.root.text,
        )
        for result in report.runs[0].results
    )


SECRET = f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\n"


@pytest.mark.parametrize(
    "files",
    [
        pytest.param({"settings.py": SECRET}, id="one-file"),
        pytest.param(
            {"settings.py": SECRET, ".ash/.ash.yaml": "project_name: p\n"},
            id="with-an-ash-config",
        ),
    ],
)
def test_the_uri_is_relative_to_the_source_when_run_from_its_parent(
    tmp_path, monkeypatch, files
):
    scanner = _scanner(tmp_path, files)
    monkeypatch.chdir(tmp_path)

    report = scanner.scan(target=scanner.context.source_dir, target_type="source")

    locations = _locations(report)
    assert locations, "the planted key was not found"
    for uri, message in locations:
        assert uri == "settings.py", f"URI {uri!r} is not relative to the source"
        assert "'settings.py'" in message, message


def test_one_file_and_two_files_give_the_same_finding(tmp_path, monkeypatch):
    one = _scanner(tmp_path / "a", {"settings.py": SECRET})
    two = _scanner(
        tmp_path / "b", {"settings.py": SECRET, "README.md": "nothing here\n"}
    )
    monkeypatch.chdir(tmp_path)

    first = _locations(one.scan(target=one.context.source_dir, target_type="source"))
    second = _locations(two.scan(target=two.context.source_dir, target_type="source"))

    assert first == second


def test_a_converted_file_outside_the_source_keeps_its_absolute_path(tmp_path):
    """The path sanitizer leaves an absolute URI outside the source alone, as it
    does for bandit's findings in converted files."""
    scanner = _scanner(tmp_path, {"app.py": "x = 1\n"})
    converted = scanner.context.work_dir / "jupyter" / "notebook.py"
    converted.parent.mkdir(parents=True)
    converted.write_text(SECRET, encoding="utf-8")

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    uris = {uri for uri, _ in _locations(report)}
    assert uris == {converted.absolute().as_posix()}, uris
