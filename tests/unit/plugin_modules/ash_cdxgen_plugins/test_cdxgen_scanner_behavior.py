# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Behavior of the cdxgen scanner with the subprocess replaced by a fake.

The fake writes the report where the argv says, as cdxgen would, so every test runs
without cdxgen or Node.js installed.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_cdxgen_plugins
from automated_security_helper.plugin_modules.ash_cdxgen_plugins.cdxgen_scanner import (
    CDXGEN_VERSION,
    CdxgenScanner,
    CdxgenScannerConfig,
    CdxgenScannerConfigOptions,
)
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport

pytestmark = pytest.mark.unit

SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.19.0",
            "name": "requests",
            "version": "2.19.0",
            "purl": "pkg:pypi/requests@2.19.0",
        }
    ],
}
EMPTY_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")


def _context(tmp_path: Path) -> PluginContext:
    output = tmp_path / "out"
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    (context.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    return context


def _scanner(tmp_path: Path, **options) -> CdxgenScanner:
    scanner = CdxgenScanner(
        context=_context(tmp_path),
        config=CdxgenScannerConfig(options=CdxgenScannerConfigOptions(**options)),
    )
    scanner.dependencies_satisfied = True
    return scanner


def _scan(scanner, response, document=None, *, raw=None, commands=None):
    def run(command, **kwargs):
        if commands is not None:
            commands.append(([str(part) for part in command], kwargs))
        written = (
            raw
            if raw is not None
            else (json.dumps(document) if document is not None else None)
        )
        if written is not None:
            token = next(a for a in command if str(a).startswith("--output="))
            destination = Path(str(token).split("=", 1)[1])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(written)
        return response

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=run),
    ):
        return scanner.scan(
            target=Path(scanner.context.source_dir), target_type="source"
        )


def test_the_module_exports_the_scanner():
    assert ash_cdxgen_plugins.ASH_SCANNERS == [CdxgenScanner]
    assert ash_cdxgen_plugins.ASH_REPORTERS == []


def test_the_scanner_is_on_by_default_once_its_module_is_listed():
    assert CdxgenScannerConfig().enabled is True


def test_happy_path_returns_the_sbom(tmp_path):
    report = _scan(_scanner(tmp_path), {"returncode": 0}, SBOM)

    assert isinstance(report, CycloneDXReport)
    assert [c.name for c in report.components] == ["requests"]


def test_negative_control_an_empty_sbom_has_no_components(tmp_path):
    report = _scan(_scanner(tmp_path), {"returncode": 0}, EMPTY_SBOM)

    assert isinstance(report, CycloneDXReport)
    assert not report.components


def test_every_fixed_flag_and_the_scan_path(tmp_path):
    scanner = _scanner(tmp_path, project_type=["python"])
    commands: list = []
    _scan(scanner, {"returncode": 0}, EMPTY_SBOM, commands=commands)

    ((argv, kwargs),) = commands
    assert argv[0] == "cdxgen"
    assert "--spec-version=1.6" in argv
    assert "--no-install-deps" in argv
    assert "--type=python" in argv
    assert any(
        a.startswith("--output=") and a.endswith("cdxgen.cdx.json") for a in argv
    )
    assert argv[-1] == Path(scanner.context.source_dir).absolute().as_posix()
    # Run from outside the scanned tree, so a .cdxgenrc in it is not read.
    cwd = Path(kwargs["cwd"]).absolute()
    assert Path(scanner.context.source_dir).absolute() not in (cwd, *cwd.parents)


@pytest.mark.parametrize("flag", ["--install-deps", "--server", "--deep", "--evidence"])
def test_flags_that_run_project_code_or_reach_out_are_never_passed(tmp_path, flag):
    commands: list = []
    _scan(_scanner(tmp_path), {"returncode": 0}, EMPTY_SBOM, commands=commands)

    ((argv, _),) = commands
    assert not any(a == flag or a.startswith(f"{flag}=") for a in argv)


def test_the_timeout_reaches_the_subprocess_and_fails_the_scan(tmp_path):
    scanner = _scanner(tmp_path)
    commands: list = []
    with pytest.raises(ScannerError, match="timed out"):
        _scan(
            scanner,
            {"returncode": -9, "timed_out": True},
            None,
            commands=commands,
        )
    ((_, kwargs),) = commands
    assert kwargs["timeout"] == scanner._effective_scan_timeout()
    assert 0 < kwargs["timeout"]


@pytest.mark.parametrize(
    "raw",
    ["", "not json", "[1, 2]", json.dumps({"bomFormat": 7, "specVersion": []})],
)
def test_malformed_output_fails_the_scan(tmp_path, raw):
    with pytest.raises(ScannerError):
        _scan(_scanner(tmp_path), {"returncode": 0}, raw=raw)


def test_a_run_that_wrote_no_report_fails_the_scan(tmp_path):
    with pytest.raises(ScannerError):
        _scan(_scanner(tmp_path), {"returncode": 0}, None)


@pytest.mark.parametrize("code", [1, 4, 5, 126, 137])
def test_a_nonzero_exit_fails_even_with_a_report_on_disk(tmp_path, code):
    with pytest.raises(ScannerError):
        _scan(_scanner(tmp_path), {"returncode": code}, SBOM)


def test_a_report_left_by_an_earlier_run_is_not_read(tmp_path):
    scanner = _scanner(tmp_path)
    _scan(scanner, {"returncode": 0}, SBOM)
    with pytest.raises(ScannerError):
        _scan(scanner, {"returncode": 0}, None)


def test_a_missing_target_never_reaches_the_tool(tmp_path):
    scanner = _scanner(tmp_path)
    with patch.object(scanner, "_run_subprocess") as run:
        result = scanner.scan(target=tmp_path / "nowhere", target_type="source")
    assert result is True
    run.assert_not_called()


def test_tool_absent_is_reported_and_the_scan_does_not_run(tmp_path):
    scanner = _scanner(tmp_path)
    with patch(
        "automated_security_helper.plugin_modules.ash_cdxgen_plugins."
        "cdxgen_scanner.find_executable",
        return_value=None,
    ):
        assert scanner.validate_plugin_dependencies() is False
    scanner.dependencies_satisfied = False
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess") as run,
    ):
        assert (
            scanner.scan(target=Path(scanner.context.source_dir), target_type="source")
            is False
        )
    run.assert_not_called()


def test_tool_present_is_accepted(tmp_path):
    with patch(
        "automated_security_helper.plugin_modules.ash_cdxgen_plugins."
        "cdxgen_scanner.find_executable",
        return_value="/usr/bin/cdxgen",
    ):
        assert _scanner(tmp_path).validate_plugin_dependencies() is True


@pytest.mark.parametrize(
    "platform,arch",
    [(p, a) for p in ("linux", "darwin", "windows") for a in ("amd64", "arm64")],
)
def test_install_commands_cover_every_platform(tmp_path, platform, arch):
    commands = _scanner(tmp_path).get_installation_commands(platform, arch)
    assert commands
    assert ["npm", "install", "-g", f"@cyclonedx/cdxgen@{CDXGEN_VERSION}"] in [
        list(getattr(c, "args", c)) for c in commands
    ]
