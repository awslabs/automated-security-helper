# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/e2e/assert_dependencies_install.py, and the Windows legs that run it.

The script runs `ashx dependencies install --tool grype` from an installed package
and checks what landed. It only meets a real package on a Windows runner, so its
judgments are held here with the installer replaced: each test plants one way an
install can be wrong and requires the script to fail for it, next to the install that
must pass. The paths, pins and exit codes come from the product itself, exactly as on
the runner.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.cli.dependencies import (
    EXIT_BAD_SELECTION,
    get_architecture,
    get_platform,
)
from automated_security_helper.utils.download_utils import receipt_path
from automated_security_helper.utils.tool_downloads import get_tool_asset

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "e2e" / "assert_dependencies_install.py"
MSIX_LEG = REPO_ROOT / "packaging" / "msix" / "verify-on-windows.ps1"
CHOCOLATEY_LEG = REPO_ROOT / "packaging" / "chocolatey" / "verify-on-windows.ps1"
CLI = "ashx-under-test"


def _load():
    spec = importlib.util.spec_from_file_location("ash_e2e_deps_install", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


script = _load()
ASSET = get_tool_asset("grype", get_platform(), get_architecture())
BARE_VERSION = ASSET.version.lstrip("v")


class FakeInstall:
    """Stands in for the installed ashx and the binary it installs.

    `mode` plants one defect. "ok" is the install the script must accept.
    """

    def __init__(self, bin_dir: Path, mode: str = "ok") -> None:
        self.bin_dir = bin_dir
        self.mode = mode
        self.binary = bin_dir / ASSET.install_as
        self.commands: list[list[str]] = []

    def _done(self, command, rc, out=""):
        return subprocess.CompletedProcess(command, rc, out, "")

    def __call__(self, command, timeout):
        self.commands.append(list(command))
        if command[0] == str(self.binary):
            if self.mode == "wrong-version":
                return self._done(command, 0, "Application: grype\nVersion: 0.1.0\n")
            return self._done(
                command, 0, f"Application: grype\nVersion: {BARE_VERSION}\n"
            )
        assert command[:3] == [CLI, "dependencies", "install"], command
        tool = command[command.index("--tool") + 1]
        if tool != "grype":
            if self.mode == "accepts-unknown":
                return self._done(command, 0, "nothing to do")
            if self.mode == "unknown-other-refusal":
                return self._done(command, EXIT_BAD_SELECTION, "some other refusal")
            return self._done(
                command,
                EXIT_BAD_SELECTION,
                f"Unknown tool(s): {tool}\nAvailable: grype",
            )
        if self.mode == "install-fails":
            return self._done(command, 1, "download failed")
        if self.mode == "no-binary":
            return self._done(command, 0)
        self.bin_dir.mkdir(parents=True, exist_ok=True)
        self.binary.write_bytes(b"the extracted grype")
        installed = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        receipt = {
            "tool": "grype",
            "version": ASSET.version,
            "url": ASSET.url,
            "sha256": ASSET.sha256.lower(),
            "installed_sha256": installed,
            "installed_as": ASSET.install_as,
        }
        if self.mode == "unverified-pin":
            receipt["sha256"] = "0" * 64
        if self.mode == "replaced-binary":
            self.binary.write_bytes(b"something else under grype's name")
        if self.mode != "no-receipt":
            path = receipt_path(self.bin_dir, ASSET.install_as)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(receipt), encoding="utf-8")
        return self._done(command, 0, "Installed grype")


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    # Path.home() reads HOME on POSIX and USERPROFILE on Windows.
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("ASH_BIN_PATH", str(home / ".ash" / "bin"))
    return home


def _run(monkeypatch, home, mode, capsys):
    fake = FakeInstall(home / ".ash" / "bin", mode)
    monkeypatch.setattr(script, "run", fake)
    rc = script.main(["--cli", CLI, "--tool", "grype"])
    return rc, capsys.readouterr().out, fake


def test_a_verified_install_passes(monkeypatch, home, capsys):
    rc, out, fake = _run(monkeypatch, home, "ok", capsys)
    assert rc == 0, out
    summary = json.loads(out.strip().splitlines()[-1])
    assert summary["binary"] == str(fake.binary)
    assert summary["home"] == str(home)
    # The negative control ran, after the real install.
    assert fake.commands[-1][-1] == script.NONEXISTENT_TOOL
    assert "OK: refused as an unknown tool" in out


@pytest.mark.parametrize(
    ("mode", "reason"),
    [
        ("install-fails", "exited 1, expected 0"),
        ("no-binary", "wrote no"),
        ("no-receipt", "no receipt"),
        ("unverified-pin", "was not verified against this ASH's pin"),
        ("replaced-binary", "not the one extracted from the verified archive"),
        ("wrong-version", f"does not name {BARE_VERSION}"),
        ("accepts-unknown", "an unknown selection was not refused"),
        ("unknown-other-refusal", "without naming it as an unknown tool"),
    ],
)
def test_each_planted_defect_fails_for_its_reason(
    monkeypatch, home, capsys, mode, reason
):
    rc, out, _ = _run(monkeypatch, home, mode, capsys)
    assert rc == 1
    errors = [line for line in out.splitlines() if line.startswith("::error::")]
    assert len(errors) == 1, out
    assert reason in errors[0]


def test_a_tool_already_present_is_not_a_measurement(monkeypatch, home, capsys):
    bin_dir = home / ".ash" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / ASSET.install_as).write_bytes(b"left over")
    rc, out, fake = _run(monkeypatch, home, "ok", capsys)
    assert rc == 1
    assert "exists before the install" in out
    assert fake.commands == [], "nothing may be installed over a leftover"


def test_the_bad_selection_code_is_the_products():
    # The script compares against the product's constant, and the documented value is 2.
    assert EXIT_BAD_SELECTION == 2
    assert "EXIT_BAD_SELECTION" in SCRIPT.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# The legs run it from the installed package and act on its exit.
# --------------------------------------------------------------------------


def test_the_msix_leg_installs_grype_through_the_installed_package():
    text = MSIX_LEG.read_text(encoding="utf-8")
    start = text.index("Write-Step '8c.")
    step = text[start : text.index("Write-Step '9.", start)]
    assert text.index("Write-Step '8.") < start, "after the scans, before the reinstall"
    # The installed venv's interpreter, with -I, and the installed alias as the CLI.
    assert re.search(
        r"& \$venvPython -I \(Join-Path \$repoRoot 'scripts/e2e/assert_dependencies_install\.py'\)"
        r" --cli \$resolved\[\$cliName\] --tool grype",
        step,
    ), step
    assert re.search(r"if \(\$LASTEXITCODE -ne 0\) \{\s*Fail ", step)


def test_the_chocolatey_leg_installs_grype_as_an_unprivileged_user():
    text = CHOCOLATEY_LEG.read_text(encoding="utf-8")
    start = text.index("Write-Host '== 7b.")
    step = text[start : text.index("Write-Host '== 8.", start)]
    assert text.index("Write-Host '== 6.") < start
    assert "Invoke-AsStandardUser" in step
    assert "assert_dependencies_install.py" in step
    assert "--tool', 'grype'" in step
    # The user is proven unprivileged from its own token, and the binary proven theirs.
    assert "whoami.exe" in step and "S-1-5-32-544" in step
    assert re.search(r"if \(\$r\.Rc -ne 0\) \{\s*Fail-Verification ", step)
    assert ".Owner" in step
    # The child gets the user's own environment, never a copy of the runner's.
    helper = text[text.index("function Invoke-AsStandardUser") :]
    helper = helper[: helper.index("\n}\n")]
    assert "$info.LoadUserProfile = $true" in helper
    assert ".Environment" not in helper.replace("Environment is deliberately", "")


def test_the_throwaway_account_is_removed_even_when_a_check_fails():
    # Fail-Verification exits, and PowerShell runs a finally block on exit, so the
    # removal belongs there rather than after the last check.
    text = CHOCOLATEY_LEG.read_text(encoding="utf-8")
    start = text.index("Write-Host '== 7b.")
    step = text[start : text.index("Write-Host '== 8.", start)]
    created = step.index("New-StandardUser -Name")
    opened = step.index("\ntry {", created)
    cleanup = step[step.index("} finally {", opened) :]
    assert "Remove-StandardUser -User $standardUser" in cleanup
    assert step.count("Remove-StandardUser") == 1, "only in the finally block"
