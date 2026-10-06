# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Linux-testable parts of the winget end-to-end leg.

The leg itself (packaging/winget/verify-on-windows.ps1, the winget-client job in
.github/workflows/ash-package.yml) needs a Windows host with the winget client. What
it relies on that can run anywhere is tested here:

- scripts/e2e/lower_version.py, which derives the N-1 tree the upgrade starts from;
- set-release-metadata.py --local-url-base, which renders the loopback manifest set;
- validate-manifests.py --local-installer, which must refuse any non-loopback URL so a
  loopback set cannot pass as a release set;
- the pins and wiring the script and job depend on.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path
from types import ModuleType

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
WINGET = REPO / "packaging" / "winget"
LOWER = REPO / "scripts" / "e2e" / "lower_version.py"
VERIFY_PS1 = WINGET / "verify-on-windows.ps1"
WORKFLOW = REPO / ".github" / "workflows" / "ash-package.yml"
FORMATS = REPO / ".github" / "workflows" / "ash-package-formats.yml"


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_lower(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(LOWER), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _project_version() -> str:
    with (REPO / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


@pytest.fixture
def real_entries_tree(tmp_path: Path) -> Path:
    """A tree holding pyproject.toml and every file its version_files names."""
    with (REPO / "pyproject.toml").open("rb") as handle:
        entries = tomllib.load(handle)["tool"]["commitizen"]["version_files"]
    tree = tmp_path / "tree"
    for relative in {"pyproject.toml", *(e.partition(":")[0] for e in entries)}:
        destination = tree / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / relative, destination)
    return tree


def test_lower_version_rewrites_every_real_version_files_entry(
    real_entries_tree: Path,
) -> None:
    current = _project_version()
    result = _run_lower("--tree", str(real_entries_tree))
    assert result.returncode == 0, result.stderr
    lowered = result.stdout.strip()
    module = _load(LOWER, "lower_version")
    assert lowered == module.lower(current)
    assert module.release_tuple(lowered) < module.release_tuple(current)

    with (real_entries_tree / "pyproject.toml").open("rb") as handle:
        data = tomllib.load(handle)
    assert data["project"]["version"] == lowered
    assert data["tool"]["commitizen"]["version"] == lowered

    # The files the winget and MSIX N-1 build reads agree with each other afterwards.
    for suffix in ("", ".installer", ".locale.en-US"):
        manifest = yaml.safe_load(
            (
                real_entries_tree
                / "packaging"
                / "winget"
                / f"Amazon.AutomatedSecurityHelper{suffix}.yaml"
            ).read_text(encoding="utf-8")
        )
        assert str(manifest["PackageVersion"]) == lowered
    installer = (
        real_entries_tree
        / "packaging"
        / "winget"
        / "Amazon.AutomatedSecurityHelper.installer.yaml"
    ).read_text(encoding="utf-8")
    assert f"/v{lowered}/automated-security-helper-{lowered}.msix" in installer


def test_lower_version_refuses_an_entry_that_matches_nothing(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "pyproject.toml").write_text(
        '[project]\nversion = "3.7.0"\n\n[tool.commitizen]\nversion = "3.7.0"\n'
        'version_files = ["pyproject.toml:^version", "other.txt:^tag"]\n',
        encoding="utf-8",
    )
    (tree / "other.txt").write_text("tag 3.6.9\n", encoding="utf-8")
    result = _run_lower("--tree", str(tree))
    assert result.returncode == 1
    assert "other.txt:^tag" in result.stderr
    assert "rewrote nothing" in result.stderr


def test_lower_version_refuses_a_version_that_does_not_sort_below(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "pyproject.toml").write_text(
        '[project]\nversion = "3.7.0"\n\n[tool.commitizen]\nversion = "3.7.0"\n'
        'version_files = ["pyproject.toml:^version"]\n',
        encoding="utf-8",
    )
    result = _run_lower("--tree", str(tree), "--to", "3.10.0")
    assert result.returncode == 1
    assert "does not sort below" in result.stderr
    assert 'version = "3.7.0"' in (tree / "pyproject.toml").read_text(encoding="utf-8")


def test_lower_version_refuses_the_checkout_it_lives_in() -> None:
    result = _run_lower("--tree", str(REPO))
    assert result.returncode == 1
    assert "exported copy" in result.stderr


@pytest.mark.parametrize(
    ("version", "expected"),
    [("3.7.0", "3.6.0"), ("3.7.2", "3.7.1"), ("4.0.0", "3.0.0"), ("3.10.0", "3.9.0")],
)
def test_lower_decrements_the_last_nonzero_component(
    version: str, expected: str
) -> None:
    assert _load(LOWER, "lower_version").lower(version) == expected


def _fake_msix(path: Path, version: str) -> Path:
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">\n'
        f'  <Identity Name="AWSLabs.AutomatedSecurityHelper" Version="{version}.0" '
        'Publisher="CN=test" ProcessorArchitecture="x64"/>\n'
        "  <Dependencies>\n"
        '    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" '
        'MaxVersionTested="10.0.26100.0"/>\n'
        "  </Dependencies>\n"
        "</Package>\n"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AppxManifest.xml", manifest)
    return path


def _render(tmp_path: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    version = _project_version()
    msix = _fake_msix(tmp_path / f"automated-security-helper-{version}.msix", version)
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(WINGET / "set-release-metadata.py"),
            "--msix",
            str(msix),
            "--out-dir",
            str(tmp_path / "out"),
            "--skip-validate",
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_local_url_base_points_the_installer_at_the_loopback_server(
    tmp_path: Path,
) -> None:
    result = _render(tmp_path, "--local-url-base", "http://127.0.0.1:8123/")
    assert result.returncode == 0, result.stderr
    installer = yaml.safe_load(
        (tmp_path / "out" / "Amazon.AutomatedSecurityHelper.installer.yaml").read_text(
            encoding="utf-8"
        )
    )["Installers"][0]
    version = _project_version()
    assert (
        installer["InstallerUrl"]
        == f"http://127.0.0.1:8123/automated-security-helper-{version}.msix"
    )
    assert installer["InstallerSha256"] != "0" * 64
    validator = _load(WINGET / "validate-manifests.py", "validate_manifests")
    assert validator.LOCAL_URL.match(installer["InstallerUrl"])


def test_local_url_base_and_a_release_tag_are_mutually_exclusive(
    tmp_path: Path,
) -> None:
    result = _render(
        tmp_path, "--local-url-base", "http://127.0.0.1:8123", "--tag", "v1.2.3"
    )
    assert result.returncode == 1
    assert "--tag" in result.stderr


def test_without_local_url_base_the_release_url_is_unchanged(tmp_path: Path) -> None:
    result = _render(tmp_path)
    assert result.returncode == 0, result.stderr
    text = (
        tmp_path / "out" / "Amazon.AutomatedSecurityHelper.installer.yaml"
    ).read_text(encoding="utf-8")
    version = _project_version()
    assert (
        "  InstallerUrl: https://github.com/awslabs/automated-security-helper/releases/"
        f"download/v{version}/automated-security-helper-{version}.msix"
    ) in text


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8123/automated-security-helper-3.7.0.msix",
        "http://localhost:80/a.msix",
    ],
)
def test_local_installer_accepts_loopback(url: str) -> None:
    validator = _load(WINGET / "validate-manifests.py", "validate_manifests")
    assert validator.LOCAL_URL.match(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/awslabs/automated-security-helper/releases/download/v3.7.0/x.msix",
        "http://127.0.0.1/a.msix",
        "http://127.0.0.1.example.com:80/a.msix",
        "http://10.0.0.1:8123/a.msix",
        "http://127.0.0.1:8123/sub/a.msix",
        "http://127.0.0.1:8123/a.msix?x=1",
        "file:///C:/a.msix",
    ],
)
def test_local_installer_refuses_anything_but_loopback(url: str) -> None:
    validator = _load(WINGET / "validate-manifests.py", "validate_manifests")
    assert validator.LOCAL_URL.match(url) is None


def test_local_installer_requires_released(tmp_path: Path) -> None:
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(WINGET / "validate-manifests.py"),
            str(tmp_path),
            "--local-installer",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "pass --released too" in result.stderr


def test_the_pinned_winget_client_is_pinned_by_digest() -> None:
    text = VERIFY_PS1.read_text(encoding="utf-8")
    tag = re.search(
        r"^\$WingetReleaseTag = 'v[0-9]+\.[0-9]+\.[0-9]+'$", text, re.MULTILINE
    )
    assert tag, "the winget-cli release is not pinned to one stable version"
    for name in ("WingetBundleSha256", "WingetDependenciesSha256"):
        assert re.search(rf"^\${name} = '[0-9A-F]{{64}}'$", text, re.MULTILINE), name
    # Both downloads are checked against their pins before anything is installed.
    assert text.count("Assert-Sha256 -Path $bundle -Expected $WingetBundleSha256") == 1
    assert (
        text.count(
            "Assert-Sha256 -Path $dependencies -Expected $WingetDependenciesSha256"
        )
        == 1
    )


def test_the_hash_mismatch_code_is_the_one_winget_returns() -> None:
    # APPINSTALLER_CLI_ERROR_INSTALLER_HASH_MISMATCH is 0x8A150011; winget's process
    # exit code is that HRESULT as a signed 32-bit integer.
    signed = 0x8A150011 - (1 << 32)
    assert f"$HashMismatchExitCode = {signed}" in VERIFY_PS1.read_text(encoding="utf-8")


def test_the_winget_client_job_installs_the_msix_job_artifact() -> None:
    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    job = jobs["winget-client"]
    assert job["runs-on"] == "windows-latest"
    assert "msix" in job["needs"]
    assert "continue-on-error" not in job
    downloads = [s for s in job["steps"] if "download-artifact" in str(s.get("uses"))]
    assert [d["with"]["name"] for d in downloads] == [
        "ash-msix-${{ github.sha }}-attempt-${{ github.run_attempt }}"
    ]
    runs = [s["run"] for s in job["steps"] if "run" in s]
    assert any("packaging/winget/verify-on-windows.ps1" in r for r in runs)
    # The schema job stays.
    assert "winget" in jobs


def test_a_push_that_changes_the_scanned_code_reruns_the_package_jobs() -> None:
    push = yaml.safe_load(FORMATS.read_text(encoding="utf-8"))[True]["push"]
    assert push["branches"] == ["**"]
    for path in ("automated_security_helper/**", "scripts/e2e/**", "tests/e2e/**"):
        assert path in push["paths"], path


def _pep723_dependencies(path: Path) -> set[str]:
    match = re.search(
        r"^# dependencies = (\[.*\])$", path.read_text(encoding="utf-8"), re.MULTILINE
    )
    assert match, f"{path.name} has no PEP 723 dependencies line"
    return set(yaml.safe_load(match.group(1)))


def test_set_release_metadata_can_run_the_validator_it_calls() -> None:
    # set-release-metadata.py runs validate-manifests.py with its own interpreter, which
    # under `uv run` is the environment built from ITS PEP 723 block. A package the
    # validator imports and this block omits fails the release render with
    # ModuleNotFoundError; requests was missing until the e2e leg first rendered a set.
    missing = _pep723_dependencies(
        WINGET / "validate-manifests.py"
    ) - _pep723_dependencies(WINGET / "set-release-metadata.py")
    assert not missing, missing
