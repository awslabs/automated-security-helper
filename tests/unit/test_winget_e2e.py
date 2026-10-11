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
import zipfile
from pathlib import Path
from types import ModuleType

import pytest
import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

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
        # The marker keeps ASH's own scan of this repository from reading the public
        # digest as a high-entropy secret.
        assert re.search(
            rf"^\${name} = '[0-9A-F]{{64}}'  # pragma: allowlist secret$",
            text,
            re.MULTILINE,
        ), name
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
    # By the ID the msix job's upload handed over: a name with run_attempt in it
    # would be recomputed by a re-run of this job and miss the msix job's upload.
    assert [d["with"]["artifact-ids"] for d in downloads] == [
        "${{ needs.msix.outputs.artifact-id }}"
    ]
    assert jobs["msix"]["outputs"]["artifact-id"] == (
        "${{ steps.upload.outputs.artifact-id }}"
    )
    upload = next(s for s in jobs["msix"]["steps"] if s.get("id") == "upload")
    assert upload["with"]["name"].startswith("ash-msix-")
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


# ---------------------------------------------------------------------------------------
# PackageFamilyName. `winget uninstall --manifest` and `winget upgrade --manifest` find an
# installed MSIX by the installer's PackageFamilyName; without one they fall back to the
# PackageIdentifier, which never matches an MSIX entry, and fail with
# NO_APPLICATIONS_FOUND. So the loopback set must carry it, and it must be right.

MICROSOFT_CORPORATION = (
    "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
)


def _verify_ps1_family(variable: str) -> str:
    match = re.search(
        rf"^\${variable} = '([^']+)'$",
        VERIFY_PS1.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert match, variable
    return match.group(1)


@pytest.mark.parametrize(
    ("name", "publisher", "expected"),
    [
        # The App Installer family verify-on-windows.ps1 registers by name. Microsoft
        # publishes it, and it is the family winget itself lives in.
        (
            "Microsoft.DesktopAppInstaller",
            MICROSOFT_CORPORATION,
            _verify_ps1_family("AppInstallerFamily"),
        ),
        # The Windows publisher, which every inbox shell package carries.
        (
            "Microsoft.Windows.ShellExperienceHost",
            "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
            "Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy",
        ),
    ],
)
def test_package_family_name_matches_real_families(
    name: str, publisher: str, expected: str
) -> None:
    module = _load(WINGET / "set-release-metadata.py", "set_release_metadata")
    assert module.package_family_name(name, publisher) == expected


def _installer_entry(out: Path) -> dict[str, object]:
    return yaml.safe_load(
        (out / "Amazon.AutomatedSecurityHelper.installer.yaml").read_text(
            encoding="utf-8"
        )
    )["Installers"][0]


def test_local_url_base_fills_the_package_family_name(tmp_path: Path) -> None:
    result = _render(tmp_path, "--local-url-base", "http://127.0.0.1:8123")
    assert result.returncode == 0, result.stderr
    module = _load(WINGET / "set-release-metadata.py", "set_release_metadata")
    # _fake_msix's Identity: Name AWSLabs.AutomatedSecurityHelper, Publisher CN=test.
    expected = module.package_family_name("AWSLabs.AutomatedSecurityHelper", "CN=test")
    assert re.fullmatch(r"AWSLabs\.AutomatedSecurityHelper_[0-9a-z]{13}", expected)
    assert _installer_entry(tmp_path / "out")["PackageFamilyName"] == expected
    assert f"PackageFamilyName: {expected}" in result.stdout


def test_the_release_set_does_not_carry_a_package_family_name(tmp_path: Path) -> None:
    result = _render(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "PackageFamilyName" not in _installer_entry(tmp_path / "out")


def test_the_rendered_installer_does_not_call_its_digest_a_placeholder(
    tmp_path: Path,
) -> None:
    for out, extra in (
        ("release", ()),
        ("loopback", ("--local-url-base", "http://127.0.0.1:1")),
    ):
        (tmp_path / out).mkdir()
        result = _render(tmp_path / out, *extra)
        assert result.returncode == 0, result.stderr
        text = (
            tmp_path / out / "out" / "Amazon.AutomatedSecurityHelper.installer.yaml"
        ).read_text(encoding="utf-8")
        assert "64 zeros" not in text, out
        assert "set-release-metadata.py" in text.split("\n# yaml-language-server")[0]
        # The schema header winget checks survives the rewrite.
        assert "# yaml-language-server: $schema=" in text


# ---------------------------------------------------------------------------------------
# The rendered sets through the real validator. set-release-metadata.py calls
# validate-manifests.py as a subprocess; here both run in this process, with the one
# network call (fetch_schema) answered by a stand-in that enforces the constraints the
# validator's self-test corrupts plus the PackageFamilyName pattern from the published
# 1.12.0 installer schema. What is under test is the wiring and the URL rules, not the
# published schemas, which the `winget` job in ash-package.yml checks against the real
# ones.

PFN_PATTERN = r"^[A-Za-z0-9][-\.A-Za-z0-9]+_[A-Za-z0-9]{13}$"
STAND_IN_SCHEMAS: dict[str, dict[str, object]] = {
    "version": {"type": "object", "required": ["PackageIdentifier"]},
    "installer": {
        "type": "object",
        "properties": {
            "Installers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "InstallerSha256": {
                            "type": "string",
                            "pattern": "^[A-Fa-f0-9]{64}$",
                        },
                        "PackageFamilyName": {"type": "string", "pattern": PFN_PATTERN},
                    },
                },
            }
        },
    },
    "defaultLocale": {
        "type": "object",
        "properties": {
            "PackageLocale": {
                "type": "string",
                "pattern": r"^([a-zA-Z]{2,3}|[iI]-[a-zA-Z]+|[xX]-[a-zA-Z]{1,8})(-[a-zA-Z]{1,8})*$",
            }
        },
    },
}


@pytest.fixture
def in_process_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ModuleType, ModuleType]:
    """set-release-metadata.py and validate-manifests.py, with the validator's
    subprocess call run in this process and its schema fetch stubbed."""
    metadata = _load(WINGET / "set-release-metadata.py", "set_release_metadata")
    validator = _load(WINGET / "validate-manifests.py", "validate_manifests")
    monkeypatch.setattr(
        validator,
        "fetch_schema",
        lambda manifest_type, _: STAND_IN_SCHEMAS[manifest_type],
    )

    def run_validator(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        assert Path(args[1]).name == "validate-manifests.py", args
        monkeypatch.setattr(sys, "argv", args[1:])
        try:
            code = validator.main()
        except validator.Failure as failure:
            print(f"FAIL: {failure}", file=sys.stderr)
            code = 1
        return subprocess.CompletedProcess(args, code)

    monkeypatch.setattr(metadata.subprocess, "run", run_validator)
    return metadata, validator


def _render_in_process(
    metadata: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *extra: str,
) -> Path:
    version = _project_version()
    msix = _fake_msix(tmp_path / f"automated-security-helper-{version}.msix", version)
    out = tmp_path / "out"
    monkeypatch.setattr(
        sys,
        "argv",
        ["set-release-metadata.py", "--msix", str(msix), "--out-dir", str(out), *extra],
    )
    assert metadata.main() == 0
    return out


def _validate(
    validator: ModuleType, monkeypatch: pytest.MonkeyPatch, *args: str
) -> None:
    monkeypatch.setattr(sys, "argv", ["validate-manifests.py", *args])
    assert validator.main() == 0


def test_a_rendered_loopback_set_passes_the_local_installer_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    in_process_validator: tuple[ModuleType, ModuleType],
    capsys: pytest.CaptureFixture[str],
) -> None:
    metadata, _ = in_process_validator
    # No --skip-validate: main() runs the validator on its own output, with the flags
    # it chooses. Without --local-installer the loopback URL fails the release-tag
    # check, so this fails if that flag is dropped from the call.
    _render_in_process(
        metadata, tmp_path, monkeypatch, "--local-url-base", "http://127.0.0.1:8123"
    )
    out = capsys.readouterr().out
    assert "the installer URL is a loopback server" in out
    assert "WINGET MANIFEST VALIDATION PASSED" in out


def test_a_release_set_fails_the_local_installer_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    in_process_validator: tuple[ModuleType, ModuleType],
) -> None:
    metadata, validator = in_process_validator
    out = _render_in_process(metadata, tmp_path, monkeypatch)
    # The same set passes as what it is...
    _validate(validator, monkeypatch, str(out), "--released")
    # ...and is refused as a loopback set.
    with pytest.raises(validator.Failure, match="--local-installer requires"):
        _validate(validator, monkeypatch, str(out), "--released", "--local-installer")


def test_a_loopback_set_without_a_package_family_name_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    in_process_validator: tuple[ModuleType, ModuleType],
) -> None:
    metadata, validator = in_process_validator
    out = _render_in_process(
        metadata, tmp_path, monkeypatch, "--local-url-base", "http://127.0.0.1:8123"
    )
    installer = out / "Amazon.AutomatedSecurityHelper.installer.yaml"
    text = installer.read_text(encoding="utf-8")
    stripped = re.sub(r"(?m)^  PackageFamilyName: .*\n", "", text)
    assert stripped != text
    installer.write_text(stripped, encoding="utf-8")
    with pytest.raises(validator.Failure, match="PackageFamilyName"):
        _validate(validator, monkeypatch, str(out), "--released", "--local-installer")


# ---------------------------------------------------------------------------------------
# verify-on-windows.ps1 wiring that cannot run off Windows.


def test_the_family_name_is_checked_before_the_first_uninstall_or_upgrade() -> None:
    text = VERIFY_PS1.read_text(encoding="utf-8")
    first_uninstall = text.index("'uninstall', '--manifest'")
    first_upgrade = text.index("'upgrade', '--manifest'")
    checks = [m.start() for m in re.finditer(r"Assert-FamilyName -Package", text)]
    # One after the N install, one after the N-1 install.
    assert len(checks) == 2, checks
    assert checks[0] < first_uninstall
    assert checks[0] < checks[1] < first_upgrade
    for manifests in ("$localN", "$localPrevious"):
        assert f"Assert-FamilyName -Package $package -Manifests {manifests}" in text


def test_the_minimum_winget_version_is_the_first_with_the_manifest_schema() -> None:
    # winget-cli added the 1.12 manifest schemas in v1.12.210-preview
    # (src/AppInstallerCommonCore/Manifest/ManifestSchemaValidation.cpp gains
    # s_ManifestVersionV1_12 there; v1.12.170-preview does not have it). An older client
    # validates a 1.12.0 manifest against the newest schema it knows.
    validator = _load(WINGET / "validate-manifests.py", "validate_manifests")
    assert validator.MANIFEST_VERSION == "1.12.0"
    assert _verify_ps1_family("MinimumWingetVersion") == "1.12.210"
    text = VERIFY_PS1.read_text(encoding="utf-8")
    assert text.count("Assert-WingetVersion -Client $client") == 1
    # The client the script installs when none is usable must itself be new enough.
    pinned = _verify_ps1_family("WingetReleaseTag").removeprefix("v")
    assert tuple(map(int, pinned.split("."))) >= (1, 12, 210), pinned


def test_the_ferret_suppression_covers_exactly_the_winget_digest_lines() -> None:
    # ferret-scan reads each 64-hex digest as a secret and ignores the inline
    # detect-secrets marker, so .ash/.ash_community_plugins.yaml suppresses it by line
    # range. A range that drifts off the digests would suppress whatever moved in.
    lines = VERIFY_PS1.read_text(encoding="utf-8").splitlines()
    digests = [
        number
        for number, line in enumerate(lines, start=1)
        if re.match(r"^\$Winget\w*Sha256 = '[0-9A-F]{64}'", line)
    ]
    assert len(digests) == 2, digests
    config = yaml.safe_load(
        (REPO / ".ash" / ".ash_community_plugins.yaml").read_text(encoding="utf-8")
    )
    entries = [
        s
        for s in config["global_settings"]["suppressions"]
        if s.get("path") == "packaging/winget/verify-on-windows.ps1"
    ]
    assert len(entries) == 1, entries
    assert entries[0]["rule_id"] == "API_KEY_OR_SECRET"
    assert (entries[0]["line_start"], entries[0]["line_end"]) == (
        digests[0],
        digests[-1],
    )
    assert digests == list(range(digests[0], digests[-1] + 1)), digests


_STRICT_SCRIPTS = sorted(
    path
    for path in (REPO / "packaging").rglob("*.ps1")
    if "Set-StrictMode -Version Latest" in path.read_text(encoding="utf-8")
)


def _array_returning_functions(text: str) -> set[str]:
    """Functions whose body has `return @(`: PowerShell unrolls that array on return."""
    names = set()
    for match in re.finditer(r"(?ms)^function ([\w-]+) \{\n(.*?)^\}", text):
        if re.search(r"^\s*return @\(", match.group(2), re.MULTILINE):
            names.add(match.group(1))
    return names


def _unwrapped_calls(text: str) -> list[str]:
    """Calls of an array-returning function that are not wrapped in @(...)."""
    found = []
    for name in sorted(_array_returning_functions(text)):
        for line_no, line in enumerate(text.splitlines(), start=1):
            code = line.split("#", 1)[0]
            for call in re.finditer(rf"(?<![\w-]){re.escape(name)}(?![\w-])", code):
                if code.lstrip().startswith("function "):
                    continue
                if not code[: call.start()].endswith("@("):
                    found.append(f"{line_no}: {line.strip()}")
    return found


def test_strict_scripts_are_found() -> None:
    names = {p.relative_to(REPO).as_posix() for p in _STRICT_SCRIPTS}
    assert "packaging/winget/verify-on-windows.ps1" in names
    assert "packaging/msix/verify-on-windows.ps1" in names


@pytest.mark.parametrize(
    "script", _STRICT_SCRIPTS, ids=lambda p: p.relative_to(REPO).as_posix()
)
def test_array_returning_functions_are_called_inside_an_array(script: Path) -> None:
    # A function's `return @(...)` reaches the caller as $null for zero items and as the
    # bare item for one. Under Set-StrictMode -Version Latest, .Count on either throws
    # "The property 'Count' cannot be found on this object", which is how the winget leg
    # died at its first Assert-NothingInstalled. Each call must be wrapped in @(...).
    assert _unwrapped_calls(script.read_text(encoding="utf-8")) == []


def test_unwrapped_call_detection_catches_the_winget_regression() -> None:
    text = (
        "function Get-AshPackage {\n"
        "    return @(Get-AppxPackage -Name $n)\n"
        "}\n"
        "$packages = Get-AshPackage\n"
        "$wrapped = @(Get-AshPackage)\n"
        "# Get-AshPackage in a comment is not a call\n"
    )
    assert _unwrapped_calls(text) == ["4: $packages = Get-AshPackage"]


# The flags each winget subcommand needs to run unattended, from the v1.29.380 sources
# (src/AppInstallerCLICore/Commands/*Command.cpp). --disable-interactivity is a common
# argument every command takes. Without --accept-source-agreements, a command that opens
# the default sources stops in PromptFlow.cpp at the msstore agreement and exits
# APPINSTALLER_CLI_ERROR_SOURCE_AGREEMENTS_NOT_ACCEPTED (0x8A150046); that is how the
# first `winget uninstall --manifest` of the leg failed. UninstallCommand.cpp declares
# AcceptSourceAgreements but not AcceptPackageAgreements, so uninstall must not carry
# --accept-package-agreements: winget refuses an argument the command does not declare.
_UNATTENDED_FLAGS = {
    "install": {
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
    },
    "upgrade": {
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
    },
    "uninstall": {"--accept-source-agreements", "--disable-interactivity"},
}
_UNDECLARED_FLAGS = {"uninstall": {"--accept-package-agreements"}}


def _winget_calls(text: str) -> list[tuple[int, list[str]]]:
    """Each Invoke-Winget call as (line number, its quoted argument strings)."""
    calls = []
    for match in re.finditer(
        r"Invoke-Winget\s+-Arguments\s+@\((.*?)\)\s+-LogName", text, re.DOTALL
    ):
        line_no = text.count("\n", 0, match.start()) + 1
        calls.append((line_no, re.findall(r"'([^']*)'", match.group(1))))
    return calls


def _unattended_problems(text: str) -> list[str]:
    problems = []
    for line_no, args in _winget_calls(text):
        if not args:
            problems.append(f"{line_no}: no quoted subcommand")
            continue
        subcommand, flags = args[0], set(args[1:])
        for missing in sorted(_UNATTENDED_FLAGS.get(subcommand, set()) - flags):
            problems.append(f"{line_no}: winget {subcommand} lacks {missing}")
        for extra in sorted(_UNDECLARED_FLAGS.get(subcommand, set()) & flags):
            problems.append(f"{line_no}: winget {subcommand} does not take {extra}")
    return problems


def test_every_winget_call_goes_through_invoke_winget() -> None:
    # The flag check below reads Invoke-Winget calls only, so a direct `& $script:winget`
    # anywhere but inside Invoke-Winget would escape it.
    text = VERIFY_PS1.read_text(encoding="utf-8")
    assert text.count("& $script:winget") == 1
    body = re.search(r"(?ms)^function Invoke-Winget \{\n(.*?)^\}", text)
    assert body and "& $script:winget" in body.group(1)


def test_every_winget_install_upgrade_uninstall_runs_unattended() -> None:
    text = VERIFY_PS1.read_text(encoding="utf-8")
    subcommands = [args[0] for _, args in _winget_calls(text) if args]
    # The leg installs three times, upgrades once and uninstalls twice; finding fewer
    # means the call parser stopped matching and the check below would pass on nothing.
    assert sorted(subcommands) == sorted(
        ["settings", "validate", "install", "install", "install", "upgrade"]
        + ["uninstall", "uninstall"]
    ), subcommands
    assert _unattended_problems(text) == []


def test_unattended_check_catches_the_uninstall_regression() -> None:
    text = (
        "$r = Invoke-Winget -Arguments @('uninstall', '--manifest', $m,"
        " '--disable-interactivity', '--silent') -LogName 'uninstall-N'\n"
        "$r = Invoke-Winget -Arguments @(\n"
        "    'install', '--manifest', $m, '--accept-source-agreements',\n"
        "    '--disable-interactivity'\n"
        ") -LogName 'install-N'\n"
        "$r = Invoke-Winget -Arguments @('uninstall', '--manifest', $m,"
        " '--accept-source-agreements', '--accept-package-agreements',"
        " '--disable-interactivity') -LogName 'uninstall-x'\n"
    )
    assert _unattended_problems(text) == [
        "1: winget uninstall lacks --accept-source-agreements",
        "2: winget install lacks --accept-package-agreements",
        "6: winget uninstall does not take --accept-package-agreements",
    ]
