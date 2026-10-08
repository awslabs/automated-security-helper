# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The release attaches, attests and gates one list of assets, and every format is on it.

packaging/release-assets.py is the list. .github/workflows/ash-release-assets.yml
builds and gates it (a push runs it as the dry run), and ash-tag-on-merge.yml attests
and attaches it. Three things can drift apart, and each has a test here:

* a new packaging/<format> or editors/<ide> directory that nobody decided how to ship
  (the coverage test, with a planted directory as its negative control);
* the workflows naming different files than the list (the attest subject, the
  `gh release create` argument and the staged directory must be one directory, held
  to the list before either runs);
* the dry run gaining a write scope, an attestation or a publish, which would make a
  push to any branch publish something.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "packaging" / "release-assets.py"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
RELEASE_ASSETS = WORKFLOWS / "ash-release-assets.yml"
TAG_ON_MERGE = WORKFLOWS / "ash-tag-on-merge.yml"
PACKAGE = WORKFLOWS / "ash-package.yml"
NATIVE = WORKFLOWS / "ash-native-packages.yml"


def _load():
    spec = importlib.util.spec_from_file_location("ash_release_assets", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ra = _load()


def _workflow(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    # PyYAML reads the bare `on:` key as the boolean True.
    if True in doc:
        doc["on"] = doc.pop(True)
    return doc


def _steps(doc: dict, job: str) -> list:
    return doc["jobs"][job]["steps"]


def _index(steps: list, predicate) -> int:
    hits = [i for i, step in enumerate(steps) if predicate(step)]
    assert len(hits) == 1, f"expected one matching step, found {len(hits)}"
    return hits[0]


# -- the list itself ---------------------------------------------------------


def test_the_self_test_passes():
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--self-test"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "self-test OK" in proc.stdout


def test_every_format_directory_has_a_release_line():
    assert ra.format_dirs_without_a_release_line(REPO_ROOT) == []


def test_a_planted_format_directory_without_a_release_line_fails(tmp_path: Path):
    # The negative control for the test above, on a copy of the real layout.
    for top in ra.FORMAT_ROOTS:
        for entry in (REPO_ROOT / top).iterdir():
            if entry.is_dir():
                (tmp_path / top / entry.name).mkdir(parents=True)
    assert ra.format_dirs_without_a_release_line(tmp_path) == []
    (tmp_path / "packaging" / "appimage").mkdir()
    (tmp_path / "editors" / "neovim").mkdir()
    assert ra.format_dirs_without_a_release_line(tmp_path) == [
        "packaging/appimage",
        "editors/neovim",
    ]


def test_every_asset_source_exists():
    for asset in ra.ASSETS:
        assert (REPO_ROOT / asset.source).exists(), asset


def test_the_release_carries_every_format_the_scope_names():
    # deb, rpm, msix, nupkg, flatpak, vsix, the JetBrains zip and the winget
    # manifests, beside the wheel, sdist and .mcpb that releases already carried.
    assert [a.key for a in ra.ASSETS] == [
        "wheel",
        "sdist",
        "mcpb",
        "deb",
        "rpm",
        "msix",
        "nupkg",
        "flatpak",
        "winget",
        "vsix",
        "jetbrains",
    ]
    assert sum(a.count for a in ra.ASSETS) == 13


def test_every_asset_has_a_gate():
    for asset in ra.ASSETS:
        assert asset.gate in ra.GATES, asset


@pytest.mark.parametrize(
    "name",
    [
        "automated_security_helper-4.0.0-py3-none-any.whl",
        "automated-security-helper_4.0.0_all.deb",
        "automated-security-helper-4.0.0-1.noarch.rpm",
        "automated-security-helper-4.0.0.msix",
        "ash.4.0.0.nupkg",
        "ash-4.0.0-x86_64.flatpak",
        "ash-vscode-4.0.0.vsix",
        "ash-jetbrains-0.1.0.zip",
        "ash-1.0.0.mcpb",
        "Amazon.AutomatedSecurityHelper.installer.yaml",
    ],
)
def test_each_real_file_name_matches_exactly_one_asset(name):
    assert len([a for a in ra.ASSETS if a.matches(name)]) == 1


def test_the_check_command_fails_on_a_missing_asset(tmp_path: Path):
    names = ra._fixture_names("4.0.0")
    ra._write_fixture(tmp_path, names)
    ok = subprocess.run(
        [sys.executable, str(SCRIPT), "check", str(tmp_path), "--version", "4.0.0"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stderr
    assert "13 file(s) for 11 asset(s)" in ok.stdout
    (tmp_path / "automated-security-helper-4.0.0.msix").unlink()
    bad = subprocess.run(
        [sys.executable, str(SCRIPT), "check", str(tmp_path), "--version", "4.0.0"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode == 1
    assert "msix: expected 1 file(s)" in bad.stderr


def test_the_real_mcpb_gate_passes_the_committed_bundle():
    bundle = REPO_ROOT / "ash-agent-plugins/agentic-coding/plugins/mcpb/ash.mcpb"
    ctx = ra.Context(REPO_ROOT, "4.0.0", ra.DEFAULT_REPOSITORY, ra.default_runner)
    ok, detail = ra.gate_mcpb_members(ctx, [bundle])
    assert ok, detail


# -- the dry run -------------------------------------------------------------


def test_the_dry_run_triggers_on_push_and_dispatch_with_its_own_paths():
    on = _workflow(RELEASE_ASSETS)["on"]
    assert on["push"]["branches"] == ["**"]
    paths = on["push"]["paths"]
    for own in (
        ".github/workflows/ash-release-assets.yml",
        "packaging/release-assets.py",
        "tests/unit/test_release_assets.py",
    ):
        assert own in paths
    assert "workflow_dispatch" in on
    assert "workflow_call" in on


def test_the_dry_run_holds_no_write_scope_and_never_attests_or_publishes():
    doc = _workflow(RELEASE_ASSETS)
    assert doc["permissions"] == {"contents": "read"}
    text = RELEASE_ASSETS.read_text(encoding="utf-8")
    assert "attest-build-provenance" not in text
    assert not re.search(r"^\s*[^#\n]*\bgh\s+release\b", text, re.MULTILINE)
    for name, job in doc["jobs"].items():
        perms = job.get("permissions")
        if "uses" in job:
            assert perms is None or perms == {"contents": "read"}, name
            continue
        assert perms == {"contents": "read"}, name


def test_signing_secrets_reach_the_build_only_for_a_release():
    package = _workflow(RELEASE_ASSETS)["jobs"]["package"]
    assert package["uses"] == "./.github/workflows/ash-package.yml"
    for name, value in package["secrets"].items():
        assert value == f"${{{{ inputs.release && secrets.{name} || '' }}}}", name


def test_the_assemble_job_gates_then_runs_both_negative_controls():
    steps = _steps(_workflow(RELEASE_ASSETS), "assemble")
    runs = [str(step.get("run", "")) for step in steps]
    gate = _index(
        steps,
        lambda s: "release-assets.py gate release-assets" in str(s.get("run", "")),
    )
    self_test = _index(
        steps, lambda s: "release-assets.py --self-test" in str(s.get("run", ""))
    )
    negative = _index(steps, lambda s: "Negative control" in str(s.get("name", "")))
    upload = _index(
        steps, lambda s: str(s.get("uses", "")).startswith("actions/upload-artifact@")
    )
    assert self_test < gate < negative < upload
    neg = runs[negative]
    assert 'rm -f "$missing"/*.deb' in neg
    assert "is not a release asset" in neg
    assert '[ "$failures" -eq 0 ]' in neg
    assert any("assert-no-image-publish.py --self-test" in run for run in runs)


def test_every_download_in_assemble_names_an_upload_in_the_call_tree():
    uploads = set()
    for path in (PACKAGE, NATIVE, RELEASE_ASSETS):
        for job in _workflow(path)["jobs"].values():
            for step in job.get("steps") or []:
                if str(step.get("uses", "")).startswith("actions/upload-artifact@"):
                    name = step["with"]["name"]
                    if "matrix.family" in name:
                        uploads.update(
                            name.replace("${{ matrix.family }}", f)
                            for f in ("deb", "rpm")
                        )
                    else:
                        uploads.add(name)
    downloads = [
        step["with"]["name"]
        for step in _steps(_workflow(RELEASE_ASSETS), "assemble")
        if str(step.get("uses", "")).startswith("actions/download-artifact@")
    ]
    assert len(downloads) == 8
    for name in downloads:
        assert name in uploads, name


def test_the_asset_legs_are_exactly_one_deb_and_one_rpm():
    matrix = _workflow(NATIVE)["jobs"]["package"]["strategy"]["matrix"]["include"]
    legs = [(leg["family"], leg["mode"]) for leg in matrix if leg.get("asset")]
    assert sorted(legs) == [("deb", "assert"), ("rpm", "assert")]


@pytest.mark.parametrize(
    "path", [PACKAGE, NATIVE, RELEASE_ASSETS], ids=lambda p: p.name
)
def test_every_checkout_builds_the_requested_ref(path: Path):
    doc = _workflow(path)
    assert doc["on"]["workflow_call"]["inputs"]["ref"]["default"] == ""
    for name, job in doc["jobs"].items():
        for step in job.get("steps") or []:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["ref"] == "${{ inputs.ref }}", (path.name, name)


# -- the release -------------------------------------------------------------


def test_the_release_attests_and_attaches_the_one_checked_directory():
    doc = _workflow(TAG_ON_MERGE)
    assert doc["permissions"] == {"contents": "read"}
    jobs = doc["jobs"]
    assert jobs["resolve"]["permissions"] == {"contents": "read"}
    assert jobs["assets"]["permissions"] == {"contents": "read"}
    assert jobs["assets"]["uses"] == "./.github/workflows/ash-release-assets.yml"
    assert jobs["assets"]["with"]["release"] is True
    assert jobs["assets"]["with"]["ref"] == "${{ needs.resolve.outputs.sha }}"
    assert jobs["tag-and-release"]["permissions"] == {
        "contents": "write",
        "id-token": "write",
        "attestations": "write",
    }
    steps = jobs["tag-and-release"]["steps"]
    checkout = _index(
        steps, lambda s: str(s.get("uses", "")).startswith("actions/checkout@")
    )
    assert steps[checkout]["with"]["ref"] == "${{ needs.resolve.outputs.sha }}"
    download = _index(
        steps, lambda s: str(s.get("uses", "")).startswith("actions/download-artifact@")
    )
    assert steps[download]["with"]["path"] == "release-assets"
    verify = _index(
        steps,
        lambda s: "release-assets.py check release-assets" in str(s.get("run", "")),
    )
    assert "sha256sum --strict -c" in steps[verify]["run"]
    assert steps[verify]["env"]["SUMS"] == "${{ needs.assets.outputs.sums }}"
    attest = _index(
        steps,
        lambda s: str(s.get("uses", "")).startswith("actions/attest-build-provenance@"),
    )
    assert steps[attest]["with"]["subject-path"] == "release-assets/*"
    create = _index(steps, lambda s: "gh release create" in str(s.get("run", "")))
    assert re.search(
        r"--title \"\$TAG\" \\\n\s+release-assets/\*\n", steps[create]["run"]
    )
    assert '--target "$RELEASE_SHA"' in steps[create]["run"]
    assert (
        jobs["tag-and-release"]["env"]["RELEASE_SHA"]
        == "${{ needs.resolve.outputs.sha }}"
    )
    after = _index(steps, lambda s: "--json assets" in str(s.get("run", "")))
    assert checkout < download < verify < attest < create < after


def test_publishing_steps_are_skipped_together_when_the_release_exists():
    steps = _workflow(TAG_ON_MERGE)["jobs"]["tag-and-release"]["steps"]
    guarded = [
        step["name"]
        for step in steps
        if step.get("if") == "needs.resolve.outputs.skip == 'false'"
    ]
    assert guarded == [
        "Download the gated release assets",
        "Verify the assets are the gated set",
        "Attest build provenance",
        "Create tag and GitHub Release",
        "Assert the release carries exactly the staged assets",
    ]
