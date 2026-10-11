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
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path, PureWindowsPath

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


_REF = re.compile(r"^\$\{\{\s*(needs|jobs|steps)\.([\w-]+)\.outputs\.([\w-]+)\s*\}\}$")


def _ref(expr: str) -> tuple:
    match = _REF.match(str(expr).strip())
    assert match, f"{expr!r} is not one needs/jobs/steps output"
    return match.groups()


def _upload_behind(doc: dict, job: str, output: str) -> dict:
    """The upload-artifact step whose artifact-id ``jobs.<job>.outputs.<output>`` is."""
    kind, step_id, name = _ref(doc["jobs"][job]["outputs"][output])
    assert kind == "steps", (job, output)
    step = next(s for s in doc["jobs"][job]["steps"] if s.get("id") == step_id)
    if str(step.get("uses", "")).startswith("actions/upload-artifact@"):
        assert name == "artifact-id", (job, output, name)
        return step
    # A run step that hands an upload's ID on under a per-family name, as the native
    # package matrix does: it writes <name>= from its ARTIFACT_ID.
    assert f"{name}=${{ARTIFACT_ID}}" in step["run"], (job, step_id, name)
    kind, upload_id, upload_output = _ref(step["env"]["ARTIFACT_ID"])
    assert (kind, upload_output) == ("steps", "artifact-id"), (job, step_id)
    upload = next(s for s in doc["jobs"][job]["steps"] if s.get("id") == upload_id)
    assert str(upload.get("uses", "")).startswith("actions/upload-artifact@")
    return upload


def test_every_download_in_assemble_takes_an_upload_id_from_the_call_tree():
    # By ID, traced back to the upload step that produced it, so a rename on either
    # side cannot leave the download asking for something nothing uploaded.
    release = _workflow(RELEASE_ASSETS)
    callees = {"package": _workflow(PACKAGE), "native": _workflow(NATIVE)}
    uploads, refs = [], []
    for step in _steps(release, "assemble"):
        if not str(step.get("uses", "")).startswith("actions/download-artifact@"):
            continue
        assert "name" not in step["with"], step["name"]
        kind, job, output = _ref(step["with"]["artifact-ids"])
        assert kind == "needs" and job in release["jobs"]["assemble"]["needs"]
        refs.append((job, output))
        if job in callees:
            callee = callees[job]
            value = callee["on"]["workflow_call"]["outputs"][output]["value"]
            kind, inner_job, inner_output = _ref(value)
            assert kind == "jobs", value
            uploads.append(_upload_behind(callee, inner_job, inner_output))
        else:
            uploads.append(_upload_behind(release, job, output))
    names = [u["with"]["name"] for u in uploads]
    assert len(names) == 8
    assert len(set(refs)) == 8, refs
    for prefix in (
        "ash-package-",
        "ash-msix-",
        "ash-nupkg-",
        "ash-flatpak-",
        "ash-release-vsix-",
        "ash-release-jetbrains-",
    ):
        assert sum(n.startswith(prefix) for n in names) == 1, (prefix, names)
    # The deb and the rpm come from the one matrix upload, once per family.
    assert (
        names.count(
            "ash-${{ matrix.family }}-${{ github.sha }}-attempt-${{ github.run_attempt }}"
        )
        == 2
    )


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
    assert steps[download]["with"] == {
        "artifact-ids": "${{ needs.assets.outputs.artifact-id }}",
        "path": "release-assets",
    }
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
        "Check the release asset artifact ID",
        "Download the gated release assets",
        "Verify the assets are the gated set",
        "Attest build provenance",
        "Create tag and GitHub Release",
        "Assert the release carries exactly the staged assets",
    ]


# -- the release trigger, exactly --------------------------------------------
#
# A push trigger, or a resolve job without its merged and title guards, would run the
# release (tag, attest, publish) on something other than a merged release PR. These
# hold the exact values, so a weakened copy that keeps a familiar substring fails.


def test_the_release_runs_only_on_a_closed_pull_request_into_main():
    assert _workflow(TAG_ON_MERGE)["on"] == {
        "pull_request": {"types": ["closed"], "branches": ["main"]}
    }


def test_the_release_runs_only_for_a_merged_release_pull_request():
    jobs = _workflow(TAG_ON_MERGE)["jobs"]
    assert jobs["resolve"]["if"] == (
        "github.event.pull_request.merged == true && "
        "startsWith(github.event.pull_request.title, 'chore(release):')"
    )
    assert jobs["assets"]["needs"] == "resolve"
    assert jobs["assets"]["if"] == "needs.resolve.outputs.skip == 'false'"
    assert jobs["tag-and-release"]["needs"] == ["resolve", "assets"]
    assert jobs["tag-and-release"]["if"] == (
        "!cancelled() && needs.resolve.result == 'success' && "
        "(needs.resolve.outputs.skip == 'true' || needs.assets.result == 'success')"
    )


def test_the_release_builds_the_merge_commit_the_attestation_names():
    steps = _workflow(TAG_ON_MERGE)["jobs"]["resolve"]["steps"]
    checkout = _index(
        steps, lambda s: str(s.get("uses", "")).startswith("actions/checkout@")
    )
    assert steps[checkout]["with"]["ref"] == (
        "${{ github.event.pull_request.merge_commit_sha }}"
    )
    pin = _index(steps, lambda s: s.get("id") == "sha")
    assert steps[pin]["env"]["MERGE_SHA"] == (
        "${{ github.event.pull_request.merge_commit_sha }}"
    )


# -- the release steps, run ---------------------------------------------------
#
# Each step's own shell, extracted from the YAML and run the way Actions runs a bash
# step, against planted inputs. A step made non-fatal (an `|| true`, a dropped
# `set -e`, an `if` that only warns) keeps every substring the structural tests look
# for and fails here.

needs_bash = pytest.mark.skipif(
    os.name == "nt" or shutil.which("bash") is None,
    reason="bash on Windows runners is the WSL stub; the steps run on ubuntu-latest",
)


def _gnu_sha256sum() -> bool:
    # The verify step runs GNU `sha256sum --strict -c` on ubuntu-latest. A macOS
    # runner's sha256sum, where there is one, is not that program.
    if shutil.which("sha256sum") is None:
        return False
    probe = subprocess.run(
        ["sha256sum", "--version"], capture_output=True, text=True, check=False
    )
    return probe.returncode == 0 and "GNU coreutils" in probe.stdout


needs_gnu_sha256sum = pytest.mark.skipif(
    not _gnu_sha256sum(),
    reason="the verify step runs GNU coreutils sha256sum on ubuntu-latest",
)

# `uv run [--flags] python ARGS` -> this interpreter, ARGS. The steps reach Python
# through uv; the harness has no reason to resolve an environment.
UV_SHIM = """#!/usr/bin/env bash
set -euo pipefail
[ "$1" = run ] || { echo "uv shim: only 'run' is supported" >&2; exit 2; }
shift
while [ "$#" -gt 0 ] && [ "$1" != python ]; do shift; done
[ "$#" -gt 0 ] || { echo "uv shim: no python in the command" >&2; exit 2; }
shift
exec "$ASH_TEST_PYTHON" "$@"
"""


def _step_run(path: Path, job: str, predicate) -> str:
    steps = _steps(_workflow(path), job)
    return str(steps[_index(steps, predicate)]["run"])


def _named(name: str):
    return lambda s: s.get("name") == name


def _shim_dir(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(UV_SHIM, encoding="utf-8")
    uv.chmod(0o755)
    (bin_dir / "python3").symlink_to(sys.executable)
    return bin_dir


def _run_step(script: str, cwd: Path, env: dict, bin_dir: Path):
    runner_temp = cwd / "_runner_temp"
    runner_temp.mkdir(exist_ok=True)
    script_file = runner_temp / "step.sh"
    script_file.write_text(script, encoding="utf-8")
    full_env = {
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(cwd),
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_OUTPUT": str(runner_temp / "github_output"),
        "GITHUB_STEP_SUMMARY": str(runner_temp / "step_summary"),
        "ASH_TEST_PYTHON": sys.executable,
        **env,
    }
    # The shell Actions uses for `shell: bash` on a hosted runner.
    return subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script_file)],
        cwd=str(cwd),
        env=full_env,
        capture_output=True,
        text=True,
        check=False,
    )


def _staged_tree(tmp_path: Path, version: str = "4.0.0") -> Path:
    """A working directory with packaging/release-assets.py and a complete set."""
    work = tmp_path / "work"
    (work / "packaging").mkdir(parents=True)
    shutil.copy2(SCRIPT, work / "packaging" / "release-assets.py")
    ra._write_fixture(work / "release-assets", ra._fixture_names(version))
    return work


def _sums(directory: Path) -> str:
    return "".join(
        f"{ra.sha256(p)}  {p.name}\n"
        for p in sorted(directory.iterdir())
        if p.is_file()
    )


VERIFY = "Verify the assets are the gated set"


@needs_bash
@needs_gnu_sha256sum
@pytest.mark.parametrize("trailing_newline", [False, True])
def test_the_verify_step_passes_the_gated_set(tmp_path: Path, trailing_newline):
    # The runner hands a heredoc output over without its last newline; with one, the
    # step must still read the sums, since --strict refuses a blank line.
    work = _staged_tree(tmp_path)
    sums = _sums(work / "release-assets")
    proc = _run_step(
        _step_run(TAG_ON_MERGE, "tag-and-release", _named(VERIFY)),
        work,
        {
            "VERSION": "4.0.0",
            "BUILT_VERSION": "4.0.0",
            "SUMS": sums if trailing_newline else sums.rstrip("\n"),
        },
        _shim_dir(tmp_path),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "release asset set OK: 13 file(s)" in proc.stdout


@needs_bash
@needs_gnu_sha256sum
@pytest.mark.parametrize(
    "case",
    ["built-for-another-version", "tampered-file", "extra-file", "empty-sums"],
)
def test_the_verify_step_refuses_what_the_gates_did_not_pass(tmp_path: Path, case):
    work = _staged_tree(tmp_path)
    staged = work / "release-assets"
    env = {
        "VERSION": "4.0.0",
        "BUILT_VERSION": "4.0.0",
        "SUMS": _sums(staged).rstrip("\n"),
    }
    expect = ""
    if case == "built-for-another-version":
        env["BUILT_VERSION"] = "3.9.0"
        expect = "the assets were built for 3.9.0, and this release is 4.0.0"
    elif case == "tampered-file":
        # Same name, so the set check alone would pass it; only the digest refuses.
        (staged / "ash.4.0.0.nupkg").write_bytes(b"swapped after the gates ran")
        expect = "FAILED"
    elif case == "extra-file":
        # Not in the sums, so sha256sum -c alone would pass it; only the check refuses.
        (staged / "ash-extra-4.0.0.bin").write_bytes(b"ungated")
        expect = "ash-extra-4.0.0.bin is not a release asset"
    elif case == "empty-sums":
        env["SUMS"] = ""
        expect = "no properly formatted"
    proc = _run_step(
        _step_run(TAG_ON_MERGE, "tag-and-release", _named(VERIFY)),
        work,
        env,
        _shim_dir(tmp_path),
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert expect in proc.stdout + proc.stderr


ARTIFACT_ID = "Check the release asset artifact ID"


@needs_bash
@pytest.mark.parametrize(
    "value, ok", [("4242424242", True), ("", False), ("ash-release-assets-x", False)]
)
def test_the_release_refuses_a_download_with_no_artifact_id(tmp_path: Path, value, ok):
    proc = _run_step(
        _step_run(TAG_ON_MERGE, "tag-and-release", _named(ARTIFACT_ID)),
        tmp_path,
        {"ARTIFACT_ID": value},
        _shim_dir(tmp_path),
    )
    assert (proc.returncode == 0) is ok, proc.stdout + proc.stderr
    if not ok:
        assert "not an artifact ID" in proc.stdout


HAND_OVER = "Hand the uploaded package's artifact ID to the release"


@needs_bash
@pytest.mark.parametrize("family, ok", [("deb", True), ("rpm", True), ("apk", False)])
def test_each_asset_leg_hands_over_its_upload_id_under_its_family(
    tmp_path: Path, family, ok
):
    # Each asset leg writes only its own family's output, so the matrix's combined
    # outputs carry one ID per family and no leg overwrites another's.
    proc = _run_step(
        _step_run(NATIVE, "package", _named(HAND_OVER)),
        tmp_path,
        {"FAMILY": family, "ARTIFACT_ID": "4242424242"},
        _shim_dir(tmp_path),
    )
    assert (proc.returncode == 0) is ok, proc.stdout + proc.stderr
    if ok:
        output = tmp_path / "_runner_temp" / "github_output"
        written = output.read_text(encoding="utf-8")
        assert written == f"{family}-artifact-id=4242424242\n", written


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@needs_bash
@pytest.mark.parametrize(
    "case",
    ["merge", "empty", "both-empty", "abbreviated", "not-github-sha", "not-head"],
)
def test_the_resolve_job_pins_the_merge_commit(tmp_path: Path, case):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    for message in ("first", "merge"):
        _git(
            repo,
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            message,
        )
    head = _git(repo, "rev-parse", "HEAD")
    first = _git(repo, "rev-parse", "HEAD^")
    env = {"MERGE_SHA": head, "GITHUB_SHA": head}
    if case == "empty":
        env["MERGE_SHA"] = ""
    elif case == "both-empty":
        # No format check exists: the HEAD comparison is what refuses this.
        env["MERGE_SHA"] = env["GITHUB_SHA"] = ""
    elif case == "abbreviated":
        env["MERGE_SHA"] = env["GITHUB_SHA"] = head[:12]
    elif case == "not-github-sha":
        env["GITHUB_SHA"] = first
    elif case == "not-head":
        env["MERGE_SHA"] = env["GITHUB_SHA"] = first
    proc = _run_step(
        _step_run(TAG_ON_MERGE, "resolve", lambda s: s.get("id") == "sha"),
        repo,
        env,
        _shim_dir(tmp_path),
    )
    output = repo / "_runner_temp" / "github_output"
    if case == "merge":
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert output.read_text(encoding="utf-8") == f"sha={head}\n"
    else:
        assert proc.returncode == 1, proc.stdout + proc.stderr
        assert "::error::" in proc.stdout
        assert not output.exists() or "sha=" not in output.read_text(encoding="utf-8")


# A stand-in for packaging/release-assets.py: `gate` writes the list and sums files and
# exits with STUB_RC; `check` exits with STUB_RC and prints STUB_MESSAGE. The gate
# writes the files even when it fails, so only its exit status can stop the step.
RELEASE_ASSETS_STUB = """import os, sys
args = sys.argv[1:]
rc = int(os.environ.get("STUB_RC", "0"))
if args[0] == "gate":
    print("  FAIL deb planted" if rc else "  PASS every asset")
    lst = args[args.index("--list-out") + 1]
    sums = args[args.index("--sums-out") + 1]
    open(lst, "w").write("a.deb\\n")
    open(sums, "w").write("0" * 64 + "  a.deb\\n")
    sys.exit(rc)
print(os.environ.get("STUB_MESSAGE", ""), file=sys.stderr)
sys.exit(rc)
"""

GATE = "Gate every release asset"


@needs_bash
@pytest.mark.parametrize("rc", [0, 1])
def test_the_gate_step_fails_with_the_gate_and_exports_sums_only_on_a_pass(
    tmp_path: Path, rc
):
    work = tmp_path / "work"
    (work / "packaging").mkdir(parents=True)
    (work / "packaging" / "release-assets.py").write_text(
        RELEASE_ASSETS_STUB, encoding="utf-8"
    )
    proc = _run_step(
        _step_run(RELEASE_ASSETS, "assemble", _named(GATE)),
        work,
        {"VERSION": "4.0.0", "STUB_RC": str(rc)},
        _shim_dir(tmp_path),
    )
    output = work / "_runner_temp" / "github_output"
    if rc == 0:
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert output.read_text(encoding="utf-8") == (
            "sums<<ASH_RELEASE_SUMS_EOF\n"
            + "0" * 64
            + "  a.deb\nASH_RELEASE_SUMS_EOF\n"
        )
    else:
        assert proc.returncode != 0, proc.stdout + proc.stderr
        assert not output.exists() or "sums" not in output.read_text(encoding="utf-8")


NEGATIVE = "Negative control: a missing or ungated asset fails the check"


@needs_bash
def test_the_negative_control_step_passes_when_the_real_check_refuses_both(
    tmp_path: Path,
):
    work = _staged_tree(tmp_path)
    proc = _run_step(
        _step_run(RELEASE_ASSETS, "assemble", _named(NEGATIVE)),
        work,
        {"VERSION": "4.0.0"},
        _shim_dir(tmp_path),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.count("OK: ") == 2


@needs_bash
@pytest.mark.parametrize(
    "rc, message",
    [
        (0, "release asset set OK"),
        (1, "failed for some other reason"),
        (2, "deb: expected 1 file(s) ash-extra-4.0.0.bin is not a release asset"),
    ],
    ids=["check-passes", "fails-without-naming-the-asset", "exit-2-not-1"],
)
def test_the_negative_control_step_fails_when_the_check_does_not_refuse(
    tmp_path: Path, rc, message
):
    work = _staged_tree(tmp_path)
    (work / "packaging" / "release-assets.py").write_text(
        RELEASE_ASSETS_STUB, encoding="utf-8"
    )
    proc = _run_step(
        _step_run(RELEASE_ASSETS, "assemble", _named(NEGATIVE)),
        work,
        {"VERSION": "4.0.0", "STUB_RC": str(rc), "STUB_MESSAGE": message},
        _shim_dir(tmp_path),
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "::error::" in proc.stdout


# -- release-assets.py gate, on planted gates ---------------------------------


def _all_gates(result):
    return {name: (lambda ctx, files, _r=result: _r) for name in ra.GATES}


def test_cmd_gate_fails_on_one_failed_verdict_and_writes_nothing(
    tmp_path: Path, monkeypatch
):
    staged = tmp_path / "staged"
    ra._write_fixture(staged, ra._fixture_names("4.0.0"))
    gates = _all_gates((True, "stub"))
    gates["flatpak-bundle"] = lambda ctx, files: (False, "planted")
    monkeypatch.setattr(ra, "GATES", gates)
    lst, sums = tmp_path / "assets.txt", tmp_path / "SHA256SUMS"
    rc = ra.cmd_gate(staged, "4.0.0", ra.DEFAULT_REPOSITORY, lst, sums)
    assert rc == 1
    assert not lst.exists() and not sums.exists()


def test_cmd_gate_writes_the_digest_of_every_staged_file(tmp_path: Path, monkeypatch):
    staged = tmp_path / "staged"
    names = ra._fixture_names("4.0.0")
    ra._write_fixture(staged, names)
    monkeypatch.setattr(ra, "GATES", _all_gates((True, "stub")))
    lst, sums = tmp_path / "assets.txt", tmp_path / "SHA256SUMS"
    assert ra.cmd_gate(staged, "4.0.0", ra.DEFAULT_REPOSITORY, lst, sums) == 0
    assert lst.read_text(encoding="utf-8").splitlines() == sorted(names)
    lines = sums.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 13
    assert lines == [f"{ra.sha256(staged / n)}  {n}" for n in sorted(names)]


def _winget_set(tmp_path: Path, digest: str, url: str) -> list:
    """The committed manifests, filled the way set-release-metadata.py fills them."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    files = []
    for source in sorted((REPO_ROOT / "packaging" / "winget").glob("*.yaml")):
        text = source.read_text(encoding="utf-8")
        if source.name.endswith(".installer.yaml"):
            text, urls = re.subn(
                r"^  InstallerUrl: .*$",
                f"  InstallerUrl: {url}",
                text,
                flags=re.MULTILINE,
            )
            text, digests = re.subn(
                r"^  InstallerSha256: .*$",
                f"  InstallerSha256: {digest}",
                text,
                flags=re.MULTILINE,
            )
            assert (urls, digests) == (1, 1), (
                "the committed installer manifest changed shape"
            )
        (tmp_path / source.name).write_text(text, encoding="utf-8")
        files.append(tmp_path / source.name)
    assert len(files) == 3
    return files


@pytest.mark.parametrize(
    "case", ["bound", "wrong-digest", "wrong-url", "validator-fails", "no-msix"]
)
def test_the_winget_gate_binds_the_manifests_to_the_attached_msix(tmp_path: Path, case):
    msix = tmp_path / "automated-security-helper-4.0.0.msix"
    msix.write_bytes(b"the msix bytes")
    digest = ra.sha256(msix).upper()
    url = f"https://github.com/{ra.DEFAULT_REPOSITORY}/releases/download/v4.0.0/{msix.name}"
    if case == "wrong-digest":
        digest = "0" * 64
    if case == "wrong-url":
        url = url.replace("v4.0.0", "v3.9.0")
    files = _winget_set(tmp_path / "winget", digest, url)
    validator_rc = 1 if case == "validator-fails" else 0
    ctx = ra.Context(
        tmp_path,
        "4.0.0",
        ra.DEFAULT_REPOSITORY,
        lambda argv, cwd: (validator_rc, "validator output"),
        staged={"msix": [] if case == "no-msix" else [msix]},
    )
    ok, detail = ra.gate_winget_manifests(ctx, files)
    assert ok is (case == "bound"), detail
    expected = {
        "bound": "InstallerSha256 and InstallerUrl name the attached",
        "wrong-digest": "InstallerSha256 is",
        "wrong-url": "InstallerUrl is",
        "validator-fails": "exited 1",
        "no-msix": "no single staged .msix",
    }[case]
    assert expected in detail


@pytest.mark.parametrize("tree_rc", [0, 1])
def test_the_flatpak_gate_runs_the_tree_gate_and_takes_its_verdict(
    tmp_path: Path, tree_rc
):
    bundle = tmp_path / "ash-4.0.0-x86_64.flatpak"
    bundle.write_bytes(b"bundle")
    calls = []

    def runner(argv, cwd):
        calls.append(list(argv))
        if "refs" in argv:
            return 0, "app/com.amazon.ash/x86_64/stable\n"
        if "--flatpak-tree" in argv:
            return tree_rc, "tree gate output"
        return 0, ""

    ctx = ra.Context(REPO_ROOT, "4.0.0", ra.DEFAULT_REPOSITORY, runner)
    ok, detail = ra.gate_flatpak_bundle(ctx, [bundle])
    tree_calls = [c for c in calls if "--flatpak-tree" in c]
    assert len(tree_calls) == 1, calls
    # PureWindowsPath splits on both separators, so this holds on every runner: the
    # gate passes str(tree / "files"), which is backslashed on windows-latest.
    assert PureWindowsPath(tree_calls[0][-1]).parts[-2:] == ("tree", "files")
    assert ok is (tree_rc == 0), detail
