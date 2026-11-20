#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The set of files a GitHub Release of ASH carries, and the gate each one passes.

    release-assets.py check DIR [--version V]
    release-assets.py gate DIR --version V [--repository OWNER/NAME]
                      [--list-out FILE] [--sums-out FILE]
    release-assets.py list
    release-assets.py --self-test

WHY THIS EXISTS

A release used to attach the wheel, the sdist and the .mcpb, while the .deb, .rpm,
.msix, .nupkg, Flatpak bundle, .vsix, JetBrains plugin zip and winget manifests were
built and tested in CI and then thrown away. Adding them is the easy half. The half
that goes wrong later is drift between three lists that have to agree: what the build
produces, what the gates check, and what `gh release create` and
`actions/attest-build-provenance` are handed. A format added to the build but not to
the upload ships nothing; one added to the upload but not to a gate ships unchecked
bytes. So the list lives here, once, and everything else reads it:

  * `check` holds a staged directory to exactly this set: one file per asset (three
    for winget), nothing missing, nothing extra. An unknown file is refused rather
    than ignored, because "ignored" is how an ungated file gets attached by a glob.
  * `gate` runs each asset's gate on the staged bytes, the ones about to be attached,
    and prints one verdict per asset. An asset whose gate fails, or that has no gate,
    fails the run.
  * `list` prints the table, for docs and for tests/unit/test_release_assets.py, which
    holds every packaging/<format> and editors/<ide> directory to an entry here.

The release workflow (.github/workflows/ash-tag-on-merge.yml) attaches and attests
`DIR/*` only after `check` has passed on that directory, so the glob and this table
cannot disagree. The dry run (.github/workflows/ash-release-assets.yml on a push)
runs `gate` and the negative controls, and never attests or publishes.

WHAT IS NEVER A RELEASE ASSET

The container image. Its rule is that it is never published anywhere, and a docker
save or OCI layout tarball in the staged directory is refused by name and by content
before the unknown-file rule would catch it, so the message says what it is.
Homebrew is not here either: its channel is Formula/ash.rb in this repository, which a
tap reads from the tag, not a file attached to the release.

Standard library only, Python 3.10+. Exit codes: 0 pass, 1 the set or a gate failed,
2 usage or an input that could not be read.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import subprocess  # nosec B404 - runs the repository's own gate scripts
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, TextIO, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPOSITORY = "awslabs/automated-security-helper"

# The PEP 440 version as it appears in a file name. Kept loose: the version check
# below compares the captured text with --version exactly.
_V = r"(?P<version>[0-9][0-9A-Za-z.+]*)"

Runner = Callable[[Sequence[str], Path], Tuple[int, str]]


@dataclass(frozen=True)
class Asset:
    """One release asset: where it comes from, what it is called, how it is gated."""

    key: str
    source: str
    pattern: str
    gate: str
    count: int = 1
    # Whether the name carries the project version verbatim, so a stale file from an
    # older build is refused by name.
    versioned: bool = True
    description: str = ""

    def matches(self, name: str) -> Optional["re.Match[str]"]:
        return re.fullmatch(self.pattern, name)


# THE TABLE. Order is the order verdicts print in.
ASSETS: Tuple[Asset, ...] = (
    Asset(
        key="wheel",
        source="pyproject.toml",
        pattern=rf"automated_security_helper-{_V}-py3-none-any\.whl",
        gate="artifact-contents",
        description="the wheel every native package installs",
    ),
    Asset(
        key="sdist",
        source="pyproject.toml",
        pattern=rf"automated_security_helper-{_V}\.tar\.gz",
        gate="artifact-contents",
        description="the source distribution",
    ),
    Asset(
        key="mcpb",
        source="ash-agent-plugins/agentic-coding",
        pattern=r"ash-[0-9][0-9A-Za-z.+]*\.mcpb",
        gate="mcpb-members",
        versioned=False,
        description="the MCP bundle for Claude Desktop; its version is the bundle's own",
    ),
    Asset(
        key="deb",
        source="packaging/deb",
        pattern=r"automated-security-helper_[0-9][0-9A-Za-z.+~-]*_all\.deb",
        gate="package-payload",
        versioned=False,
        description="the .deb, built in Debian 12 (dpkg's version mapping changes the name)",
    ),
    Asset(
        key="rpm",
        source="packaging/rpm",
        pattern=r"automated-security-helper-[0-9][0-9A-Za-z.+~^_]*-[0-9]+\.noarch\.rpm",
        gate="package-payload",
        versioned=False,
        description="the .rpm, built in Amazon Linux 2023",
    ),
    Asset(
        key="msix",
        source="packaging/msix",
        pattern=rf"automated-security-helper-{_V}\.msix",
        gate="package-contents",
        description="the signed .msix",
    ),
    Asset(
        key="nupkg",
        source="packaging/chocolatey",
        pattern=rf"ash\.{_V}\.nupkg",
        gate="package-contents",
        description="the Chocolatey package",
    ),
    Asset(
        key="flatpak",
        source="packaging/flatpak",
        pattern=rf"ash-{_V}-x86_64\.flatpak",
        gate="flatpak-bundle",
        description="the Flatpak single-file bundle",
    ),
    Asset(
        key="winget",
        source="packaging/winget",
        pattern=r"Amazon\.AutomatedSecurityHelper(\.installer|\.locale\.en-US)?\.yaml",
        gate="winget-manifests",
        count=3,
        versioned=False,
        description="the winget manifest set, rendered for the attached .msix",
    ),
    Asset(
        key="vsix",
        source="editors/vscode",
        pattern=rf"ash-vscode-{_V}\.vsix",
        gate="vsix-contents",
        description="the VS Code extension",
    ),
    Asset(
        key="jetbrains",
        source="editors/jetbrains",
        pattern=r"ash-jetbrains-[0-9][0-9A-Za-z.+-]*\.zip",
        gate="plugin-zip-contents",
        versioned=False,
        description="the JetBrains plugin zip; it is versioned on its own (pyproject.toml)",
    ),
)

# Directories under packaging/ and editors/ that are not a release asset, and why.
# tests/unit/test_release_assets.py requires every such directory to be in ASSETS or
# here, so a new format cannot be added without deciding how it ships.
NOT_RELEASE_ASSETS: Dict[str, str] = {
    "packaging/homebrew": (
        "Homebrew installs from Formula/ash.rb, which names the release tag's source "
        "tarball; the tap is the channel, not an attached file"
    ),
}

# The directories whose subdirectories are formats or IDE plugins.
FORMAT_ROOTS: Tuple[str, ...] = ("packaging", "editors")

_CONTAINER_IMAGE_SUFFIXES = (".oci", ".docker", ".img")


def format_dirs_without_a_release_line(root: Path) -> List[str]:
    """Every packaging/<format> and editors/<ide> directory with no decision here.

    A directory is covered when an asset names it as its source or
    NOT_RELEASE_ASSETS says why it ships no file. Anything else is a format that was
    added without deciding how a release carries it.
    """
    covered = {asset.source for asset in ASSETS} | set(NOT_RELEASE_ASSETS)
    missing: List[str] = []
    for top in FORMAT_ROOTS:
        base = root / top
        if not base.is_dir():
            continue
        for entry in sorted(base.iterdir()):
            if entry.is_dir() and not entry.name.startswith((".", "_")):
                rel = f"{top}/{entry.name}"
                if rel not in covered:
                    missing.append(rel)
    return missing


class InputError(Exception):
    """An input could not be read at all; exit 2."""


@dataclass
class Verdict:
    key: str
    files: List[str]
    ok: bool
    detail: str


@dataclass
class Context:
    repo: Path
    version: str
    repository: str
    run: Runner
    staged: Dict[str, List[Path]] = field(default_factory=dict)


def default_runner(argv: Sequence[str], cwd: Path) -> Tuple[int, str]:
    try:
        proc = subprocess.run(  # nosec B603 - argv built from this file's own table
            list(argv),
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except FileNotFoundError as error:
        return 127, f"{argv[0]} is not on PATH: {error}"
    return proc.returncode, proc.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def looks_like_container_image(path: Path) -> bool:
    """True for a docker-save or OCI-layout archive, by name or by content."""
    name = path.name.lower()
    if name.endswith(_CONTAINER_IMAGE_SUFFIXES):
        return True
    if not name.endswith((".tar", ".tar.gz", ".tgz")):
        return False
    try:
        with tarfile.open(path) as archive:
            top = {
                m.name.lstrip("./")
                for m in archive.getmembers()
                if "/" not in m.name.lstrip("./")
            }
    except (tarfile.TarError, OSError):
        return False
    return "oci-layout" in top or "repositories" in top or "manifest.json" in top


def classify(
    directory: Path, version: Optional[str]
) -> Tuple[Dict[str, List[Path]], List[str]]:
    """Match every file in DIRECTORY to an asset. Returns (staged, problems)."""
    if not directory.is_dir():
        raise InputError(f"{directory} is not a directory")
    staged: Dict[str, List[Path]] = {asset.key: [] for asset in ASSETS}
    problems: List[str] = []
    for entry in sorted(directory.iterdir()):
        if entry.is_dir():
            problems.append(
                f"{entry.name}/ is a directory. A release carries files only, and "
                "`gh release create DIR/*` would refuse it at publish time"
            )
            continue
        if looks_like_container_image(entry):
            problems.append(
                f"{entry.name} is a container image archive. The image is never "
                "published, as a release asset or anywhere else"
            )
            continue
        owners = [asset for asset in ASSETS if asset.matches(entry.name)]
        if not owners:
            problems.append(
                f"{entry.name} is not a release asset in packaging/release-assets.py, "
                "so no gate has checked it. Add it to ASSETS with a gate, or keep it "
                "out of the staged directory"
            )
            continue
        if len(owners) > 1:
            problems.append(
                f"{entry.name} matches {len(owners)} assets "
                f"({', '.join(a.key for a in owners)}); the patterns must not overlap"
            )
            continue
        asset = owners[0]
        match = asset.matches(entry.name)
        if match is None:  # owners was built from this same test
            raise InputError(f"{entry.name} stopped matching {asset.pattern}")
        if (
            version is not None
            and asset.versioned
            and match.group("version") != version
        ):
            problems.append(
                f"{entry.name} carries version {match.group('version')}, but this "
                f"release is {version}. A file from another build is not this release"
            )
            continue
        if entry.stat().st_size == 0:
            problems.append(f"{entry.name} is empty")
            continue
        staged[asset.key].append(entry)
    for asset in ASSETS:
        found = len(staged[asset.key])
        if found != asset.count:
            names = ", ".join(p.name for p in staged[asset.key]) or "none"
            problems.append(
                f"{asset.key}: expected {asset.count} file(s) matching "
                f"{asset.pattern}, found {found} ({names}). It comes from {asset.source}"
            )
    return staged, problems


# ---------------------------------------------------------------------------
# Gates. Each takes the asset's staged files and returns (ok, detail). A gate is
# never satisfied by having nothing to look at: every one either runs a checker
# that exits non-zero on an empty input, or reads the bytes itself.
# ---------------------------------------------------------------------------


def _python() -> str:
    return sys.executable


def _tail(text: str, lines: int = 6) -> str:
    kept = [line for line in text.strip().splitlines() if line.strip()]
    return " | ".join(kept[-lines:])


def _run_gate(ctx: Context, argv: Sequence[str]) -> Tuple[bool, str]:
    rc, out = ctx.run(argv, ctx.repo)
    shown = " ".join(str(a) for a in argv[:4])
    if rc != 0:
        return False, f"`{shown} ...` exited {rc}: {_tail(out)}"
    return True, f"`{shown} ...` exited 0: {_tail(out, 2)}"


def gate_artifact_contents(ctx: Context, files: List[Path]) -> Tuple[bool, str]:
    script = ctx.repo / ".github/scripts/assert-artifact-contents.py"
    return _run_gate(ctx, [_python(), str(script), *map(str, files)])


def gate_mcpb_members(ctx: Context, files: List[Path]) -> Tuple[bool, str]:
    # The archive holds exactly one member, manifest.json, which ASH authors. The
    # drift check that makes the committed archive trustworthy runs when it is staged.
    (path,) = files
    try:
        with zipfile.ZipFile(path) as archive:
            members = [i.filename for i in archive.infolist() if not i.is_dir()]
    except zipfile.BadZipFile as error:
        return False, f"{path.name} is not a zip: {error}"
    if members != ["manifest.json"]:
        return False, f"{path.name} must hold exactly manifest.json, found {members}"
    return True, f"{path.name}: 1 member, manifest.json"


def gate_package_payload(ctx: Context, files: List[Path]) -> Tuple[bool, str]:
    script = ctx.repo / "packaging/assert-package-payload.py"
    gate = ctx.repo / ".github/scripts/assert-artifact-contents.py"
    return _run_gate(
        ctx, [_python(), str(script), "--artifact-gate", str(gate), *map(str, files)]
    )


def gate_package_contents(ctx: Context, files: List[Path]) -> Tuple[bool, str]:
    # `uv run --script` because the MSIX checks parse XML through defusedxml, which
    # the script's PEP 723 block declares. The .nupkg path is stdlib-only and runs the
    # same way so both go through one invocation.
    script = ctx.repo / "packaging/assert-package-contents.py"
    return _run_gate(ctx, ["uv", "run", "--script", str(script), *map(str, files)])


def gate_flatpak_bundle(ctx: Context, files: List[Path]) -> Tuple[bool, str]:
    """Unpack the bundle back into a tree and run the tree gate build.sh ran.

    A .flatpak bundle is an OSTree static delta, which nothing in the standard library
    reads. Importing it into a scratch repository and checking the commit out gives the
    exact files the bundle installs, so the gate packaging/flatpak/build.sh runs on the
    build directory runs again here on what is about to be published.
    """
    (bundle,) = files
    with tempfile.TemporaryDirectory(prefix="ash-flatpak-gate-") as scratch:
        repo = Path(scratch) / "repo"
        tree = Path(scratch) / "tree"
        for argv in (
            ["ostree", "init", f"--repo={repo}", "--mode=archive"],
            ["flatpak", "build-import-bundle", str(repo), str(bundle)],
        ):
            rc, out = ctx.run(argv, ctx.repo)
            if rc != 0:
                return False, f"`{' '.join(argv[:2])}` exited {rc}: {_tail(out)}"
        rc, out = ctx.run(["ostree", f"--repo={repo}", "refs"], ctx.repo)
        refs = [
            line.strip() for line in out.splitlines() if line.strip().startswith("app/")
        ]
        if rc != 0 or len(refs) != 1:
            return (
                False,
                f"expected one app ref in {bundle.name}, got rc {rc}: {out.strip()}",
            )
        rc, out = ctx.run(
            ["ostree", f"--repo={repo}", "checkout", "-U", refs[0], str(tree)], ctx.repo
        )
        if rc != 0:
            return False, f"ostree checkout exited {rc}: {_tail(out)}"
        ok, detail = _run_gate(
            ctx,
            [
                _python(),
                str(ctx.repo / "packaging/assert-package-contents.py"),
                "--flatpak-tree",
                str(tree / "files"),
            ],
        )
        return ok, f"{refs[0]}: {detail}"


def gate_winget_manifests(ctx: Context, files: List[Path]) -> Tuple[bool, str]:
    """The published-schema validator, then the one binding no schema can check.

    validate-manifests.py --released checks the schemas, the version, the release
    tag in InstallerUrl and the filename build.ps1 writes. It cannot know which
    .msix is attached beside the manifests, so the digest and the URL are compared
    with that file here.
    """
    msix_files = ctx.staged.get("msix") or []
    if len(msix_files) != 1:
        return False, "no single staged .msix to bind the manifests to"
    msix = msix_files[0]
    with tempfile.TemporaryDirectory(prefix="ash-winget-gate-") as scratch:
        for path in files:
            shutil.copy2(path, Path(scratch) / path.name)
        ok, detail = _run_gate(
            ctx,
            [
                "uv",
                "run",
                "--script",
                str(ctx.repo / "packaging/winget/validate-manifests.py"),
                scratch,
                "--released",
            ],
        )
    if not ok:
        return ok, detail
    installer = next(p for p in files if p.name.endswith(".installer.yaml"))
    text = installer.read_text(encoding="utf-8")
    digests = re.findall(
        r"^\s*InstallerSha256:\s*([0-9A-Fa-f]{64})\s*$", text, re.MULTILINE
    )
    urls = re.findall(r"^\s*InstallerUrl:\s*(\S+)\s*$", text, re.MULTILINE)
    if len(digests) != 1 or len(urls) != 1:
        return False, (
            f"{installer.name} has {len(digests)} InstallerSha256 and {len(urls)} "
            "InstallerUrl lines; one of each was expected"
        )
    want = sha256(msix)
    if digests[0].lower() != want:
        return False, (
            f"InstallerSha256 is {digests[0]} but the attached {msix.name} is {want}. "
            "winget would refuse the download"
        )
    expected_url = f"https://github.com/{ctx.repository}/releases/download/v{ctx.version}/{msix.name}"
    if urls[0] != expected_url:
        return False, f"InstallerUrl is {urls[0]}, expected {expected_url}"
    return (
        True,
        f"schemas OK; InstallerSha256 and InstallerUrl name the attached {msix.name}",
    )


def gate_vsix_contents(ctx: Context, files: List[Path]) -> Tuple[bool, str]:
    """vsix-contents.ts, then an independent ZIP reader over the same bytes.

    The TypeScript walk is the gate the extension's own workflow runs. Python's
    zipfile is a second implementation, so a central directory the first one
    mis-read shows up as a disagreement instead of a clean subset.
    """
    (path,) = files
    verifier = ctx.repo / "editors/vscode/out/verify-vsix.js"
    if not verifier.is_file():
        return False, (
            f"{verifier.relative_to(ctx.repo)} is missing; run `npm ci && npm run "
            "compile` in editors/vscode before gating"
        )
    ok, detail = _run_gate(ctx, ["node", str(verifier), str(path)])
    if not ok:
        return ok, detail
    with zipfile.ZipFile(path) as archive:
        members = archive.namelist()
    bundled = [m for m in members if "/node_modules/" in m]
    if bundled:
        return False, f"{len(bundled)} member(s) under node_modules/, e.g. {bundled[0]}"
    if "extension/out/extension.js" not in members:
        return (
            False,
            "extension/out/extension.js is absent, so the extension activates nothing",
        )
    return True, f"{detail}; zipfile agrees: {len(members)} member(s), no node_modules"


def gate_plugin_zip_contents(ctx: Context, files: List[Path]) -> Tuple[bool, str]:
    (path,) = files
    # The checker reads a directory and requires exactly one zip in it, so the file
    # gets a directory of its own.
    with tempfile.TemporaryDirectory(prefix="ash-jetbrains-gate-") as scratch:
        shutil.copy2(path, Path(scratch) / path.name)
        return _run_gate(
            ctx,
            [
                _python(),
                str(ctx.repo / "editors/jetbrains/assert-plugin-zip-contents.py"),
                "--dist-dir",
                scratch,
                "--own-jar-prefix",
                "ash-jetbrains",
            ],
        )


GATES: Dict[str, Callable[[Context, List[Path]], Tuple[bool, str]]] = {
    "artifact-contents": gate_artifact_contents,
    "mcpb-members": gate_mcpb_members,
    "package-payload": gate_package_payload,
    "package-contents": gate_package_contents,
    "flatpak-bundle": gate_flatpak_bundle,
    "winget-manifests": gate_winget_manifests,
    "vsix-contents": gate_vsix_contents,
    "plugin-zip-contents": gate_plugin_zip_contents,
}


def run_gates(
    directory: Path,
    version: str,
    repository: str,
    repo: Path = REPO_ROOT,
    runner: Runner = default_runner,
    assets: Sequence[Asset] = ASSETS,
    gates: Optional[
        Dict[str, Callable[[Context, List[Path]], Tuple[bool, str]]]
    ] = None,
) -> Tuple[List[Verdict], List[str]]:
    gates = GATES if gates is None else gates
    staged, problems = classify(directory, version)
    ctx = Context(
        repo=repo, version=version, repository=repository, run=runner, staged=staged
    )
    verdicts: List[Verdict] = []
    for asset in assets:
        files = staged.get(asset.key, [])
        names = [p.name for p in files]
        gate = gates.get(asset.gate)
        if gate is None:
            verdicts.append(
                Verdict(asset.key, names, False, f"no gate named {asset.gate!r}")
            )
            continue
        if len(files) != asset.count:
            verdicts.append(
                Verdict(asset.key, names, False, "not staged; see the set check")
            )
            continue
        try:
            ok, detail = gate(ctx, files)
        except (OSError, zipfile.BadZipFile, ValueError) as error:
            ok, detail = False, f"the gate raised {type(error).__name__}: {error}"
        verdicts.append(Verdict(asset.key, names, ok, detail))
    return verdicts, problems


def write_outputs(
    directory: Path, list_out: Optional[Path], sums_out: Optional[Path]
) -> None:
    files = sorted(p for p in directory.iterdir() if p.is_file())
    if list_out is not None:
        list_out.write_text("".join(f"{p.name}\n" for p in files), encoding="utf-8")
    if sums_out is not None:
        sums_out.write_text(
            "".join(f"{sha256(p)}  {p.name}\n" for p in files), encoding="utf-8"
        )


def _print_problems(problems: List[str], stream: TextIO) -> None:
    stream.writelines(f"  - {problem}\n" for problem in problems)


def cmd_check(directory: Path, version: Optional[str]) -> int:
    staged, problems = classify(directory, version)
    total = sum(len(v) for v in staged.values())
    if problems:
        sys.stderr.write(f"release asset set FAILED ({len(problems)} problem(s)):\n")
        _print_problems(problems, sys.stderr)
        return 1
    print(
        f"release asset set OK: {total} file(s) for {len(ASSETS)} asset(s) in {directory}"
    )
    for asset in ASSETS:
        for path in staged[asset.key]:
            print(f"  {asset.key:<10} {path.name}")
    return 0


def cmd_gate(
    directory: Path,
    version: str,
    repository: str,
    list_out: Optional[Path],
    sums_out: Optional[Path],
) -> int:
    verdicts, problems = run_gates(directory, version, repository)
    print(f"release asset gates for {version}, staged in {directory}:")
    for verdict in verdicts:
        mark = "PASS" if verdict.ok else "FAIL"
        print(f"  {mark} {verdict.key:<10} {', '.join(verdict.files) or '-'}")
        print(f"       {verdict.detail}")
    failed = [v for v in verdicts if not v.ok]
    if problems or failed:
        sys.stderr.write(
            f"\nrelease assets FAILED: {len(problems)} set problem(s), "
            f"{len(failed)} gate failure(s)\n"
        )
        _print_problems(problems, sys.stderr)
        return 1
    write_outputs(directory, list_out, sums_out)
    total = sum(len(v.files) for v in verdicts)
    print(
        f"\nrelease assets OK: {total} file(s), {len(verdicts)} asset(s), every gate passed"
    )
    return 0


def cmd_list() -> int:
    print(
        json.dumps(
            {
                "assets": [
                    {
                        "key": a.key,
                        "source": a.source,
                        "pattern": a.pattern,
                        "count": a.count,
                        "gate": a.gate,
                        "description": a.description,
                    }
                    for a in ASSETS
                ],
                "not_release_assets": NOT_RELEASE_ASSETS,
            },
            indent=2,
        )
    )
    return 0


# ---------------------------------------------------------------------------
# Self-test: the set check and the gate dispatch, shown failing on planted sets.
# The gates themselves have their own self-tests, which the workflows run.
# ---------------------------------------------------------------------------

_SELF_TEST_RELEASE = "9.8.7"


def _fixture_names(version: str) -> List[str]:
    return [
        f"automated_security_helper-{version}-py3-none-any.whl",
        f"automated_security_helper-{version}.tar.gz",
        "ash-1.0.0.mcpb",
        f"automated-security-helper_{version}_all.deb",
        f"automated-security-helper-{version}-1.noarch.rpm",
        f"automated-security-helper-{version}.msix",
        f"ash.{version}.nupkg",
        f"ash-{version}-x86_64.flatpak",
        "Amazon.AutomatedSecurityHelper.yaml",
        "Amazon.AutomatedSecurityHelper.installer.yaml",
        "Amazon.AutomatedSecurityHelper.locale.en-US.yaml",
        f"ash-vscode-{version}.vsix",
        "ash-jetbrains-0.1.0.zip",
    ]


def _write_fixture(directory: Path, names: List[str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        (directory / name).write_bytes(b"fixture bytes for " + name.encode())


def _image_tar(path: Path) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for member, data in (
            ("oci-layout", b'{"imageLayoutVersion": "1.0.0"}'),
            ("index.json", b"{}"),
        ):
            info = tarfile.TarInfo(member)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    path.write_bytes(buffer.getvalue())


def _passing_gates() -> Dict[str, Callable[[Context, List[Path]], Tuple[bool, str]]]:
    return {name: (lambda ctx, files: (True, "stub")) for name in GATES}


def self_test() -> int:
    failures: List[str] = []
    version = _SELF_TEST_RELEASE
    names = _fixture_names(version)

    def expect(label: str, ok: bool) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
        if not ok:
            failures.append(label)

    with tempfile.TemporaryDirectory(prefix="ash-release-assets-self-test-") as scratch:
        root = Path(scratch)

        def case(name: str, mutate: Callable[[Path], object]) -> List[str]:
            directory = root / name
            _write_fixture(directory, names)
            mutate(directory)
            _staged, problems = classify(directory, version)
            return problems

        problems = case("complete", lambda d: None)
        expect("the complete set passes the set check", problems == [])

        problems = case("missing-deb", lambda d: (d / names[3]).unlink())
        expect(
            "a set missing the .deb fails, naming the deb asset",
            any(p.startswith("deb:") for p in problems),
        )

        problems = case("missing-winget-locale", lambda d: (d / names[10]).unlink())
        expect(
            "a winget set missing one manifest fails",
            any(p.startswith("winget:") for p in problems),
        )

        problems = case("ungated-extra", lambda d: (d / "notes.txt").write_text("x"))
        expect(
            "an extra file with no gate fails as an unknown asset",
            any("notes.txt is not a release asset" in p for p in problems),
        )

        problems = case(
            "second-wheel",
            lambda d: (
                d / f"automated_security_helper-{version}-py2-none-any.whl"
            ).write_text("x"),
        )
        expect(
            "a second wheel-shaped file that matches no asset fails",
            any("py2-none-any.whl is not a release asset" in p for p in problems),
        )

        problems = case(
            "stale-version",
            lambda d: (d / names[0]).rename(
                d / "automated_security_helper-9.8.6-py3-none-any.whl"
            ),
        )
        expect(
            "a wheel from another version fails on its version",
            any("carries version 9.8.6" in p for p in problems),
        )

        problems = case("image", lambda d: _image_tar(d / "ash-image.tar"))
        expect(
            "a container image archive is refused as an image",
            any("container image" in p for p in problems),
        )

        problems = case("empty-file", lambda d: (d / names[6]).write_bytes(b""))
        expect("an empty asset fails", any("is empty" in p for p in problems))

        problems = case("subdir", lambda d: (d / "nested").mkdir())
        expect(
            "a directory in the staged set fails", any("nested/" in p for p in problems)
        )

        # Gate dispatch: every asset is gated, a failing gate fails the run, an asset
        # whose gate is unknown fails rather than passing unchecked.
        complete = root / "complete"
        verdicts, problems = run_gates(
            complete, version, DEFAULT_REPOSITORY, gates=_passing_gates()
        )
        expect(
            "every asset receives a verdict when every gate passes",
            not problems
            and len(verdicts) == len(ASSETS)
            and all(v.ok for v in verdicts),
        )
        gates = _passing_gates()
        gates["package-payload"] = lambda ctx, files: (False, "planted")
        verdicts, _ = run_gates(complete, version, DEFAULT_REPOSITORY, gates=gates)
        expect(
            "a failing gate fails exactly the assets it gates (deb, rpm)",
            sorted(v.key for v in verdicts if not v.ok) == ["deb", "rpm"],
        )
        ungated = _passing_gates()
        del ungated["vsix-contents"]
        verdicts, _ = run_gates(complete, version, DEFAULT_REPOSITORY, gates=ungated)
        expect(
            "an asset with no gate fails instead of passing unchecked",
            [v.key for v in verdicts if not v.ok] == ["vsix"],
        )

        # The real mcpb gate, on a planted archive.
        bad = root / "bad.mcpb"
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("manifest.json", "{}")
            archive.writestr("server/vendored.py", "x")
        ok, _ = gate_mcpb_members(
            Context(REPO_ROOT, version, DEFAULT_REPOSITORY, default_runner), [bad]
        )
        expect("the mcpb gate refuses a second member", not ok)

        # A gate that runs a checker must fail when the checker fails.
        ctx = Context(
            REPO_ROOT, version, DEFAULT_REPOSITORY, lambda argv, cwd: (1, "planted")
        )
        ok, _ = gate_artifact_contents(ctx, [complete / names[0]])
        expect("a checker's non-zero exit fails its gate", not ok)

    if failures:
        sys.stderr.write(f"\nself-test FAILED: {len(failures)} case(s)\n")
        return 1
    print(
        "\nself-test OK: the set check and the gate dispatch fail on every planted set"
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="command")
    check = sub.add_parser("check", help="hold a staged directory to the asset set")
    check.add_argument("directory", type=Path)
    check.add_argument("--version", default=None)
    gate = sub.add_parser("gate", help="the set check, then every asset's gate")
    gate.add_argument("directory", type=Path)
    gate.add_argument("--version", required=True)
    gate.add_argument(
        "--repository",
        default=DEFAULT_REPOSITORY,
        help="the repository the winget InstallerUrl must name; "
        "packaging/winget/set-release-metadata.py writes this one",
    )
    gate.add_argument("--list-out", type=Path, default=None)
    gate.add_argument("--sums-out", type=Path, default=None)
    sub.add_parser("list", help="print the asset table as JSON")
    args = parser.parse_args(argv)

    try:
        if args.self_test:
            if args.command:
                parser.error("--self-test takes no command")
            return self_test()
        if args.command == "check":
            return cmd_check(args.directory, args.version)
        if args.command == "gate":
            return cmd_gate(
                args.directory,
                args.version,
                args.repository,
                args.list_out,
                args.sums_out,
            )
        if args.command == "list":
            return cmd_list()
    except InputError as error:
        sys.stderr.write(f"release-assets: {error}\n")
        return 2
    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
