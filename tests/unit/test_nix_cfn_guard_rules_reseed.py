# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The nix shell reinstalls the cfn-guard rules whenever they are not the pinned bundle.

Why this file exists
--------------------
flake.nix's shellHook used to install the AWS Guard Rules Registry only when
``$ASH_CFN_GUARD_RULES_DIR`` was empty. A bundle installs as
``<dir>/<bundle>-<version>/``, and the cfn-guard scanner reads only the pinned
version's directory (``utils/rules_bundles.verify_installed_bundle``). So after an ASH
upgrade that bumps the pin, the old release's directory kept the hook from installing
the new one, and cfn-guard was MISSING in the nix shell from then on.

The hook now asks ``install-pinned-tool --rules-bundle --check`` whether the
installed bundle is the pinned one, which is the test ``ash dependencies install``
applies before it skips a bundle: the rule files in the pinned version's directory
match the pinned ``contents_sha256``. The manifest beside them plays no part.

What these tests do
-------------------
No nix. The hook's cfn-guard block is taken out of flake.nix as text and run under
``sh`` against bundle directories built here, with ``python3`` on PATH replaced by a
shim that logs each call, runs the real ``--check`` and turns the install itself into
a no-op, so nothing is downloaded. Separately, the script's ``--check`` and
``verify_installed_bundle`` are asked about the same directories and must agree.

The bundles here hold one small rule file, not the registry's 50, so both checks are
given a pin whose ``contents_sha256`` is that file's: ``verify_installed_bundle`` as a
``RulesBundle``, and the script and the hook through a copy of the pins table with
that one value replaced, the way tests/unit/assets/test_install_pinned_tool.py's
``_pins_dir`` replaces digests. Everything else in the copy is the checkout's.
"""

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from automated_security_helper.utils.rules_bundles import (
    MANIFEST_NAME,
    RulesBundleUnavailable,
    verify_installed_bundle,
)
from automated_security_helper.utils.tool_downloads import RULES_BUNDLES

REPO_ROOT = Path(__file__).resolve().parents[2]
FLAKE = REPO_ROOT / "flake.nix"
PACKAGE = REPO_ROOT / "automated_security_helper"
SCRIPT = PACKAGE / "assets" / "install-pinned-tool.py"
PIN = RULES_BUNDLES["aws-guard-rules-registry"]

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the shell hook is POSIX sh")

_RULE = b"rule A { }\n"
_RULE_NAME = "wa-Security-Pillar.guard"

#: contents_sha256 of a bundle holding only _RULE as _RULE_NAME, written out by hand.
FIXTURE_CONTENTS = hashlib.sha256(
    f"{_RULE_NAME}\t{hashlib.sha256(_RULE).hexdigest()}\n".encode("ascii")
).hexdigest()
FIXTURE_PIN = replace(PIN, contents_sha256=FIXTURE_CONTENTS)


def _pinned_tree(tmp_path: Path) -> Path:
    """A ``${self}`` for the hook: the script and the pins, contents pin replaced."""
    tree = tmp_path / "self"
    for relative in (
        ("assets", "install-pinned-tool.py"),
        ("core", "exceptions.py"),
        ("utils", "tool_downloads.py"),
    ):
        target = tree.joinpath("automated_security_helper", *relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        text = PACKAGE.joinpath(*relative).read_text(encoding="utf-8")
        if relative[-1] == "tool_downloads.py":
            assert text.count(PIN.contents_sha256) == 1, "the pin is not written once"
            text = text.replace(PIN.contents_sha256, FIXTURE_CONTENTS)
        target.write_text(text, encoding="utf-8")
    return tree


def _write_bundle(root: Path, version: str, url: str, sha256: str) -> Path:
    directory = root / f"{PIN.name}-{version}"
    directory.mkdir(parents=True)
    (directory / _RULE_NAME).write_bytes(_RULE)
    manifest = {
        "bundle": PIN.name,
        "version": version,
        "url": url,
        "sha256": sha256,
        "files": {_RULE_NAME: hashlib.sha256(_RULE).hexdigest()},
    }
    (directory / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def _current(root: Path) -> Path:
    return _write_bundle(root, PIN.version, PIN.url, PIN.sha256)


def _older_release(root: Path) -> None:
    """What an ASH upgrade leaves: the previous pin's directory, intact."""
    old = "0.9.9"
    _write_bundle(root, old, PIN.url.replace(PIN.version, old), "1" * 64)


def _manifest_names_another_archive(root: Path) -> None:
    """Only the manifest disagrees with the pin; the rule file is the pinned one."""
    _write_bundle(root, PIN.version, PIN.url, "0" * 64)


def _tampered_file(root: Path) -> None:
    (_current(root) / _RULE_NAME).write_bytes(b"rule A { true }\n")


def _edited_rule_manifest_rewritten(root: Path) -> None:
    directory = _current(root)
    edited = b"rule A { true }\n"
    (directory / _RULE_NAME).write_bytes(edited)
    manifest = json.loads((directory / MANIFEST_NAME).read_text(encoding="utf-8"))
    manifest["files"][_RULE_NAME] = hashlib.sha256(edited).hexdigest()
    (directory / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")


def _added_rule_file(root: Path) -> None:
    (_current(root) / "added.guard").write_bytes(b"rule added { }\n")


def _linked_rule_file(root: Path) -> None:
    directory = _current(root)
    elsewhere = root / "elsewhere.guard"
    elsewhere.write_bytes(_RULE)
    (directory / _RULE_NAME).unlink()
    (directory / _RULE_NAME).symlink_to(elsewhere)


def _other_file_beside_the_rules(root: Path) -> None:
    (_current(root) / "README.md").write_text("notes\n", encoding="utf-8")


def _listed_file_missing(root: Path) -> None:
    (_current(root) / _RULE_NAME).unlink()


def _no_manifest(root: Path) -> None:
    (_current(root) / MANIFEST_NAME).unlink()


def _malformed_manifest(root: Path) -> None:
    (_current(root) / MANIFEST_NAME).write_text("[]", encoding="utf-8")


def _empty(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)


# (state, builds it, is it the pinned bundle)
STATES = [
    ("current", _current, True),
    ("older release", _older_release, False),
    ("manifest names another archive", _manifest_names_another_archive, True),
    ("tampered file", _tampered_file, False),
    ("edited rule, manifest rewritten", _edited_rule_manifest_rewritten, False),
    ("added rule file", _added_rule_file, False),
    ("linked rule file", _linked_rule_file, False),
    ("other file beside the rules", _other_file_beside_the_rules, True),
    ("listed file missing", _listed_file_missing, False),
    ("no manifest", _no_manifest, True),
    ("malformed manifest", _malformed_manifest, True),
    ("empty", _empty, False),
]
IDS = [state for state, _, _ in STATES]


def _hook_block(self_dir: Path) -> str:
    """The shellHook's cfn-guard block, as sh would see it after nix evaluates it."""
    text = FLAKE.read_text(encoding="utf-8")
    hook = text[text.index("shellHook = ''") : text.rindex("'';")]
    lines = hook.splitlines()
    blocks = []
    for start, line in enumerate(lines):
        if not line.strip().startswith("if "):
            continue
        indent = len(line) - len(line.lstrip())
        for end in range(start + 1, len(lines)):
            closing = lines[end]
            if (
                closing.strip() == "fi"
                and len(closing) - len(closing.lstrip()) == indent
            ):
                blocks.append("\n".join(lines[start : end + 1]))
                break
    found = [block for block in blocks if "aws-guard-rules-registry" in block]
    assert len(found) == 1, f"expected one cfn-guard rules block in the hook: {found}"
    # Nix interpolates ${self}; ''${ is nix's escape for a literal ${.
    return found[0].replace("${self}", str(self_dir)).replace("''${", "${")


_PYTHON_SHIM = """#!/bin/sh
printf '%s\\n' "$*" >> "$SHIM_LOG"
for arg in "$@"; do
  if [ "$arg" = "--check" ]; then exec "$REAL_PYTHON" "$@"; fi
done
exit 0
"""


def _run_hook_block(tmp_path: Path, rules_dir: Path) -> tuple:
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    (shim_dir / "python3").write_text(_PYTHON_SHIM, encoding="utf-8")
    (shim_dir / "python3").chmod(0o755)
    log = tmp_path / "python3-calls.log"
    env = {k: v for k, v in os.environ.items() if k != "ASH_PINS_DIR"}
    env.update(
        PATH=f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
        ASH_CFN_GUARD_RULES_DIR=str(rules_dir),
        SHIM_LOG=str(log),
        REAL_PYTHON=sys.executable,
    )
    result = subprocess.run(  # nosec B603 B607 - flake text against a logging shim
        ["sh", "-c", _hook_block(_pinned_tree(tmp_path))],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, calls


def _installs(calls: list) -> list:
    return [c for c in calls if "--rules-bundle" in c and "--check" not in c.split()]


@pytest.mark.parametrize(("state", "build", "pinned"), STATES, ids=IDS)
def test_the_hook_reinstalls_exactly_when_the_bundle_is_not_the_pin(
    tmp_path, state, build, pinned
):
    rules_dir = tmp_path / "rules"
    build(rules_dir)

    result, calls = _run_hook_block(tmp_path, rules_dir)

    assert result.returncode == 0, result.stderr
    installs = _installs(calls)
    if pinned:
        assert installs == [], f"the pinned bundle was reinstalled: {calls}"
        assert "installing" not in result.stderr
    else:
        assert len(installs) == 1, (
            f"{state}: the installed rules are not the pinned bundle and the hook "
            f"did not reinstall them; python3 calls: {calls}"
        )
        assert f"-d {rules_dir}" in installs[0]
        assert PIN.name in installs[0]


def test_the_hook_installs_the_pin_it_reads_from_the_flake(tmp_path):
    """Both calls name the flake's own pins, whatever ASH_PINS_DIR says."""
    rules_dir = tmp_path / "rules"
    _older_release(rules_dir)
    _, calls = _run_hook_block(tmp_path, rules_dir)
    pins = str(tmp_path / "self" / "automated_security_helper")
    assert len(calls) == 2, calls
    assert all(f"--pins-dir {pins}" in call for call in calls), calls


def _script_check(rules_dir: Path, pins_dir: Path) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != "ASH_PINS_DIR"}
    return subprocess.run(  # nosec B603 - the repository's own script
        [
            sys.executable,
            str(SCRIPT),
            PIN.name,
            "--rules-bundle",
            "--check",
            "--pins-dir",
            str(pins_dir),
            "-d",
            str(rules_dir),
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


@pytest.mark.parametrize(("state", "build", "pinned"), STATES, ids=IDS)
def test_the_scripts_check_agrees_with_ash_dependencies_install(
    tmp_path, state, build, pinned
):
    """The hook's test and the installer's skip decision are the same test."""
    rules_dir = tmp_path / "rules"
    build(rules_dir)

    try:
        verify_installed_bundle(FIXTURE_PIN, rules_dir)
        ash_skips = True
    except RulesBundleUnavailable:
        ash_skips = False
    checked = _script_check(
        rules_dir, _pinned_tree(tmp_path) / "automated_security_helper"
    )

    assert ash_skips is pinned, f"{state}: verify_installed_bundle said {ash_skips}"
    assert checked.returncode == (0 if pinned else 1), (
        f"{state}: --check exited {checked.returncode}: {checked.stderr}"
    )
    if not pinned:
        assert checked.stderr.strip(), "a bundle that is not the pin needs a reason"


def test_the_checkouts_own_pin_refuses_the_fixture_bundle(tmp_path):
    """Unreplaced, the pin is the registry's 50 files: both checks refuse a
    one-file bundle that the replaced pin accepts."""
    rules_dir = tmp_path / "rules"
    _current(rules_dir)
    with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
        verify_installed_bundle(PIN, rules_dir)
    checked = _script_check(rules_dir, PACKAGE)
    assert checked.returncode == 1
    assert "pinned contents" in checked.stderr


def test_check_installs_nothing(tmp_path):
    rules_dir = tmp_path / "rules"
    _older_release(rules_dir)
    before = sorted(p.relative_to(rules_dir) for p in rules_dir.rglob("*"))
    assert _script_check(rules_dir, PACKAGE).returncode == 1
    assert sorted(p.relative_to(rules_dir) for p in rules_dir.rglob("*")) == before


def test_check_needs_rules_bundle():
    result = subprocess.run(  # nosec B603 - the repository's own script
        [sys.executable, str(SCRIPT), "trivy", "--check"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 2
    assert "--check needs --rules-bundle" in result.stderr
