# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/e2e/release_defects.py: a published release's defects, matched exactly.

The Homebrew upgrade leg installs v3.7.1's formula as its users have it, and that keg
cannot start (`ModuleNotFoundError: No module named 'typer'`, measured with Homebrew on
Linux). The leg asserts that exact failure, then requires `brew upgrade` to repair it.
These tests hold the judge to "exactly": the release working, or failing another way,
fails, and no release without an entry, nor any v4 release, is exempted.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "e2e" / "release_defects.py"


def _load():
    spec = importlib.util.spec_from_file_location("ash_e2e_release_defects", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rd = _load()

# What `ash --version` printed from v3.7.1's keg (Homebrew on Linux, 2026-10-08).
V371_KEG = """Traceback (most recent call last):
  File "/home/linuxbrew/.linuxbrew/bin/ash", line 5, in <module>
    from automated_security_helper.cli.main import app
ModuleNotFoundError: No module named 'typer'
"""


def _judge(tmp_path, release, rc, output):
    log = tmp_path / "version.log"
    log.write_text(output, encoding="utf-8")
    return rd.main(
        [
            "homebrew-version",
            "--release",
            release,
            "--rc",
            str(rc),
            "--output",
            str(log),
        ]
    )


def test_the_recorded_failure_matches(tmp_path):
    assert _judge(tmp_path, "v3.7.1", 1, V371_KEG) == 0


@pytest.mark.parametrize(
    "rc, output",
    [
        (0, "awslabs/automated-security-helper v3.7.1\n"),  # the release works now
        (1, "ModuleNotFoundError: No module named 'rich'\n"),  # another missing module
        (1, "Segmentation fault\n"),
        (0, V371_KEG),  # the text, but a clean exit
    ],
    ids=["works", "other-module", "other-failure", "exit-zero"],
)
def test_anything_but_the_recorded_failure_fails(tmp_path, rc, output):
    assert _judge(tmp_path, "v3.7.1", rc, output) == 1


@pytest.mark.parametrize("release", ["v3.6.1", "v4.0.0", "v3.7.2"])
def test_a_release_without_an_entry_must_work(tmp_path, release):
    assert _judge(tmp_path, release, 1, V371_KEG) == 2


def test_no_v4_release_and_no_build_of_this_tree_is_ever_recorded():
    for table in (rd.HOMEBREW_VERSION_DEFECTS, rd.MCPB_BUNDLE_DEFECTS):
        for tag in table:
            assert tag.startswith("v3."), tag


def test_the_homebrew_leg_asserts_the_defect_and_then_requires_the_upgrade_to_work():
    script = (SCRIPT.parent / "homebrew.sh").read_text(encoding="utf-8")
    # The release keg is judged by this module, by its own tag, and only 0 (exactly the
    # recorded defect) or 2 (none recorded, so it must work) lets the leg go on.
    assert 'release_defects.py" homebrew-version --release "${PREV_REF%% *}"' in script
    assert '[ "$defect_rc" -eq 0 ] || [ "$defect_rc" -eq 2 ]' in script
    # A release without a recorded defect is held to the full N-1 checks.
    gate = script.index('if [ "$defect_rc" -eq 0 ]; then')
    rest = script[gate:]
    assert rest.index('require_version_line "$prev_cli" "$prev_version"') < rest.index(
        "brew upgrade"
    )
    # The upgraded keg must work: version, the findings case, and the formula's test.
    upgrade_leg = script[script.index("leg_upgrade() {") :]
    upgrade_leg = upgrade_leg[: upgrade_leg.index("\n}\n")]
    after = upgrade_leg[upgrade_leg.index("brew upgrade --verbose") :]
    assert 'require_version_line "$cli" "$VERSION"' in after
    assert 'run_case "$cli" findings upgrade-after' in after
    assert '\n  brew test --verbose "$FORMULA"\n' in after
