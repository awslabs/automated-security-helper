# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The generated blocks in ``./ash`` and ``utils/ash_helpers.ps1`` match the ash CLI.

``scripts/generate_wrapper_tables.py`` renders the wrapper contract into marked blocks
inside the two wrappers. A CLI change that adds a subcommand or an option makes a block
stale; the lint job runs the script with ``--check``, and this test runs the same check
in every matrix cell so a stale block fails wherever the unit tests run.

The control: the check is run against a copy of the wrappers with one table entry
changed, and with a marker removed, and must fail naming the file and the block. A
check that passed everything would otherwise read as a clean tree.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "generate_wrapper_tables.py"


@pytest.fixture(scope="module")
def generator():
    name = "generate_wrapper_tables_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(name, None)


def _copy_of_the_wrappers(tmp_path: Path, generator) -> Path:
    for file in generator.BLOCKS:
        target = tmp_path / file
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / file, target)
    return tmp_path


def test_every_generated_block_matches_the_cli(generator):
    drifts = generator.check()
    assert not drifts, "\n\n".join(f"{d.file} {d.block}\n{d.diff}" for d in drifts)


def test_the_check_command_passes_on_this_tree(generator, capsys):
    assert generator.main(["--check"]) == 0
    assert "match the ash CLI" in capsys.readouterr().out


def test_every_block_has_its_markers_in_its_file(generator):
    for file, blocks in generator.BLOCKS.items():
        lines = (REPO_ROOT / file).read_text(encoding="utf-8").split("\n")
        for name, _ in blocks:
            generator._find_block(lines, name, file)


@pytest.mark.parametrize(
    ("file", "block", "old", "new"),
    [
        (
            "utils/ash_helpers.ps1",
            "ps1-option-subcommands",
            "= 'scan build-image'\n",
            "= 'scan'\n",
        ),
        (
            "utils/ash_helpers.ps1",
            "ps1-runner-discovery",
            "@('finch', 'docker', 'nerdctl', 'podman')",
            "@('docker', 'finch', 'nerdctl', 'podman')",
        ),
        (
            "ash",
            "sh-subcommands",
            ' plugin express"',
            ' plugin"',
        ),
        (
            "ash",
            "sh-root-value-options",
            "--workspace-config -c",
            "--workspace-config -c -x",
        ),
    ],
)
def test_a_perturbed_block_is_reported_by_file_and_block(
    generator, tmp_path, file, block, old, new
):
    root = _copy_of_the_wrappers(tmp_path, generator)
    path = root / file
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"the control's anchor is not in {file}: {old!r}"
    path.write_text(text.replace(old, new), encoding="utf-8")

    drifts = generator.check(root)

    assert [(d.file, d.block) for d in drifts] == [(file, block)]
    # The diff shows the change itself: the perturbed text on a removed line and the
    # generated text on an added one. A diff that names the block but carries neither
    # (an empty body, or the header lines alone) fails here, which the old check, true
    # of every unified diff's "---" header, could not.
    body = [
        line
        for line in drifts[0].diff.split("\n")
        if not line.startswith(("---", "+++"))
    ]
    removed = "\n".join(line for line in body if line.startswith("-"))
    added = "\n".join(line for line in body if line.startswith("+"))
    assert new.strip() in removed, drifts[0].diff
    assert old.strip() in added, drifts[0].diff


def test_regenerating_a_perturbed_copy_restores_the_committed_text(generator, tmp_path):
    root = _copy_of_the_wrappers(tmp_path, generator)
    path = root / "ash"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace(' plugin express"', ' plugin"'), encoding="utf-8")
    assert generator.check(root)

    written = generator.write(root)

    assert written == ["ash"]
    assert path.read_text(encoding="utf-8") == text
    assert not generator.check(root)


def test_a_missing_marker_is_an_error_not_a_pass(generator, tmp_path):
    root = _copy_of_the_wrappers(tmp_path, generator)
    path = root / "utils" / "ash_helpers.ps1"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace("# END generated: ps1-subcommands\n", ""), encoding="utf-8"
    )
    with pytest.raises(generator.MarkerError, match="ps1-subcommands"):
        generator.check(root)
