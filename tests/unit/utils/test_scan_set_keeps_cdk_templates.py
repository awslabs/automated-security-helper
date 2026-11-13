# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Synthesized CDK templates stay in the scan set when the root .gitignore lists cdk.out.

``ASH_INCLUSIONS`` carries ``!**/*.template.json`` so that cdk-nag and cfn-nag,
which read the scan set, see the templates ``cdk synth`` writes. That is enough for a
``cdk.out`` line in a nested ignore file, not for the same line in the root one: the
root ``.gitignore`` is also used to prune the walk, so a pruned directory is never
entered and its templates are not there to be kept. CDK's own project template
puts ``cdk.out`` in the root ``.gitignore``, so without the walk below the common
case would lose cfn-nag and cdk-nag coverage, and only checkov, which walks the
tree itself, would read the templates.

A directory the root ``.gitignore`` excludes is walked when it is a CDK
cloud assembly: named ``cdk.out``, or holding the ``cdk.out`` and ``manifest.json``
files every assembly holds. Inside it only the templates come back; its asset
directories are not walked. Any other ignored directory is pruned.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import scan_set

pytestmark = pytest.mark.unit


def _write(root: Path, relative: str, text: str = "{}\n") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _assembly(root: Path, directory: str) -> None:
    _write(root, f"{directory}/cdk.out", '{"version": "48.0.0"}\n')
    _write(root, f"{directory}/manifest.json")
    _write(root, f"{directory}/tree.json")
    _write(root, f"{directory}/AppStack.template.json")
    _write(root, f"{directory}/AppStack.assets.json")
    _write(root, f"{directory}/asset.0a1b2c/index.py", "print('bundled')\n")
    _write(root, f"{directory}/asset.0a1b2c/Bundled.template.json")
    _write(root, f"{directory}/assembly-Prod/cdk.out", '{"version": "48.0.0"}\n')
    _write(root, f"{directory}/assembly-Prod/manifest.json")
    _write(root, f"{directory}/assembly-Prod/ProdStack.template.json")


def _found(root: Path) -> set[str]:
    return {Path(f).relative_to(root).as_posix() for f in scan_set(source=str(root))}


@pytest.mark.parametrize("rule", ["cdk.out", "cdk.out/", "cdk.out/*", "/cdk.out"])
def test_templates_survive_a_root_gitignore_rule(tmp_path, rule):
    root = tmp_path / "app"
    _write(root, ".gitignore", f"{rule}\n")
    _write(root, "app.py", "print('app')\n")
    _assembly(root, "cdk.out")

    found = _found(root)

    assert {
        "cdk.out/AppStack.template.json",
        "cdk.out/assembly-Prod/ProdStack.template.json",
    } <= found, f"templates missing from the scan set for rule {rule!r}: {found}"
    assert "app.py" in found


def test_the_rest_of_the_assembly_stays_out(tmp_path):
    root = tmp_path / "app"
    _write(root, ".gitignore", "cdk.out\n")
    _assembly(root, "cdk.out")

    found = _found(root)

    leaked = {f for f in found if f.startswith("cdk.out/")} - {
        "cdk.out/AppStack.template.json",
        "cdk.out/assembly-Prod/ProdStack.template.json",
    }
    assert not leaked, f"non-template assembly files in the scan set: {leaked}"


def test_an_assembly_synthesized_elsewhere_is_recognized_by_its_files(tmp_path):
    """cdk synth -o out: the directory is not named cdk.out."""
    root = tmp_path / "app"
    _write(root, ".gitignore", "infra/out/\n")
    _assembly(root, "infra/out")

    assert "infra/out/AppStack.template.json" in _found(root)


def test_other_ignored_directories_are_pruned(tmp_path):
    root = tmp_path / "app"
    _write(root, ".gitignore", "node_modules/\nbuild/\n")
    _write(root, "node_modules/pkg/Fixture.template.json")
    _write(root, "build/Copied.template.json")
    _write(root, "app.py", "print('app')\n")

    found = _found(root)

    assert found == {".gitignore", "app.py"}, found


def test_an_ignore_file_inside_the_assembly_is_not_applied(tmp_path):
    """git does not read ignore files under an ignored directory, and neither does ASH.

    Read, this one would bring manifest.json back and its text would be copied
    into ash-ignore-report.txt.
    """
    root = tmp_path / "app"
    output = tmp_path / "out"
    _write(root, ".gitignore", "cdk.out\n")
    _assembly(root, "cdk.out")
    _write(root, "cdk.out/.gitignore", "!manifest.json\n")
    _write(root, "app.py", "print('app')\n")

    found = {
        Path(f).relative_to(root).as_posix()
        for f in scan_set(source=str(root), output=str(output), write_lists=True)
    }

    assert "app.py" in found
    assert "cdk.out/AppStack.template.json" in found
    assert "cdk.out/manifest.json" not in found, found
    report = (output / "ash-ignore-report.txt").read_text(encoding="utf-8")
    assert "cdk.out/.gitignore" not in report, report
