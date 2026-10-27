# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A directory named ``cdk.out`` is a CDK cloud assembly by its name alone.

The scan-set walk prunes a directory the root ``.gitignore`` excludes, except a
CDK cloud assembly, which it walks for the templates ``cdk synth`` wrote
(``get_scan_set._is_cdk_cloud_assembly``). An assembly is recognized by its name,
``cdk.out``, or by the ``cdk.out`` and ``manifest.json`` files it holds. Every
``cdk.out`` fixture elsewhere holds both files, so the name never decided, and a
mutant removing the name test survived. Here the directory holds neither file: its
templates are kept because of its name, and the same directory under another name
is pruned.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import scan_set


def _write(root: Path, relative: str, text: str = "{}\n") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _found(root: Path) -> set[str]:
    return {Path(f).relative_to(root).as_posix() for f in scan_set(source=str(root))}


def _unmarked_assembly(root: Path, directory: str) -> None:
    """Templates and a tree file, without the cdk.out and manifest.json markers."""
    _write(root, f"{directory}/AppStack.template.json")
    _write(root, f"{directory}/tree.json")


@pytest.mark.parametrize("rule", ["cdk.out", "cdk.out/", "/cdk.out"])
def test_a_cdk_out_without_the_assembly_files_keeps_its_templates(tmp_path, rule):
    root = tmp_path / "app"
    _write(root, ".gitignore", f"{rule}\n")
    _write(root, "app.py", "print('app')\n")
    _unmarked_assembly(root, "cdk.out")
    assert not (root / "cdk.out" / "cdk.out").exists()
    assert not (root / "cdk.out" / "manifest.json").exists()

    found = _found(root)

    assert "cdk.out/AppStack.template.json" in found, found
    assert "cdk.out/tree.json" not in found, found
    assert "app.py" in found


def test_the_same_directory_under_another_name_is_pruned(tmp_path):
    """The control: without the name or the files, nothing marks an assembly."""
    root = tmp_path / "app"
    _write(root, ".gitignore", "synth/\n")
    _write(root, "app.py", "print('app')\n")
    _unmarked_assembly(root, "synth")

    found = _found(root)

    assert not any(f.startswith("synth/") for f in found), found
    assert "app.py" in found
