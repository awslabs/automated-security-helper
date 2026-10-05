# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: an ignore rule for build output must not hide tracked source.

The root ``.gitignore`` carries the standard Python packaging block, in which
``lib/`` and ``lib64/`` name the directories a distutils build drops beside
``setup.py``. Written without a leading slash, a gitignore directory pattern
matches at *every* depth, so the rule also matched ``deploy/cdk/lib/`` -- the
entire source directory of this repository's CDK application.

``deploy/cdk/.gitignore`` already carries a ``!lib/`` negation for exactly this
reason, and it is enough for git. It is not enough for
:func:`~automated_security_helper.utils.get_scan_set.scan_set`, which prunes
directories during its walk using a parser built from the *root* ``.gitignore``
alone -- so the walk never descends into ``deploy/cdk/lib`` and the nested
negation is never consulted. The files were tracked, and unscanned.

Nothing pinned this, which is why a rule meant for Python build output could
drift into matching TypeScript source unnoticed. The assertions here are on the
resolved scan set rather than on the text of any ignore file.
"""

import shutil
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import scan_set

REPO_ROOT = Path(__file__).resolve().parents[3]

CDK_LIB = REPO_ROOT / "deploy" / "cdk" / "lib"

#: Directories beside ``deploy/cdk/lib`` that are already in the scan set.
#: Asserted alongside it so that a wholesale ``scan_set`` failure cannot read as
#: a pass here.
CDK_CONTROL_DIRS = ("templates", "test")


@pytest.fixture(scope="module")
def repo_scan_set() -> set:
    """The scan set for this checkout, as POSIX paths relative to the repo root.

    Module-scoped: this walks the whole tree, and every test below asks the same
    question of it.
    """
    resolved = set()
    for entry in scan_set(source=str(REPO_ROOT)):
        path = Path(entry)
        if not path.is_absolute():
            path = REPO_ROOT / path
        try:
            resolved.add(path.resolve().relative_to(REPO_ROOT).as_posix())
        except ValueError:
            # Outside the checkout; not what these tests are about.
            continue
    return resolved


def test_the_cdk_application_sources_are_in_the_scan_set(repo_scan_set):
    """The one-line assertion that was missing.

    Every tracked ``.ts`` file under ``deploy/cdk/lib`` has to be scannable.
    Derived from the directory rather than from a hardcoded list, so adding a
    stack cannot silently fall outside the assertion.
    """
    sources = sorted(path.name for path in CDK_LIB.glob("*.ts"))
    assert sources, (
        f"fixture precondition: no .ts sources found under {CDK_LIB}, so this "
        "test would pass without asserting anything"
    )

    missing = [
        name for name in sources if f"deploy/cdk/lib/{name}" not in repo_scan_set
    ]
    assert not missing, (
        "tracked CDK sources are absent from the scan set, so ASH does not scan "
        f"its own CDK application: {missing}"
    )


def test_the_neighbouring_cdk_directories_are_in_the_scan_set(repo_scan_set):
    """Control for the test above: prove the scan set covers this subtree at all."""
    for directory in CDK_CONTROL_DIRS:
        prefix = f"deploy/cdk/{directory}/"
        assert any(entry.startswith(prefix) for entry in repo_scan_set), (
            f"no files under {prefix} are in the scan set, so the assertion "
            "above cannot distinguish a narrowed ignore rule from a broken walk"
        )


def test_no_lib_directory_is_excluded_wholesale(repo_scan_set):
    """States the defect's shape rather than one instance of it.

    Before the rule was anchored, *no* file under any directory named ``lib``
    reached the scan set anywhere in the tree.
    """
    under_lib = [
        entry
        for entry in repo_scan_set
        if "lib/" in entry and not entry.startswith(".venv/")
    ]
    assert under_lib, (
        "not one file under any 'lib' directory is in the scan set, which is the "
        "signature of an unanchored 'lib/' ignore rule"
    )


def test_the_packaging_rule_still_ignores_root_build_output(tmp_path):
    """The narrowing must not cost what the packaging block was written for.

    Uses this repository's own root ``.gitignore`` against a synthetic tree, so
    the rule under test is the shipped one rather than a restatement of it. A
    root-level ``lib/`` is distutils build output and stays excluded; a nested
    one is source and must not be.
    """
    shutil.copyfile(REPO_ROOT / ".gitignore", tmp_path / ".gitignore")

    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "build_artifact.py").write_text("# distutils output\n")
    (tmp_path / "pkg" / "lib").mkdir(parents=True)
    (tmp_path / "pkg" / "lib" / "source.ts").write_text("export const x = 1;\n")

    resolved = {
        Path(entry).resolve().relative_to(tmp_path.resolve()).as_posix()
        for entry in scan_set(source=str(tmp_path))
    }

    assert "lib/build_artifact.py" not in resolved, (
        "the Python packaging block is meant to keep root-level build output out "
        f"of the scan set: {sorted(resolved)}"
    )
    assert "pkg/lib/source.ts" in resolved, (
        "a nested directory named 'lib' holds source, not build output, and must "
        f"be scanned: {sorted(resolved)}"
    )
