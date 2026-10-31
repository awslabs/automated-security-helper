# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``cwd_outside_scanned_tree`` makes one fallback directory and removes it at exit.

* Under a sandbox the working directory is made under the results directory. One is
  made for a results directory and reused while it stays empty, and it is recorded
  for the removal at exit, as the other fallback directories are.
* Scanners that ask at the same time share one directory: the cache is read, filled
  and recorded under one lock, so no directory is left out of the removal.
* A directory made for one scanned tree is not replaced by the one made for another
  tree, which would leave it out of the removal.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config import path_trust
from automated_security_helper.utils.sandbox import scope

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]


@pytest.fixture(autouse=True)
def _the_filesystem_root_is_inside_the_tree(monkeypatch):
    """The filesystem root counts as inside the tree, as for a drive-root source."""
    monkeypatch.setattr(
        path_trust,
        "in_scanned_tree",
        lambda path, scan_root: Path(path) == Path("/"),
    )
    monkeypatch.setattr(path_trust, "_FALLBACK_CWDS", {})
    yield
    path_trust._remove_fallback_cwds()


def _source(tmp_path: Path, name: str = "src") -> Path:
    source = tmp_path / name
    source.mkdir()
    return source


def test_a_sandboxed_fallback_cwd_is_made_once_and_removed_at_exit(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(scope, "active_scope", lambda: object())
    source = _source(tmp_path)
    results = tmp_path / "results"

    first = path_trust.cwd_outside_scanned_tree(
        source, results_dir=results, source_dir=source
    )
    again = path_trust.cwd_outside_scanned_tree(
        source, results_dir=results, source_dir=source
    )

    assert first.parent == results
    assert again == first
    path_trust._remove_fallback_cwds()
    assert not first.exists()


def test_a_sandboxed_fallback_cwd_that_holds_a_file_is_left_and_replaced(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(scope, "active_scope", lambda: object())
    source = _source(tmp_path)
    results = tmp_path / "results"
    first = path_trust.cwd_outside_scanned_tree(
        source, results_dir=results, source_dir=source
    )
    (first / "written-by-the-tool.txt").write_text("x", encoding="utf-8")

    again = path_trust.cwd_outside_scanned_tree(
        source, results_dir=results, source_dir=source
    )

    assert again != first
    assert again.parent == results
    assert not any(again.iterdir())
    assert (first / "written-by-the-tool.txt").exists()


def test_scanners_asking_together_share_one_fallback_cwd(tmp_path, monkeypatch):
    system_temp = tmp_path / "system-temp"
    system_temp.mkdir()
    real = path_trust._new_directory
    made: List[Path] = []

    def slow_new_directory(parent):
        # Long enough that every caller has looked at the empty cache before the
        # first directory exists.
        time.sleep(0.05)
        directory = real(system_temp if parent is None else parent)
        made.append(directory)
        return directory

    monkeypatch.setattr(path_trust, "_new_directory", slow_new_directory)
    source = _source(tmp_path)
    results = tmp_path / "results"
    callers = 8
    together = threading.Barrier(callers)
    found: List[Path] = []

    def ask() -> None:
        together.wait()
        found.append(
            path_trust.cwd_outside_scanned_tree(
                source, results_dir=results, source_dir=source
            )
        )

    threads = [threading.Thread(target=ask) for _ in range(callers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(found) == callers
    assert len(set(found)) == 1
    assert len(made) == 1


def test_the_directory_of_one_scanned_tree_is_not_dropped_for_another(
    tmp_path, monkeypatch
):
    system_temp = tmp_path / "system-temp"
    system_temp.mkdir()
    under_root = tmp_path / "under-root"
    under_root.mkdir()
    first_tree = _source(tmp_path, "first")
    second_tree = _source(tmp_path, "second")

    def in_tree(path, scan_root):
        # The system temp directory sits inside the second tree only.
        return Path(path) == Path("/") or (
            Path(scan_root) == second_tree
            and system_temp in (Path(path), *Path(path).parents)
        )

    monkeypatch.setattr(path_trust, "in_scanned_tree", in_tree)
    real = path_trust._new_directory
    monkeypatch.setattr(
        path_trust,
        "_new_directory",
        lambda parent: real(system_temp if parent is None else under_root),
    )
    results = tmp_path / "results"

    first = path_trust.cwd_outside_scanned_tree(
        first_tree, results_dir=results, source_dir=first_tree
    )
    second = path_trust.cwd_outside_scanned_tree(
        second_tree, results_dir=results, source_dir=second_tree
    )

    assert first.parent == system_temp
    assert second.parent == under_root
    path_trust._remove_fallback_cwds()
    assert not first.exists()
    assert not second.exists()
