# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container and Nix mode clear on the host what a local scan clears.

Before an outer mode starts, ``_discard_prior_run_artifacts`` removes the previous
run's output, so that a results file found afterwards is this run's. A hand-kept
copy of the orchestrator's lists can miss a name, such as ``ash-scan-set-run.json``,
the record of the run that wrote the scan-set lists, which the orchestrator
removes with them. Both come from the same names, and this compares what each
leaves behind in the same directory.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _discard_prior_run_artifacts,
)
from tests.unit.test_committed_results_paths_are_never_deleted import (
    _confined,
    _initialize,
    _orchestrator,
)

#: A previous run's output, the previous results an MCP scan set aside with the
#: marker a restore leaves, and two files no scan removes.
PREVIOUS_RUN = (
    "ash_aggregated_results.json",
    "ash-ignore-report.txt",
    "ash-scan-set-files-list.txt",
    "ash-scan-set-run.json",
    "analysis/notes.json",
    "reports/ash.sarif",
    "scanners/bandit/source/bandit.sarif",
    "converted/jupyter/notebook.py",
    ".ash_previous_results/reports/ash.sarif",
    ".ash_previous_results_restored",
    "ash.log",
    "projects/api/ash_aggregated_results.json",
)


def _populate(source: Path) -> Path:
    output = source / ".ash" / "ash_output"
    for relative in PREVIOUS_RUN:
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"previous {relative}\n", encoding="utf-8")
    return output


def _files(output: Path) -> set[str]:
    return {
        path.relative_to(output).as_posix()
        for path in output.rglob("*")
        if path.is_file()
    }


def test_the_host_removes_the_files_a_local_scan_removes(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    host_source, local_source = tmp_path / "host", tmp_path / "local"
    host, local = _populate(host_source), _populate(local_source)
    _confined(tmp_path, host, local)

    _discard_prior_run_artifacts(
        ScanOptions(source_dir=host_source, output_dir=host),
        logging.getLogger("test-prior-run-artifacts"),
    )
    _initialize(_orchestrator(local_source, local))

    assert _files(host) == _files(local)
    assert _files(host) == {"ash.log", "projects/api/ash_aggregated_results.json"}
