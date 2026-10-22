# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Metadata recorded after the orchestrator is built still reaches the results.

run_ash_scan records ``scan_source`` (utils/scan_source.py) once
``ASHScanOrchestrator.create`` has returned, because working it out starts git,
and a command line that ``create`` refuses (an invalid configuration, a scanner
selection that cancels itself) starts no process. ``create`` has applied the
metadata it was handed by then, so a value added later needs its own way onto
the results model, and has to be part of what a report over saved results
applies again when it loads their model in place of the new one.

A report over saved results (``ash scan --use-existing``) is not a scan of this
run's directory, though, and does not know whether the saved set was filtered.
So over a loaded set this run's ``scan_source`` is never applied, and its
``changed_files_only`` only when it is True (this run's report is narrowed to
the changed files). The aws-security-hub reporter archives under the recorded
directory, and only when ``changed_files_only`` is an explicit False, so this
run's "." never replaces a saved ``services/api``, and its False never replaces
a saved unknown (a merge of shards that disagreed, or an older ASH).
"""

import logging

import pytest

from automated_security_helper.core.enums import ExecutionPhase, ExportFormat
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults

#: Stands for "the saved set does not have this key at all".
_ABSENT = object()


def _create(tmp_path, **kwargs):
    source = tmp_path / "src"
    source.mkdir()
    return ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=tmp_path / "out",
        metadata={"changed_files_only": False},
        **kwargs,
    )


def _saved(tmp_path, *, scan_source=_ABSENT, changed_files_only=_ABSENT):
    saved = AshAggregatedResults()
    if scan_source is not _ABSENT:
        setattr(saved.metadata, "scan_source", scan_source)
    if changed_files_only is not _ABSENT:
        setattr(saved.metadata, "changed_files_only", changed_files_only)
    path = tmp_path / "saved.json"
    path.write_text(saved.model_dump_json(by_alias=True), encoding="utf-8")
    return path


def _recorded(metadata, key):
    """The value *metadata* holds for *key*, or _ABSENT when it has none."""
    extra = metadata.__pydantic_extra__ or {}
    if key in extra:
        return extra[key]
    return getattr(metadata, key, _ABSENT)


def test_added_metadata_reaches_the_results_model(tmp_path):
    orchestrator = _create(tmp_path)

    orchestrator.add_metadata(scan_source="services/api")

    metadata = orchestrator.execution_engine._asharp_model.metadata
    assert metadata.scan_source == "services/api"
    # What create() applied is still there beside it.
    assert metadata.changed_files_only is False


def test_added_metadata_reaches_results_loaded_from_a_saved_set(tmp_path):
    """Over a loaded set, what this run adds reaches it, except the directory
    this run scanned, which is not the saved set's: the saved services/api is
    kept, and this run's changed-files filter (True) is recorded over the saved
    False, because this run's report is narrowed to the changed files."""
    saved_path = _saved(tmp_path, scan_source="services/api", changed_files_only=False)
    orchestrator = _create(
        tmp_path,
        existing_results_path=saved_path,
        output_formats=[ExportFormat.FLAT_JSON],
        show_summary=False,
    )

    orchestrator.add_metadata(scan_source=".", changed_files_only=True)
    results = orchestrator.execute_scan(phases=["report"])

    assert _recorded(results.metadata, "scan_source") == "services/api"
    assert _recorded(results.metadata, "changed_files_only") is True


@pytest.mark.parametrize(
    "saved_source, saved_marker",
    [
        # ash merge over shards that recorded different directories, one of them
        # filtered and one not saying.
        (None, None),
        # A full scan of services/api.
        ("services/api", False),
        # A full scan of a clone nested in another repository: no directory.
        (None, False),
        # Results from an ASH that recorded neither.
        (_ABSENT, _ABSENT),
    ],
    ids=[
        "merge-of-disagreeing-shards",
        "services-api-full-scan",
        "nested-clone-full-scan",
        "older-ash",
    ],
)
def test_a_report_over_saved_results_keeps_their_scan_markers(
    tmp_path, monkeypatch, saved_source, saved_marker
):
    """``ash scan --use-existing`` from the repository root, without
    --changed-files-only: this run records "." and False, and neither replaces
    what the saved set says, in what the run returns or in the results it
    writes. What the aws-security-hub reporter archives for each saved pair is
    tested with the reporter (test_security_hub_batch_import.py)."""
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )

    source = tmp_path / "src"
    source.mkdir()
    # This run's own answers: the source is a repository's root, so ".".
    monkeypatch.setattr(
        "automated_security_helper.utils.get_scan_set.git_repository_root",
        lambda path: source,
    )
    monkeypatch.setattr(
        "automated_security_helper.utils.scan_source.repository_is_nested",
        lambda root: False,
        raising=False,
    )
    saved_path = _saved(
        tmp_path, scan_source=saved_source, changed_files_only=saved_marker
    )
    output_dir = tmp_path / "out"

    returned, _ = _run_local_mode(
        ScanOptions(
            source_dir=source,
            output_dir=output_dir,
            existing_results=saved_path.as_posix(),
            phases=[ExecutionPhase.REPORT],
            output_formats=[ExportFormat.FLAT_JSON],
            show_summary=False,
            changed_files_only=False,
        ),
        logging.getLogger("test-saved-scan-markers"),
    )
    written = AshAggregatedResults.model_validate_json(
        (output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )

    for results in (returned, written):
        assert _recorded(results.metadata, "scan_source") == saved_source
        assert _recorded(results.metadata, "changed_files_only") == saved_marker


@pytest.mark.parametrize("saved_marker", [_ABSENT, None, False, True])
def test_this_runs_changed_files_filter_marks_any_saved_set(tmp_path, saved_marker):
    """This run's True is the one value it records over a loaded set: the
    report it writes is narrowed to the changed files whatever the saved set
    says."""
    saved_path = _saved(tmp_path, changed_files_only=saved_marker)
    orchestrator = _create(
        tmp_path,
        existing_results_path=saved_path,
        output_formats=[ExportFormat.FLAT_JSON],
        show_summary=False,
    )

    orchestrator.add_metadata(changed_files_only=True)
    results = orchestrator.execute_scan(phases=["report"])

    assert _recorded(results.metadata, "changed_files_only") is True
