# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reporting over saved results never forgets that they were filtered.

Why this exists
---------------
``metadata.changed_files_only: true`` says a result set was narrowed to the
changed files, so a finding it does not list was left out, not fixed. The
aws-security-hub reporter archives findings a scan no longer reports, and it
trusts an explicit ``false``.

A report over saved results (``ash scan --use-existing``, the orchestrator's
``existing_results_path``) re-applies this run's metadata to the loaded model.
run_ash_scan writes ``changed_files_only`` on every run, ``false`` when the flag
was not given. Re-applied over a saved filtered set, that would record ``false`` on
results that are filtered, and the archiving step would close findings that were
never fixed.

A saved ``true`` survives re-application: this run's metadata can set it, but
never clear it. Nor does this run's ``false`` replace a saved set's unknown (no
value): only this run's ``true`` is recorded over a loaded set (see
test_metadata_added_after_create.py). Most tests below hand the orchestrator the
run's value directly; the last one takes it from run_ash_scan's own local-mode
path.
"""

import logging

import pytest

from automated_security_helper.core.enums import ExecutionPhase, ExportFormat
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit

#: One scanner's entry, which is what a scan phase records for every scanner it
#: considered. A saved set with no scanner results and no findings holds no scan,
#: and --use-existing refuses it (utils/inner_run_outcome.py,
#: existing_results_problem); these tests are about the metadata it carries.
_SCANNED = {"bandit": {"source": {"scanner_name": "bandit", "status": "PASSED"}}}


def _report_over_saved(tmp_path, saved_marker, this_run_marker):
    source = tmp_path / "src"
    source.mkdir()
    saved = AshAggregatedResults(scanner_results=_SCANNED)
    if saved_marker is not None:
        setattr(saved.metadata, "changed_files_only", saved_marker)
    saved_path = tmp_path / "saved.json"
    saved_path.write_text(saved.model_dump_json(by_alias=True), encoding="utf-8")

    orchestrator = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=tmp_path / "out",
        existing_results_path=saved_path,
        output_formats=[ExportFormat.FLAT_JSON],
        show_summary=False,
        metadata=(
            None if this_run_marker is None else {"changed_files_only": this_run_marker}
        ),
    )
    results = orchestrator.execute_scan(phases=["report"])
    return getattr(results.metadata, "changed_files_only", None)


def test_a_saved_true_survives_a_run_that_writes_false(tmp_path):
    assert _report_over_saved(tmp_path, True, False) is True


@pytest.mark.parametrize("this_run", [None, True])
def test_a_saved_true_survives_any_run(tmp_path, this_run):
    assert _report_over_saved(tmp_path, True, this_run) is True


def test_this_runs_true_marks_an_unmarked_set(tmp_path):
    assert _report_over_saved(tmp_path, None, True) is True


@pytest.mark.parametrize("saved", [None, False])
def test_this_runs_false_never_replaces_what_the_saved_set_says(tmp_path, saved):
    """A saved False stays False, and a set that does not say (None: the key is
    absent) still does not: this run did not scan it, so its False says nothing
    about whether the saved findings were filtered, and the aws-security-hub
    reporter archives only on an explicit False."""
    assert _report_over_saved(tmp_path, saved, False) is saved


def test_a_report_over_saved_filtered_results_through_run_ash_scan_keeps_true(
    tmp_path,
):
    """The two halves together: run_ash_scan's own marker, and the reload.

    Without --changed-files-only, _run_local_mode hands the orchestrator
    ``{"changed_files_only": False}``. Over results saved as filtered, the
    report must still say they are filtered, both in what the run returns and in
    the aggregated results it writes.
    """
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _run_local_mode,
    )

    source = tmp_path / "src"
    source.mkdir()
    saved = AshAggregatedResults(scanner_results=_SCANNED)
    setattr(saved.metadata, "changed_files_only", True)
    saved_path = tmp_path / "saved.json"
    saved_path.write_text(saved.model_dump_json(by_alias=True), encoding="utf-8")
    output_dir = tmp_path / "out"

    opts = ScanOptions(
        source_dir=source,
        output_dir=output_dir,
        existing_results=saved_path.as_posix(),
        phases=[ExecutionPhase.REPORT],
        output_formats=[ExportFormat.FLAT_JSON],
        show_summary=False,
        changed_files_only=False,
    )
    returned, _ = _run_local_mode(opts, logging.getLogger("test-reload-marker"))

    assert getattr(returned.metadata, "changed_files_only", None) is True
    written = AshAggregatedResults.model_validate_json(
        (output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    assert getattr(written.metadata, "changed_files_only", None) is True
