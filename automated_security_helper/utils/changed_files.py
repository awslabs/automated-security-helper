# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The ``--changed-files-only`` result filter.

Why this exists
---------------
``--changed-files-only`` scans everything and reports only the findings in files
changed against the base ref. The scan execution engine applies the filter once,
to the model, before the summary counts and the reporters read it
(``ScanExecutionEngine._drop_findings_outside_changed_files``). So every report
(HTML, Markdown, CSV, flat-json, JUnit, GitLab SAST, OCSF, ...), the summary
counts, ``ash.sarif``, the aggregated results file and the exit code all leave
out the same findings.
"""

from pathlib import Path
from typing import TYPE_CHECKING, Set

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.undecodable_text import (
    path_in_record_form,
    undecodable_of_text,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


def filter_results_to_changed_files(
    results: "AshAggregatedResults",
    changed_files: Set[Path],
    source_dir: Path,
) -> "AshAggregatedResults":
    """Remove SARIF results whose primary location is not in *changed_files*.

    *changed_files* holds resolved absolute paths; a result's location is
    resolved against *source_dir* to compare. A result with no location is kept,
    since it cannot be placed outside the changed files. Mutates and returns
    *results*.

    A URI holds a file name that is not UTF-8 in its record form, each lone surrogate
    as ``\\udcNN`` (utils/undecodable_text.py), and git's names hold the surrogate.
    The URI is resolved by the name the file has on disk, and the two sides are
    compared in the record form.
    """
    if not results or not results.sarif or not results.sarif.runs:
        return results
    recorded_changed = {path_in_record_form(path) for path in changed_files}
    discarded = 0
    for run in results.sarif.runs:
        if not run.results:
            continue
        filtered = []
        for result in run.results:
            if not result.locations:
                filtered.append(result)
                continue
            loc = result.locations[0]
            if (
                not loc.physicalLocation
                or not loc.physicalLocation.root.artifactLocation
            ):
                filtered.append(result)
                continue
            uri = loc.physicalLocation.root.artifactLocation.uri or ""
            if uri.startswith("file://"):
                uri = uri[7:]
                if uri.startswith("///"):
                    uri = uri[2:]
            resolved = Path(source_dir).joinpath(undecodable_of_text(uri)).resolve()
            if path_in_record_form(resolved) in recorded_changed:
                filtered.append(result)
        discarded += len(run.results) - len(filtered)
        run.results = filtered

    # An empty *changed_files* is a filter that matches nothing, so it discards
    # every located result and the run reports zero findings at exit 0 --
    # indistinguishable from a clean tree. Said at WARNING, with the count, because
    # a filter that quietly empties a result set is how a filter becomes a false
    # negative; the same reasoning as the output-path exclusion in
    # `utils.sarif_utils.apply_suppressions_to_sarif`, which counts for this reason.
    #
    # Both routes here are reachable without operator error. `--changed-files-only`
    # against a base ref that resolves to an empty diff produces an empty set, and
    # so does a diff falling entirely outside `--source-dir` once the caller
    # intersects the two scopings. The caller passes the empty set deliberately --
    # `is not None` there distinguishes a filter matching nothing from no filter --
    # so this reports the consequence rather than refusing it.
    #
    # Conditional on something actually being lost. An empty set over an empty
    # result set costs nothing, and a count printed on every such run is noise.
    # Workspace mode never reaches this branch: `workspace.execution` passes a
    # changed set only when it is non-empty, because there an empty set means
    # skip the project.
    #
    # On ASH_LOGGER rather than `logging.getLogger(__name__)`, which is what the
    # exit-code gates in this module use. Those emit at ERROR for a caller that
    # reads the exit code; this one has to reach the operator's console, and
    # ASH_LOGGER is the logger ASH configures and renders. It is also the logger
    # every comparable disclosure already uses -- `apply_suppressions_to_sarif`'s
    # exclusion count, `cli.merge`'s coverage notices.
    if not changed_files and discarded:
        ASH_LOGGER.warning(
            "Discarded %d finding(s): the changed-file set is empty, so it matched "
            "no location and every located finding was removed. This report is "
            "therefore not evidence that the tree is clean. Either the diff against "
            "--base-ref is empty, or none of the paths it names are inside "
            "--source-dir.",
            discarded,
        )
    return results
