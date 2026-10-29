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
from typing import TYPE_CHECKING, List, Mapping, Optional, Set
from urllib.parse import unquote

from automated_security_helper.utils.finding_identity import CONVERTED_PATH_PROPERTY
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.undecodable_text import (
    path_in_record_form,
    resolve_uri_reading,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


def _location_readings(uri: str) -> List[str]:
    """The texts a location ``uri`` may name a file as: literal, and percent-decoded.

    A relative URI is a URI reference, and a tool may percent-encode it: checkov
    writes ``out(1)/x.tf`` as ``out%281%29/x.tf``, which ``sanitize_sarif_paths``
    leaves encoded. Read literally, that text names no file, so a finding in such a
    directory was dropped from a ``--changed-files-only`` report whether or not
    its file had changed. Both readings are tried; the decoded one is left out
    when it is the same text.
    """
    if uri.startswith("file://"):
        uri = uri[7:]
        if uri.startswith("///"):
            uri = uri[2:]
    readings = [uri]
    decoded = unquote(uri)
    if decoded != uri:
        readings.append(decoded)
    return readings


def _converted_path(result) -> Optional[str]:
    """The ``converted_path`` property of a result located in a converted file.

    Set by ``utils.scan_output_dirs.mark_converted_results`` on every result a
    scanner reported in a file a converter wrote (a notebook's Python, an archive
    member): the path relative to the converted root, ``/``-separated.
    """
    properties = getattr(result, "properties", None)
    if properties is None:
        return None
    value = getattr(properties, CONVERTED_PATH_PROPERTY, None)
    return value if isinstance(value, str) and value else None


def filter_results_to_changed_files(
    results: "AshAggregatedResults",
    changed_files: Set[Path],
    source_dir: Path,
    converted_sources: Optional[Mapping[str, str]] = None,
) -> "AshAggregatedResults":
    """Remove SARIF results whose primary location is not in *changed_files*.

    *changed_files* holds resolved absolute paths; a result's location is
    resolved against *source_dir* to compare. A result with no location is kept,
    since it cannot be placed outside the changed files; so is one whose location
    cannot be resolved to a path at all (:func:`resolve_uri_reading`), rather
    than that one location raising out of the filter and failing the scan.
    Mutates and returns *results*.

    A result located in a converted file (its ``converted_path`` property is
    set) is placed by the source file the converter read, not by the converted
    file, which sits in the output directory and so is never in the changed set.
    *converted_sources* maps each ``converted_path`` to that source, relative to
    *source_dir* or absolute. A converted result whose source the mapping does
    not name is kept, and the run says once how many were: before this, every
    finding in a converted file was dropped from a ``--changed-files-only``
    report, including those from a notebook or archive that was in the diff, and
    nothing said so.

    A URI holds a file name that is not UTF-8 in its record form, each lone surrogate
    as ``\\udcNN`` (utils/undecodable_text.py), and git's names hold the surrogate.
    The URI is resolved by the name the file has on disk, and the two sides are
    compared in the record form. Each URI is read literally and percent-decoded
    (:func:`_location_readings`); either reading in the changed set keeps the result.
    """
    if not results or not results.sarif or not results.sarif.runs:
        return results
    recorded_changed = {path_in_record_form(path) for path in changed_files}
    discarded = 0
    unplaced_converted = 0
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
            converted = _converted_path(result)
            if converted is not None:
                source = (converted_sources or {}).get(converted)
                if source is None:
                    unplaced_converted += 1
                    filtered.append(result)
                    continue
                readings = [source]
            else:
                readings = _location_readings(
                    loc.physicalLocation.root.artifactLocation.uri or ""
                )
            placed = [
                path_in_record_form(resolved)
                for resolved in (
                    resolve_uri_reading(reading, base=Path(source_dir))
                    for reading in readings
                )
                if resolved is not None
            ]
            if not placed or any(path in recorded_changed for path in placed):
                filtered.append(result)
        discarded += len(run.results) - len(filtered)
        run.results = filtered

    if unplaced_converted:
        ASH_LOGGER.warning(
            "Kept %d finding(s) located in converted files (notebooks, archive "
            "members): the changed-file filter has no record of the source file "
            "each was converted from, so it cannot tell whether that source "
            "changed. They are reported rather than dropped.",
            unplaced_converted,
        )

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
