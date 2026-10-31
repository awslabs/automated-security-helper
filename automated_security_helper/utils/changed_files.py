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

import re
from pathlib import Path
from typing import TYPE_CHECKING, List, Mapping, Optional, Set, Tuple
from urllib.parse import unquote

from automated_security_helper.utils.finding_identity import CONVERTED_PATH_PROPERTY
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.undecodable_text import (
    path_in_record_form,
    resolve_uri_reading,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


def _split_file_uri(uri: str) -> Tuple[str, str]:
    """The host segment and the path of a ``file://`` *uri*, split at the first ``/``.

    By hand and not by a URL parser: a parser reads ``file://[locale]/page.tsx`` as
    a malformed IPv6 host and raises, and one location raising out of the filter
    fails the scan.
    """
    rest = uri[len("file://") :]
    slash = rest.find("/")
    if slash < 0:
        return rest, ""
    return rest[:slash], rest[slash:]


def _without_drive_slash(path: str) -> str:
    """*path* without the slash before a drive letter (``/C:/p`` is ``C:/p``)."""
    if len(path) > 2 and path[0] == "/" and path[2] == ":":
        return path[1:]
    return path


def _file_uri_path(uri: str) -> str:
    """The path a ``file://`` *uri* names, still percent-encoded.

    The reduction ``sarif_utils._file_uri_to_path_text`` makes, less its decoding,
    which :func:`_location_readings` does itself so that it can also keep the
    encoded text as a reading. A host segment is not part of the path
    (``file://host/p`` names ``/p``), and the slash before a drive letter is not
    either (``file:///C:/proj`` names ``C:/proj``). Slicing the scheme off left the
    host as a directory of the path and the slash on the drive, so such a URI
    never matched the changed file it names. A query or fragment is not part of the
    path either; :func:`_location_readings` also keeps the path with them in, for a
    name that holds a ``#`` or a ``?``.

    Both readers cut the URI on its own slash by hand and neither parses it (a URL
    parser raises on ``file://[locale]/page.tsx``), so they agree on every URI the
    parity test lists, bracket forms included. They differ on one thing, on purpose:
    the sarif reader keeps a ``#`` or ``?`` in the name, and this one cuts there and
    reads the whole path as well, so the sarif reader's text is always among the
    readings. A test pins each of the two.
    """
    _host, path = _split_file_uri(uri)
    return _without_drive_slash(re.split(r"[?#]", path, maxsplit=1)[0])


def _location_readings(uri: str) -> List[str]:
    """The texts a location ``uri`` may name a file as: literal, and percent-decoded.

    A relative URI is a URI reference, and a tool may percent-encode it: checkov
    writes ``out(1)/x.tf`` as ``out%281%29/x.tf``, which ``sanitize_sarif_paths``
    leaves encoded. Read literally, that text names no file, so a finding in such a
    directory was dropped from a ``--changed-files-only`` report whether or not
    its file had changed. Both readings are tried; the decoded one is left out
    when it is the same text.

    Decoded with ``surrogateescape``: a name that is not UTF-8 is percent-encoded
    byte by byte (``secr%E9t.py`` for latin-1), and the default ``replace``
    handler turned that byte into U+FFFD, a name no file has, so the finding was
    dropped though its file had changed. With ``surrogateescape`` the byte becomes
    the lone surrogate ``\\udce9``, which is the name git and ``os.fsdecode`` give
    the file, so the reading resolves to it.
    """
    texts = [uri]
    if uri.startswith("file://"):
        host, path = _split_file_uri(uri)
        texts = [_file_uri_path(uri)]
        # An unencoded ``#`` or ``?`` can be part of a name (``My#Proj/a.cs``), and
        # the reduction above cuts the path there; the whole path is read too.
        whole = _without_drive_slash(path)
        if whole not in texts:
            texts.append(whole)
        # ``file://lib/helper.js`` is not a standard URI, but a scanner writes it for
        # a path relative to the scan root, and then "lib" is a directory, not a host.
        # Both are read, host and relative: the result is kept when either names a
        # changed file, so no tool's spelling is dropped for the other's.
        if host:
            texts.append(uri[len("file://") :])
    readings: List[str] = []
    for text in texts:
        for reading in (text, unquote(text, errors="surrogateescape")):
            if reading not in readings:
                readings.append(reading)
    return readings


def _filesystem_readings(readings: List[str]) -> List[str]:
    """*readings*, plus each one's spelling in the filesystem encoding.

    A percent-encoded byte that is not UTF-8 (``secr%E9t.py`` for latin-1) is
    decoded with ``surrogateescape`` into the lone surrogate ``\\udce9``, the name
    git and ``os.fsdecode`` give the file on a UTF-8 host. On a host whose
    filesystem encoding is a legacy POSIX locale the same file is named
    ``secrét.py``, so the surrogate reading matched nothing and the finding was
    dropped though its file had changed. The bytes of each reading (turned back by
    the same handler) are therefore also read through the codec git's names and
    the changed set are decoded with (``get_scan_set._git_output_codec``: UTF-8
    with ``surrogatepass`` on Windows whatever the filesystem encoding says
    there, the filesystem's own codec elsewhere), not ``os.fsdecode``, which
    differs from it under ``PYTHONLEGACYWINDOWSFSENCODING``.

    Every reading is re-read, not only one that holds a surrogate: a percent-encoded
    name is bytes by definition, and a valid UTF-8 name (``secr%C3%A9t.py``)
    decodes to ``secrét.py`` with no surrogate at all. On a latin-1 host git and
    the changed set name that file ``secrÃ©t.py``, so a re-read limited to
    surrogates dropped the finding of a changed file. The extra spelling can only
    keep a finding it would otherwise drop (an unrelated changed file with the
    same mojibake name), which is the safe side for a filter of findings.

    A spelling equal to an earlier one is left out, so a UTF-8 host sees the
    readings it did before; a text that cannot be re-encoded (a lone surrogate
    outside the escape range) adds none, and neither does one the codec cannot
    decode (``surrogatepass`` refuses a byte that is not UTF-8), rather than that
    one location raising out of the filter and failing the scan.
    """
    from automated_security_helper.utils.get_scan_set import _git_output_codec

    encoding, errors = _git_output_codec()
    spellings = list(readings)
    for reading in readings:
        try:
            spelling = reading.encode("utf-8", "surrogateescape").decode(
                encoding, errors
            )
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        if spelling not in spellings:
            spellings.append(spelling)
    return spellings


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


def _converted_source(
    converted: str, converted_sources: Mapping[str, str]
) -> Optional[str]:
    """The source *converted* was converted from, by *converted_sources*, or None.

    The mapping is what the converters recorded
    (``utils.scan_output_dirs.record_converted_sources``): a file's own path, or a
    directory's with a trailing ``/`` for every file below it, as an extracted
    archive's members are all from the one archive. The file's own entry wins;
    else the nearest directory entry above it.
    """
    source = converted_sources.get(converted)
    if source is not None:
        return source
    parts = converted.split("/")
    for depth in range(len(parts) - 1, 0, -1):
        source = converted_sources.get("/".join(parts[:depth]) + "/")
        if source is not None:
            return source
    return None


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
    names no file (an empty URI) and one whose location cannot be resolved to a
    path at all (:func:`resolve_uri_reading`), rather than that one location
    raising out of the filter and failing the scan.
    Mutates and returns *results*.

    A result located in a converted file (its ``converted_path`` property is
    set) is placed by the source file the converter read, not by the converted
    file, which sits in the output directory and so is never in the changed set.
    *converted_sources* maps each ``converted_path`` to that source, relative to
    *source_dir* or absolute: the mapping the converters record beside their
    output and the engine reads back (``utils.scan_output_dirs``); a directory
    entry, keyed with a trailing ``/``, covers every file below it
    (:func:`_converted_source`). A converted result whose source no entry names
    (a converter that records none) is kept, and the run says once how many
    were: before this, every finding in a converted file was dropped from a
    ``--changed-files-only`` report, including those from a notebook or archive
    that was in the diff, and nothing said so.

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
                source = _converted_source(converted, converted_sources or {})
                if source is None:
                    unplaced_converted += 1
                    filtered.append(result)
                    continue
                readings = [source]
            else:
                # A URI that names no file (empty, or ``file://`` with no path) places
                # the result nowhere, so it is kept like a result with no location;
                # read as a path it was the source directory itself, which is in the
                # changed set only when every file is.
                readings = [
                    reading
                    for reading in _location_readings(
                        loc.physicalLocation.root.artifactLocation.uri or ""
                    )
                    if reading
                ]
                if not readings:
                    filtered.append(result)
                    continue
            placed = [
                path_in_record_form(resolved)
                for resolved in (
                    resolve_uri_reading(reading, base=Path(source_dir))
                    for reading in _filesystem_readings(readings)
                )
                if resolved is not None
            ]
            if not placed or any(path in recorded_changed for path in placed):
                filtered.append(result)
        discarded += len(run.results) - len(filtered)
        run.results = filtered

    if unplaced_converted and _not_yet_said(results, unplaced_converted):
        ASH_LOGGER.warning(
            "Kept %d finding(s) located in converted files (notebooks, archive "
            "members): no converter recorded the source file each was converted "
            "from, so the changed-file filter cannot tell whether that source "
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
            "no location and every finding it could place was removed (a finding "
            "in a converted file with no recorded source is kept and said above; "
            "one at a location no path resolves is kept without a line). This "
            "report is therefore not evidence that the tree is clean. Either the "
            "diff against --base-ref is empty, or none of the paths it names are "
            "inside --source-dir.",
            discarded,
        )
    return results


def _not_yet_said(results: "AshAggregatedResults", kept: int) -> bool:
    """Whether the kept-converted count is new for *results*; records it if so.

    The scan execution engine narrows the one result model at the end of the scan
    phase and again at the report phase (the filter is idempotent on the
    findings), and a kept converted finding survives both passes, so the same
    count was said twice. The count said is kept on the model as a private
    attribute (``AshAggregatedResults._changed_files_kept_said``, never
    serialized); a model without it is told every time.
    """
    try:
        if getattr(results, "_changed_files_kept_said", None) == kept:
            return False
        results._changed_files_kept_said = kept
    except (AttributeError, ValueError):
        return True
    return True
