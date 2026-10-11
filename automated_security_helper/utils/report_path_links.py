# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Refuse to write reports when a link is already at a path a report goes to.

ASH writes each enabled reporter's report to ``reports/ash.<extension>``. Some
reporters write files of their own beside it (the unused-suppressions reporter's
markdown, the S3 reporter's local copy, the Bedrock summary reporter's files), and
a workspace run writes ``reports/workspace-reports.json``. Each of those files is
written by replacing it, so a link at the name is not followed. But if the link
leads out of the reports directory, the write is refused and the link stays where
it is, and whatever reads ``reports/ash.sarif`` afterwards reads the file the link
points to.

So when the reports directory, or one of the files the reporters about to run
write there, is a symlink or a directory junction, the run is refused before any
reporter writes. The names come from the reporters themselves
(``reporter_file_names`` in base/reporter_plugin.py), so a reporter's own files
are covered as soon as it declares them. Called by ReportPhase at its start, by
the workspace report step before a project is scanned and again before it writes,
and by ``ash report`` for the files a reporter writes itself. run_ash_scan also
uses it where ASH reads a report back: container and nix mode before reading the
inner run's results, and ``_compute_exit_code`` before it counts
``reports/ash.sarif``. A ``reports/`` that is itself a link, dangling or not, is
refused before anything creates or clears it (``ensure_reports_dir``, the
orchestrator's directory setup, and container and nix mode before they clear the
output directory).

A report file name (``ash.<extension>``) that is not a single path component,
such as one built from an ``extension`` with a ``/`` or ``..`` in it, refuses the
run too (``refuse_report_names_outside``, ``ReportPathRefused``):
``confined_report_path`` would not write it, and a report the operator asked for
and did not get is a failed run, not a log line. So does such a name among the
files a reporter declares it writes beside its report, which ``write_report_file``
would not write either.
A reporter config built from ``ReporterPluginConfigBase`` never gets there,
because its ``extension`` is replaced by the default when it is not a file name
suffix, and the Bedrock summary reporter's file name options are replaced the same
way (``base/options.py:report_file_name``); a config that skips that validation,
or a reporter that declares a fixed name of its own, does. Links above the reports
directory are not examined here.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable, Optional, Tuple, Union

from automated_security_helper.core.exceptions import ASHValidationError

PathLike = Union[str, "os.PathLike[str]"]

#: Ends every refusal. It suits every caller: the CLI, ``ash report``, ``ash merge``
#: and MCP scans alike.
REMEDY = (
    "ASH does not write a report through a link. Remove the link and run ASH again."
)

# Values from the Windows SDK, for an interpreter whose stat module lacks them.
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_IO_REPARSE_TAG_MOUNT_POINT = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)


#: Ends a refusal of a report file name that is not a file in the reports directory.
NAME_REMEDY = (
    "ASH writes a report only as a file directly inside the reports directory. "
    "Give the reporter an extension that is a file name suffix, such as json."
)

#: Ends a refusal of a file a reporter writes beside its report that is not a file
#: in the reports directory.
COMPANION_NAME_REMEDY = (
    "ASH writes a reporter's files only directly inside the reports directory. "
    "Give that file a plain file name, such as summary.md, in the reporter's "
    "configuration, or disable the reporter."
)


class ReportPathRefused(ASHValidationError):
    """ASH would write a report somewhere other than a file in the reports directory.

    ``found`` describes the path; the message adds the remedy.
    """

    def __init__(self, found: str, remedy: str = NAME_REMEDY):
        self.found = found
        super().__init__(f"{found[0].upper()}{found[1:]}. {remedy}")


class ReportPathLinkRefused(ReportPathRefused):
    """A path ASH would write a report to is a link."""

    def __init__(self, found: str, remedy: str = REMEDY):
        super().__init__(found, remedy)


def _is_junction(path: Path) -> bool:
    """Whether ``path`` is a Windows directory junction.

    os.path.isjunction exists from Python 3.12. Before that, a junction is a reparse
    point whose tag is IO_REPARSE_TAG_MOUNT_POINT; off Windows the fields are absent
    and the answer is False.
    """
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None:
        return bool(isjunction(path))
    try:
        found = os.lstat(path)
    except OSError:
        return False
    attributes = getattr(found, "st_file_attributes", 0)
    tag = getattr(found, "st_reparse_tag", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT) and (
        tag == _IO_REPARSE_TAG_MOUNT_POINT
    )


def link_kind(path: Path) -> Optional[str]:
    """ "a symlink" or "a directory junction" when ``path`` is one, else None."""
    return _link_kind(path)


def _link_kind(path: Path) -> Optional[str]:
    if path.is_symlink():
        return "a symlink"
    if _is_junction(path):
        return "a directory junction"
    return None


def is_report_file_name(name: object) -> bool:
    """Whether ``name`` is a single path component, the only kind of name ASH writes."""
    return (
        isinstance(name, str)
        and name not in ("", ".", "..")
        and not any(part in name for part in ("/", "\\", "\x00"))
    )


def linked_report_path(report_dir: PathLike, names: Iterable[str]) -> Optional[str]:
    """Describe the first link ASH would write a report through, or None.

    Examined when at least one of ``names`` is a file name: the reports directory
    itself, then ``report_dir / name`` for each of them, in order.
    """
    directory = Path(report_dir)
    entries = [
        directory / name for name in dict.fromkeys(names) if is_report_file_name(name)
    ]
    if not entries:
        return None
    kind = _link_kind(directory)
    if kind is not None:
        return f"the reports directory {directory.as_posix()} is {kind}"
    for entry in entries:
        kind = _link_kind(entry)
        if kind is not None:
            return f"{entry.as_posix()} is {kind}"
    return None


def refuse_linked_report_paths(
    report_dir: PathLike, names: Iterable[str], remedy: str = REMEDY
) -> None:
    """Raise ReportPathLinkRefused if a report would be written through a link.

    See linked_report_path for what is examined.
    """
    found = linked_report_path(report_dir, names)
    if found is not None:
        raise ReportPathLinkRefused(found, remedy)


def refuse_a_linked_reports_dir(report_dir: PathLike) -> None:
    """Raise ReportPathLinkRefused if the reports directory itself is a link.

    Before the directory is created: ``mkdir`` on a dangling link fails with
    ``FileExistsError``, which would report a crash instead of the refusal.
    """
    directory = Path(report_dir)
    kind = _link_kind(directory)
    if kind is not None:
        raise ReportPathLinkRefused(
            f"the reports directory {directory.as_posix()} is {kind}"
        )


def ensure_reports_dir(report_dir: PathLike) -> Path:
    """Create the reports directory, after refusing it if it is a link.

    ``mkdir`` on a dangling link fails with ``FileExistsError``, and on a link to a
    directory succeeds and keeps the link, so creating the directory first would end
    in a crash or a write through the link instead of the refusal. Every place that
    sets up ``reports/`` for a run creates it through this.
    """
    directory = Path(report_dir)
    refuse_a_linked_reports_dir(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def refuse_report_names_outside(
    report_dir: PathLike,
    names: Iterable[str],
    companions: Iterable[Tuple[str, str]] = (),
) -> None:
    """Raise ReportPathRefused if a file a reporter would write is not a file name.

    ``names`` are the reporters' report files (``reporter_file_name``), which
    ``ReportPhase`` writes. ``companions`` are ``(reporter, name)`` pairs for the
    files each reporter declares it writes itself beside its report
    (``reporter_companion_file_names``), which ``write_report_file`` would refuse
    to write. Either kind refuses the run, before any reporter writes.
    """
    directory = Path(report_dir).as_posix()
    for name in names:
        if not is_report_file_name(name):
            raise ReportPathRefused(
                f"the report file name {name!r} is not a file in {directory}"
            )
    for reporter, name in companions:
        if not is_report_file_name(name):
            raise ReportPathRefused(
                f"the file name {name!r} that the {reporter} reporter writes beside "
                f"its report is not a file in {directory}",
                COMPANION_NAME_REMEDY,
            )
