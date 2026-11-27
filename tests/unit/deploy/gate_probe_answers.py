"""How a stand-in for a CodeCommit gate's subprocess runner answers its help probes.

Before it scans, each gate asks the image's ASH how it scans a directory and whether
it can fail an incomplete scan. ``ash scan fs --help`` comes first: ASH 3.9 and later
name the subject (``ash scan fs PATH``) and print a deprecation line for the
subject-less ``ash scan --source-dir PATH``. Only an ASH with the subject prints
``scan fs`` in that help. An older ASH shows the subject-less scan's own help for it,
since click reads ``--help`` before it refuses the extra argument, and the gate then
asks ``ash scan --help``. Both are probes, not scans, so a stand-in answers them and
records only the rest.

``RELEASE_WITH_SUBJECT`` is how this tree's ASH answers. ``RELEASE_WITHOUT_SUBJECT``
is how ASH 3.8 and earlier answer.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Optional

FLAG = "--fail-on-incomplete-scanners"
FLAG_LINE = f"  {FLAG} / --no-fail-on-incomplete-scanners\n"

RELEASE_WITH_SUBJECT = "with-subject"
RELEASE_WITHOUT_SUBJECT = "without-subject"

#: ``ash scan fs --help`` from an ASH with the subject. Its ``ash scan --help`` is
#: the same text: the subject-less form shows the subject's help.
FS_HELP = "Usage: ash scan fs [OPTIONS] [PATH]\n  --output-dir PATH\n" + FLAG_LINE

#: ``ash scan --help`` from an ASH without the subject, which also answers
#: ``ash scan fs --help`` with it.
SUBJECTLESS_HELP = "Usage: ash scan [OPTIONS]\n  --source-dir PATH\n" + FLAG_LINE

FS_PROBE = ["ash", "scan", "fs", "--help"]
SCAN_PROBE = ["ash", "scan", "--help"]


def answer(argv, release: str = RELEASE_WITH_SUBJECT) -> Optional[SimpleNamespace]:
    """The answer to a help probe, or None when *argv* is not one."""
    argv = list(argv)
    if argv not in (FS_PROBE, SCAN_PROBE):
        return None
    if release == RELEASE_WITH_SUBJECT:
        text = FS_HELP
    elif release == RELEASE_WITHOUT_SUBJECT:
        text = SUBJECTLESS_HELP
    else:
        raise ValueError(f"unknown release {release!r}")
    return SimpleNamespace(returncode=0, stdout=text, stderr="")


def fs_arguments(argv) -> list[str]:
    """What the ``fs`` subject parses from a gate's scan argv, in either form.

    ``ash scan fs PATH ...`` hands ``fs`` everything after its name, and the
    subject-less ``ash scan --source-dir PATH ...`` runs as ``fs`` with everything
    after ``scan``. So either argv resolves through ``commands["scan"].commands["fs"]``.
    """
    argv = list(argv)
    if argv[:3] == ["ash", "scan", "fs"]:
        return argv[3:]
    assert argv[:2] == ["ash", "scan"], f"unexpected argv prefix: {argv[:3]}"
    return argv[2:]
