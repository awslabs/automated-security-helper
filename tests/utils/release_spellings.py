"""What a page, a template or a plugin names that ASH 3.8 does not read, and since when.

Four tests hold the docs and the agent plugins to the command spellings of the release
they pin (tests/unit/test_version_template_release_spellings.py,
test_docs_pinned_pages_spelling.py, test_docs_site_release_spellings.py and
test_agent_plugin_scan_spellings.py), and a fifth reads the deprecated ones
(test_docs_no_legacy_spellings.py). Each used to carry its own copy of the pattern, the
release threshold and the verb list, so a verb added to one copy never reached the
others. They import this module, and test_version_template_release_spellings.py holds
it to scripts/version_template_manager.py, which keeps its own list of what to rewrite.

The patterns read a command the way a shell and a list of arguments write it:
``ash scan fs .``; ``ash \\`` with ``scan fs .`` on the next line; and
``["ash", "scan", "fs", "."]``, which may put each item on a line of its own.
"""

from __future__ import annotations

import re

#: The first release whose CLI reads the spellings below: ``ash scan fs``,
#: ``ash results <verb>``, ``ash container build``, and the scanner options
#: ``--only-scanners`` and ``--add-scanners``.
SUBJECTS_RELEASE = (3, 9, 0)

#: What ``ash scan`` can be told to scan once the subjects exist. ``workspace``, ``image``
#: and ``git`` are no subjects in 3.8, so a page pinned to 3.8 must not name them as
#: subjects. A workspace is ``ash scan --workspace FILE`` there, and a render for 3.8
#: writes it that way (scripts/version_template_manager.py).
SCAN_SUBJECTS = ("fs", "workspace", "image", "git")

#: The commands 3.9 moved under ``ash results`` that 3.8.0 has as top-level commands
#: (``ash report``, ``ash merge``, ``ash inspect``). A page that pins 3.8 spells them that
#: way, and a render for 3.8 writes it.
RESULTS_VERBS_MOVED = ("report", "merge", "inspect")

#: The commands 3.9 added under ``ash results``. 3.8.0 has neither of them, and no
#: release has had either as a top-level command (``ash diff``, ``ash trend``), so there
#: is no older spelling to write. A page that pins a release before 3.9 cannot name them
#: at all, in either form, and the render leaves them as they are.
RESULTS_VERBS_ADDED = ("diff", "trend")

#: Every command under ``ash results`` in 3.9.
RESULTS_VERBS = (*RESULTS_VERBS_MOVED, *RESULTS_VERBS_ADDED)

#: What separates two words of one command: blanks, a backslash that ends a line (a
#: blank must still stand beside it: ``ash\`` and ``scan`` on the next line are one
#: word), or the quotes and comma between two items of a list of arguments, which may
#: put each item on a line of its own.
WORD_GAP = r"""(?:(?:\\\r?\n)*[ \t](?:[ \t]|\\\r?\n)*|["'][ \t]*,\s*["'])"""

_SUBJECTS = "|".join(SCAN_SUBJECTS)
_VERBS = "|".join(RESULTS_VERBS)
_ADDED_VERBS = "|".join(RESULTS_VERBS_ADDED)

#: A spelling that ASH 3.8 does not read. ``ash diff`` and ``ash trend`` are in it
#: although no release has them: a page beside a pin before 3.9 that names one gives
#: its reader a command that is not there, and the older spelling of ``ash results
#: diff`` that a render could write instead does not exist.
NEWER_SPELLING = re.compile(
    rf"(?<![\w./-])ash(?:v3)?{WORD_GAP}(?:"
    rf"scan{WORD_GAP}(?:{_SUBJECTS})(?![\w-])"
    rf"|results{WORD_GAP}(?:{_VERBS})(?![\w-])"
    rf"|(?:{_ADDED_VERBS})(?![\w-])"
    rf"|container{WORD_GAP}build(?![\w-])"
    r")"
)

#: The scanner-selection options ASH 3.8 does not read. It has ``--scanners``, which 3.9
#: deprecates in favor of these two.
NEWER_OPTION = re.compile(r"(?<![\w-])--(?:only|add)-scanners(?![\w-])")

#: The same two options, inside an ``ash scan`` command: where a sentence that names a
#: flag says the flag, whatever release the page pins, only a command is a spelling.
NEWER_SCANNER_FLAG = re.compile(
    rf"(?<![\w./-])ash(?:v3)?{WORD_GAP}scan(?![\w-])(?:\\\n|[^\n;&|`)\]])*?"
    r"(?<![\w-])--(?:only|add)-scanners(?![\w-])"
)

#: ``ash scan`` with no subject after it: the spelling 3.9 deprecates. The workspace and
#: image forms keep their option spellings until their subjects exist, so a command that
#: names one of those options is not this.
SUBJECTLESS_SCAN = re.compile(
    rf"(?<![\w./-])ash(?:v3)?{WORD_GAP}scan(?![\w-])"
    rf"(?!{WORD_GAP}(?:{_SUBJECTS})(?![\w-]))"
    r"(?![^\n`]*--(?:workspace|image|source-git))"
)


def release_tuple(version: str) -> tuple[int, int, int]:
    """``3.8.0`` or ``v3.8.0`` as ``(3, 8, 0)``."""
    major, minor, patch = (int(part) for part in version.lstrip("v").split(".")[:3])
    return major, minor, patch
