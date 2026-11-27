"""What makes a sentence fit to be shown as the reason a scanner failed.

A report can be posted where the paths of the machine that ran the scan, and the
text of the tool's own output, should not be. So the one line a report shows for
a scanner that ended in ERROR is held to a single rule, kept here so that the
type that records it (``core/exceptions.py``) and the reports that show it
(``plugin_modules/ash_builtin/reporters``) read the same one: the line is text
that is one printable line, not empty, at most :data:`SHORT_REASON_LIMIT`
characters, and with nothing in it that looks like a path on the local machine.

The reading of a recorded failure down to its first sentence
(:func:`short_error_reason`) is here too. The reports use it for an error nobody
gave a reason, and the unified metrics use it to know whether such an error
already has a sentence to show, so that a sentence made from the target counts
does not take its place; ``core`` cannot import a report plugin, so both read it
from here.

Standard library only. ``core/exceptions.py`` imports this module, and the
package import has to stay free of third-party modules.
"""

import re

#: The longest reason shown; a longer sentence is not a short reason.
SHORT_REASON_LIMIT = 200

#: Anything that looks like a path on the machine that ran the scan: a POSIX
#: absolute path, a home-relative one, a drive path or a UNC path, at the start of
#: the text or after a space, a quote, an equals sign, an opening bracket or
#: parenthesis, a backtick, a less-than sign or a comma. Not after a colon, which
#: would refuse every URL ("https://...").
LOCAL_PATH = re.compile(r"(?:\A|[\s'\"=(\[`<,])(?:/|~/|[A-Za-z]:[\\/]|\\\\)")


def names_a_local_path(text: str) -> bool:
    """Whether ``text`` holds something that looks like a local path."""
    return LOCAL_PATH.search(text) is not None


def is_short_reason(text: object) -> bool:
    """Whether ``text`` may be shown as the reason a scanner failed.

    It has to be a string that is not blank, fits :data:`SHORT_REASON_LIMIT`, is
    one printable line (no line break and no control character, which
    ``str.isprintable`` also refuses for the Unicode line separators and a lone
    surrogate), and names no local path.
    """
    return (
        isinstance(text, str)
        and bool(text.strip())
        and len(text) <= SHORT_REASON_LIMIT
        and text.isprintable()
        and not names_a_local_path(text)
    )


#: The prefix the scan phase gives a scanner's failure: ``Failed to execute
#: <scanner> scanner on <target>: `` and, for a failure of the scan itself,
#: ``<ScannerClass> scan failed: ``.
_FAILURE_PREFIX = re.compile(r"\AFailed to execute .+? scanner on [^:]+: ")
_SCAN_FAILED_PREFIX = re.compile(r"\A[A-Za-z0-9_]+ scan failed: ")
#: A parenthetical aside, innermost first; asides hold paths, exit-code details
#: and the launch command.
_ASIDE = re.compile(r"\s*\([^()]*\)")
#: Where the first sentence ends: a full stop, a colon or a semicolon before a
#: space, or the end of the text.
_SENTENCE_END = re.compile(r"[.:;](?:\s|\Z)|\Z")


def short_error_reason(error: str) -> str | None:
    """The first sentence of a scanner's recorded failure, for a report, or None.

    ``Failed to execute checkov scanner on source: CheckovScanner scan failed:
    its tool (launched through ...) exited with code 2, which this scanner does
    not accept as a completed run, so its results file is not graded (exit code
    2: ...). Stderr not read: ...`` gives ``its tool exited with code 2, which
    this scanner does not accept as a completed run, so its results file is not
    graded``.

    Only a message that opens with the scan phase's prefix is read. The asides in
    parentheses are removed, and the text is cut at the end of its first
    sentence, so the stderr, the log paths and validation details that follow it
    are never shown. A result that is not a short reason (:func:`is_short_reason`:
    empty, longer than :data:`SHORT_REASON_LIMIT`, more than one printable line,
    or something that looks like a local path) or still holds a parenthesis gives
    None: the report then names the scanner in the table only, as it did before.
    """
    match = _FAILURE_PREFIX.match(error)
    if match is None:
        return None
    body = _SCAN_FAILED_PREFIX.sub("", error[match.end() :], count=1)
    previous = None
    while previous != body:
        previous, body = body, _ASIDE.sub("", body)
    end = _SENTENCE_END.search(body)
    sentence = body[: end.start() if end else len(body)].strip()
    if not is_short_reason(sentence) or "(" in sentence or ")" in sentence:
        return None
    return sentence
