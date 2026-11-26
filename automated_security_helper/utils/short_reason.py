"""What makes a sentence fit to be shown as the reason a scanner failed.

A report can be posted where the paths of the machine that ran the scan, and the
text of the tool's own output, should not be. So the one line a report shows for
a scanner that ended in ERROR is held to a single rule, kept here so that the
type that records it (``core/exceptions.py``) and the reports that show it
(``plugin_modules/ash_builtin/reporters``) read the same one: the line is text
that is one printable line, not empty, at most :data:`SHORT_REASON_LIMIT`
characters, and with nothing in it that looks like a path on the local machine.

Standard library only. ``core/exceptions.py`` imports this module, and the
package import has to stay free of third-party modules.
"""

import re

#: The longest reason shown; a longer sentence is not a short reason.
SHORT_REASON_LIMIT = 200

#: Anything that looks like a path on the machine that ran the scan: a POSIX
#: absolute path, a home-relative one, a drive path or a UNC path, at the start of
#: the text or after a space, a quote or an equals sign.
LOCAL_PATH = re.compile(r"(?:\A|[\s'\"=])(?:/|~/|[A-Za-z]:[\\/]|\\\\)")


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
