"""The read-edge trim drops cut codes, never the diagnostics behind them.

_TRAILING_JUNK's cut-off-OSC branch had an unbounded body that spans
newlines, so when the last ESC in a carried text opened an OSC the pattern
saw no terminator for, everything from that ESC to the end read as "a code
cut off before its end" and was removed. The common shape is an OSC 8
hyperlink ended by the C1 string terminator (U+009C), which the shared
pattern did not accept: every carried stderr or failure excerpt after such a
link was dropped, silently. Nothing leaked; the cost was lost diagnostics.
"""

import pytest

from automated_security_helper.base.plugin_base import trimmed_at_read_edge
from automated_security_helper.utils.error_text import ESCAPE_CODES


def test_a_c1_terminated_hyperlink_is_a_complete_code_everywhere():
    """U+009C ends an OSC for the sinks and the trim alike, so a link a
    terminal-aware tool ends that way is stripped as one code and the text
    behind it is kept."""
    text = "\x1b]8;;https://host\x9cshown text\x1b]8;;\x9c\n" + (
        "diagnostic line\n" * 50
    )

    assert "diagnostic line" in trimmed_at_read_edge(text, ())
    stripped = ESCAPE_CODES.sub("", "A\x1b]8;;https://host\x9cB")
    assert stripped == "AB", repr(stripped)


def test_an_unterminated_osc_far_from_the_edge_keeps_the_text_behind_it():
    """A dangling OSC opener pages before the end is a tool's stray escape,
    not a code the READ cut: the cut-off branch reaches only a bounded body,
    so the diagnostics behind the opener survive the trim."""
    text = "\x1b]zzz " + ("diagnostic line " * 400)
    assert len(text) > 5000  # well past the cut-off body bound

    assert "diagnostic line" in trimmed_at_read_edge(text, ())


def test_an_osc_cut_at_the_read_edge_is_still_trimmed():
    """Must-not-flag control, green before and after: a hyperlink the read
    bound cut before its terminator is exactly the junk the trim exists for."""
    text = "real output \x1b]8;;https://hos"

    assert trimmed_at_read_edge(text, ()) == "real output "


# Four distinct values of 100 down to 97 characters whose 90-character
# prefixes sit back to back at the read edge, LONGEST last so the
# longest-first trim pass meets them in order from the end.
_CHAINED_VALUES = [("KLMN"[n] + "Qv7Wd3Hx" * 13)[: 100 - n] for n in range(4)]
_OSC_LINK = "\x1b]8;;https://docs.example.com/" + "p" * 200 + "\x1b\\"

_CHAIN_FILLERS = {
    "plain-filler": ("-" * 5000, ""),
    "code-filler": ("-\x1b[31m" * 2000, "\x1b[1m"),
    "osc-between": ("-" * 3000, _OSC_LINK),
}


@pytest.mark.parametrize("shape", sorted(_CHAIN_FILLERS))
def test_chained_value_prefixes_at_the_edge_are_all_trimmed(shape):
    """Each trim moves the edge, so after the first trim the walk's original
    window no longer holds the next value's prefix: only re-walking from the
    new edge can see it. A trim that keeps the first walk's view leaves the
    remaining prefixes in the carried text. One cell per filler shape: a
    failure in one shape must not hide the others, and a fix that re-walks
    only for one shape must stay red for the rest."""
    filler, glue = _CHAIN_FILLERS[shape]
    text = filler + glue + glue.join(value[:90] for value in reversed(_CHAINED_VALUES))
    kept = trimmed_at_read_edge(text, _CHAINED_VALUES)
    for value in _CHAINED_VALUES:
        assert value[:12] not in kept, (shape, value[:12], repr(kept[-200:]))
