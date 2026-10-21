"""Every escape regex in the package strips what the shared pattern strips.

error_text.ESCAPE_CODES is the one escape pattern the sinks, the uv layers,
the mixin's cause match and the read-edge trim read, so no side strips a code
another keeps. The two module-level copies -- pre_installed_tool.ANSI_ESCAPE
(color-only) and npm_audit_scanner's CSI-only pattern -- kept narrower sets,
and _dry_run's cause match repeated the defect the mixin's offline explainer
fixed: a non-color escape inside uv's resolver phrase turned "unsatisfied"
into "unverifiable".
"""

from types import SimpleNamespace

from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
)
from automated_security_helper.utils import error_text, pre_installed_tool

#: One probe per escape family a narrower pattern kept: SGR color, a
#: non-color CSI (erase line), a colon-form SGR, a private-mode code, an
#: intermediate-byte code, and an OSC hyperlink.
_PROBES = (
    "\x1b[31mred\x1b[0m",
    "\x1b[2K",
    "\x1b[38:5:196m",
    "\x1b[?25l",
    "\x1b[2 q",
    "\x1b]8;;https://host\x1b\\",
)


def test_the_module_level_escape_patterns_strip_what_the_shared_one_strips():
    for probe in _PROBES:
        text = f"EDGE{probe}TAIL"
        expected = error_text.ESCAPE_CODES.sub("", text)
        assert pre_installed_tool.ANSI_ESCAPE.sub("", text) == expected, repr(probe)
        assert npm_audit_scanner._ANSI_ESCAPE.sub("", text) == expected, repr(probe)


def test_a_dry_run_cause_match_survives_a_non_color_escape(monkeypatch):
    """An erase-line code inside uv's "No solution found when resolving"
    phrase must not turn "unsatisfied" into "unverifiable"."""
    answer = SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="No solution\x1b[2K found when resolving qtool==9.9",
    )
    monkeypatch.setattr(pre_installed_tool, "_run", lambda command, timeout: answer)

    status, detail = pre_installed_tool._dry_run("uv", "python3", "qtool==9.9")

    assert status == "unsatisfied", (status, detail)
    assert "\x1b[" not in detail, detail


def test_a_colored_resolver_phrase_still_reads_unsatisfied(monkeypatch):
    """Must-not-flag control, green before and after the shared pattern."""
    answer = SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="\x1b[31mNo solution found when resolving qtool==9.9\x1b[0m",
    )
    monkeypatch.setattr(pre_installed_tool, "_run", lambda command, timeout: answer)

    status, _detail = pre_installed_tool._dry_run("uv", "python3", "qtool==9.9")

    assert status == "unsatisfied"


def test_the_yarn_version_reads_through_a_hyperlink():
    """A terminal-aware yarn wraps its version answer in an OSC hyperlink;
    the version probe must still read the major."""
    wrapped = "\x1b]8;;https://yarnpkg.com\x1b\\1.22.19\x1b]8;;\x1b\\"
    assert NpmAuditScanner._yarn_major(wrapped) == 1


def test_error_text_keeps_no_second_color_only_pattern():
    """The color-only SGR pattern was unused and its comment stale; one
    shared pattern means no second public name to drift."""
    assert not hasattr(error_text, "SGR_CODES")
    assert not hasattr(error_text, "_SGR_CODES")
