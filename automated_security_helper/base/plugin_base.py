"""Module containing the PluginBase class."""

from bisect import bisect_left
from contextvars import ContextVar
from datetime import datetime
import logging
import os
import re
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from automated_security_helper.base.plugin_config import PluginConfigBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.uv_tool_mixin import (
    UVToolMixin,
    guarded_values,
    guarded_values_read,
)
from automated_security_helper.core.enums import PackageManager
from automated_security_helper.core.exceptions import (
    ScannerError,
    ToolNotProvisionableError,
)
from automated_security_helper.utils.error_text import ESCAPE_CODES as _ESCAPE_CODES
from automated_security_helper.utils.error_text import (
    config_environment_values,
    error_text,
    redact_then_split,
    shown_tool_stderr,
    text_without_values,
    timeout_limit_token,
    traceback_text,
)
from automated_security_helper.utils.uv_tool_runner import (
    spelled_forms as _spelled_forms,
)
from automated_security_helper.utils.log import ASH_LOGGER, MARKUP, escape_markup
from automated_security_helper.utils.offline_tool_env import (
    with_offline_tool_environment,
)
from automated_security_helper.utils.redacted_model import (
    NO_RICH_REPR,
    carry_environment_values,
)
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.terminal_text import as_written
from automated_security_helper.utils.python_installer import (
    python_package_install_command as _python_package_install_command,
)
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    RESPONSE_FLAGS,
    WAS_KILLED_ENDING,
    could_not_stop_default,
    exit_status,
    flagged_returncode,
    is_exit_code,
    response_could_not_stop,
    signal_ending,
)


class PluginDependency(BaseModel):
    name: str
    version: str = "latest"
    package_manager: PackageManager = PackageManager.APT


# Version strings starting with one of these are PEP 440 specifiers (a range),
# not a single version.
_VERSION_SPECIFIER_START = ("<", ">", "!", "~", "=")


def pep440_requirement(name: str, version: str) -> str:
    """Render ``name`` and ``version`` as one pip/uv requirement string.

    ``version`` is interpreted three ways:

    - ``"latest"`` -- no constraint, so the resolver takes the newest release.
    - a PEP 440 specifier such as ``">=0.1.0,<2.0.0"`` -- passed through verbatim.
    - a bare version such as ``"1.2.3"`` -- pinned exactly, with ``==``.

    The middle case is why this helper exists. Rendering every non-``latest``
    version as ``f"{name}=={version}"`` turns a range into a requirement pip
    cannot parse (``ferret-scan==>=0.1.0,<2.0.0``), so a plugin that declared a
    supported *range* had no way to get it honoured. The observable failure was
    not an error, which is what made it expensive: the range went undeclared,
    the installer fell back to "latest", and CI installed whichever release
    happened to be newest at the moment the job ran. ferret-scan 2.3.3 was
    published mid-run on 2026-08-20 and turned every open PR red without a
    single source change.

    Only pip and uv use this. apt, npm, brew, yum and choco all spell ranges
    differently, and guessing a translation between them would trade a loud
    failure for a quiet mis-install.
    """
    if version == "latest":
        return name
    if version.startswith(_VERSION_SPECIFIER_START):
        return f"{name}{version}"
    return f"{name}=={version}"


def _versioned(dep: "PluginDependency", separator: str) -> str:
    """Render ``name<separator>version``, or bare ``name`` for ``"latest"``.

    The separator is the package manager's own spelling of a pin: ``=`` for apt
    and conda, ``@`` for npm and brew, ``-`` for yum. Ranges are not translated
    between managers -- see ``pep440_requirement`` for why.
    """
    if dep.version == "latest":
        return dep.name
    return f"{dep.name}{separator}{dep.version}"


#: How each package manager's dependencies are rendered into one argv.
#:
#: A mapping rather than an ``if``/``elif`` chain so the set of handled members is a
#: value this module can compare against ``PackageManager`` -- see
#: ``_UNRENDERED_PACKAGE_MANAGERS``. The chain this replaced covered eight of the ten
#: members and ended without an ``else``, so a plugin declaring ``package_manager:
#: conda`` produced an empty command list, the installer reported success, and the
#: scanner turned up MISSING at scan time with nothing naming the cause.
_INSTALL_COMMAND_BUILDERS: Dict[
    PackageManager, Callable[["PluginDependency"], List[str]]
] = {
    PackageManager.APT: lambda dep: [
        "apt-get",
        "install",
        "-y",
        _versioned(dep, "="),
    ],
    # Into the environment running ASH, with pip or uv, whichever owns it.
    PackageManager.PIP: lambda dep: _python_package_install_command(
        [pep440_requirement(dep.name, dep.version)]
    ),
    PackageManager.UV: lambda dep: [
        "uv",
        "tool",
        "install",
        pep440_requirement(dep.name, dep.version),
    ],
    # conda pins with a single `=`, the same spelling apt uses. A real command rather
    # than a refusal because "conda" is a published, user-facing value: it is in the
    # generated AshConfig schema, so a custom plugin may already declare it, and such a
    # plugin means `conda install` -- rejecting the member would break a documented
    # input while installing it is what the author asked for.
    PackageManager.CONDA: lambda dep: [
        "conda",
        "install",
        "-y",
        _versioned(dep, "="),
    ],
    PackageManager.NPM: lambda dep: [
        "npm",
        "install",
        "-g",
        _versioned(dep, "@"),
    ],
    PackageManager.BREW: lambda dep: [
        "brew",
        "install",
        _versioned(dep, "@"),
    ],
    PackageManager.YUM: lambda dep: [
        "yum",
        "install",
        "-y",
        _versioned(dep, "-"),
    ],
    # choco's version pin is its own argv element. Argv elements do not
    # word-split, so a pin rendered inside the package-name element
    # ("tool --version=1.2") was looked up as a package of that name, the
    # install failed, and the pin was never applied.
    PackageManager.CHOCO: lambda dep: [
        "choco",
        "install",
        "-y",
        dep.name,
        *([f"--version={dep.version}"] if dep.version != "latest" else []),
    ],
}

#: Members that intentionally render no command, each for a stated reason.
#:
#: URL downloads are performed by ``download_utils`` through a plugin's
#: ``custom_install_commands``, and ``CUSTOM`` says only "not one of the managers
#: above" -- it carries no package name a command could be built from, so its
#: commands also live in ``custom_install_commands``. Both are listed here so that
#: "renders nothing" is a recorded decision rather than a missing branch.
_NO_INSTALL_COMMAND_PACKAGE_MANAGERS = frozenset(
    {
        PackageManager.URL,
        PackageManager.CUSTOM,
    }
)

#: Every PackageManager member that is neither rendered nor deliberately skipped.
#:
#: Derived, not listed, so it cannot drift from the enum. It must stay empty: a new
#: member added without either a builder or an entry above lands here, and
#: ``tests/unit/base/test_install_command_dispatch_is_exhaustive.py`` fails on it.
#: That test is the mechanism -- without it a new member would reach
#: ``get_installation_commands`` and raise there, which is loud but only for whoever
#: happens to run that plugin.
_UNRENDERED_PACKAGE_MANAGERS = (
    frozenset(PackageManager)
    - frozenset(_INSTALL_COMMAND_BUILDERS)
    - _NO_INSTALL_COMMAND_PACKAGE_MANAGERS
)


#: The package managers whose dependencies are Python packages, for
#: ``PluginBase.is_python_only``: ``pip install`` and ``uv tool install`` both
#: install from a Python package index.
_PYTHON_PACKAGE_MANAGERS = frozenset({PackageManager.PIP, PackageManager.UV})


#: What a timeout message names in place of the limit's number: the token
#: ``error_text.timeout_limit_token`` gives when an environment value typed the
#: limit, used when the values hook could not be read.
_LIMIT_TOKEN_WITHOUT_A_NUMBER = "the configured scan_timeout"


#: The most of a run's stderr log _run_subprocess reads back into a post-run
#: response. Past it the text ends " ...[truncated]", as a failure's stderr
#: excerpt does (scanner_plugin._STDERR_EXCERPT_LIMIT); the log keeps it all.
_STDERR_LOG_READ_LIMIT = 1 << 20


#: One piece of tail junk a cut can leave or hide behind: a run of
#: replacement characters, a complete escape code (error_text.ESCAPE_CODES,
#: the one CSI-plus-OSC pattern the sinks strip -- the trim MUST read the
#: same set, or a code one side strips and the other keeps re-joins a split
#: value in clear), a lone ESC, or a code cut off before its end: a CSI cut
#: before its final byte, or an OSC cut before its terminator.
#: ONE token per match, anchored at the end: a single `(junk)+\Z` sub over
#: the whole text backtracked combinatorially, because a complete color
#: code parsed under two branches -- a 64 KB log that was mostly color
#: codes hung the scan on that regex (measured by this fix's red cell).
#: The cut-off-OSC body is BOUNDED: only a read's edge makes a cut-off code,
#: so a real one sits within a code's length of the end. Unbounded, and with
#: a body that spans newlines, a stray OSC opener anywhere made everything
#: behind the text's last unterminated ESC-] read as "a code cut off before
#: its end", and megabytes of carried diagnostics were dropped for one
#: dangling opener (the body also excludes U+009C, an OSC terminator the
#: shared pattern accepts, so a C1-ended hyperlink is a complete code and
#: never this branch's).
_TRAILING_JUNK = re.compile(
    rf"(?:�+|{_ESCAPE_CODES.pattern}|\x1b(?:\[[0-?]*[ -/]*|\][^\x07\x1b\x9c]{{0,4096}})?)\Z"
)


def _spellings_pattern(folded_forms: Sequence[str]) -> "re.Pattern[str]":
    """One pattern that finds every occurrence of any of ``folded_forms``.

    A lookahead alternation, the shape ``config_validator.redact_values`` finds
    occurrences with: a zero-width match at every position where some form
    starts, so occurrences that overlap one another (or themselves) are all
    found, and group 1 holds the form that matched. The alternatives keep the
    order they are given in, longest first, so at one position the longest
    form is the one found; a shorter form there lies inside it and settles
    nothing the longer one does not.
    """
    alternatives = "|".join(re.escape(form) for form in folded_forms)
    return re.compile(f"(?=({alternatives}))")


def _overlap_run_start(
    pattern: "re.Pattern[str]", plain_folded: str, kept: int, stop: int
) -> int:
    """Where the run of overlapping occurrences that ``kept`` falls inside
    starts, or ``kept`` itself when no occurrence runs through it.

    ``pattern`` is :func:`_spellings_pattern` over the forms and
    ``plain_folded`` the text it is matched in. ``stop`` is how far to look: an
    occurrence that starts before ``kept`` ends before ``kept`` plus the
    longest form's length, so ``kept + longest - 1`` (or the text's end) takes
    in every occurrence that can run through ``kept``.

    One pass over the occurrences that start before ``kept``, in order of
    start. A run is a stretch the occurrences cover without a gap: an
    occurrence that starts before the run's end joins it, and one that starts
    where the run ends (touching, not overlapping) begins the next run. The
    cut is inside the last run when that run ends past it, and then every
    position of the run lies inside some occurrence, so no position short of
    the run's start is a place to cut. That is the answer the one-step-at-a-
    time walk back across spanning occurrences reached, found without the
    steps: the work is linear in ``stop`` plus the occurrences, at most one
    per position, however the forms overlap one another or themselves.
    """
    run_start = run_end = 0
    for match in pattern.finditer(plain_folded, 0, stop):
        begin, end = match.span(1)
        if begin >= kept:
            break
        if begin >= run_end:
            run_start = begin
        if end > run_end:
            run_end = end
    return run_start if run_end > kept else kept


def trimmed_at_read_edge(
    text: str, values: Iterable[str], inputs: Iterable[str] = ()
) -> str:
    """Drop from ``text``'s tail anything a bound-cut read could have split.

    A bounded read can split a quoted env-read value at its edge, and the
    sinks that redact the text match whole spellings, so a split tail would
    survive them. Bytes past the bound were never read, which is why no
    redact-before-cut order exists for a read edge: instead the cut SHRINKS,
    and a trailing piece that is a prefix of any value's printable spelling
    goes with the rest of the cut text. The cut can also land inside a
    multibyte character (a U+FFFD after ``errors="replace"``) or inside an
    escape code the tool wrapped the value in; both are stripped from the
    tail first so the prefix right behind them is still seen. The trailing
    strip takes any complete CSI code -- the SAME ECMA-48 set the sinks
    strip -- plus a lone ESC and a code cut off before its final byte,
    which no sink removes: either kind of tail junk hides the value
    fragment right behind it.

    The forms are computed once, per value, not per trim. Each form is
    checked ONCE, longest first, against the end the earlier forms left: a
    trim moves the end, so a later form meets the piece an earlier trim
    exposed, and the number of trims is bounded by the number of forms. A
    tail that already ends with a COMPLETE spelling is left alone: the sinks
    redact whole spellings, so the value there is already covered, and
    trimming a shorter form's one-character prefix off its end turned a
    redactable value into a partial no sink could match.

    After that pass the cut moves left only across a complete spelling that
    the walked tail holds whole and the cut runs through (a shorter form's
    one-character prefix trimmed the last character of a longer value that
    was complete at the end). Text past a cut was read, so a proper prefix
    left at the new end is not a split value; a whole spelling cut in two is
    the piece no sink can match. Every occurrence of every form in the walked
    tail is found in ONE pass (:func:`_overlap_run_start`), and the cut goes
    to the start of the run of overlapping occurrences it falls inside: each
    position between that start and the cut lies inside some complete
    spelling, so none is a place to cut. The work is linear in the walked
    tail plus its occurrences (at most one per position), however the forms
    overlap one another.

    What goes with the cut depends on whether a spelling overlaps ITSELF. A
    tail that is a long run of one value's first character loses that one
    character when no spelling repeats it, because the one-character cut runs
    through no complete spelling. A spelling that repeats itself ("aaa", a
    placeholder such as "********") starts a complete occurrence at every
    position of such a run, so the run is ONE run of overlapping occurrences
    and all of it goes, up to the read limit: any shorter cut would leave the
    front of a spelling the read held whole in clear in front of the cut. The
    text in front of the run stays.
    """
    # One junk token stripped per pass, each found inside a short window
    # ending at the current end (a token the window cannot hold whole is
    # left for the code-skipping walk below). See _TRAILING_JUNK for why
    # this is a loop and not one `(junk)+\Z` sub. The loop tracks an END
    # INDEX and slices once at the bottom: slicing the string on every pass
    # copied up to O(tokens x text) bytes -- about 13 GB for a 64 KB tail of
    # color codes, seconds of CPU at _carry_stderr_log's 1 MiB bound. With
    # ``endpos`` set, ``\Z`` matches at ``end``.
    end = len(text)
    while end:
        cut = _TRAILING_JUNK.search(text, max(0, end - 128), end)
        if cut is None:
            # A single code longer than the window straddles it, so the
            # windowed search cannot see the code's start. One rfind to the
            # last ESC and one anchored search from there catches it,
            # complete or cut short, without giving the loop back its
            # O(tokens x text) passes: a match starting inside the window
            # was already excluded, so this fires at most once per
            # over-long code, and once at the loop's end.
            # ANCHORED at the ESC (match, not search): the code this looks
            # for starts there. An unanchored search tried the pattern at
            # every position between the ESC and the end, and the
            # replacement-run alternative scanned to the end from each of
            # them: a long run of U+FFFD behind the last ESC that did not
            # reach the end (a tail the sinks left after a bad decode)
            # cost a quadratic walk inside a scan's failure handling.
            esc = text.rfind("\x1b", 0, end)
            if esc != -1:
                cut = _TRAILING_JUNK.match(text, esc, end)
                if cut is None and text.startswith("\x1b\\", esc):
                    # The last ESC can be a string terminator's own: an OSC
                    # body holds no ESC, so a long ST-ended OSC ends
                    # "\x1b\\" and the rfind lands on the terminator rather
                    # than the code's opener. One more rfind reaches the
                    # opener; still at most two steps per over-long code.
                    opener = text.rfind("\x1b", 0, esc)
                    if opener != -1:
                        cut = _TRAILING_JUNK.match(text, opener, end)
            if cut is None:
                break
        end = cut.start()
    text = text[:end]
    # The raw value joins its spellings: _spelled_forms strips spaces, so a
    # value WITH a space would otherwise never match the tail the cut left
    # of it.
    # Every spelling the SINKS can match, so the trim sees the same set: the
    # value as written, each uv respelling (_spelled_forms), and each of
    # those as a message can PRINT it -- repr body, unicode_escape, JSON,
    # URL-quoted (config_validator.printed_forms, the set redact_values
    # matches in any case). A cut inside any printed spelling leaves a piece
    # the sinks cannot match ("Zq7Kx9Lm%3AP" for a value with ":"). For a uv
    # run the sinks also hide the run's plugin-built INPUTS whole, so a cut
    # tail that is a proper prefix of an input's spelling is the same edge
    # piece ("bandit[sarifqz4b" cut just after a glued extra's value): the
    # uv callers pass the run's inputs.
    from automated_security_helper.config.config_validator import printed_forms

    spellings: set = set()
    for value in values:
        for spelled in (value, *_spelled_forms(value)):
            if not spelled:
                continue
            spellings.add(spelled)
            spellings.update(form for form in printed_forms(spelled) if form)
    for entry in inputs:
        spellings.update(form for form in (entry, *_spelled_forms(entry)) if form)
    # Longest first, ties in text order: the pass below meets each form once,
    # against the end the forms before it left, so the order cannot be a set's
    # iteration order (it changes with the hash seed).
    forms = sorted(spellings, key=lambda form: (-len(form), form))
    if not forms:
        return text
    longest_form = len(forms[0])
    # An escape code INSIDE the fragment ("EDGE\x1b[1mSE") defeats a raw
    # endswith: the sinks strip every CSI code before matching, so the split
    # halves would print around the code. The tail is matched with codes
    # removed, each plain character mapped back to its raw position, so the
    # trim removes the raw span. The window is counted in PLAIN characters
    # (codes inside the fragment otherwise pushed its start out of a raw
    # window), by widening the raw slice until it holds enough plain text or
    # the whole string.
    plain_needed = longest_form * 2 + 128

    # Any complete escape code is skipped, by the SAME pattern the sinks
    # strip (error_text.ESCAPE_CODES): a walk reading a narrower set than the
    # sinks leaves a code the sink later removes, re-joining the split value
    # in clear ("EDGE\x1b[?25lSE" printed "EDGES"). A skipped code is only
    # ever trimmed away with the fragment, never kept.
    any_code = _ESCAPE_CODES

    def _folded(piece: str) -> str:
        # The sinks match in any case; a length-preserving fold keeps each
        # compared character on one raw position (a character whose lower()
        # changes length, the dotted I, stays as written).
        return "".join(ch.lower() if len(ch.lower()) == 1 else ch for ch in piece)

    def _plain_tail(raw: str, needed: int) -> Tuple[str, List[int], int]:
        raw_window = min(len(raw), needed)
        while True:
            start = len(raw) - raw_window
            if start > 0:
                # Never open the window inside an escape code: the walk
                # would read the code's body as plain text and match the
                # body's characters where the value's would be. A window
                # start that lands mid-code moves back to that code's ESC,
                # which the walk below skips whole.
                esc = raw.rfind("\x1b", 0, start)
                if esc != -1:
                    code = any_code.match(raw, esc)
                    if code and code.end() > start:
                        start = esc
            tail = raw[start:]
            plain_chars: List[str] = []
            positions: List[int] = []
            index = 0
            while index < len(tail):
                code = any_code.match(tail, index)
                if code and code.end() > index:
                    index = code.end()
                    continue
                plain_chars.append(tail[index])
                positions.append(index)
                index += 1
            if len(plain_chars) >= needed or raw_window >= len(raw):
                return "".join(plain_chars), positions, start
            raw_window = min(len(raw), raw_window * 2 + 128)

    # The folded forms, ONCE: each form's fold is per value, not per trim, and
    # two spellings that fold alike are one form (the pass would otherwise
    # trim a second time on a duplicate).
    folded_forms = list(dict.fromkeys(_folded(form) for form in forms))

    # One walk serves every form: the walk reads up to the whole text, and
    # running it per form multiplied that read by values x spellings x
    # printed forms -- seconds per cut read of a code-dense log. The walked
    # tail is never shortened. ``kept`` is the plain index where the kept text
    # ends, so the characters behind it stay readable for the spanning check
    # below, and a fresh, wider walk is bought only when ``kept`` has come
    # within one form's length of the window's start while unwalked text
    # remains in front of it.
    wanted = plain_needed
    plain, positions, start = _plain_tail(text, wanted)
    plain_folded = _folded(plain)
    end_plain = len(plain_folded)

    def _look_back_from(kept: int) -> int:
        # A check at ``kept`` reads up to one form's length of plain text in
        # front of it. Where the window cannot hold that and text remains in
        # front of the window, walk again with a window at least twice as
        # wide (so the walks sum to a few reads of the text, not one per
        # step) and answer ``kept`` in the new window by its raw position.
        nonlocal plain_folded, positions, start, end_plain, wanted
        if start == 0 or kept >= longest_form:
            return kept
        kept_raw = start + positions[kept]
        while start > 0 and kept < longest_form:
            wanted = max(wanted * 2, end_plain - kept + plain_needed)
            walked, positions, start = _plain_tail(text, wanted)
            plain_folded = _folded(walked)
            end_plain = len(plain_folded)
            kept = bisect_left(positions, kept_raw - start)
        return kept

    kept = end_plain
    for form_folded in folded_forms:
        kept = _look_back_from(kept)
        if plain_folded.endswith(form_folded, 0, kept):
            # The tail holds the COMPLETE spelling, which the sinks redact
            # whole. Trimming a proper prefix here cuts the spelling's own
            # end (a value whose first character equals its last matches
            # itself at keep=1) and leaves a partial no sink can match.
            # Leave it for the sinks.
            continue
        for keep in range(min(len(form_folded) - 1, kept), 0, -1):
            if plain_folded.endswith(form_folded[:keep], 0, kept):
                kept -= keep
                break
    if kept == end_plain:
        return text

    # Text past the cut was read, so a proper prefix left at the new end is
    # not a split value. A complete spelling that the cut runs through is:
    # its first part is all a sink would be left with, and no sink matches
    # it (a shorter form's one-character prefix trimming the last character
    # of a longer value that was whole at the end). Take the cut back to the
    # start of the run of overlapping occurrences it falls inside, found in
    # one pass over the walked tail. A step back from one spanning occurrence
    # to the next, with every form searched again at each step, cost the
    # length of the run times the number of forms, and a spelling that
    # overlaps itself makes a whole read one run.
    forms_pattern = _spellings_pattern(folded_forms)
    while True:
        kept = _look_back_from(kept)
        run_start = _overlap_run_start(
            forms_pattern, plain_folded, kept, min(kept + longest_form - 1, end_plain)
        )
        # ``kept`` has a form's length of walked text in front of it, or the
        # walk starts at the text's start, so every occurrence that can run
        # through it has been seen. A run that starts at least a form's
        # length into the window is therefore whole. One that reaches the
        # window's front may go on in text not walked yet: the cut goes to
        # its start, and the next pass walks a wider window to look further.
        if run_start == kept or start == 0 or run_start >= longest_form:
            return text[: start + positions[run_start]]
        kept = run_start


def read_log_bounded(
    log_path: Path,
    byte_bound: int,
    values: Iterable[str],
    inputs: Iterable[str] = (),
) -> Tuple[str, bool]:
    """ONE bounded read for every excerpt of a tool's log.

    Reads ``byte_bound + 1`` bytes through the guarded read (no symlink is
    followed), so a cut is KNOWN rather than inferred from an exact fit;
    decodes with ``errors="replace"``; and on a cut trims the tail
    (:func:`trimmed_at_read_edge`), because bytes past the bound were never
    read and a value split at the edge leaves a piece whole-spelling
    redaction cannot match. Returns ``(text, cut)``.

    Raises what the read raises: each caller owns its fallback (the carried
    log adds a could-not-be-read note, the scan-failure excerpt falls to its
    no-stderr branch, the offline explainer skips its cause-first message).
    Every raw read of tool text goes through here -- a site reading and
    cutting on its own re-creates the split-value leak one bound at a time,
    which is how the scan-failure excerpt and the offline explainer each
    grew their own copy of it.
    """
    from automated_security_helper.utils.sandbox import fs_guard

    raw = fs_guard.read_bytes_at_most(log_path, byte_bound + 1)
    cut = len(raw) > byte_bound
    text = raw[:byte_bound].decode("utf-8", errors="replace")
    if cut:
        text = trimmed_at_read_edge(text, values, inputs)
    return text, cut


def log_says(log: Path, phrase: str, bound: int = 8 * 1024 * 1024) -> bool:
    """Whether *phrase* occurs in *log*'s first *bound* bytes, folded.

    A verdict and never text, so it needs no redaction and no cut: the one
    reader for a cause match that has to see more of a log than the shown
    excerpt's small bound (the offline resolver's "No solution found" can
    come after kilobytes of earlier output, and matching only the excerpt's
    read silently skipped the cause-first message). Escape codes are
    stripped and every whitespace run reads as one space, as the excerpt's
    match does. Chunks overlap by a carried raw tail, so a phrase, a code or
    a whitespace run split across a chunk boundary is still seen; a single
    code or whitespace run longer than that carry is the one shape past this
    reader, and uv wraps at the scan's COLUMNS.

    The log is opened under fs_guard's reader semantics
    (:func:`fs_guard.open_for_read`): this runs after read_log_bounded's
    guarded read, and _carry_stderr_log's docstring names the threat -- a
    process the sandboxed scanner left running may have replaced the log
    since, so a symlink at the name is not followed and a FIFO cannot block
    the open. The chunks are bytes through an incremental decoder, so a
    multi-byte character split at a chunk edge still decodes as itself.
    """
    import codecs

    from automated_security_helper.utils.sandbox import fs_guard

    carry = 4096
    carried = ""
    remaining = bound
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    with fs_guard.open_for_read(log) as handle:
        while remaining > 0:
            data = handle.read(min(65536, remaining))
            if not data:
                return False
            remaining -= len(data)
            window = carried + decoder.decode(data)
            folded = " ".join(_ESCAPE_CODES.sub("", window).split())
            if phrase in folded:
                return True
            carried = window[-carry:]
    return False


def shown_excerpt(
    text: str,
    cut: bool,
    log_path: Path,
    keep: int,
    show: Callable[[str], str],
) -> str:
    """Redact, cut and MARK one log excerpt for a message.

    ``show`` is the caller's redaction layer (uv or neutral), applied before
    the cut so the cut cannot split a value. The excerpt keeps ``keep``
    characters with ``...[truncated]`` past them -- and when the READ was
    cut, the excerpt always ends by naming the log, whatever its length: a
    code-heavy log redacts to under the excerpt bound, so without the
    marker the message ended at the read's cut as if that were the tool's
    last line, and a log the trim and redaction emptied fell through to a
    false "No stderr captured". An emptied excerpt returns the marker alone,
    so the caller's no-stderr branch cannot swallow a cut read.
    """
    shown = show(text.strip())
    if len(shown) > keep:
        shown = shown[:keep] + " ...[truncated]"
    if cut:
        marker = f"(the log continues beyond this excerpt; see {log_path.as_posix()})"
        shown = f"{shown} {marker}" if shown else marker
    return shown


def _log_identity(path: Path | None) -> Tuple[int, int, int, int] | None:
    """What tells one write of the file at ``path`` from another, or None."""
    if path is None:
        return None
    try:
        status = os.lstat(path)
    except (OSError, ValueError):
        return None
    return (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns)


#: The response flags that say the tool did not finish its scan, so whatever
#: scan() made of the run, the scan is graded ERROR (_record_kept_flag).
_UNFINISHED_RUN_FLAGS = ("timed_out", "cancelled", "result_rejected", "signaled")

#: How a run whose stop failed is keyed in ``scan_could_not_stop_runs``: the flag
#: it ended with, then the wait that failed after the tool ran. A response that
#: carries none of these recorded only the failed stop, and is keyed "unflagged".
_COULD_NOT_STOP_RUN_KEYS = _UNFINISHED_RUN_FLAGS + ("post_run_error",)


def _could_not_stop_run_key(response: Dict) -> str:
    """Which run of one ``scan()`` a could-not-stop response belongs to: the first
    of :data:`_COULD_NOT_STOP_RUN_KEYS` the response carries as True, else
    ``unflagged``."""
    for flag in _COULD_NOT_STOP_RUN_KEYS:
        if response.get(flag) is True:
            return flag
    return "unflagged"


def worse_exit_code(current: int | None, new: int) -> int:
    """The worse of two runs' exit codes, for a plugin's accumulated ``exit_code``.

    A negative code is a signal death, which no exit code describes and no
    accepted set admits. It is recorded as the shell reports it, ``128 + N``
    (``exit_status``), the form ``_record_target_exit_code`` records for the run
    that scanned one target, so the two readers agree on one number; its
    absolute value is never used, because that would put SIGHUP's 1 inside a
    ``{0, 1}`` set. A signal death outranks every code a tool returned before
    it. Otherwise the larger code.
    """
    if new < 0:
        return exit_status(new)
    if current is not None and current < 0:
        return exit_status(current)
    return max(current if current is not None else 0, new)


def _folded_exit_code(plugin: Any, current: int | None, new: int) -> int:
    """*current* and *new* folded by the plugin's own ranking, ``_worse_exit_code``.

    The hook is read through ``getattr``, like the accumulator's other helpers:
    a host that carries only the accumulator fields has none, and an override
    that raises or answers something that is no exit code must not lose the
    run's code. Both get :func:`worse_exit_code`, the default ranking.
    """
    rank = getattr(plugin, "_worse_exit_code", None)
    if callable(rank):
        try:
            ranked = rank(current, new)
        except Exception:  # noqa: BLE001 -- an overridable hook
            ranked = None
        if is_exit_code(ranked):
            return ranked
    return worse_exit_code(current, new)


def _response_text(response: Dict, keys: Tuple[str, ...], default: str) -> str:
    """The first readable, non-empty value under ``keys``, as text, or ``default``.

    The recorders' state step reads response values a failing run assembled, so a
    value whose str() raises must not leave the state unset: the next key, or the
    default, answers instead.
    """
    for key in keys:
        try:
            value = response.get(key)
            if value:
                return str(value)
        except Exception:
            continue
    return default


def _raised_key(recorder: str) -> str:
    """What ``_record_response`` adds to ``invoked`` when ``recorder`` raised."""
    return f"{recorder}:raised"


def _error_text_read_once(error: BaseException, read: Any) -> str:
    """``error`` as text for a record, redacted with a values read already taken.

    ``read`` is a :func:`guarded_values_read` result: the handler's one read of
    the values hook. Without values the text is not shown, and only the error's
    class and the note say why."""
    if read.values is not None:
        return error_text(error, read.values)
    return (
        f"{type(error).__name__} (text not shown: the plugin's values hook "
        f"{read.failure()})"
    )


def _uv_interpreter_inside(
    environment: Optional[Dict[str, str]], cwd: Path, tree: Path
) -> bool:
    """Whether ``UV_PYTHON`` in ``environment`` names an interpreter inside ``tree``.

    ``environment`` is what the child gets (this process's when None). A value
    that is a path, absolute or relative to ``cwd`` (where the child starts), is
    inside the scanned tree when it lies below it by its spelling: a ``.venv``
    python is a link to the interpreter it was made from, so a path resolved
    through links would read as outside and let the tree's environment in. A
    version request or a name looked up on PATH names no path and is not inside.
    """
    chosen = (snapshot_environ() if environment is None else environment).get(
        "UV_PYTHON"
    )
    if not isinstance(chosen, str) or not chosen:
        return False
    if not (os.path.isabs(chosen) or "/" in chosen or "\\" in chosen):
        return False
    candidate = os.path.abspath(
        os.path.join(os.fspath(cwd), os.path.expanduser(chosen))
    )
    # By its own spelling, and with its directory resolved: the tree may be
    # reached through a link above it by either name.
    spelled = [
        candidate,
        os.path.join(
            os.path.realpath(os.path.dirname(candidate)), os.path.basename(candidate)
        ),
    ]
    roots = {os.path.abspath(os.fspath(tree)), os.path.realpath(os.fspath(tree))}
    return any(
        os.path.normcase(path).startswith(
            os.path.normcase(root).rstrip(os.sep) + os.sep
        )
        for path in spelled
        for root in roots
    )


def _log_name(plugin: Any) -> str:
    """The name a plugin's own lines carry: its config's, else its class's.

    ``config`` is optional and defaults to None, so a plugin built without one
    has no name to read there. A function over the plugin, as
    :func:`guarded_values_read` is, so the unbound ``PluginBase._plugin_log``
    still runs on a stand-in."""
    return getattr(plugin.config, "name", None) or plugin.__class__.__name__


class CustomCommand(BaseModel):
    args: List[str]
    shell: bool = False  # Set to True only when shell expansion is absolutely necessary


#: Whether the plugin being constructed was handed a configuration read from its
#: context (True) or a typed object the caller built (False); read by the
#: private-attribute default of PluginBase while it is constructed.
_CONFIG_FROM_CONTEXT: ContextVar[bool] = ContextVar(
    "plugin_config_from_context", default=True
)


def _declared_provenance(data: Dict[str, Any]) -> Optional[bool]:
    """Pop the ``config_from_context`` declaration from constructor *data*.

    None when the caller declared nothing. Only a real boolean declares
    provenance: ``bool("false")`` is True, so a coerced string would declare
    the opposite of its text, and the TypeError names the type, never the
    value."""
    declared = data.pop("config_from_context", None)
    if declared is not None and not isinstance(declared, bool):
        raise TypeError(
            "config_from_context declares where the configuration came "
            "from and must be a bool when given, not "
            f"{type(declared).__name__}"
        )
    return declared


class PluginBase(UVToolMixin, BaseModel):
    """Base plugin class with common functionality for all plugin types."""

    model_config = ConfigDict(
        extra="allow",
        arbitrary_types_allowed=True,
        use_enum_values=True,
        # A phase builds a plugin from its config section, which a config model
        # may not type (a plugin module's section), so the plugin's own error is
        # the one raised. A refused value can be a secret read from the
        # environment, and an error's text goes wherever the error is shown.
        hide_input_in_errors=True,
    )
    context: PluginContext | None = None
    config: PluginConfigBase | None = None

    output: List[str] = []
    errors: List[str] = []
    results_dir: Path | None = None
    tool_version: str | None = None
    tool_description: str | None = None
    dependencies_satisfied: bool = False
    start_time: datetime | None = None
    end_time: datetime | None = None
    # The worst exit code of the tools this plugin started. None means it started
    # none: a scanner that runs one tool per target resets it to None at the top of
    # scan(), so a scan that never reached its tool (a lockfile whose package manager
    # is absent, a template the model rejects) reports no exit code rather than the 0
    # it starts at. Every subprocess goes through _process_command_response, which is
    # what sets it.
    exit_code: int | None = 0

    # UV tool execution support
    use_uv_tool: bool = False
    command: str | None = None
    uv_tool_install_commands: List[str] = []

    # UV special use cases
    uv_tool_package_name: str | None = None

    # Seconds after which this plugin's most recent timed-out subprocess was
    # killed, or None. See scan_timed_out_after.
    _scan_timed_out_after: float | None = PrivateAttr(default=None)

    # Why this plugin's most recent tool could not be started, or None. See
    # scan_spawn_failure.
    _scan_spawn_failure: str | None = PrivateAttr(default=None)

    # A version probe construction deferred, as (tool, --from spec), or None. See
    # uv_tool_mixin.deferred_tool_version_probes.
    _deferred_tool_version_probe: tuple | None = PrivateAttr(default=None)

    # The targets of this plugin's most recent run that its tool never evaluated:
    # no rule ran against them, whatever the failure type. See unevaluated_targets.
    _unevaluated_targets: List[str] = PrivateAttr(default_factory=list)

    # Why ASH could not record the output of this plugin's most recent tool run,
    # or None. See scan_post_run_error.
    _scan_post_run_error: str | None = PrivateAttr(default=None)

    # Whether this plugin has already said it ignored a UV_PYTHON that names an
    # interpreter inside the scanned tree (once per plugin, not per tool run).
    _warned_in_tree_uv_python: bool = PrivateAttr(default=False)

    # The flag, and its reason, of this plugin's most recent run that did not
    # finish (a timeout, a cancel, a rejected result, a signal death), or None.
    # See scan_kept_flag.
    _scan_kept_flag: Tuple[str, str] | None = PrivateAttr(default=None)
    # The recorded reason this plugin's most recent run ended with a tool ASH
    # could not stop, or None. See scan_could_not_stop.
    _scan_could_not_stop: str | None = PrivateAttr(default=None)
    # The same reason for every run of this plugin's current scan() whose stop
    # failed, keyed by the flag that run ended with. See scan_could_not_stop_runs.
    _scan_could_not_stop_runs: Dict[str, str] = PrivateAttr(default_factory=dict)

    # Why the last UVToolMixin._try_uv_tool_execution could not run the tool
    # through uv, or None. _run_subprocess reports it.
    _uv_run_failure: str | None = PrivateAttr(default=None)

    #: The responses ``_process_command_response`` has folded and no recorder
    #: has yet retired. Held as the objects themselves, never their ``id()``:
    #: a mark keyed on an address outlived its dict on the paths that never
    #: discarded it, and a later response allocated at that address would have
    #: read as "already processed" and never reached exit_code and errors. A
    #: held reference keeps the address taken for as long as the mark stands.
    _processed_responses: list = PrivateAttr(default_factory=list)

    # The lines ``_plugin_log`` itself put in ``errors``: ASH's own notes, kept
    # apart from the lines a tool's stderr added (``_process_command_response``),
    # so a reader that needs to know whether the tool said anything can tell the
    # two apart. ``errors`` still holds both. See ``_tool_error_lines``.
    _plugin_log_lines: List[str] = PrivateAttr(default_factory=list)

    # Whether this plugin's configuration was read from its context's resolved
    # configuration (a section ``AshConfig.get_plugin_config`` answered, as a
    # scan hands it over) rather than built by the embedding caller as a typed
    # configuration object. Set once, at construction; the ownership check of
    # a configured path (``operator_only_options.operator_wrote_value``) judges
    # the first by the operator's view of the configuration and takes the
    # second as the operator's own. Unset (a plugin made without __init__) is
    # the first, which is the stricter judgment.
    # The value is fixed before the model's post-init hooks run, because a
    # scanner reads its configured paths there and the ownership check needs it.
    _config_from_context: bool = PrivateAttr(
        default_factory=lambda: _CONFIG_FROM_CONTEXT.get()
    )

    def __init__(self, **data: Any) -> None:
        # The caller's own declaration wins over the type inference: a dict
        # section is read as the context's, a typed object as caller-built,
        # but the ownership check no longer trusts the type alone (a typed
        # object can be built from the resolved section), so a caller that
        # knows the provenance states it.
        declared = _declared_provenance(data)
        token = _CONFIG_FROM_CONTEXT.set(
            declared
            if declared is not None
            else not isinstance(data.get("config"), PluginConfigBase)
        )
        try:
            super().__init__(**data)
        finally:
            _CONFIG_FROM_CONTEXT.reset(token)

    # The pydantic mypy plugin types model_construct per model, field by field;
    # this override takes the fields as **values and passes them on unchanged.
    @classmethod
    def model_construct(  # type: ignore[override]
        cls, _fields_set: Optional[set[str]] = None, **values: Any
    ) -> "PluginBase":
        """``model_construct`` skips ``__init__``, so the provenance
        declaration is consumed here too: popped (never kept as a field),
        checked as a real boolean, and in force while the model's post-init
        hooks run, as in ``__init__``. With no declaration the provenance is
        the context's, the stricter judgment, whatever an enclosing
        construction had set.

        It also skips the validator that gives the plugin's section its
        context's environment values, so they are carried here, as
        ``_give_its_section_the_environment_values`` does for a validated
        plugin: a section handed in this way otherwise printed them in
        clear."""
        declared = _declared_provenance(values)
        token = _CONFIG_FROM_CONTEXT.set(declared if declared is not None else True)
        try:
            built = super().model_construct(_fields_set, **values)
        finally:
            _CONFIG_FROM_CONTEXT.reset(token)
        carry_environment_values(
            built.__dict__.get("config"), built._values_for_its_section()
        )
        return built

    def model_copy(self, *, update: Any = None, deep: bool = False) -> "PluginBase":
        """A copy whose replacement section carries the environment values.

        ``model_copy`` runs neither the validators nor ``__setattr__``, the two
        places a plugin's section is given its context's environment values,
        so a ``config`` passed in ``update`` was put in the copy bare and
        printed them in clear. The copy's section is carried to when ``update``
        names a ``config`` (a section that was never in a plugin) or a
        ``context`` (whose values the shared section may not yet hold), the two
        keys ``__setattr__`` acts on. The carry adds the context's values beside
        the ones the section already holds and never removes any, so a section
        still shared with the original keeps what the original gave it."""
        copied = super().model_copy(update=update, deep=deep)
        if update and ("config" in update or "context" in update):
            carry_environment_values(
                copied.__dict__.get("config"), copied._values_for_its_section()
            )
        return copied

    # Installation-related properties
    dependencies: Annotated[
        Dict[str, Dict[str, List[PluginDependency]]],
        Field(
            description="Dependencies by platform and architecture",
        ),
    ] = {}

    custom_install_commands: Annotated[
        Dict[str, Dict[str, List[CustomCommand]]],
        Field(
            description="Custom installation commands by platform and architecture",
        ),
    ] = {}

    def __repr_str__(self, join_str: str) -> str:
        """repr and str of this plugin, redacted with the values its context's
        configuration read from the environment.

        A traceback with locals (show_debug_locals) prints a plugin wherever a
        frame holds one, as ReportPhase holds every reporter, and the plugin's
        own section, built from the configuration, holds those values in its
        fields.

        The hook is overridable and can raise, so it is read through
        guarded_values_read like every other sink: without the values nothing
        can be redacted, and a repr that raised here would hide the original
        error the traceback printer was showing. A failed read answers a
        placeholder with no field values at all.
        """
        read = guarded_values_read(self)
        if read.values is None:
            return f"values hook {read.failure()}; no fields shown"
        return text_without_values(
            super().__repr_str__(join_str),  # type: ignore[misc]
            read.values,
        )

    # As for a configuration (utils/redacted_model.py): no field-by-field
    # __rich_repr__ for Rich to print around the redacted path.
    __rich_repr__ = NO_RICH_REPR

    def _values_for_its_section(self) -> Tuple[str, ...]:
        """The values the plugin's own section is redacted with.

        The hook's answer, read guarded, when it gives one. When the read
        fails (the hook raised, or answered something that is not a value
        set) the section still gets the values the context's configuration
        read from the environment, the half of the hook's set that does not
        come through the hook: the base hook always includes it, and an
        override that fails cannot take it away.

        A section has no placeholder to fall back to. It prints itself from
        the values it carries, so carrying none (the carry skipped, as it was)
        left ``repr(plugin.config)`` in clear beside a ``repr(plugin)`` that
        shows a value-free note, against the module's guarding rule that a
        failed read never ends in an empty value set
        (``UVToolMixin._values_to_redact``). Values only the failed hook could
        have named stay unknown: the plugin's own repr is the sink that hides
        every field when that happens, and it does not read the section's
        record.

        The fallback read is guarded as well. It runs exactly when the hook's
        read failed, and the base hook reads the same configuration values
        without a guard: when that read is why the hook failed (an iterable
        that raises while it is drained), reading it again here would raise
        out of the after-validator and out of every ``plugin.config`` and
        ``plugin.context`` assignment, which this method exists to keep from
        raising. A failure of the fallback gives no values, the same as a
        failed hook did before the fallback existed; the plugin's own repr
        still hides every field in that case.
        """
        read = guarded_values_read(self)
        if read.values is not None:
            return read.values
        try:
            return config_environment_values(
                getattr(getattr(self, "context", None), "config", None)
            )
        except Exception:  # noqa: BLE001 -- the configuration's own read can raise
            return ()

    @model_validator(mode="after")
    def _give_its_section_the_environment_values(self) -> "PluginBase":
        """The plugin's own section carries its context's environment values,
        so the section printed on its own is redacted too.

        The values come from :meth:`_values_for_its_section`, which reads the
        hook guarded: a raise here would fail building the plugin, and a
        failed read still carries the configuration's own values rather than
        none."""
        carry_environment_values(self.config, self._values_for_its_section())
        return self

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if name in ("config", "context"):
            # Guarded as in the validator: a raising hook must not turn
            # every `plugin.config = ...` assignment into an error, and must
            # not leave the new section with no values either.
            carry_environment_values(
                self.__dict__.get("config"), self._values_for_its_section()
            )

    def _plugin_log(
        self,
        *msg: str,
        level: int = 15,
        target_type: str | None = "source",
        append_to_stream: Literal["stderr", "stdout", "none"] = "none",
    ):
        """Log a message to the plugin's log file.

        Args:
            *msg: Message to log
            level: Log level
            target_type: Target type (e.g. source, converted)
            append_to_stream: Append to stdout or stderr stream
        """
        name = _log_name(self)
        tt = ""
        if target_type is not None:
            tt = f" @ [magenta]{escape_markup(target_type)}[/magenta]"

        # The prefix is styled, so the record asks for markup, and everything
        # interpolated is escaped: the message is the plugin's, and it often names a
        # path in the scanned repository ("Target directory <dir> is empty"), where
        # "[/x]" raised MarkupError out of the logging call. Each part is escaped on
        # its own: a part the caller showed already (a ShownText) is shown once, and
        # joined first it would be plain text, shown a second time.
        ASH_LOGGER._log(
            level,
            f"([yellow]{escape_markup(name)}[/yellow]{tt})"
            "\t" + "\n".join(escape_markup(part) for part in msg),
            args=(),
            extra=MARKUP,
        )
        # Stored as written: whatever reads errors or output shows it once, so a
        # part the call site showed already (a ShownText) is read back first, or
        # it was shown a second time there.
        written = "\n".join(as_written(part) for part in msg)
        # ERROR and above: a CRITICAL message is at least as much the plugin's
        # error as an ERROR one.
        if level >= logging.ERROR or append_to_stream == "stderr":
            line = f"({name}) " + written
            self.errors.append(line)
            # Remembered as ASH's own, not the tool's: ``errors`` is one list
            # for both, and a stand-in without the list (the unbound call in
            # the tests) records as before.
            ours = getattr(self, "_plugin_log_lines", None)
            if isinstance(ours, list):
                ours.append(line)
        elif append_to_stream == "stdout":
            self.output.append(f"({name}) " + written)

    def _reset_errors(self) -> None:
        """Start a run's error lines afresh.

        ``errors`` is cleared together with the record of which of its lines
        are ASH's own notes (``_plugin_log_lines``). The two belong together: a
        reset of ``errors`` alone leaves the record holding notes of a run that
        is over, which grows across targets and, when a later tool line reads
        the same, drops that line from ``_tool_error_lines``. Anything that
        starts a run's lines over, such as a ``scan()`` override, calls this
        instead of assigning ``errors``.
        """
        self.errors = []
        self._plugin_log_lines = []

    def _tool_error_lines(self) -> List[str]:
        """``errors`` without the lines ``_plugin_log`` added: what the tool's
        stderr put there.

        ``errors`` holds both, in the order they came, and stays that way for
        every reader that wants the whole story. A reader that decides whether
        the tool said anything (a failure message choosing between ``errors``
        and the stderr log) asks this instead: ASH's own note ("timed out
        after ...") is not the tool's stderr, and counted as it, it kept the
        tool's real text in the log unread.

        Each note removes one equal line, so a tool line that repeats a note
        word for word is only dropped as many times as the note was written.
        """
        pending: Dict[str, int] = {}
        for line in getattr(self, "_plugin_log_lines", None) or ():
            pending[line] = pending.get(line, 0) + 1
        kept: List[str] = []
        for line in self.errors:
            if pending.get(line):
                pending[line] -= 1
            else:
                kept.append(line)
        return kept

    def is_python_only(self) -> bool:
        """
        Determine if this plugin only depends on Python and has no external dependencies.

        A plugin is considered Python-only if:
        1. It has no dependencies defined in self.dependencies, or
        2. It only has pip or uv dependencies (Python packages, installed by
           ``pip install`` and ``uv tool install``)
        3. It has no custom installation commands

        Returns:
            bool: True if the plugin only depends on Python, False otherwise
        """
        # Check if there are any custom installation commands
        if len(self.custom_install_commands) > 0:
            ASH_LOGGER.debug(
                f"Plugin {self.__class__.__name__} has custom install commands, this is not Python-only"
            )
            return False

        # Check if there are any dependencies
        if len(self.dependencies) == 0:
            ASH_LOGGER.debug(
                f"Plugin {self.__class__.__name__} has no dependencies and no custom install commands, this is Python-only"
            )
            return True

        # Check if all dependencies are Python packages (pip or uv)
        for platform in self.dependencies:
            for arch in self.dependencies[platform]:
                for dep in self.dependencies[platform][arch]:
                    if dep.package_manager not in _PYTHON_PACKAGE_MANAGERS:
                        ASH_LOGGER.debug(
                            f"Plugin {self.__class__.__name__} has non-Python dependencies with {dep.package_manager}, this is not Python-only"
                        )
                        return False

        # If we got here, all dependencies are Python packages
        return True

    @model_validator(mode="after")
    def setup_paths(self) -> "PluginBase":
        """Set up default paths and initialize plugin configuration."""
        # Use context if provided, otherwise fall back to instance attributes
        if self.context is None:
            raise ScannerError(f"No context provided for {self.__class__.__name__}!")
        ASH_LOGGER.trace(f"Using provided context for {self.__class__.__name__}")
        return self

    def _tool_text_for_records(self, text: Any, stream: str) -> Any:
        """The text of a tool's ``stream`` ("stdout" or "stderr") as the records keep it.

        A hook for a plugin whose tool prints a finding's OWN secret in its
        output: actionlint's JSON carries a credentials finding's hard-coded
        password as its snippet, and a failed run's stdout reached the recorded
        ``output`` lines, and from there the results file's raw_results, with
        only the environment-value redaction applied. The default keeps the
        text as it is; an override returns the text with such values removed
        before the lines are split and recorded. Called with whatever the
        response holds (None included), and must return the same kind.
        """
        return text

    def _mark_processed(self, response: Any) -> None:
        """Remember that *response* has been folded into exit_code and errors."""
        if not self._was_processed(response):
            self._processed_responses.append(response)

    def _was_processed(self, response: Any) -> bool:
        """Whether *response* (this object, by identity) is marked processed."""
        return any(seen is response for seen in self._processed_responses)

    def _forget_processed(self, response: Any) -> None:
        """Retire *response*'s mark; the recorders call this, so every path does."""
        self._processed_responses[:] = [
            seen for seen in self._processed_responses if seen is not response
        ]

    def _worse_exit_code(self, current: int | None, new: int) -> int:
        """The worse of two runs' exit codes, for the accumulated ``exit_code``.

        A hook: the accumulator folds every run's code through it. The default
        is :func:`worse_exit_code`, the larger code. A plugin that knows which
        codes it accepts overrides it to rank by that, since the larger code
        is not always the worse one (``ScannerPluginBase`` does).
        """
        return worse_exit_code(current, new)

    def _process_command_response(self, response: dict) -> None:
        """Accumulate stdout, stderr, and exit code from a subprocess response.

        Args:
            response: Dictionary with optional stdout, stderr, and returncode keys.

        A uv run's plugin-built requirement strings are computed here from
        the plugin's own hooks when ``use_uv_tool`` is set, NOT passed as a
        parameter: this method is a documented extension seam, and a subclass
        overriding it with this one-argument signature must keep working.
        Computed rather than carried on an attribute, since per-instance
        state set around the call let two concurrent responses on one
        instance erase each other's inputs mid-call.
        """
        # The helpers below are read through getattr, like the uv inputs hook:
        # this method is bound onto hosts that carry only the accumulator fields
        # (a mixin test drives the real accumulator through a stub plugin), and
        # a host without them records as before. It sets no "processed" mark: the
        # caller that hands it a response owns the mark (the uv mixin marks the
        # response it processed), so an override of this seam that never calls
        # super() is still counted.
        plugin_inputs: Tuple[str, ...] = ()
        if getattr(self, "use_uv_tool", False):
            inputs_getter = getattr(self, "_uv_run_inputs_for_records", None)
            if callable(inputs_getter):
                plugin_inputs = tuple(inputs_getter() or ())
        shape = getattr(self, "_tool_text_for_records", None)
        if not callable(shape):

            def shape(text: Any, _stream: str) -> Any:
                return text

        # The shaping hook is overridable like the values hook, and guarded the
        # same way: a raise must not escape into the run's own outcome, and the
        # unshaped text is not recorded in its place (the hook is what hides
        # the plugin's own inputs from the lines), so that stream's lines are
        # replaced by a value-free note.
        shape_failed: List[str] = []

        def shaped(text: Any, stream: str) -> Any:
            try:
                return shape(text, stream)
            except Exception:  # noqa: BLE001
                if text:
                    shape_failed.append(stream)
                return ""

        stdout_text = shaped(response.get("stdout"), "stdout")
        stderr_text = shaped(response.get("stderr"), "stderr")
        if "stdout" in shape_failed:
            self.output.append(
                "(stdout not shown: the plugin's text-shaping hook raised)"
            )
        if "stderr" in shape_failed:
            self.errors.append(
                "(stderr not shown: the plugin's text-shaping hook raised)"
            )
        # _values_to_redact is an overridable hook, called once for both
        # streams and guarded: without the values nothing can be redacted,
        # so a raising hook loses the lines (a value-free note takes their
        # place) and never turns the run's own outcome into a post-run
        # error. An override that answers None, or anything that is not a
        # value set at all, is the same broken answer as a raise: the
        # normalizer reads such an answer as no values, which here would be
        # the license to record the lines in clear, so the gate takes the
        # conservative arm instead, as the DEBUG dumps' gate does. The note
        # says which of the two it was. The read is guarded_values_read,
        # the one every sink reads the hook through.
        values: Optional[Tuple[str, ...]] = None
        hook_said = ""
        if stdout_text or stderr_text:
            read = guarded_values_read(self)
            values = read.values
            if values is None:
                hook_said = (
                    "raised"
                    if read.raised is not None
                    else "returned an unusable answer"
                )
        if stdout_text:
            # Record lines: redacted WHOLE before the split, because a value
            # can hold a line break, a split is a cut, and the per-line
            # redaction the results layer applies matches neither half of a
            # cut one. The stream log keeps the tool's text verbatim. The
            # escape codes come out whatever the values are: with values,
            # text_without_values matches the text as written first (a value
            # that holds a code is matched in the band its as-written length
            # earns) and then stripped, so the text goes to it as written;
            # with none, there is nothing to match and the codes come out
            # here, so the same output does not keep its codes in the reports
            # of a run that read no environment values.
            if values is None:
                self.output.append(
                    f"(stdout not shown: the plugin's redaction hook {hook_said})"
                )
            else:
                self.output.extend(
                    redact_then_split(stdout_text, values)
                    if values
                    else _ESCAPE_CODES.sub("", stdout_text).splitlines()
                )

        if stderr_text:
            # Report lines: a tool's stderr can quote back a requirement or a
            # path holding a value the plugin's config read from the
            # environment, and these lines go into the reports. The stream
            # log keeps the tool's text verbatim; only these report lines are
            # redacted. A uv run's stderr goes through the full uv layer
            # (shown_uv_output, unbounded): uv RESPELLS what it quotes
            # ("9.9.9-RC777" prints as "9.9.9rc777") and its plugin-built
            # inputs are hidden by the same arms as the debug record, so the
            # reports never get WEAKER redaction than that line. Any other
            # tool's stderr gets the neutral layer -- escape codes removed,
            # values hidden as written -- because the respelling premise is
            # uv's own.
            if values is None:
                self.errors.append(
                    f"(stderr not shown: the plugin's redaction hook {hook_said})"
                )
            else:
                if plugin_inputs:
                    from automated_security_helper.utils.uv_tool_runner import (
                        shown_uv_output,
                    )

                    shown = shown_uv_output(
                        stderr_text,
                        values,
                        plugin_inputs=plugin_inputs,
                        tool_name=self.command,
                        limit=None,
                    )
                else:
                    shown = shown_tool_stderr(stderr_text, values)
                self.errors.extend(shown.splitlines())

        # Accumulate worst exit code across multiple subprocess calls.
        if "returncode" in response:
            new_code = response.get("returncode")
            if new_code is None:
                # A tool ASH stopped while it ran, or could not stop, has no
                # exit code of its own: the response keeps its None, no code
                # is made up on it, and judging reads the flag's own
                # conventional code, so a scanner that overrides scan() and
                # reaches only this reader does not keep an accepted-looking
                # 0 for a run that never finished. An unflagged None (a test
                # double's stand-in) contributes nothing.
                new_code = flagged_returncode(response)
                if new_code is None:
                    return
            elif not is_exit_code(new_code):
                # A bool or any other non-int is NO exit code: bool is an
                # int subclass, so a False here read as an accepted 0
                # through the integer comparison, and a True as a 1 some
                # accepted sets admit. Judged from the lead flag, and with
                # no flag as the wrapper's own failure, like a missing key.
                new_code = flagged_returncode(response)
                if new_code is None:
                    new_code = 125
        else:
            # A response with no returncode key at all is not a run's verdict.
            # The old default of 1 is a code scanners such as bandit accept
            # ("ran and found issues"), so a failure shaped like this was
            # judged successful. It is judged from its lead flag, and with no
            # flag it is graded as the wrapper's own failure.
            new_code = flagged_returncode(response)
            if new_code is None:
                new_code = 125
        # A negative code is a signal death by the runner's own reading
        # (``signal_ending``: POSIX only, never for a code of 0 or more). The
        # accumulated code records it as the shell reports it, ``128 + N``
        # (``worse_exit_code``), and that number alone cannot be told from a
        # tool's own count of findings by a reader whose accepted band is wide
        # (cfn_nag's violation count, yarn audit's severity bitmask). So the
        # death is kept as the run's cause as well, where every such reader
        # looks before any band (``_sarif_execution_successful``): a run a
        # signal ended is never a completed one, whatever number it left.
        # ``_run_subprocess`` records the same cause from its response's flag
        # and overwrites this one with the response's own text; a caller of
        # this seam that hands over a bare negative code gets the same
        # judgment. Worded without an attribution: the response may have
        # withheld the flag because ASH itself may have ended the tool.
        # A response that carries ``post_run_error`` is left out: the runner
        # keeps the tool's own negative code there and leaves ``signaled`` out
        # on purpose when ASH's own stop may have sent the signal (SIGKILL or
        # SIGTERM after a failed wait while the server is stopping), so the
        # code names no sender. The post-run error grades that run, and
        # ``_run_subprocess``'s handler, which folds the same code without a
        # cause, then agrees with this seam.
        if self._scan_kept_flag is None and response.get("post_run_error") is not True:
            ending = signal_ending(
                new_code, str(getattr(self, "command", "") or "tool")
            )
            if ending is not None:
                self._scan_kept_flag = ("signaled", ending[1])
        self.exit_code = _folded_exit_code(self, self.exit_code, new_code)

    @property
    def scan_timed_out_after(self) -> float | None:
        """The timeout a subprocess of this plugin was killed at, or None.

        Set by ``_run_subprocess``, which every scanner's tool invocation goes
        through on both the uv and the direct path. It exists for the scanners
        that override ``scan()``: they never reach the template's own timeout
        check, so their failure reads as whatever the missing output caused, and
        ``ScannerExecutor`` uses this to report the timeout instead.
        """
        return self._scan_timed_out_after

    def clear_scan_timeout(self) -> None:
        """Forget a recorded timeout, so one target's timeout is not charged to the
        next. ``ScannerExecutor`` calls this before each ``scan()``."""
        self._scan_timed_out_after = None

    @property
    def unevaluated_targets(self) -> List[str]:
        """The targets of this plugin's most recent run that its tool never
        evaluated, in the order they were met.

        A run that would otherwise grade PASSED while any target is named here is
        not a clean result, and ``ScannerExecutor`` grades it ERROR naming them. A
        failure the run surfaces as its own raise is not recorded here; this
        covers the per-target failures the run returns normally from.
        """
        return list(self._unevaluated_targets)

    def clear_unevaluated_targets(self) -> None:
        """Forget the previous run's unevaluated targets, so one target's failures
        are not charged to the next. ``ScannerExecutor`` calls this before each
        ``scan()``."""
        self._unevaluated_targets = []

    def record_unevaluated_target(self, name: str | Path) -> None:
        """Name one target of the current run that the tool never evaluated."""
        self._unevaluated_targets.append(str(name))

    @property
    def scan_spawn_failure(self) -> str | None:
        """Why this plugin's tool could not be started, or None.

        Set by ``_run_subprocess`` when the command never started (exit code 127,
        ``spawn_failed`` in the response): the OS refused it, or something raised
        while preparing or starting the spawn. A tool that never ran
        produced no results, so ``ScannerExecutor`` reports the scan as ERROR
        from this, whatever the scanner's ``scan()`` made of the missing output
        and whichever exit codes it accepts.
        """
        return self._scan_spawn_failure

    def clear_scan_spawn_failure(self) -> None:
        """Forget a recorded spawn failure. ``ScannerExecutor`` calls this before
        each ``scan()``, as it does ``clear_scan_timeout``."""
        self._scan_spawn_failure = None

    def _spawn_failure_state(self, response: Dict) -> None:
        """Set the spawn-failure state from ``response``: the pure half of
        _record_spawn_failure, run directly by _run_subprocess's handler when a
        recorder raised before setting it."""
        if not isinstance(response, dict) or response.get("spawn_failed") is not True:
            return
        self._scan_spawn_failure = _response_text(
            response, ("stderr", "error"), "the command never ran"
        )

    def _record_spawn_failure(self, response: Dict) -> None:
        # Recording retires the processed mark (the handler calls this one
        # directly, outside _record_response).
        self._forget_processed(response)
        # State before the log, so the grade lands even when the log raises.
        if not isinstance(response, dict) or response.get("spawn_failed") is not True:
            return
        self._spawn_failure_state(response)
        # The reason names the command, which can carry a value the config read
        # from the environment; the recorded state keeps it as the runner gave
        # it, for the results' own redaction.
        # The one guarded read: a hook that raised or gave no usable answer
        # loses the text, and a value-free note takes its place.
        read = guarded_values_read(self)
        if read.values is None:
            self._plugin_log(
                "could not start its tool: (not shown: the plugin's values "
                f"hook {read.failure()})",
                level=logging.ERROR,
            )
            return
        self._plugin_log(
            text_without_values(
                f"could not start its tool: {self._scan_spawn_failure}",
                read.values,
            ),
            level=logging.ERROR,
        )

    @property
    def scan_post_run_error(self) -> str | None:
        """Why ASH could not record the output of this plugin's tool, or None.

        Set by ``_run_subprocess`` when the tool ran and exited and ASH then failed
        (``post_run_error`` in the response): writing its stream logs, or handling
        the response. The tool's own exit code is kept, so a scanner may read the
        run as clean; ``ScannerExecutor`` reports the scan as ERROR from this
        instead, whatever ``scan()`` made of it.
        """
        return self._scan_post_run_error

    def clear_scan_post_run_error(self) -> None:
        """Forget a recorded post-run error. ``ScannerExecutor`` calls this before
        each ``scan()``, as it does ``clear_scan_spawn_failure``."""
        self._scan_post_run_error = None

    def _post_run_error_state(self, response: Dict) -> None:
        """Set the post-run-error state from ``response``: the pure half of
        _record_post_run_error, shared with _run_subprocess's handler."""
        if not isinstance(response, dict) or response.get("post_run_error") is not True:
            return
        self._scan_post_run_error = _response_text(
            response, ("error",), "the run's output could not be recorded"
        )

    def _record_post_run_error(self, response: Dict) -> None:
        # State before the log, like _record_spawn_failure.
        if not isinstance(response, dict) or response.get("post_run_error") is not True:
            return
        self._post_run_error_state(response)
        # Redacted as the could-not-start line is: a tool that ended on a signal
        # before ASH's own failure leads the error with "<command> ended on ...",
        # and the command can carry a value the config read from the environment.
        # The recorded state keeps it as the runner gave it.
        read = guarded_values_read(self)
        if read.values is None:
            self._plugin_log(
                "ran, but ASH could not record its tool's output: (not shown: "
                f"the plugin's values hook {read.failure()})",
                level=logging.ERROR,
            )
            return
        self._plugin_log(
            text_without_values(
                "ran, but ASH could not record its tool's output: "
                f"{self._scan_post_run_error}",
                read.values,
            ),
            level=logging.ERROR,
        )

    @property
    def scan_kept_flag(self) -> Tuple[str, str] | None:
        """The flag, and its reason, of this plugin's last run that did not finish,
        or None.

        Set by ``_run_subprocess`` from the response it returns: timed_out,
        cancelled, result_rejected or signaled. Each says the tool's output is
        not the whole scan, so ``ScannerExecutor`` reports the scan as ERROR from
        this, whatever ``scan()`` made of the run.

        ``_process_command_response`` also sets ``signaled`` for a response that
        hands over a bare negative return code with no flag, worded without an
        attribution. It does not when the response carries ``post_run_error``:
        the runner leaves ``signaled`` out there when ASH's own stop may have
        sent the signal, so no cause is named for that ending and
        ``scan_post_run_error`` grades the scan instead.
        """
        return self._scan_kept_flag

    def clear_scan_kept_flag(self) -> None:
        """Forget a recorded flag. ``ScannerExecutor`` calls this before each
        ``scan()``, as it does ``clear_scan_post_run_error``."""
        self._scan_kept_flag = None

    def _kept_flag_state(self, response: Dict) -> None:
        """Set the kept-flag state from ``response``: the pure half of
        _record_kept_flag, shared with _run_subprocess's handler so the grade
        lands even when the recorder itself raised."""
        if not isinstance(response, dict):
            return
        for flag in _UNFINISHED_RUN_FLAGS:
            if response.get(flag) is True:
                self._scan_kept_flag = (
                    flag,
                    _response_text(response, ("error",), f"the run ended {flag}"),
                )
                return

    def _record_kept_flag(self, response: Dict) -> None:
        self._kept_flag_state(response)

    @property
    def scan_could_not_stop(self) -> str | None:
        """The recorded reason this plugin's last run ended with a tool ASH could
        not stop, or None.

        Set by ``_run_subprocess`` from the run's recorded state alone: the
        response's ``could_not_stop`` key, or the shape the runner gives such an
        ending (the timeout kept with no exit code). The response's text is never
        read for it, so a tool printing the same words cannot set it, and a
        reason that cannot be read cannot drop it. The tool may still be running
        and can write into the output directory after the report is read, so
        ``run_ash_scan`` fails the run on this whatever
        ``fail_on_incomplete_scanners`` says.
        """
        return self._scan_could_not_stop

    @property
    def scan_could_not_stop_runs(self) -> Dict[str, str]:
        """Every run of this plugin's current ``scan()`` whose stop failed: the
        flag the run ended with (``timed_out``, ``cancelled``,
        ``result_rejected``, ``signaled``; ``post_run_error`` for a wait that
        failed after the tool ran; ``unflagged`` for a response that recorded
        only the failed stop) mapped to the reason recorded for it.

        ``scan_could_not_stop`` keeps the most recent of these reasons alone, so
        when one ``scan()`` launched its tool more than once it cannot say WHICH
        run ASH could not stop: a first launch that timed out and was killed,
        then a second that was cancelled and could not be stopped, left one
        record, and the timeout headline read it as the timed-out tool still
        running. A reader that attributes a failed stop to a run reads this
        mapping instead (``"timed_out" in scan_could_not_stop_runs``). Cleared
        with ``clear_scan_could_not_stop``. A copy: a reader cannot change it.
        """
        return dict(self._scan_could_not_stop_runs)

    def clear_scan_could_not_stop(self) -> None:
        """Forget a recorded could-not-stop ending, and the per-run records with
        it. ``ScannerExecutor`` calls this before each ``scan()``, as it does
        ``clear_scan_kept_flag``."""
        self._scan_could_not_stop = None
        self._scan_could_not_stop_runs = {}

    def _could_not_stop_state(self, response: Dict) -> None:
        """Set the could-not-stop state from ``response``: state only, shared with
        _run_subprocess's handler like the other pure state steps.

        Two recorded signals say it, and only these: the ``could_not_stop`` key a
        runner's response carries, and the shape the runner gives this ending --
        ``timed_out`` with no exit code, since a timeout whose stop worked always
        has one (TIMEOUT_RETURNCODE, or run_command's -1). Nothing here matches
        text.
        """
        if not response_could_not_stop(response):
            return
        # The reason is the response's own error. When that text is missing or
        # unreadable, the fallback still names the process ASH left running,
        # from the pid the response carries as data beside the flag. Writing the
        # shared marker here keeps the wording one string; nothing parses it.
        default = could_not_stop_default(response.get("could_not_stop_pid"))
        reason = _response_text(response, ("error",), default)
        # The runner keeps the returned error raw and redacts only what it
        # logs itself; this recorder is where the text is KEPT -- the executor
        # copies it verbatim onto the published result container -- so the
        # run's values are hidden here. A guarded read, per _values_to_redact's
        # rule for record paths: a hook that raised or gave no usable answer
        # degrades to the value-free pid fallback, never to the raw text an
        # empty value set would print.
        values = guarded_values(self)
        recorded = default if values is None else text_without_values(reason, values)
        self._scan_could_not_stop = recorded
        # Kept per run as well, under the flag this run ended with, so a reader
        # can tell which run's stop failed when scan() launched more than once.
        self._scan_could_not_stop_runs[_could_not_stop_run_key(response)] = recorded

    def _record_could_not_stop(self, response: Dict) -> None:
        self._could_not_stop_state(response)

    def _record_response(
        self,
        response: Dict,
        timeout: float | None,
        invoked: Set[str],
        guard: bool = False,
    ) -> None:
        """Run each recorder once for ``response``.

        Each is named in ``invoked`` before its call, so a recorder that raises
        counts as run and is never called again for this response: its report
        was given twice, and a recorder raising at every call escaped the
        handler through its second call. Outside ``guard`` a recorder that
        raised is also named in ``invoked`` by ``_raised_key``, for the handler
        that catches the raise to tell it from one that finished. Under
        ``guard``, for the handler, a recorder that raises stays inside this
        call, with its error added to the response's reason once.

        Recording a response retires its processed mark: once recorded, the
        response is done with, and the mark must not outlive it.
        """
        self._forget_processed(response)
        for name, record in (
            ("timeout", lambda: self._record_timeout(response, timeout)),
            ("spawn_failure", lambda: self._record_spawn_failure(response)),
            ("post_run_error", lambda: self._record_post_run_error(response)),
            ("kept_flag", lambda: self._record_kept_flag(response)),
            ("could_not_stop", lambda: self._record_could_not_stop(response)),
        ):
            if name in invoked:
                continue
            invoked.add(name)
            if not guard:
                try:
                    record()
                except BaseException:
                    # Remembered beside the name for the handler that catches
                    # this: a recorder that raised has had its one call, and
                    # must not be given a second by a handler that wants the
                    # ones the raise skipped (see _raised_key).
                    invoked.add(_raised_key(name))
                    raise
                continue
            try:
                record()
            except Exception as again:
                earlier = response.get("error")
                # Redacted as the handler redacted the error it is added to,
                # through the one guarded read: a hook that raised or gave no
                # usable answer leaves only the error's class and a note.
                read = guarded_values_read(self)
                addition = (
                    error_text(again, read.values)
                    if read.values is not None
                    else (
                        f"{type(again).__name__} (text not shown: the plugin's "
                        f"values hook {read.failure()})"
                    )
                )
                response["error"] = f"{earlier}; {addition}" if earlier else addition

    def _carry_stderr_log(
        self, post_run: Dict, log: Path, environment_values: Sequence[str]
    ) -> None:
        """Put the run's stderr, read back from its log, into ``post_run``.

        ASH's own failure is when the tool's diagnostics matter, and under
        "write" the run's response holds none. Read without following a link,
        since a process the sandboxed scanner left running may have replaced the
        log, and bounded by _STDERR_LOG_READ_LIMIT. A read that fails is named
        in the error and raises nothing: this runs in _run_subprocess's handler.

        ``environment_values`` are the enclosing handler's ONE guarded read of
        the values hook: reading the hook again here could raise inside that
        handler, and a guard of its own could only produce a note claiming a
        read that was never attempted. The parameter has NO default: a record
        path must never degrade to an empty value set because a caller forgot
        to pass what the handler read, so forgetting is a TypeError.
        """
        # A uv run's inputs join the trim: the sinks hide them whole, so a
        # cut just after a glued extra's value is the same edge piece a value
        # split leaves. Only for a plugin that runs through uv, as the report
        # lines read them (_process_command_response): for any other the
        # accessor still answers the command's own name, and the trim would
        # drop a cut log's last characters for starting like it. The accessor
        # is the best-effort one and never raises, but an override can answer
        # None (no inputs) or raise, and this runs in a handler: the trim then
        # has the values alone, as the mixin's own fallback does.
        inputs: Tuple[str, ...] = ()
        if getattr(self, "use_uv_tool", False):
            inputs_for_records = getattr(self, "_uv_run_inputs_for_records", None)
            if callable(inputs_for_records):
                try:
                    inputs = tuple(inputs_for_records() or ())
                except Exception:  # noqa: BLE001 -- an overridable accessor
                    inputs = ()
        try:
            # The one bounded read (read_log_bounded): bound + 1 so a cut is
            # known, and a cut tail trimmed past anything it could have
            # split. The carried text stays the tool's own (the sinks redact
            # it), so nothing is redacted here.
            text, cut = read_log_bounded(
                log, _STDERR_LOG_READ_LIMIT, environment_values, inputs
            )
        except Exception as read_error:
            # Redacted as the handler redacted the error it is added to.
            post_run["error"] = (
                f"{post_run['error']}; its stderr log could not be read: "
                f"{error_text(read_error, environment_values)}"
            )
            return
        if cut:
            text += " ...[truncated]"
        if text:
            post_run["stderr"] = text

    def _timeout_limit_token(
        self, limit: float | None, values: Optional[Sequence[str]] = None
    ) -> str:
        """The scan_timeout limit as a timeout message prints it:
        ``error_text.timeout_limit_token`` over this plugin's environment
        values. One token for every timeout message, the executor's included,
        so the sites cannot drift.

        ``values`` is the caller's own guarded read of the values hook, for a
        message that also redacts with them: the message then reads the hook
        once, and the token and the redaction cannot disagree. Without it the
        hook is read here, once, guarded: a hook that raised or gave no usable
        answer leaves nothing to tell whether an environment value typed the
        limit, so the token names the option and prints no number, the form it
        takes when one did. A caller that redacts with the hook's values
        itself and does not pass them reads the hook a second time, unguarded."""
        if values is not None:
            return timeout_limit_token(limit, values)
        read = guarded_values_read(self)
        if read.values is None:
            return _LIMIT_TOKEN_WITHOUT_A_NUMBER
        return timeout_limit_token(limit, read.values)

    def _record_timeout(self, response: Dict, timeout: float | None) -> None:
        """Name the scanner and the limit when its tool was killed at the timeout.

        ``run_command_with_output_handling`` already logs the command that timed
        out, but not which scanner it belonged to, and a scanner that swallows
        the failure leaves that line as the only trace.
        """
        if not isinstance(response, dict) or response.get("timed_out") is not True:
            return
        self._scan_timed_out_after = timeout
        # The limit through the shared token (_timeout_limit_token): a quoted
        # whole number, which redact_values replaces only where the text quotes
        # it whole, never inside "60s", or the option's name where the
        # environment wrote the limit in another spelling. "Was killed" only
        # when the stop worked, read from the response's recorded state (the
        # same test _could_not_stop_state records through): a stop that failed
        # left the tool running, and this line must not say it is gone.
        ending = (
            COULD_NOT_STOP_ENDING
            if response_could_not_stop(response)
            else WAS_KILLED_ENDING
        ) + "."
        # The ONE guarded read for this record line: a hook that raised or
        # gave no usable answer cannot abort the line. Without the values
        # neither the limit nor the scanner's name can be shown safely, so
        # a value-free note takes their place.
        read = guarded_values_read(self)
        if read.values is None:
            self._plugin_log(
                f"timed out{ending} The limit is not shown: the plugin's "
                f"values hook {read.failure()}. Raise the scanner's "
                "scan_timeout option if this target legitimately needs longer.",
                level=logging.ERROR,
            )
            return
        limit = timeout_limit_token(timeout, read.values)
        self._plugin_log(
            text_without_values(
                f"timed out after {limit}{ending} Raise "
                f"scanners.{getattr(self.config, 'name', '<scanner>')}.options."
                "scan_timeout if this target legitimately needs longer.",
                read.values,
            ),
            level=logging.ERROR,
        )

    def _run_subprocess(
        self,
        command: List[str],
        results_dir: str | Path | None = None,
        stdout_preference: Literal["return", "write", "both", "none"] = "write",
        stderr_preference: Literal["return", "write", "both", "none"] = "write",
        cwd: Path | str | None = None,
        env: Dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> Dict[str, Any]:
        """Run a subprocess with the given command.

        This method supports both direct command execution and UV tool execution
        based on the use_uv_tool flag. When UV tool execution is enabled, the
        plugin's own command runs via 'uv tool run'; if uv cannot run it, the
        response reports that the tool could not start (``spawn_failed``), and no
        other copy of the tool runs in its place.

        Args:
            command: Command to run
            results_dir: Directory to write output files to
            stdout_preference: How to handle stdout
            stderr_preference: How to handle stderr
            cwd: Working directory for the command (defaults to context.source_dir)
            env: Environment variables for the child process. When None, the
                child inherits the parent env. Pass a local dict (e.g.
                ``{**os.environ, "MY_VAR": "v"}``) to add/override vars
                without mutating the parent process ``os.environ`` — this
                matters because scanners run in parallel threads and share
                the parent env.

        Returns:
            Dictionary with stdout and stderr if requested
        """
        from automated_security_helper.utils.subprocess_utils import (
            SPAWN_FAILURE_RETURNCODE,
            run_command_with_output_handling,
            spawn_failure_message,
        )

        # Set once a run returned a response, so the handler below can tell an
        # exception from before the command ran from one while reading its result.
        response: Dict | None = None
        # The recorders already run for this response (_record_response), so none
        # runs twice, in the handler below included.
        invoked: Set[str] = set()
        # Where the run writes its stderr under "write" and "both", and that file
        # as it was before the run: the handler below reads back only a log this
        # run wrote, not one an earlier command of the scan left there.
        stderr_log = (
            Path(results_dir) / f"{self.__class__.__name__}.stderr.log"
            if results_dir is not None and stderr_preference in ("write", "both")
            else None
        )
        stderr_log_before = _log_identity(stderr_log)
        try:
            # Use provided cwd or fall back to context.source_dir
            working_dir = cwd if cwd is not None else Path(self.context.source_dir)

            # Offline, the tool's own update, version and telemetry checks are
            # turned off in the environment it gets (utils/offline_tool_env.py).
            # Asked of the scanner, so a scanner whose own `offline` option is set
            # gets them while the rest of the run is online.
            scanner_offline = getattr(self, "_scanner_offline", None)
            env = with_offline_tool_environment(
                env, scanner_offline() if callable(scanner_offline) else None
            )

            # A uv command started in the scanned tree (`uv pip ...`, `uv run ...`)
            # runs the tree's .venv python and builds its project unless told not
            # to; see utils/python_child.uv_child_overrides.
            from automated_security_helper.utils import python_child

            # The choice of interpreter is read from the environment the child
            # gets (``env``, this process's when None): an interpreter the
            # caller named there is theirs, and replacing it with ASH's would
            # run the tool on another Python than the one the caller asked for.
            # uv_child_overrides applies its own reading of UV_SYSTEM_PYTHON
            # (a "0" or "false" is no choice), so that is not redone here.
            #
            # Except an interpreter inside the scanned tree: the tree's own
            # .venv python is what these overrides exist to keep uv from
            # finding, and an env a scanner assembled (its extra_env merged over
            # this process's) is not known to be the operator's alone. Such a
            # UV_PYTHON is dropped before the choice is read, so ASH's
            # interpreter is set in its place.
            if _uv_interpreter_inside(env, working_dir, Path(self.context.source_dir)):
                # Said once per plugin, as a warning: the operator or the scan's
                # config set a variable that is not honored, and one line per
                # tool run would repeat it for every run. The value is not shown.
                if not self._warned_in_tree_uv_python:
                    self._warned_in_tree_uv_python = True
                    self._plugin_log(
                        "Ignoring a UV_PYTHON that names an interpreter inside the "
                        "scanned tree; it is not passed to the tool.",
                        level=logging.WARNING,
                    )
                env = {
                    key: value
                    for key, value in (
                        snapshot_environ() if env is None else env
                    ).items()
                    if key != "UV_PYTHON"
                }
            uv_overrides = python_child.uv_child_overrides(command, env)
            if uv_overrides:
                child_env = snapshot_environ() if env is None else env
                env = {**child_env, **uv_overrides}

            # The ONE guarded read of the overridable values hook for this run
            # (_values_to_redact's guarding rule). The runner prints the command
            # line and the timeout limit with these, and the uv path reads them
            # for its records. A hook that raised, or answered something that is
            # no value set, gives nothing to redact with, and the runner read
            # such an answer as "no values" and logged the command line in clear.
            # The run is refused instead, as the uv path refuses it, and recorded
            # as a tool that never started; the refusal names the hook.
            values_read = guarded_values_read(self)
            if values_read.values is None:
                hook_failure = (
                    f"the plugin's values hook {values_read.failure()}, so the "
                    "run's records could not be redacted"
                )
                refused_run: Dict = {
                    "stdout": "",
                    "stderr": (
                        f"{self.command or 'The tool'} was not run: {hook_failure}."
                    ),
                    "returncode": SPAWN_FAILURE_RETURNCODE,
                    "spawn_failed": True,
                    "error": hook_failure,
                }
                response = refused_run
                self._process_command_response(refused_run)
                self._record_response(refused_run, timeout, invoked)
                return refused_run
            run_values: Tuple[str, ...] = values_read.values

            # Attempt UV tool execution if enabled
            if self.use_uv_tool and self.command and len(command) > 0:
                # Check if the first element of the command is our tool command
                if command[0] == self.command:
                    # timeout has to be handed to this path too, not just to the
                    # direct-execution call below. This branch returns, so a
                    # timeout passed only below would apply exclusively to
                    # scanners for which uv is unavailable. bandit, checkov and
                    # semgrep all set use_uv_tool=True unconditionally and only
                    # clear it when uv is missing, and ASH ships via uv -- so on a
                    # normal install the reported bandit hang went through here,
                    # unbounded, no matter what scan_timeout said.
                    uv_result = self._try_uv_tool_execution(
                        command,
                        working_dir,
                        results_dir=Path(results_dir) if results_dir else None,
                        stdout_preference=stdout_preference,
                        stderr_preference=stderr_preference,
                        env=env,
                        timeout=timeout,
                        values=run_values,
                    )
                    if uv_result is not None:
                        response = uv_result
                        # Processed exactly once. The uv path hands a run that
                        # returned to _process_command_response itself, but a
                        # failure after its child started, or a response whose
                        # building raised, comes back unprocessed: the child's
                        # exit code and stderr then never reached exit_code and
                        # errors, so a scanner reading those judged such a run
                        # accepted and reported none of the tool's text.
                        if not self._was_processed(uv_result):
                            self._process_command_response(uv_result)
                        self._record_response(uv_result, timeout, invoked)
                        return uv_result
                    # uv could not run it, and nothing runs in its place: the tool
                    # on PATH was never checked against the scanner's requirement.
                    # The scan reports that its tool could not start.
                    failure = self._uv_run_failure or "uv could not run it"
                    refused: Dict = {
                        "stdout": "",
                        "stderr": (
                            f"{self.command} could not run through uv: {failure}. "
                            f"The {self.command} on PATH was not checked against "
                            "the scanner's requirement, so it is not run in its "
                            "place."
                        ),
                        "returncode": SPAWN_FAILURE_RETURNCODE,
                        "spawn_failed": True,
                        "error": failure,
                    }
                    response = refused
                    self._process_command_response(refused)
                    self._record_response(refused, timeout, invoked)
                    return refused

            # Run the command using the centralized utility (direct execution)
            response = run_command_with_output_handling(
                command=command,
                results_dir=results_dir,
                stdout_preference=stdout_preference,
                stderr_preference=stderr_preference,
                cwd=working_dir,
                env=env,
                shell=False,
                class_name=self.__class__.__name__,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                # The runner logs its own timeout line, and prints the limit
                # with these: a limit read from the environment never reaches it.
                values=run_values,
            )

            self._process_command_response(response)
            self._record_response(response, timeout, invoked)

            return response

        except Exception as e:
            # The ONE guarded read of the values hook for this handler
            # (_values_to_redact's guarding rule). Read bare here, a hook that
            # raised raised again out of the handler that was meant to record
            # the run's failure, and one that answered no value set printed the
            # error's text in clear; without the values the records below keep
            # only the error's class and a note saying why.
            read = guarded_values_read(self)
            environment_values: Tuple[str, ...] = read.values or ()
            withheld: str | None = None
            if read.values is None:
                withheld = (
                    f"{type(e).__name__} (text not shown: the plugin's values "
                    f"hook {read.failure()})"
                )
                ASH_LOGGER.debug(f"({_log_name(self)}) Full error details: {withheld}")
            else:
                # Show the full stack trace in debug, redacted: ``exc_info=True``
                # would append the raw traceback, whose last line repeats the
                # exception's message with any configured value in it.
                ASH_LOGGER.debug(
                    f"({_log_name(self)}) Full error details: "
                    f"{error_text(e, environment_values)}\n"
                    f"{traceback_text(e, values=environment_values)}"
                )
            if response is None:
                # Raised before any run returned, so the command never ran: recorded
                # as a spawn failure the OS refused is, and ScannerExecutor reports
                # ERROR from it. This answered exit code 1, which most scanners
                # accept as "ran and found issues", so one that ignores the
                # response was reported PASSED.
                # Without the values the command line is not quoted (an
                # argument can carry a value the config read from the
                # environment): the stderr names the tool and the note.
                spawn_failure: Dict = {
                    "error": withheld or error_text(e, environment_values),
                    "returncode": SPAWN_FAILURE_RETURNCODE,
                    "spawn_failed": True,
                    "stderr": (
                        spawn_failure_message(" ".join(map(str, command)), e)
                        if withheld is None
                        else (
                            f"Could not start {self.command or 'the tool'}: "
                            f"{withheld}. The command never ran "
                            f"(exit code {SPAWN_FAILURE_RETURNCODE})."
                        )
                    ),
                }
                # ASH's own handling of this response can raise too (an
                # override of the seams it calls), and this is the handler
                # that records the failure: each step stays inside it, as the
                # post-run arm's recorders do. A step that raised leaves its
                # error on the response's reason, and the spawn failure's code
                # and state land whatever it did.
                try:
                    self._process_command_response(spawn_failure)
                except Exception as again:  # noqa: BLE001 -- see above
                    self._forget_processed(spawn_failure)
                    self.exit_code = _folded_exit_code(
                        self, self.exit_code, SPAWN_FAILURE_RETURNCODE
                    )
                    spawn_failure["error"] = (
                        f"{spawn_failure['error']}; "
                        f"{_error_text_read_once(again, read)}"
                    )
                try:
                    self._record_spawn_failure(spawn_failure)
                except Exception as again:  # noqa: BLE001 -- see above
                    self._spawn_failure_state(spawn_failure)
                    spawn_failure["error"] = (
                        f"{spawn_failure['error']}; "
                        f"{_error_text_read_once(again, read)}"
                    )
                return spawn_failure
            # A run returned and ASH's own handling of its response raised. The
            # response already assembled is kept: its exit code (None for a tool
            # ASH stopped, never made a number), and the flag that says what
            # happened, so a timeout stays a timeout. The handling error is added
            # to its error. A response with no flag gets post_run_error: the tool
            # ran, so it is no spawn failure, and exit code 1 with only an "error"
            # would let a scanner that ignores the response report PASSED.
            post_run: Dict = dict(response)
            earlier = response.get("error")
            described = withheld or error_text(e, environment_values)
            # ``earlier`` is the response's own error text, so the joined text
            # is redacted whole: the run's error can carry a configured value
            # too, and this field is copied into the recorded post-run error,
            # the executor's report and the results file. Without the values
            # (``withheld``) nothing could redact it, and the runner keeps it
            # raw, so it is left out and the note stands alone, as the other
            # records of this handler do.
            post_run["error"] = text_without_values(
                f"{earlier}; {described}"
                if earlier and withheld is None
                else described,
                environment_values,
            )
            if not any(response.get(flag) is True for flag in RESPONSE_FLAGS):
                post_run["post_run_error"] = True
                post_run["spawn_failed"] = False
                # The post-run recorder may have run already, as a no-op on the
                # response as it was (a later recorder raised before the flag
                # was added). It is called for the flagged copy, or its line
                # and errors entry are never written. Not when it raised: that
                # raise is the error this handler caught, and a second call
                # would raise it again, with the recorder's side effects and
                # its text on the response's reason twice.
                if _raised_key("post_run_error") not in invoked:
                    invoked.discard("post_run_error")
            # The tool's stderr: what the run returned, or under "write", where the
            # run returns none, its stderr log read back.
            # Not carried without the values: the log holds the tool's text in
            # clear, and _carry_stderr_log takes this handler's one guarded
            # read rather than reading the hook again.
            if (
                withheld is None
                and not post_run.get("stderr")
                and (
                    stderr_log is not None
                    and _log_identity(stderr_log) not in (None, stderr_log_before)
                )
            ):
                self._carry_stderr_log(post_run, stderr_log, environment_values)
            returncode = post_run.get("returncode")
            if not is_exit_code(returncode):
                # A flagged run that carries no code (stopped, could not be
                # stopped, cancelled, never spawned) is graded by its flag's
                # own conventional code here too, so a raise between the run
                # and its records does not leave the default looking accepted.
                # A bool is no code either: it passes a bare isinstance(int),
                # and False then recorded as an accepted-looking 0.
                returncode = flagged_returncode(post_run)
            if is_exit_code(returncode):
                self.exit_code = _folded_exit_code(self, self.exit_code, returncode)
            # Recorded by the flag the response keeps, so the scan is graded by
            # it. Each recorder runs at most once for a response, the ones the
            # raise skipped run now, and under guard a recorder that raises again
            # stays inside this handler, with its error added once. Each
            # recorder sets its state before it logs, so the state lands even
            # when the log raises.
            self._record_response(post_run, timeout, invoked, guard=True)
            # A recorder can have raised before setting its state (a patched or
            # overridden one sets nothing), and the scan is graded by that
            # state: each pure state step runs directly when its state is still
            # unset, never the recorder a second time.
            if post_run.get("timed_out") is True and self._scan_timed_out_after is None:
                self._scan_timed_out_after = timeout
            if self._scan_spawn_failure is None:
                self._spawn_failure_state(post_run)
            if self._scan_post_run_error is None:
                self._post_run_error_state(post_run)
            if self._scan_kept_flag is None:
                self._kept_flag_state(post_run)
            # Unset for THIS run: a second launch whose stop failed has its own
            # key, so an earlier run's record does not stand in for it.
            if (
                self._scan_could_not_stop is None
                or _could_not_stop_run_key(post_run)
                not in self._scan_could_not_stop_runs
            ):
                self._could_not_stop_state(post_run)
            return post_run

    def get_installation_commands(self, platform: str, arch: str) -> List[List[str]]:
        """Generate installation commands for the specified platform/architecture as arrays of arguments"""
        commands = []

        # Process standard dependencies
        if platform in self.dependencies and arch in self.dependencies[platform]:
            for dep in self.dependencies[platform][arch]:
                # Normalised so a plugin that declares the raw string ("conda") and one
                # that declares the member (PackageManager.CONDA) take the same path. A
                # value that is not a member at all raises here, naming the value.
                package_manager = PackageManager(dep.package_manager)

                if package_manager in _NO_INSTALL_COMMAND_PACKAGE_MANAGERS:
                    # Installed through custom_install_commands, not from here.
                    continue

                builder = _INSTALL_COMMAND_BUILDERS.get(package_manager)
                if builder is None:
                    # Reachable only for a PackageManager member added without a
                    # builder. Refused rather than skipped: returning no command for a
                    # declared dependency lets the install report success and defers the
                    # failure to scan time, where it appears as a scanner reported
                    # MISSING and names neither the dependency nor the manager.
                    raise ToolNotProvisionableError(
                        f"{self.__class__.__name__} declares dependency "
                        f"'{dep.name}' with package manager "
                        f"'{package_manager.value}', which ASH has no install "
                        f"command for. Add a renderer to "
                        f"_INSTALL_COMMAND_BUILDERS, or list the member in "
                        f"_NO_INSTALL_COMMAND_PACKAGE_MANAGERS if it is installed "
                        f"through custom_install_commands."
                    )

                commands.append(builder(dep))

        # Add UV tool installation commands if available
        if self.use_uv_tool and self.uv_tool_install_commands:
            for install_cmd in self.uv_tool_install_commands:
                # Convert string command to list of arguments
                if isinstance(install_cmd, str):
                    commands.append(install_cmd.split())
                else:
                    commands.append(install_cmd)

        # Add custom installation commands
        if (
            platform in self.custom_install_commands
            and arch in self.custom_install_commands[platform]
        ):
            for cmd in self.custom_install_commands[platform][arch]:
                commands.append(cmd.args)

        return commands
