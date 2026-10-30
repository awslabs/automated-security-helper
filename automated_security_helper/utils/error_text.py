# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An error's text for the console, a log, a report or an MCP payload.

pydantic's own text for a ValidationError quotes every refused input
(``input_value='...'``), and a config value can be a secret read from the
environment. Every place that shows an error it did not raise itself, where
that error can be or wrap a ValidationError, shows ``error_text(error)``
rather than ``str(error)``, and logs an unexpected one with
``log_unexpected_error``. ``describe_validation_error`` is the one
description: the field and the problem, with no input.

An OSError's own text quotes its file by repr, which writes a control as the text
of its escape and doubles each backslash, and every sink that prints to a
terminal shows its text again (utils/terminal_text.py's shown_not_obeyed), so a
name was shown twice: an ESC in an output directory printed as two backslashes
before ``x1b``, and each backslash of a Windows path as two. Both functions here
give the file names back as given, inside the quotes Python put around them.

Both functions also remove every complete escape sequence from the text they
return, with values to hide or without: the text is saved into results, reports
and MCP payloads, and a sequence in an exception's message (a file name a
repository chose) must not reach them. ``text_without_values`` is the layer that
keeps codes where none hid a value, for streams a terminal shows.
"""

from __future__ import annotations

import os
import re
import sys
import traceback
from typing import Any, Iterable, Iterator, List, Optional, Set, Tuple, Union

from pydantic import ValidationError

# The one normalizer every entry here reads a caller's ``values`` through: a
# bare string is one value, never its characters. redacted_model imports
# nothing from this module at import time, so this import cannot cycle.
from automated_security_helper.utils.redacted_model import environment_strings


def _chain(error: BaseException) -> Iterator[BaseException]:
    """``error`` and each error it was raised from or during, ``error`` first.

    Both links are followed: ``raise ... from other`` inside an ``except``
    block fills the raised-from link (``__cause__``) with ``other`` and leaves
    the error being handled on the raised-during link (``__context__``), so
    taking one link alone would miss the other's branch. Raised-from first,
    each error once.

    ``__suppress_context__`` is ignored on purpose: the chain is read to find
    inner errors whose text an outer message quotes, so their inputs can be
    replaced. Of a suppressed member's own words, only input-free parts are
    printed, a ValidationError's titles and field descriptions; an unsuppressed
    member's words, other than a ValidationError's, are also printed whole by
    traceback_text and log_unexpected_error. Reading a suppressed
    context only adds redaction; honoring the flag would leave the quote of a
    ValidationError raised ``from None`` unredacted. Python's own renderers
    already honor the flag, so a ``from None`` refusal prints without its
    context everywhere.

    An exception group's members are walked too, each with its own chain:
    Python's renderers print every member's message, so a ValidationError
    inside a group is quoted with its inputs unless it is found here."""
    seen: Set[int] = set()
    pending: List[Optional[BaseException]] = [error]
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        pending.append(current.__context__)
        pending.append(current.__cause__)
        # getattr's default covers AttributeError alone; an error whose lookup
        # raises something else (a proxying error class) names no group, and a
        # printer that raised here would replace the error it was printing, as
        # carried_environment_values says of its carried-values read.
        try:
            members = getattr(current, "exceptions", None)
        except Exception:  # noqa: BLE001 -- whatever the error's lookup raised
            members = None
        if isinstance(members, tuple):
            pending.extend(
                member for member in members if isinstance(member, BaseException)
            )


def _own_text(error: BaseException) -> str:
    """``str(error)``, or a line naming its type when its own ``__str__`` raises.

    The printers here report an error; one whose message cannot be rendered
    must not replace the error it is reporting with the renderer's own.
    """
    try:
        return str(error)
    except Exception:  # noqa: BLE001 -- whatever the error's __str__ raised
        return f"<{type(error).__name__}: its message could not be rendered>"


def _with_carried_values(error: BaseException, values: Iterable[str]) -> List[str]:
    """*values*, then the values each error in ``error``'s chain carries, each once.

    The ``values`` every printer here redacts with: the caller's, and those
    :func:`carry_environment_values` recorded. Read by the printers themselves,
    so one that passes no values, or one written without knowing of the
    carrier, still hides what the run read from the environment. The whole
    chain, as ``_chain`` walks it, because a wrapper raised from the carrier
    can quote its text.
    """
    merged = dict.fromkeys(environment_strings(values))
    for current in _chain(error):
        merged.update(dict.fromkeys(carried_environment_values(current)))
    return list(merged)


def caused_by(error: BaseException, kinds: Union[type, Tuple[type, ...]]) -> bool:
    """Whether ``error`` is, or was deliberately raised from, one of ``kinds``.

    The raised-from link only (``__cause__``): what a handler chained with
    ``raise ... from``, not whatever happened to be handled when it was raised,
    which is the wider walk ``_chain`` makes for display. With a seen set,
    because ``raise e from e`` makes the chain a cycle (``e.__cause__ is e``)
    and a bare walk never ends; in an MCP request handler that is a hung
    request, not an error.
    """
    seen: Set[int] = set()
    current: Optional[BaseException] = error
    while current is not None and id(current) not in seen:
        if isinstance(current, kinds):
            return True
        seen.add(id(current))
        current = current.__cause__
    return False


def validation_errors_in(error: BaseException) -> List[ValidationError]:
    """The pydantic ValidationErrors in ``error``'s chain, ``error`` first."""
    return [
        current for current in _chain(error) if isinstance(current, ValidationError)
    ]


def _files_quoted(error: OSError) -> Optional[Tuple[str, str]]:
    """The end of ``str(error)`` that quotes its files, and that end with them as given.

    None for an error naming no file, or one Python did not name as a string.
    """
    filename, filename2 = error.filename, error.filename2
    if not isinstance(filename, str) or not isinstance(filename2, (str, type(None))):
        return None
    # Inside the quotes repr chose: double quotes around a name that holds a
    # single quote and no double quote, single quotes otherwise. Single quotes
    # written in every case left such a name between mismatched quotes.
    quoted, given = f": {filename!r}", f": {_quoted_as_given(filename)}"
    if filename2 is not None:
        quoted = f"{quoted} -> {filename2!r}"
        given = f"{given} -> {_quoted_as_given(filename2)}"
    return quoted, given


def _quoted_as_given(name: str) -> str:
    """*name* as given, between the quote characters ``repr`` puts around it."""
    quote = repr(name)[0]
    return f"{quote}{name}{quote}"


def _files_as_given(error: BaseException, text: str) -> str:
    """*text* with each OSError's own text in ``error``'s chain naming its files as given.

    Only Python's own text is changed: an error whose class writes its own
    ``__str__`` is left as it is, even where that text ends the same way.
    """
    for current in _chain(error):
        if (
            not isinstance(current, OSError)
            or type(current).__str__ is not OSError.__str__
        ):
            continue
        quoted = _files_quoted(current)
        own = str(current)
        if quoted is None or not own.endswith(quoted[0]):
            continue
        text = text.replace(own, own[: -len(quoted[0])] + quoted[1])
    return text


def _counted(error: ValidationError) -> str:
    """How pydantic's own text heads a ValidationError: ``1 validation error for
    AshConfig``. The title is the model's name, never an input."""
    count = error.error_count()
    return f"{count} validation error{'' if count == 1 else 's'} for {error.title}"


#: In place of an error's message that quotes a ValidationError's entries with
#: an input in a form no replacement reaches.
MESSAGE_WITHHELD = (
    "its message is not shown: it repeats a refused value in another form"
)


def _without_refused_inputs(
    text: str, validation_error: ValidationError, described: str
) -> "tuple[str, bool]":
    """``text``, which may quote ``validation_error``, with no input of it: its
    own text replaced by ``described``, and a quote of its entries
    (``e.errors()``, ``e.json()``) with each input replaced as a model error's
    message replaces it. And whether a changed form of an input is still there.
    """
    from automated_security_helper.config.config_validator import (
        redact_refused_input,
    )

    text = text.replace(str(validation_error), described)
    return redact_refused_input(text, validation_error.errors())


def _described(error: BaseException, values: Iterable[str], counted: bool) -> str:
    # Imported here: the config package imports utils at start-up.
    from automated_security_helper.config.config_validator import (
        describe_validation_error,
    )

    values = list(environment_strings(values))
    text = _own_text(error)
    descriptions: List[str] = []
    withheld = False
    for validation_error in validation_errors_in(error):
        described = describe_validation_error(validation_error, values)
        if counted:
            described = f"{_counted(validation_error)}: {described}"
        if validation_error is error:
            # Redacted as the other path is below: as written by the describer,
            # then stripped of codes and matched again, so a value an escape
            # code split in a location's text is not re-joined in clear by the
            # strip alone.
            return _without_escape_codes(
                _redacted_keeping_codes(described, values) if values else described
            )
        text, changed = _without_refused_inputs(text, validation_error, described)
        withheld = withheld or changed
        descriptions.append(described)
    if withheld:
        text = "; ".join(
            [f"{type(error).__name__} ({MESSAGE_WITHHELD})", *descriptions]
        )
    text = _files_as_given(error, text)
    # Redacted as text_without_values redacts (the raw text first, so a value
    # that itself holds codes is matched as written, then stripped and matched
    # again), and then every complete code is removed whether or not a value was
    # hidden. This text is saved into results, reports and MCP payloads, which
    # are not terminals: a code in an exception's message, such as a file name a
    # repository chose, must not reach them. The sinks that print it to a
    # terminal show what remains (utils/terminal_text.py).
    return _without_escape_codes(
        _redacted_keeping_codes(text, values) if values else text
    )


def os_error_without_named_file(e: OSError, named: "os.PathLike[str] | str") -> str:
    """``error_text(e)``, without the OSError's own filename when it names
    ``named``: a message built around it already names that file
    (``could not read <file>: ...``), so the error's copy said it twice.

    The rest of Python's own text is kept: the code as Python heads it
    (``[WinError N]`` where the error carries a Windows error code, ``[Errno N]``
    otherwise) and the second file of a two-file error (``-> 'other'``), as given.
    An error whose filename is a file descriptor (an int) names no path, so its
    text is ``error_text(e)`` as it is.
    """
    from pathlib import Path

    filename = e.filename
    if not isinstance(filename, (str, bytes, os.PathLike)):
        return error_text(e)
    try:
        name = os.fsdecode(filename)
    except TypeError:
        return error_text(e)
    if not (e.strerror and name and Path(name) == Path(named)):
        return error_text(e)
    winerror = getattr(e, "winerror", None)
    if winerror is not None:
        code = f"[WinError {winerror}] "
    elif e.errno is not None:
        code = f"[Errno {e.errno}] "
    else:
        code = ""
    text = f"{code}{e.strerror}"
    other = e.filename2
    if isinstance(other, (str, bytes, os.PathLike)):
        try:
            text = f"{text} -> {_quoted_as_given(os.fsdecode(other))}"
        except TypeError:
            pass
    return text


def error_text(error: BaseException, values: Iterable[str] = ()) -> str:
    """``str(error)``, with each ValidationError in its chain described.

    A ValidationError is replaced by its description, headed as pydantic's own
    text is (``1 validation error for AshConfig: Invalid value at 'x': ...``)
    and without any input. An error raised from one, or while handling one,
    whose message quotes it (``f"... {e}"``), has that quote replaced the same
    way. One that quotes it with neither link (raised after the ``except``
    block, say) is left as it is: the ValidationError is not in its chain
    (_chain), so nothing here can know its inputs. An OSError in the
    chain names its files as given rather than by repr (see the module's
    docstring); any other error's text is ``str(error)`` unchanged. Every
    complete escape sequence is removed from the result, since the text is kept
    in results, reports and MCP payloads.

    ``values`` are the values and keys the loaded config read from the
    environment (``AshConfig._environment_values``), where the caller has the
    config the error came from. A description names no input, but it names a
    field by its location, and a key the file read from the environment is
    the variable's value there; the whole text is redacted with them. The
    values any error in the chain carries (:func:`carry_environment_values`)
    are always added, so a caller with no config to read them from passes none.
    """
    return _described(error, _with_carried_values(error, values), counted=True)


def traceback_text(
    error: Optional[BaseException] = None, values: Iterable[str] = ()
) -> str:
    """``traceback.format_exc()``, or the traceback of ``error``, with each
    ValidationError in the chain described rather than quoting its inputs, and
    each OSError naming its files as given.

    For a stack trace a results file, a report or a log keeps. ``values`` as
    for error_text; so is the removal of every complete escape sequence.
    """
    from automated_security_helper.config.config_validator import (
        describe_validation_error,
    )

    if error is None:
        error = sys.exc_info()[1]
        if error is None:
            return traceback.format_exc()
    values = _with_carried_values(error, values)
    try:
        text = "".join(traceback.format_exception(error))
    except Exception:
        # TracebackException reads attributes off the error, the exception
        # notes among them, and before Python 3.11's guard an attribute lookup that
        # raises fails the whole formatting. The frames and the error's own
        # description still print.
        text = "".join(
            [
                "Traceback (most recent call last):\n",
                *traceback.format_tb(error.__traceback__),
                f"{type(error).__name__}: {_described(error, values, counted=True)}\n",
            ]
        )
    descriptions: List[str] = []
    withheld = False
    for validation_error in validation_errors_in(error):
        described = describe_validation_error(validation_error, values)
        text, changed = _without_refused_inputs(text, validation_error, described)
        withheld = withheld or changed
        descriptions.append(described)
    if withheld:
        # The frames, and no exception's message: one of them repeats an input
        # in a form no replacement reaches.
        text = "".join(
            [
                "Traceback (most recent call last):\n",
                *traceback.format_tb(error.__traceback__),
                f"{type(error).__name__}: {MESSAGE_WITHHELD}\n",
                *(f"  {described}\n" for described in descriptions),
            ]
        )
    text = _files_as_given(error, text)
    # Redacted and stripped as in _described: the traceback is kept in results
    # and reports, so no complete code survives it.
    return _without_escape_codes(
        _redacted_keeping_codes(text, values) if values else text
    )


def limit_text(limit: Any) -> str:
    """A limit as a timeout line prints it inside its quoted token.

    The token (``timed out after '60' s``) is what lets a limit read from the
    environment be redacted: a short number is replaced only where a line
    quotes it whole. A whole number prints whole, ``'1000000'``, never the
    ``'1e+06'`` that ``:g`` writes; a fraction as Python writes it, ``'7.5'``.
    Anything that is not a number prints as ``str()`` does.
    """
    if isinstance(limit, bool) or not isinstance(limit, (int, float)):
        return str(limit)
    if isinstance(limit, int):
        return str(limit)
    if limit.is_integer():
        return str(int(limit))
    return str(limit)


def timeout_limit_token(limit: Any, values: Iterable[str]) -> str:
    """A scan_timeout limit as a timeout message's token, one that cannot
    carry an environment-derived number. ``values`` are the run's
    environment values (``config_environment_values``).

    The quoted token ("'67' s", :func:`limit_text` writing a whole number
    whole) matches the redaction needle only when the environment wrote the
    same spelling: a value the model typed ("067" read as 67) prints Python's
    spelling, which the needle -- the text as the environment wrote it --
    never matches. So where any environment value's text types to this limit
    (``config_validator.typed_from``), the token names the option instead of
    printing any number. The needles themselves stay what they are; nothing
    matches converted spellings against text. Every timeout message prints
    its limit through this one function, so the messages cannot drift.
    """
    if limit_typed_by_a_value(limit, values):
        return "the configured scan_timeout"
    return f"'{limit_text(limit)}' s"


def limit_typed_by_a_value(limit: Any, values: Iterable[str]) -> bool:
    """Whether any environment value's text types to this limit.

    A caller that must follow the same rule as :func:`timeout_limit_token`
    (to keep a machine-readable copy of the limit out of a context when the
    message hides it) asks this, rather than inspecting the token's text.
    """
    values = environment_strings(values)
    if not values:
        return False
    # Imported here, and only when there is a value to compare: the config
    # package imports this module at start-up, and a call with no values
    # (a limit a config file cannot read from the environment, which the
    # strict load refuses there) has nothing to type.
    from automated_security_helper.config.config_validator import typed_from

    return any(typed_from(limit, value) for value in values)


def timeout_limit_phrase(
    limit: Any, values: Iterable[str], option_name: str = "scan_timeout"
) -> str:
    """The limit with the option that set it, as one phrase: ``scan_timeout of
    '67' s``, or ``configured scan_timeout`` when an environment value types
    to the limit (the same check as :func:`timeout_limit_token`).

    For a message that names its own option around the limit. A site whose
    option is not the scanner's (the MCP server's ``scan_timeout_seconds``)
    cannot build that sentence from the bare token: the token's fallback names
    the scanner option, so the message read "scan_timeout_seconds of the
    configured scan_timeout" -- repeating itself and sending the reader to the
    wrong knob.
    """
    if limit_typed_by_a_value(limit, values):
        return f"configured {option_name}"
    return f"{option_name} of '{limit_text(limit)}' s"


def config_environment_values(config: Any) -> Tuple[str, ...]:
    """The values and keys *config* read from the environment, for ``values``.

    ``AshConfig._environment_values``. Empty for no config, or for one that has
    none to give (a test double, a dict), so a caller holding whatever config a
    plugin context carries can pass it straight to error_text or traceback_text.
    A string there is one value (``redacted_model.environment_strings``).
    """
    return environment_strings(getattr(config, "_environment_values", None))


def plugin_environment_values(
    plugin_instance: Any, values: Iterable[str] = ()
) -> Tuple[str, ...]:
    """The values to redact text a plugin is the source of with: ``values``,
    the run's configuration's, then each non-empty string the plugin's own
    ``_environment_values()`` gives that they lack.

    A plugin can know a value the run's configuration does not, and any text it
    is the source of can quote it: its dependency reason (the scan's MISSING
    row, ``ash dependencies install``'s check-refused line), its
    nothing-to-scan reason, the lines its tool wrote, its runner's own lines,
    and its scan's exception text. Each of those redacts with these, so none
    prints a value another hides. A plugin's ``_environment_values()`` that
    gives fewer values than ``values`` drops none of them. A plugin is not
    required to inherit ``PluginBase``, a test double answers with a Mock, and
    a getter can raise: none of those adds a value, and none removes one.
    """
    merged = list(environment_strings(values))
    try:
        # Read inside the guard too: a plugin that is not a PluginBase can
        # answer the read of the attribute itself with an exception, and the
        # callers are handlers recording another failure.
        getter = getattr(plugin_instance, "_environment_values", None)
        if not callable(getter):
            return tuple(merged)
        own = list(environment_strings(getter()))
    except Exception:  # noqa: BLE001 -- the run's values still redact the text
        return tuple(merged)
    for value in own:
        if value not in merged:
            merged.append(value)
    return tuple(merged)


#: The attribute an error carries the run's environment values on, for a
#: failure handler that cannot see the configuration the run read them with.
_CARRIED_VALUES = "ash_environment_values"


def carry_environment_values(error: BaseException, values: Iterable[str]) -> None:
    """Record on *error* the values the failing run read from the environment.

    For the handler at the top of a run, which prints and logs an error nothing
    expected but holds no configuration to redact its text with: the
    orchestrator's construction fails before it is returned, and the workspace
    prewarm fails before any project's config is in reach. Where the error is
    raised the values are known, so they ride on it, and error_text,
    traceback_text and log_unexpected_error redact with them whatever values
    their caller passes. Accumulates; an error that takes no attributes is left
    as it is, whatever its assignment raises: the caller is a handler about to
    re-raise *error*, and raising here would replace it.
    """
    merged = dict.fromkeys(
        [*carried_environment_values(error), *environment_strings(values)]
    )
    try:
        setattr(error, _CARRIED_VALUES, tuple(value for value in merged if value))
    except Exception:  # noqa: BLE001 -- see the docstring
        pass


def carried_environment_values(error: BaseException) -> Tuple[str, ...]:
    """The values :func:`carry_environment_values` recorded on *error*.

    error_text, traceback_text and log_unexpected_error read them from every
    error in the chain themselves, so their callers do not pass them. None for
    an error whose attribute lookup raises, whatever it raises: a printer that
    raised here would replace the error it was printing."""
    try:
        values = getattr(error, _CARRIED_VALUES, ())
    except Exception:  # noqa: BLE001 -- see the docstring
        return ()
    if not isinstance(values, tuple):
        return ()
    return tuple(value for value in values if isinstance(value, str) and value)


def text_without_values(
    text: str, values: Iterable[str], min_length: int | None = None
) -> str:
    """*text* redacted with *values*, as error_text redacts an error's text.

    ``min_length`` moves the shortest band a value is matched in without
    quotes (``redact_values``); None keeps the default. The streamed
    container output passes the anywhere band's floor, so a bare common word
    equal to a short carried value prints while a quoted echo does not.

    For text ASH records that is not an exception's: a line a tool printed, or a
    message a report recorded. ``values`` as for error_text.

    Whenever there are values to hide, the text is matched twice: as written,
    then stripped of escape codes and matched again. The raw pass is for a
    value that itself holds codes: its as-written spelling earns the band its
    own length and characters give it, while its stripped spelling is matched
    in the band of the shorter stripped length, so stripping first alone let
    a short code-holding value print where word boundaries did not line up.
    The stripped pass is for a value a complete CSI or OSC sequence in the
    TEXT splits ("EDGE\\x1b[KSECRET"): a sink or terminal that drops or obeys
    the code would show the value whole, and only the stripped text holds the
    re-joined match.

    The two passes are then compared. If matching the stripped text hid
    nothing the raw pass had not (redacting the stripped raw result changes
    nothing), no code concealed a value and the raw result returns with its
    codes intact: colors, live-progress redraws and a file name's own bytes
    survive an unrelated value. Only when stripping exposed a further match
    does the stripped, redacted text return, so a text that holds a code is
    stripped exactly where a code was hiding a value. With nothing to redact
    there is nothing a code could split, and the text passes through
    unchanged.
    """
    values = list(environment_strings(values))
    return _redacted_keeping_codes(text, values, min_length) if values else text


def _redacted_keeping_codes(
    text: str, values: List[str], min_length: int | None = None
) -> str:
    """*text* redacted with *values*, keeping its escape codes unless a code
    was what hid a value. ``values`` are already normalized and non-empty;
    ``min_length`` as for :func:`text_without_values`.

    ``first`` is the text redacted as written. ``stripped`` is ``first``
    without its complete codes, and ``again`` is ``stripped`` redacted. If
    ``again == stripped`` the strip exposed no further match: no code in the
    text split or concealed a value, so ``first`` is the answer and its codes
    (colors, a live-progress redraw, a file name's own bytes) are untouched.
    Otherwise a code was splitting a value ("EDGE\\x1b[KSECRET"), and the
    stripped, redacted text is the answer, as it was before this compare.
    """
    from automated_security_helper.config.config_validator import redact_values

    if min_length is None:
        first = redact_values(text, values)
        stripped = _without_escape_codes(first)
        again = redact_values(stripped, values)
    else:
        first = redact_values(text, values, min_length=min_length)
        stripped = _without_escape_codes(first)
        again = redact_values(stripped, values, min_length=min_length)
    return first if again == stripped else again


def redact_then_split(text: str, values: Iterable[str]) -> List[str]:
    """*text* redacted whole, then split into lines, in that order.

    For a tool's text that is recorded line by line: a value can hold a line
    break (a PEM, a multi-line token), so a site that splits first cuts the
    value in two, and a per-line redaction matches neither half. Redacting
    the whole text first (``values`` normalized as :func:`text_without_values`
    does) and splitting the redacted text (``str.splitlines``) means no stored
    line can hold a piece of a value.
    The caller cuts the returned list where it would have cut the raw lines.

    The lines are stored or quoted in reports, not written to a terminal, so
    their escape codes are removed from the redacted text, with values to hide
    or without (text_without_values keeps them where no code hid a value).
    """
    values = list(environment_strings(values))
    if not values:
        return _without_escape_codes(text).splitlines()
    return _without_escape_codes(_redacted_keeping_codes(text, values)).splitlines()


#: Every complete CSI sequence, color included: the shown layers strip these
#: before matching, because any escape inside a value splits the match the
#: same way a color code does ("EDGE\\x1b[KSECRET"), and a sink or terminal
#: that drops or obeys the code then shows the value whole. CSI_CODES is the
#: public name importers use.
#: The full ECMA-48 CSI grammar: parameter bytes 0x30-0x3F ("0"-"?", colon
#: and "?" included), intermediate bytes 0x20-0x2F (" "-"/"), one final byte
#: 0x40-0x7E ("@"-"~"). A narrower set split the trim from the sinks: a
#: private-mode code ("\x1b[?25l"), a colon-form SGR ("\x1b[38:5:196m") or an
#: intermediate-byte code ("\x1b[2 q") was stripped on one side and kept on
#: the other, re-joining a split value in clear. Every escape regex in the
#: package is built from this one pattern.
_CSI_CODES = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CSI_CODES = _CSI_CODES

#: One complete OSC (operating system command) sequence: ESC ] body BEL,
#: ESC ] body ESC-backslash, or ESC ] body U+009C -- the C1 string
#: terminator, which terminal-aware tools also use to end a hyperlink; left
#: out, every reader treated such a link as a code cut off before its end
#: and the trim dropped the text behind it. The hyperlink form
#: ("\x1b]8;;https://host\x1b\\") is OSC, not CSI, so the CSI strip leaves
#: it, and one inside a value splits the contiguous match the same way a
#: color code does. The body excludes ESC, BEL and U+009C, and a line break,
#: so an unterminated OSC never swallows the text behind it: one that is not
#: ended on its own line is left as it is rather than matched up to a BEL or
#: a U+009C lines later, which dropped every line between them from the
#: saved text (ECMA-48 admits a line break in a command string; a line is
#: the unit every sink here keeps). A cut-off OSC at a read's edge is the
#: trim's incomplete-code branch, not this pattern's. Other C1 bytes, DCS and
#: APC stay unstripped, as before.
_OSC_CODES = re.compile(r"\x1b\][^\x07\x1b\x9c\r\n]*(?:\x07|\x1b\\|\x9c)")
OSC_CODES = _OSC_CODES

#: Every escape sequence the shown layers strip: the CSI set and the OSC
#: set, one alternation built from the two patterns above. ESCAPE_CODES is
#: the public name importers use -- the sinks, the uv layers, the mixin's
#: cause match and the read-edge trim all read THIS set, so no side strips a
#: code another keeps.
_ESCAPE_CODES = re.compile(rf"(?:{_CSI_CODES.pattern}|{_OSC_CODES.pattern})")
ESCAPE_CODES = _ESCAPE_CODES


#: The bytes a CSI sequence may hold between its "[" and its final byte: the
#: parameter bytes 0x30-0x3F and the intermediate bytes 0x20-0x2F, as
#: _CSI_CODES admits them.
_CSI_MIDDLE = frozenset(chr(code) for code in range(0x20, 0x40))

#: The final byte of a CSI sequence, 0x40-0x7E, as _CSI_CODES admits it.
_CSI_FINAL = frozenset(chr(code) for code in range(0x40, 0x7F))

#: What ends an OSC sequence on its own: BEL or the C1 string terminator. The
#: third ending, ESC then a backslash, arrives as two characters and is read
#: where the ESC's next character is.
_OSC_END = frozenset({"\x07", "\x9c"})

#: What an OSC body may not hold (_OSC_CODES): a sequence that meets one of
#: these before its end is never completed.
_OSC_BREAK = frozenset({"\r", "\n"})


def _without_escape_codes(text: str) -> str:
    """*text* with every complete escape sequence removed, until none is left.

    One removal is not enough: removing an inner sequence can join the bytes on
    either side of it into a sequence that was not there before ("\\x1b[" then
    "\\x1b[2K" then "m" is "\\x1b[m" once the inner one goes), and that one has
    to be removed too. The result is the fixed point of removing complete sequences,
    read in ONE pass over the text: each ESC that could still begin a sequence
    is kept open on a stack, a character is read against the innermost open one,
    a sequence that completes is dropped (so what came before its ESC and what
    follows now touch, and the next character is read against the sequence
    outside it), and an open sequence that meets a character no sequence admits
    is closed as text, together with every one outside it, since a text ESC
    inside a sequence's body ends that sequence for good. A sequence is matched
    against the patterns above at most once, when it completes or when it is
    closed, so the cost is linear in the text: removing sequences pass by pass
    until none was left re-read the whole text once per nesting level, and
    "\\x1b[" repeated k times before "m" repeated k times cost about k squared.
    """
    if "\x1b" not in text:
        return text
    kept: List[str] = []
    # Indexes in ``kept`` of each ESC that may still begin a sequence, innermost
    # last.
    open_escapes: List[int] = []
    for character in text:
        kept.append(character)
        if character == "\x1b":
            open_escapes.append(len(kept) - 1)
            continue
        while open_escapes:
            start = open_escapes[-1]
            if len(kept) - start == 2:
                # The character after an ESC: "[" opens a CSI, "]" an OSC. A
                # backslash may end an OSC this ESC sits inside, so the ESC is
                # closed as text and the backslash is read against that OSC.
                if character in "[]":
                    break
                open_escapes.pop()
                if character == "\\" and open_escapes:
                    continue
                open_escapes.clear()
                break
            kind = kept[start + 1]
            if kind not in "[]":
                # An ESC whose next character was itself an ESC that is now
                # closed as text: no sequence starts with two of them.
                open_escapes.clear()
                break
            if kind == "[":
                if character in _CSI_FINAL:
                    if _CSI_CODES.fullmatch("".join(kept[start:])):
                        del kept[start:]
                        open_escapes.pop()
                    else:
                        open_escapes.clear()
                    break
                if character in _CSI_MIDDLE:
                    break
                open_escapes.clear()
                break
            if character in _OSC_END or (character == "\\" and kept[-2] == "\x1b"):
                if _OSC_CODES.fullmatch("".join(kept[start:])):
                    del kept[start:]
                    open_escapes.pop()
                else:
                    open_escapes.clear()
                break
            if character in _OSC_BREAK:
                open_escapes.clear()
            break
    return "".join(kept)


def shown_tool_stderr(text: str, values: Iterable[str]) -> str:
    """A tool's stderr as the reports carry it: the caller's environment-read
    values hidden as written, then escape codes removed from the result.

    The redaction reads the RAW text, so text_without_values' as-written
    pass sees a value that itself holds codes in the spelling it was given;
    stripping first would leave only the stripped spelling to match. The
    strip runs on the result, so the no-codes contract holds even when
    there are no values to hide.

    The strip takes every complete CSI or OSC sequence, not only color: a
    non-color escape inside a value ("EDGE\\x1b[KSECRET", or an OSC
    hyperlink) would split the match and print the value in clear around
    the code.

    The NEUTRAL report-line layer, for any tool's stderr: no uv respellings.
    The premise that the tool reprints a value in another spelling (PEP 440
    and 503 canonical forms) is uv's; the uv run path routes its stderr
    through shown_uv_output instead, which adds those spellings and the
    plugin-input origin filter.
    """
    return _without_escape_codes(text_without_values(text, values))


def pattern_error_text(
    error: BaseException, pattern: str, values: Iterable[str]
) -> str:
    """A failed ``re.compile``'s text, unless ``pattern`` holds a configured value.

    ``re.error``'s own message quotes a fragment of the pattern ("bad character
    range Y-5", "bad character in group name '...'"), and a fragment of a value
    escapes whole-value redaction, which matches the value's printed forms, not
    its pieces. Where redacting ``pattern`` with ``values`` would change it, the
    text is the type and the position only, as runtime_patch words its own
    refusal of a pattern it cannot trace.
    """
    values = list(environment_strings(values))
    if values and text_without_values(pattern, values) != pattern:
        position = getattr(error, "pos", None)
        return (
            f"re.error at position {position}" if position is not None else "re.error"
        )
    return str(error)


def log_unexpected_error(
    logger: Any,
    error: BaseException,
    context: Optional[str] = None,
    values: Iterable[str] = (),
) -> None:
    """Log an error nothing expected, with its traceback, quoting no input.

    A logged traceback renders the message of every exception in the chain;
    for a chain holding a ValidationError the error is logged at ERROR as
    ``error_text`` describes it, after its type and the title of each model
    that refused (``ValidationError for AshConfig``), and the traceback's
    frames, without the messages, at DEBUG. Neither the type nor a title is
    input, and without them the line names a field with nothing to say what
    failed. Any other error is logged with its traceback, as
    ``logger.exception`` would. ``context`` ("Error in get_config") goes
    before the error's text. With ``values`` (as for error_text, the ones the
    error carries included), the text and the traceback are redacted with them:
    any other error is then logged with its traceback_text rather than its own
    traceback.

    Logged with NO_MARKUP: the text is data, a key, a path or a scanner's own
    words, and a "[/" in it is a closing Rich tag that raises MarkupError in
    the console handler, which then replaces the error it was logging.
    """
    from automated_security_helper.utils.log import NO_MARKUP

    values = _with_carried_values(error, values)
    found = validation_errors_in(error)
    if not found and values:
        text = error_text(error, values)
        message = f"{context}: {text}" if context is not None else text
        logger.error(
            f"{message}\n{traceback_text(error, values)}".rstrip(), extra=NO_MARKUP
        )
        return
    if not found:
        text = error_text(error)
        logged: object
        if context is not None:
            logged = f"{context}: {text}"
        else:
            # The error itself, as before, unless an OSError in it names a file,
            # which its own text quotes by repr, or its own __str__ raises,
            # which would fail the record's formatting in the handler.
            try:
                own: Optional[str] = str(error)
            except Exception:  # noqa: BLE001 -- whatever the error's __str__ raised
                own = None
            logged = error if own is not None and text == own else text
        try:
            # Every member of the chain: the handlers' formatter walks them all
            # as traceback_text does, and before Python 3.11's guard a notes
            # lookup that raises on any of them fails the record's formatting,
            # losing the record. Logged pre-rendered instead, through
            # traceback_text's own fallback.
            for member in _chain(error):
                getattr(member, "__notes__", None)
        except Exception:
            logger.error(f"{logged}\n{traceback_text(error)}".rstrip(), extra=NO_MARKUP)
            return
        if _names_a_file_by_repr(error):
            # The handlers' formatter would render the traceback from the
            # error, whose own text quotes its files by repr: the doubled
            # backslashes this module removes. Pre-rendered, the names are as
            # given, through traceback_text.
            logger.error(f"{logged}\n{traceback_text(error)}".rstrip(), extra=NO_MARKUP)
            return
        logger.error(logged, exc_info=error, extra=NO_MARKUP)
        return
    # pydantic's title is the model's name, or what the code that raised it
    # passed: never a value the model was given.
    titles = ", ".join(dict.fromkeys(str(item.title) for item in found))
    kind = (
        f"{type(error).__name__} for {titles}"
        if found[0] is error
        else f"{type(error).__name__} (from a ValidationError for {titles})"
    )
    # Not headed again: ``kind`` already names the type and each model.
    message = f"{kind}: {_described(error, values, counted=False)}"
    if context is not None:
        message = f"{context}: {message}"
    logger.error(message, extra=NO_MARKUP)
    # The frames alone, redacted as traceback_text redacts them: a frame's path
    # or source line can quote a value, and the file handlers write what they
    # are given.
    frames = "".join(traceback.format_tb(error.__traceback__))
    if values:
        frames = _without_escape_codes(_redacted_keeping_codes(frames, values))
    logger.debug(frames, extra=NO_MARKUP)


def _names_a_file_by_repr(error: BaseException) -> bool:
    """Whether an OSError in ``error``'s chain has Python's own text quote a file
    whose repr differs from the name as given (a backslash, a control)."""
    for current in _chain(error):
        if (
            not isinstance(current, OSError)
            or type(current).__str__ is not OSError.__str__
        ):
            continue
        quoted = _files_quoted(current)
        if quoted is not None and quoted[0] != quoted[1]:
            return True
    return False
