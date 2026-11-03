# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Console-script entry point that cannot fail without saying why.

The bug this exists for: ``ash --version`` exited 1 with *completely empty*
stdout and stderr, leaving an operator a bare exit code and nothing to act on.
Seen on the MSIX packaging leg (job 105400271151, run 35279579798), both through
the Windows app-execution alias and by invoking the venv's own ``ash.exe``
directly.

Nothing in ASH was catching the exception. The *sink* was missing. Every
reporting path ASH has -- ``ASH_LOGGER`` through its ``RichHandler``, Typer's
Rich traceback hook, ``typer.echo``, Click's usage-error printer and CPython's
own ``sys.excepthook`` -- ends at ``sys.stdout`` or ``sys.stderr``. When one of
those is ``None`` every single one of them writes nowhere, and CPython drops an
unhandled traceback silently rather than complaining, so the process exits 1
having said nothing at all.

``sys.stderr`` being ``None`` is documented, not exotic. From the CPython ``sys``
docs, on ``__stdin__``/``__stdout__``/``__stderr__``:

    Under some conditions ``stdin``, ``stdout`` and ``stderr`` as well as the
    original values ``__stdin__``, ``__stdout__`` and ``__stderr__`` can be
    ``None``. It is usually the case for Windows GUI apps that aren't connected
    to a console and Python apps started with pythonw.

An MSIX-packaged app launched through an app-execution alias is precisely "a
Windows app that isn't connected to a console". Note that the *saved originals*
can be ``None`` too, which is why :func:`ensure_std_streams` reattaches from a
file descriptor rather than restoring from ``sys.__stderr__``.

Two mechanisms here, because they cover different failures:

* :func:`ensure_std_streams` gives the process a writable stream *before*
  anything else runs. This is the actual fix, and it is deliberately the first
  statement in :func:`main`: once the sink exists, every reporter above works
  again, and the Rich traceback ASH configures with
  ``pretty_exceptions_enable=True`` renders exactly as it does on a normal
  terminal. Repairing the sink beats teaching each reporter to cope.
* :func:`_report_failure` is the floor for whatever the repair could not save.
  In place of typer's hook, rich.traceback's and the interpreter's own, which
  only print the traceback, it reports through
  :func:`_ash_traceback`, which prints the traceback typer's hook would, through
  ASH's console, so the pretty traceback is not lost in the common case. Any
  other ``sys.excepthook``, one a library, a plugin or the user installed, is
  called, so what else it does (a crash reporter, say) still happens, with
  ``sys.stdout`` and ``sys.stderr`` writing each line it writes shown, not
  obeyed, for that call only. typer's own hook, on its standard-traceback path
  (``TYPER_STANDARD_TRACEBACK``, or an exception it did not tag), prints
  nothing itself and calls the hook that was installed when typer was imported
  (a crash reporter a ``sitecustomize`` installed, say); ASH, reporting in
  typer's place, calls that hook the same way. If that hook raises,
  :func:`_ash_traceback` reports; a ``sys.exit`` in either ends the process
  with its code, as CPython lets it, and a Ctrl-C with 130, printing nothing.
  After those comes plain ``traceback`` formatting, then ``os.write`` on a raw
  descriptor, each written whole.
  :func:`_ash_traceback` imports typer, Rich
  and ASH's console itself, and when one of them cannot be imported the floor
  falls back. Otherwise the floor imports nothing outside the standard library:
  not Rich, not the ASH logger, not the config. Anything it needed could be the
  thing that is broken. Every text it prints is shown, not obeyed, when ASH's
  text rule can be imported.

Known limit of the installed-hook path: a hook that writes to a descriptor
itself (``os.write(2, ...)``), or to a stream object it took before the call
(``sys.__stderr__``, or ``sys.stderr`` saved at install time), writes past the
shown streams, as given. A hook whose console decided on color when it was made
still writes its color codes, and those are shown as text. That is why
``rich.traceback.install()``'s hook, which only prints, is reported through
ASH's traceback rather than called: on a terminal its frame came out as color
codes written as text.

The heavy import of ``automated_security_helper.cli.main`` happens *inside*
:func:`main`, after the streams are known good. That ordering is load-bearing.
An incompatibility that breaks importing pydantic models, plugins or config --
the shape a new Python release produces -- would otherwise raise before any of
this ran, and be discarded by the same missing sink.

Known limitation: an exception raised while importing this module, or
``automated_security_helper/__init__.py`` above it, still precedes the repair and
is still silent on a console-less host. Closing that would require code in the
console-script stub, which pip generates and ASH does not control. Keeping this
module's own imports to ``errno``, ``os``, ``sys``, ``traceback`` and ``typing``
is what holds that window as narrow as it can be, so do not add imports at
module scope.
"""

import errno
import os
import sys
import traceback
from typing import Any, Callable

#: Prefix for the last-resort report. Deliberately greppable, and it names the
#: program because on this path nothing else has identified itself yet.
_BANNER = "ash: fatal error"

#: The modules whose exception hooks only print the traceback, which ASH's
#: traceback prints in their place: typer's, and rich.traceback.install()'s. A
#: wrapper of one (it has ``__wrapped__``) is not one of them.
_PRINTERS = frozenset({"typer.main", "rich.traceback"})

#: The descriptors :func:`ensure_std_streams` found closed when it ran: a
#: stream was ``None`` and the descriptor under it was closed (EBADF). A number
#: the run opens later (the scan log, a report) can be given that descriptor, so
#: the raw floor never writes to one of these. A descriptor that was open but
#: could not be given a stream is not recorded: the floor still writes to it.
#: Empty until ensure_std_streams has run, and on every normal invocation.
_CLOSED_AT_START: set[int] = set()


def _stream_codec() -> tuple[str | None, str]:
    """The encoding and error handler a reattached stream is opened with.

    As the interpreter chooses them for the streams it makes at start:
    ``PYTHONIOENCODING`` (``encoding[:errors]``, unless ``python -E`` ignores the
    environment), UTF-8 under UTF-8 mode (``-X utf8``, ``PYTHONUTF8=1``), else the
    locale's codec, ``None`` here. A repaired channel written in a codec other
    than the one the environment asked for gave a reader of machine output
    (JSON through echo_raw) bytes it did not expect.

    The handler is ``PYTHONIOENCODING``'s when it names one, else
    ``backslashreplace``: on Windows the locale's codec is often a code page
    which cannot represent the box-drawing characters Rich uses to frame a
    traceback, and a stream that raises ``UnicodeEncodeError`` while reporting
    an error is no better than no stream at all.
    """
    requested = (
        "" if sys.flags.ignore_environment else os.environ.get("PYTHONIOENCODING", "")
    )
    encoding, _, errors = requested.partition(":")
    if not encoding and getattr(sys.flags, "utf8_mode", False):
        encoding = "utf-8"
    return encoding or None, errors or "backslashreplace"


#: The standard descriptors that were closed when the process started. A closed
#: descriptor number is free, so the next ``open()`` anywhere in ASH would be
#: handed 1 or 2, and from then on everything that writes to the descriptor by
#: number -- the raw floor below, a child's inherited stderr -- would write into
#: that file. :func:`ensure_std_streams` records each one here and holds it with
#: ``os.devnull`` where the null device can be opened (:func:`_reserve_descriptor`).
#: The record does not depend on the hold: :func:`_write_raw` never writes to a
#: recorded descriptor, whether it is held or, with no null device, still free
#: and by then possibly a file ASH opened. There was nothing there to read it.
_RESERVED_DESCRIPTORS: set[int] = set()


def _descriptor_is_closed(fd: int) -> bool:
    """Whether descriptor *fd* is closed (EBADF), as distinct from unattached."""
    try:
        os.fstat(fd)
    except OSError as error:
        return error.errno == errno.EBADF
    return False


def _reserve_descriptor(fd: int, flags: int = os.O_WRONLY) -> bool:
    """Hold the closed descriptor *fd* with ``os.devnull``, opened with *flags*
    (for writing by default; stdin is held for reading).

    Returns whether it is held: True once *fd* is open on the null device in
    this process, whether or not the step after it succeeded. Opening the null
    device may itself be handed *fd*, the lowest free number; then it is already
    in place and stays open.

    Held inheritable on both paths, as best effort. ``os.open`` gives a
    descriptor children do not inherit (PEP 446), so on the path where it was
    handed *fd* itself a child that inherits stderr would start with that number
    closed again, and its first ``open()`` would land there: the hazard this
    hold exists for. ``os.dup2`` gives an inheritable one by default; it is set
    the same way so the two paths cannot drift apart. A failure to set it leaves
    the hold in place for this process and is not reported: the descriptor is
    held, which is what the result says.
    """
    try:
        null = os.open(os.devnull, flags)
    except OSError:
        return False
    if null != fd:
        try:
            os.dup2(null, fd)
        except OSError:
            return False
        finally:
            os.close(null)
    try:
        os.set_inheritable(fd, True)
    except OSError:
        pass
    return True


def _reattach(fd: int):
    """Return a text stream writing to descriptor *fd*, or ``None``.

    Opened with the codec :func:`_stream_codec` chooses. ``closefd=False`` so
    garbage collection of this object does not close the process's real stderr
    underneath anything else holding it.
    """
    encoding, errors = _stream_codec()
    try:
        return os.fdopen(
            fd, "w", buffering=1, encoding=encoding, errors=errors, closefd=False
        )
    except (OSError, LookupError):
        # EBADF: the descriptor is genuinely closed, not merely unattached. A
        # LookupError is a PYTHONIOENCODING naming a codec Python does not
        # have, which the interpreter itself refuses at start.
        return None


def ensure_std_streams() -> tuple[str, ...]:
    """Reattach ``sys.stdout``/``sys.stderr`` when they are ``None``.

    Returns the names repaired, which is empty on every normal invocation.

    Only ever acts on ``None``. A stream replaced by a test harness, a capture
    object or a pipe is left alone -- this is repairing an absent sink, not
    second-guessing a caller who installed one.

    A descriptor that is closed outright gets no stream, and is held with
    ``os.devnull`` instead (:data:`_RESERVED_DESCRIPTORS`): left free, the next
    file ASH opened would take its number, and the raw floor and every child's
    inherited stderr would then write into that file. A closed stdin is held
    the same way, for reading: left free, the next file ASH opened would become
    descriptor 0, and every child that inherits stdin would read from it. No
    stream is attached for it; nothing in ASH reads a stdin that was closed.
    """
    repaired = []
    if getattr(sys, "stdin", None) is None and _descriptor_is_closed(0):
        _RESERVED_DESCRIPTORS.add(0)
        _reserve_descriptor(0, os.O_RDONLY)
    for name, fd in (("stdout", 1), ("stderr", 2)):
        if getattr(sys, name, None) is not None:
            continue
        stream = _reattach(fd)
        if stream is None:
            if _descriptor_is_closed(fd):
                # Recorded first: the raw floor skips a descriptor that was
                # closed at startup whether or not the hold below succeeds.
                _RESERVED_DESCRIPTORS.add(fd)
                _reserve_descriptor(fd)
                _CLOSED_AT_START.add(fd)
            # A descriptor that is open but could not be reattached (a
            # PYTHONIOENCODING naming a codec Python lacks) is left out of both
            # records: something is still reading it, and the raw floor is the
            # one channel that does not need a stream object.
            continue
        _CLOSED_AT_START.discard(fd)
        setattr(sys, name, stream)
        # The docs quoted above warn that the saved original can be None as
        # well. logging's lastResort handler and several libraries reach for
        # sys.__stderr__ when sys.stderr looks unusable, so leaving it None
        # keeps a hole open behind the one just closed.
        if getattr(sys, f"__{name}__", None) is None:
            setattr(sys, f"__{name}__", stream)
        repaired.append(name)
    return tuple(repaired)


def _flush_quietly(stream) -> None:
    """Flush *stream*, a Python-level stream that may be broken, and tell nobody."""
    flush = getattr(stream, "flush", None)
    if flush is None:
        return
    try:
        flush()
    except Exception:
        pass


#: How long :func:`_write_raw` waits for one descriptor whose pipe is full and
#: non-blocking to take a write again, in total, before it hands the report on.
_RAW_WRITE_WAIT_SECONDS = 5.0


def _wait_writable(fd: int, seconds: float) -> bool:
    """Whether descriptor *fd* can take a write within *seconds*.

    ``select`` is imported here, not at module scope (see the module docstring).
    Where it cannot wait on *fd* (a Windows handle that is not a socket) the
    answer is False, and the caller hands the report on.
    """
    try:
        import select

        _, ready, _ = select.select([], [fd], [], max(seconds, 0.0))
    except (ImportError, OSError, ValueError):
        return False
    return bool(ready)


def _handed_on(report: bytes, written: int) -> bytes:
    """What the next descriptor is given after one took the first *written*
    bytes of *report* and no more, so that no line is read cut in two.

    Nothing taken: the whole report, as it was. Otherwise the report from the
    last line the descriptor took whole, under a line that says the report
    continues there; when the descriptor took no whole line, from its start,
    with no such line, since there is nothing before it to continue. A line the
    descriptor took only part of is ended first, with a newline: descriptors 1
    and 2 can be one pipe (``2>&1``), and the next descriptor's first line would
    be written straight after the fragment.
    """
    if written == 0:
        return report
    boundary = report.rfind(b"\n", 0, written) + 1
    ends_the_fragment = b"\n" if written > boundary else b""
    if boundary == 0:
        return ends_the_fragment + report
    handoff = f"{_BANNER}: the report continues from the last whole line\n"
    return ends_the_fragment + handoff.encode("utf-8") + report[boundary:]


def _write_raw(text: str) -> bool:
    """Write *text* to a raw descriptor, bypassing ``sys.stderr`` entirely.

    Reached only when there is no Python-level stream object left to trust, so
    it uses ``os.write`` and tries stderr before stdout. Returns whether the
    whole text reached something.

    Each ``os.write`` is repeated until its count covers the text: a pipe can
    take part of a write, and a short write counted as the whole report cut
    the report. A pipe that is full and non-blocking raises
    ``BlockingIOError``, which is not a broken descriptor: the write waits for
    the pipe to drain (:func:`_wait_writable`, at most
    :data:`_RAW_WRITE_WAIT_SECONDS`) and is repeated. When the wait runs out, or
    a descriptor fails part-way (a broken pipe, an I/O error), the next
    descriptor is given the report as :func:`_handed_on` says: from the last line
    this one took whole, not the whole text again and not from the middle of a
    line. A descriptor that had no stream when the process started
    (:data:`_CLOSED_AT_START`), or that was closed outright and is held with
    ``os.devnull`` (:data:`_RESERVED_DESCRIPTORS`), is skipped: nothing is
    reading it, and had it not been held, its number could by now be a file the
    run opened. Before stdout is written, ``sys.stdout`` is flushed, so the
    report lands after what ASH printed through it, not ahead.
    """
    import time

    report = text.encode("utf-8", "backslashreplace")
    written = 0
    for fd in (2, 1):
        if fd in _CLOSED_AT_START or fd in _RESERVED_DESCRIPTORS:
            continue
        if fd == 1:
            _flush_quietly(getattr(sys, "stdout", None))
        give_up_at = time.monotonic() + _RAW_WRITE_WAIT_SECONDS
        try:
            while written < len(report):
                try:
                    count = os.write(fd, report[written:])
                except BlockingIOError:
                    left = give_up_at - time.monotonic()
                    if left <= 0 or not _wait_writable(fd, left):
                        raise
                    continue
                if count == 0:
                    # Accepted nothing and raised nothing: repeated, this
                    # would never end. Handed on as a failed write is.
                    raise OSError(errno.EIO, "write of 0 bytes")
                written += count
            return True
        except OSError:
            # BlockingIOError, whose wait ran out, is one. This descriptor took
            # the report up to `written` and no further; the next one gets it
            # from the start of the line that was cut (_handed_on).
            report = _handed_on(report, written)
            written = 0
    return False


def _exception_text(exc: BaseException) -> str:
    """``str(exc)``, or a stand-in when that raises: the floor reports every
    exception, the ones whose ``__str__`` is broken included."""
    try:
        return str(exc)
    except Exception:
        return f"<{type(exc).__name__} whose text could not be read>"


def _is_printer(hook: Any) -> bool:
    """Whether *hook* is one of :data:`_PRINTERS`' own hooks, which only print.

    By module, and only unwrapped: a functools.wraps wrapper takes the module
    name of the hook it wraps, but is a crash reporter's own, so it runs.
    """
    return getattr(hook, "__module__", None) in _PRINTERS and not hasattr(
        hook, "__wrapped__"
    )


def _standard_traceback(exc: BaseException, typer_main: Any) -> bool:
    """Whether typer's hook would print the plain traceback for *exc*, as
    typer.main.except_hook decides: ``TYPER_STANDARD_TRACEBACK`` set, or no
    pretty-traceback tag on the exception. On that path typer's hook prints
    nothing itself and calls the hook it found installed when it was imported.
    """
    if os.getenv("TYPER_STANDARD_TRACEBACK", os.getenv("_TYPER_STANDARD_TRACEBACK")):
        return True
    attribute = getattr(
        typer_main,
        "_typer_developer_exception_attr_name",
        "__typer_developer_exception__",
    )
    config = getattr(exc, attribute, None)
    return config is None or not getattr(config, "pretty_exceptions_enable", False)


def _installed_hook(exc: BaseException) -> Callable[..., Any] | None:
    """The ``sys.excepthook`` an installer put there, to call for *exc*, or None.

    The interpreter's own and the printers' (:data:`_PRINTERS`) are None: ASH's
    traceback reports in their place. typer's hook, on its standard-traceback
    path, calls the hook that was installed before typer was imported
    (``typer.main._original_except_hook``, a crash reporter a sitecustomize or
    a ``.pth`` installed); replacing typer's hook dropped that call, so that
    hook is the one to call then, unless it is the interpreter's or a printer.
    """
    hook = getattr(sys, "excepthook", None)
    if hook is None or hook is sys.__excepthook__:
        return None
    if not _is_printer(hook):
        return hook
    typer_main = sys.modules.get("typer.main")
    if typer_main is None or getattr(hook, "__module__", None) != "typer.main":
        return None
    if not _standard_traceback(exc, typer_main):
        return None
    chained = getattr(typer_main, "_original_except_hook", None)
    if chained is None or chained is sys.__excepthook__ or _is_printer(chained):
        return None
    return chained


def _report_failure(exc: BaseException, repaired: tuple[str, ...] = ()) -> None:
    """Report *exc*, degrading through every channel rather than giving up.

    With typer's hook, rich.traceback's or the interpreter's own in
    ``sys.excepthook`` (one of :data:`_PRINTERS`' modules, or
    ``sys.__excepthook__``), reports through :func:`_ash_traceback`. By the time
    an exception escapes ``app()``,
    ``Typer.__call__`` has already tagged it for pretty rendering, and
    :func:`_ash_traceback` reads the tag, so the report keeps the Rich traceback
    that ``pretty_exceptions_enable`` and ``ASH_DEBUG_SHOW_LOCALS`` exist to
    produce, printed through a console set up as typer's is, with its text shown,
    not obeyed. Any other hook is called through :func:`_call_shown`, and ASH
    prints no report of its own on top; if the hook raises,
    :func:`_ash_traceback` reports. A ``SystemExit`` from either is raised on, so
    a hook's exit code stands; a ``KeyboardInterrupt`` ends the process with 130,
    ``from None``, since the interrupt held *exc* as its context and the
    interpreter would print that chain as given.

    *repaired* names the streams :func:`ensure_std_streams` had to reattach. It
    is passed in rather than read from module state so nothing here depends on
    an earlier call having happened. A console-less host is itself the diagnosis
    an operator needs, so it is worth saying -- but only on a failure. Saying it
    on a successful run would put noise ahead of the output the user asked for.
    """
    stderr = getattr(sys, "stderr", None)

    # Emitted before the traceback, not alongside the fallback below, because a
    # process that started with no console is the root cause an operator needs
    # and the delegated path returns without ever reaching the fallback.
    if repaired:
        _emit(
            f"{_BANNER}: started with no usable {'/'.join(repaired)}; ASH "
            f"reattached {'it' if len(repaired) == 1 else 'them'} to report the "
            "failure below.\n",
            stderr,
        )

    # typer's hook prints with typer's own Rich console, and the interpreter's
    # own (still in place when the failure comes before typer installs its hook)
    # prints the traceback: both write the exception's text as given, and that
    # text quotes paths and values from the scanned tree. rich.traceback's
    # (rich.traceback.install()) does nothing else but print, with a console
    # that picked color when it was made, so through the shown streams its frame
    # was color codes written as text. ASH's renders the same traceback through
    # ASH's console instead of each. Any other hook is the installer's, so it
    # runs, writing through streams that show what it writes (_installed_hook).
    # With no stderr as well: its call is the module's promise, and _call_shown
    # gives it a shown stream onto stdout as its stderr, so a hook that reports
    # only there is still read. With no stream at all the hook's report reached
    # nothing a reader has, so the floor below writes ASH's own after the hook.
    hook = _installed_hook(exc)
    if hook is not None:
        try:
            _call_shown(hook, exc)
            if stderr is not None or getattr(sys, "stdout", None) is not None:
                return
        except SystemExit:
            # A hook's sys.exit ends the process with its code, as CPython lets
            # it when it reports an uncaught exception: not a failed report.
            raise
        except KeyboardInterrupt:
            # A Ctrl-C ends it as an interrupted process ends, with 130. Not the
            # KeyboardInterrupt itself: it holds the failure as its context, and
            # the interpreter's top level would print that chain as given, the
            # failure's text raw, after calling the installed hook again.
            raise SystemExit(130) from None
        except BaseException:
            # The installed hook failed: ASH's traceback reports instead.
            pass
    if stderr is not None:
        try:
            _ash_traceback(type(exc), exc, exc.__traceback__)
            return
        except SystemExit:
            raise
        except KeyboardInterrupt:
            raise SystemExit(130) from None
        except BaseException:
            # The reporter destroyed the report. Keep going: a plain traceback
            # is worth more than a pretty one that never arrived.
            pass

    # traceback's own formatting reads a broken __str__ past; the banner's
    # text does the same (_exception_text), so this line cannot be the one
    # that makes the floor raise.
    detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    _emit(
        _shown(f"{_BANNER}: {type(exc).__name__}: {_exception_text(exc)}\n{detail}"),
        stderr,
    )


#: The letters a command name is made of in the CI forms ASH's text rule breaks
#: (``##vso[``, ``##teamcity[``); the pattern there reads ASCII letters only.
_ASCII_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


class _ShownLines:
    """A text stream that writes each line written to it to *stream*, shown.

    A line is held until its newline, until :meth:`flush`, or until :meth:`end`,
    so a line written in pieces is shown whole: a ``::`` that starts it is a CI
    command only as a whole line. A flush writes the held piece as far as it
    goes: a hook that writes a prompt without its newline and flushes before it
    reads the answer is waiting for a reader who must see the prompt. The one
    piece a flush keeps is a line start that could be the front of a command
    form (:meth:`_holds_the_start_of_a_command`): shown alone, the rest of the
    line written after it would finish the reader's line as one. Not a
    terminal (``isatty()`` is false) and no descriptor, so a writer that asks
    does not color its text or write past the stream.
    """

    def __init__(self, stream) -> None:
        # ASH's text rule, imported here: when it cannot be, no stream is made
        # and the hook is not called.
        from automated_security_helper.utils.terminal_text import shown_not_obeyed

        self._show = shown_not_obeyed
        self._stream = stream
        self._held = ""
        # A line a flush wrote without its newline: end() still ends it.
        self._unended = False
        self.encoding = getattr(stream, "encoding", None) or "utf-8"
        self.errors = getattr(stream, "errors", None) or "strict"

    def write(self, text: str) -> int:
        self._held += text
        lines, newline, self._held = self._held.rpartition("\n")
        if newline:
            self._stream.write(self._show(lines + newline))
            self._unended = False
        return len(text)

    def writelines(self, lines) -> None:
        for line in lines:
            self.write(line)

    def _holds_the_start_of_a_command(self) -> bool:
        """Whether the held piece is the front of a CI command form that the
        next write could finish.

        Two shapes. At a line's start, after its leading blanks, a piece that
        starts with ``:`` or ``#`` and holds no blank: a command's name has none
        (``::warning``, ``##vso``, ``##teamcity``), and the bracket that
        completes the Azure and TeamCity forms can arrive in the next write.
        Anywhere in a line, a piece that ends in two hash marks or more followed
        only by ASCII letters (``done ##vso``), or in a single mark (the second
        may be the next write's first): Azure and TeamCity read those forms in
        the middle of a line too, whether the marks follow a blank or are glued
        to the text before them (``done x##vso``, ``path/##teamcity``, ``x#``
        before ``#vso[``): the reader's pattern has no word boundary, so the
        front does not have to start a word, and it reads ASCII letters only.
        One mark followed by letters (``done #vso``, ``x#vso``) cannot be
        finished into a form by what is written next, and a prompt such as ``#
        Send the report? [y/N] `` ends in a blank: both are written."""
        piece = self._held.lstrip()
        if not piece:
            return False
        if (
            not self._unended
            and piece[:1] in (":", "#")
            and not any(character.isspace() for character in piece)
        ):
            return True
        # The piece's tail, read from the end: letters, then hash marks. Two
        # marks or more with letters after them, or a single mark that ends the
        # piece (the second one may be the next write's first), can be finished
        # by the next write into a ``##name[`` form.
        letters_end = len(piece)
        while letters_end and piece[letters_end - 1] in _ASCII_LETTERS:
            letters_end -= 1
        marks = letters_end - len(piece[:letters_end].rstrip("#"))
        return marks >= 2 or (marks == 1 and letters_end == len(piece))

    def flush(self) -> None:
        # A piece that could be the front of a CI command form (at a line's
        # start ":" before "::warning::", "#" before "##vso[", and "##vso"
        # before "["; anywhere in a line the "##vso" before "[") stays held:
        # shown on its own it is no command, and the rest of the line, written
        # after, would finish the line for the reader as one. Shown
        # with its line by the next write or by end().
        if self._held and not self._holds_the_start_of_a_command():
            self._stream.write(self._show(self._held))
            self._held = ""
            self._unended = True
        self._stream.flush()

    def end(self) -> None:
        """Write the line still held, ended, so nothing after it joins it."""
        if self._held or self._unended:
            self.write("\n")
        self.flush()

    def isatty(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def fileno(self) -> int:
        import io

        raise io.UnsupportedOperation("fileno")


def _call_shown(hook: Callable[..., Any], exc: BaseException) -> None:
    """Call *hook*, an installed ``sys.excepthook``, for *exc*, with ``sys.stdout``
    and ``sys.stderr`` writing each line it writes shown, not obeyed.

    The streams are put back after the call, whatever it did, and a line the hook
    left unended is ended. The shown streams are made before the call: when ASH's
    text rule cannot be imported, nothing could be shown, and the hook is not
    called. With no ``sys.stderr`` the hook's stderr is the shown stdout, so a
    report written only to stderr is read; with neither stream the hook is
    called and nothing it writes is carried, which the caller reads as no report.

    For the call, the environment says no color (``PYTHON_COLORS=0``,
    ``NO_COLOR``, no ``FORCE_COLOR``): the shown streams are not terminals, but
    the interpreter's own traceback printer, which a hook may chain to, colors
    under ``FORCE_COLOR`` or ``PYTHON_COLORS=1`` whatever it writes to, and its
    codes would be shown as text. Ending a shown stream writes and flushes the
    real one; a failure there is swallowed, so a hook's outcome (its report, its
    ``sys.exit`` code) is never replaced by the cleanup's, and the other stream's
    held line is still ended.
    """
    # Imported here, not at the top: this module is the floor, and this call is
    # made only once ASH's own modules import (the shown streams need them).
    from automated_security_helper.utils.process_env import environ_overrides

    stdout, stderr = sys.stdout, sys.stderr
    shown_stdout = _ShownLines(stdout) if stdout is not None else None
    # With no stderr, the hook's stderr is a shown stream onto stdout: a hook
    # that writes its report only there (the interpreter's own printer, which a
    # crash reporter chains to, drops its output when sys.stderr is None) would
    # otherwise report to nothing, and the run would fail saying nothing.
    shown_stderr = _ShownLines(stderr) if stderr is not None else shown_stdout
    shown = [shown_stdout, shown_stderr]
    sys.stdout, sys.stderr = shown
    try:
        # Set and put back through process_env, under its lock, so a scanner
        # thread copying the environment for a spawn never reads it half-written.
        with environ_overrides(
            {"PYTHON_COLORS": "0", "NO_COLOR": "1", "FORCE_COLOR": None}
        ):
            hook(type(exc), exc, exc.__traceback__)
    finally:
        sys.stdout, sys.stderr = stdout, stderr
        # Each shown stream ended once: the two names hold one stream when
        # stderr was None.
        for stream in dict.fromkeys(shown):
            if stream is not None:
                try:
                    stream.end()
                except Exception:
                    pass


def _shown(text: str) -> str:
    """*text* shown, not obeyed, when ASH's text rule can be imported, else as is.

    The floor imports nothing it needs: ASH's own modules could be what is broken.
    A Ctrl-C is not that: it ends the report, with 130, as the callers say.
    """
    try:
        from automated_security_helper.utils.terminal_text import shown_not_obeyed

        return shown_not_obeyed(text)
    except Exception:
        return text


def _shown_suppress(paths: list[str]) -> list[str]:
    """*paths*, Rich's suppress list, shown as _show_trace shows each frame's file name.

    Rich leaves out the source of a frame whose file name starts with one of
    these. _show_trace rewrites the file names in place, so a path holding the
    text of an escape (a Windows install under ``C:\\x64``) no longer started
    with the path as given, and typer's frames, which the suppress list is for,
    came back. Shown the same way, the prefix matches again.
    """
    from automated_security_helper.utils.terminal_text import shown_not_obeyed

    return [str(shown_not_obeyed(path)) for path in paths]


def _ash_traceback(exc_type, exc, tb) -> None:
    """Print *exc*'s traceback as typer's hook would, through ASH's console.

    The exception's text, notes and file names quote repository paths and tool
    output, so they go through the console log's traceback rule (utils/log.py's
    _show_trace): controls shown, CI command forms broken. As typer's hook does,
    it reads the app's choices from the tag Typer.__call__ puts on the exception:
    typer's frames, the vendored click's among them, are left out, locals are
    shown only when the app shows them (ASH_DEBUG_SHOW_LOCALS), and the widths and
    console are typer's. With TYPER_STANDARD_TRACEBACK set, or no pretty
    traceback asked for, the plain traceback is printed, shown the same way.
    Called in place of typer's hook, rich.traceback's and the interpreter's own,
    and after an installed hook that raised; when the failure came before typer
    could be imported, importing it here fails too, and the floor falls back to
    its own shown report.
    """
    import typer
    import typer.main
    from typer.main import _typer_developer_exception_attr_name

    # As typer's hook decides, read once for this module in _standard_traceback
    # (which _installed_hook asks too, so the two cannot drift apart): the plain
    # traceback under TYPER_STANDARD_TRACEBACK, or when the exception carries no
    # tag asking for a pretty one.
    if _standard_traceback(exc, typer.main):
        detail = "".join(traceback.format_exception(exc_type, exc, tb))
        _emit(_shown(detail), sys.stderr)
        return
    # The tag Typer.__call__ put on the exception, for its locals setting. Its
    # name is bound to this read and nothing else in the module: the locals check
    # (tests/unit/utils/test_debug_locals_on_ci.py) accepts a setting read back
    # from typer's tag only through such a name.
    tag: Any = getattr(exc, _typer_developer_exception_attr_name, None)

    from rich.traceback import Traceback

    from automated_security_helper.utils.console import typer_console
    from automated_security_helper.utils.log import _show_trace

    terminal_width = os.environ.get("TERMINAL_WIDTH", "")
    rendered = Traceback.from_exception(
        exc_type,
        exc,
        tb,
        show_locals=bool(tag.pretty_exceptions_show_locals),
        suppress=[os.path.dirname(typer.__file__)],
        # typer's widths, its TERMINAL_WIDTH or else the console's, where Rich's
        # own defaults are 100 and 88; read now, as typer_console reads it.
        width=int(terminal_width) if terminal_width.isdigit() else None,
        code_width=None,
        word_wrap=True,
    )
    _show_trace(rendered.trace)
    rendered.suppress = _shown_suppress(list(rendered.suppress))
    typer_console(stderr=True).print(rendered)


def _emit(text: str, stream) -> None:
    """Write *text* to *stream*, falling back to a raw descriptor.

    The raw fallback is for a write that failed: the text never reached the
    stream. A flush that fails after a write that succeeded leaves the text with
    the stream, which writes it when it can; written raw as well, it was shown
    twice. A Ctrl-C in either is not swallowed: it ends the report with 130.
    """
    if stream is not None:
        try:
            stream.write(text)
        except Exception:
            _write_raw(text)
            return
        try:
            stream.flush()
        except Exception:
            pass
        return
    _write_raw(text)


def main() -> None:
    """Entry point for the ``ash``, ``ashv3`` and ``automated-security-helper`` scripts.

    Shutdown contract: this is the one place that installs ASH's SIGTERM and
    SIGINT handlers (core/cancellation.install_sigterm_shutdown and
    install_sigint_shutdown; the cancellation module docstring, "SIGTERM on
    the CLI", is the contract). A SIGTERM to the process then stops a running
    ``ash scan`` through the same cancellation path a timeout uses, the
    running tool included, and the command exits ASH_EXIT_TERMINATED (143);
    with no scan running, on a second SIGTERM, on Windows and for a process
    started with SIGTERM ignored, the signal keeps the semantics it had
    without the handler. A Ctrl-C keeps raising KeyboardInterrupt (the
    handler chains the default one) and additionally latches the registered
    scan's cancellation at once; a second Ctrl-C takes the recorded tool
    processes along and dies by SIGINT, so a tool mid-stop is not orphaned.
    Library imports of ASH never install either, so an embedder's disposition
    is its own; the MCP server paths install their own handling over this one
    once they start.
    """

    def run() -> None:
        # Imported here, not at module scope: see the module docstring. The
        # streams have to be usable before this line can fail. The handler
        # install comes first so it covers the CLI import and everything after;
        # core.cancellation imports only the standard library.
        from automated_security_helper.core.cancellation import (
            install_sigint_shutdown,
            install_sigterm_shutdown,
        )

        install_sigterm_shutdown()
        install_sigint_shutdown()

        from automated_security_helper.cli.main import run_app

        run_app()

    _run_reporting_failures(run)


def run_module_app(app: Callable[..., Any]) -> None:
    """Run *app*, one of the CLI's Typer apps, with :func:`main`'s failure path.

    For a command module run as a script (``python -m
    automated_security_helper.cli.config``), which calls its own app rather than
    ASH's: an exception escaping it is reported as main() reports one, through
    ASH's console, instead of by typer's hook. A usage error exits as it does
    under the ``ash`` root group (cli/main.py's AshTyperGroup): with
    ASH_EXIT_USAGE_ERROR, its message shown, not obeyed. Run as its own app the
    sub-app had click's own handling, which exits 2, ASH's code for actionable
    findings, and prints the mistyped token as given.
    """

    def run() -> None:
        _run_module_app(app)

    _run_reporting_failures(run)


def _run_module_app(app: Callable[..., Any]) -> None:
    """Run *app* outside click's standalone mode and exit as the root group would.

    click's standalone handling prints a usage error itself and exits with its
    code, 2; outside it the error is raised to here, where ASH prints it as
    cli/main.py does for the root group and exits ASH_EXIT_USAGE_ERROR. typer's
    NoArgsIsHelpError prints the help instead: typer's Rich mode prints it when
    the error is built, and in the plain markup mode it is written here, from
    the error's message. A command's ``typer.Exit`` comes back as its code, and
    Abort (an end of input at a prompt) exits 1 with its one word. A
    KeyboardInterrupt never reaches here as itself: typer turns it into
    ``Exit(130)``, which comes back as 130 with nothing printed. Outside
    standalone mode click returns a command's own return value through the same
    channel as ``Exit``'s code, so a command that returns an ``int`` exits with
    it where standalone mode exited 0; a command that returns anything else
    exits 0. Imports are inside: this runs after the streams are known good.
    """
    # Abort is typer's own (typer.exceptions, exported at the top level); the
    # vendored click package has no Abort, so importing it from there raised an
    # ImportError that the failure path turned into exit 1 for every module app.
    from typer import Abort
    from typer._click.exceptions import ClickException, UsageError

    from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

    try:
        result = app(standalone_mode=False)
    except UsageError as exc:
        from automated_security_helper.cli.main import _shown_usage_error

        exc.exit_code = ASH_EXIT_USAGE_ERROR
        shown = _shown_usage_error(exc)
        if shown is exc:
            # typer's NoArgsIsHelpError, which _shown_usage_error leaves to
            # the caller. In typer's Rich markup mode (the default) the help
            # was printed while the error was built and the message is empty,
            # so nothing is written here. In the plain markup mode the help is
            # the message and nothing else prints it, so it is written here, to
            # stderr as the class's own show() writes it.
            message = exc.format_message()
            if message:
                from automated_security_helper.utils.terminal_text import (
                    shown_not_obeyed,
                )

                _emit(
                    str(shown_not_obeyed(message)) + "\n",
                    getattr(sys, "stderr", None),
                )
            raise SystemExit(exc.exit_code) from None
        raise SystemExit(getattr(shown, "exit_code", ASH_EXIT_USAGE_ERROR)) from None
    except Abort:
        _emit("Aborted!\n", getattr(sys, "stderr", None))
        raise SystemExit(1) from None
    except ClickException as exc:
        # Every other click error (a command's own ClickException, a
        # FileError): outside standalone mode click raises it to here, where
        # the standalone handling would have printed its one "Error:" line and
        # exited with its code. Printed so, shown, not obeyed: the message can
        # quote a path or a value from the scanned tree. It is not a crash to
        # report with a traceback.
        _emit(_shown(f"Error: {exc.format_message()}\n"), getattr(sys, "stderr", None))
        raise SystemExit(exc.exit_code) from None
    code = result if isinstance(result, int) and not isinstance(result, bool) else 0
    raise SystemExit(code)


def _run_reporting_failures(run: Callable[[], Any]) -> None:
    """Call *run* with usable streams, reporting any exception that escapes it."""
    repaired = ensure_std_streams()

    try:
        run()
    except SystemExit:
        # Normal control flow. Click raises it on success, `raise typer.Exit()`
        # backs `--version`, and run_ash_scan calls sys.exit with the scan's
        # verdict. Swallowing or rewriting these would corrupt every exit code
        # ASH reports.
        raise
    except KeyboardInterrupt:
        # Not a defect to diagnose; the operator knows why. A Ctrl-C that gets
        # here, during the CLI's import say, before Click has a handler of its
        # own, ends the process with 130 and prints nothing. Not the interrupt
        # itself: it can hold the exception being handled when it came as its
        # context, and the interpreter's top level would print that chain as
        # given.
        raise SystemExit(130) from None
    except BaseException as exc:
        try:
            _report_failure(exc, repaired)
        except KeyboardInterrupt:
            # A Ctrl-C anywhere in the report, the plain traceback and the line
            # saying a console was missing included, ends the process with 130.
            # Not the interrupt itself: it holds exc as its context, and the
            # interpreter's top level would print that chain as given.
            raise SystemExit(130) from None
        # `from None` because _report_failure has already printed exc in full;
        # re-raising it would render the same traceback a second time.
        raise SystemExit(1) from None
