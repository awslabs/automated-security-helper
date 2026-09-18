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
  It prefers ``sys.excepthook`` so the pretty traceback is not lost in the
  common case, then falls back to plain ``traceback`` formatting, then to
  ``os.write`` on a raw descriptor. It imports nothing outside the standard
  library: not Rich, not the ASH logger, not the config. Anything it needed
  could be the thing that is broken.

The heavy import of ``automated_security_helper.cli.main`` happens *inside*
:func:`main`, after the streams are known good. That ordering is load-bearing.
An incompatibility that breaks importing pydantic models, plugins or config --
the shape a new Python release produces -- would otherwise raise before any of
this ran, and be discarded by the same missing sink.

Known limitation: an exception raised while importing this module, or
``automated_security_helper/__init__.py`` above it, still precedes the repair and
is still silent on a console-less host. Closing that would require code in the
console-script stub, which pip generates and ASH does not control. Keeping this
module's own imports to ``os``, ``sys`` and ``traceback`` is what holds that
window as narrow as it can be, so do not add imports at module scope.
"""

import os
import sys
import traceback

#: Prefix for the last-resort report. Deliberately greppable, and it names the
#: program because on this path nothing else has identified itself yet.
_BANNER = "ash: fatal error"


def _reattach(fd: int):
    """Return a text stream writing to descriptor *fd*, or ``None``.

    ``errors="backslashreplace"`` because this stream is opened with the
    platform's default encoding, and on Windows that is often a code page which
    cannot represent the box-drawing characters Rich uses to frame a traceback.
    A stream that raises ``UnicodeEncodeError`` while reporting an error is no
    better than no stream at all.

    ``closefd=False`` so garbage collection of this object does not close the
    process's real stderr underneath anything else holding it.
    """
    try:
        return os.fdopen(fd, "w", buffering=1, errors="backslashreplace", closefd=False)
    except OSError:
        # EBADF: the descriptor is genuinely closed, not merely unattached.
        return None


def ensure_std_streams() -> tuple[str, ...]:
    """Reattach ``sys.stdout``/``sys.stderr`` when they are ``None``.

    Returns the names repaired, which is empty on every normal invocation.

    Only ever acts on ``None``. A stream replaced by a test harness, a capture
    object or a pipe is left alone -- this is repairing an absent sink, not
    second-guessing a caller who installed one.
    """
    repaired = []
    for name, fd in (("stdout", 1), ("stderr", 2)):
        if getattr(sys, name, None) is not None:
            continue
        stream = _reattach(fd)
        if stream is None:
            continue
        setattr(sys, name, stream)
        # The docs quoted above warn that the saved original can be None as
        # well. logging's lastResort handler and several libraries reach for
        # sys.__stderr__ when sys.stderr looks unusable, so leaving it None
        # keeps a hole open behind the one just closed.
        if getattr(sys, f"__{name}__", None) is None:
            setattr(sys, f"__{name}__", stream)
        repaired.append(name)
    return tuple(repaired)


def _write_raw(text: str) -> bool:
    """Write *text* to a raw descriptor, bypassing ``sys.stderr`` entirely.

    Reached only when there is no Python-level stream object left to trust, so
    it uses ``os.write`` and tries stderr before stdout. Returns whether the
    text reached anything.
    """
    payload = text.encode("utf-8", "backslashreplace")
    for fd in (2, 1):
        try:
            os.write(fd, payload)
            return True
        except OSError:
            continue
    return False


def _report_failure(exc: BaseException, repaired: tuple[str, ...] = ()) -> None:
    """Report *exc*, degrading through every channel rather than giving up.

    Tries ``sys.excepthook`` first. By the time an exception escapes ``app()``,
    ``Typer.__call__`` has already tagged it for pretty rendering, so going
    through the hook keeps the Rich traceback that ``pretty_exceptions_enable``
    and ``ASH_DEBUG_SHOW_LOCALS`` exist to produce. Output on a healthy terminal
    is therefore unchanged by this module.

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

    hook = getattr(sys, "excepthook", None)
    if stderr is not None and hook is not None:
        try:
            hook(type(exc), exc, exc.__traceback__)
            return
        except BaseException:
            # The reporter destroyed the report. Keep going: a plain traceback
            # is worth more than a pretty one that never arrived.
            pass

    detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    _emit(f"{_BANNER}: {type(exc).__name__}: {exc}\n{detail}", stderr)


def _emit(text: str, stream) -> None:
    """Write *text* to *stream*, falling back to a raw descriptor."""
    if stream is not None:
        try:
            stream.write(text)
            stream.flush()
            return
        except BaseException:
            pass
    _write_raw(text)


def main() -> None:
    """Entry point for the ``ash``, ``ashv3`` and ``automated-security-helper`` scripts."""
    repaired = ensure_std_streams()

    try:
        # Imported here, not at module scope: see the module docstring. The
        # streams have to be usable before this line can fail.
        from automated_security_helper.cli.main import run_app

        run_app()
    except SystemExit:
        # Normal control flow. Click raises it on success, `raise typer.Exit()`
        # backs `--version`, and run_ash_scan calls sys.exit with the scan's
        # verdict. Swallowing or rewriting these would corrupt every exit code
        # ASH reports.
        raise
    except KeyboardInterrupt:
        # Not a defect to diagnose; the operator knows why. Re-raised so the
        # interpreter's own signal semantics are untouched.
        raise
    except BaseException as exc:
        _report_failure(exc, repaired)
        # `from None` because _report_failure has already printed exc in full;
        # re-raising it would render the same traceback a second time.
        raise SystemExit(1) from None
