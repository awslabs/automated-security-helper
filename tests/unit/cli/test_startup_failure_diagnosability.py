# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests: ASH must never exit non-zero with nothing on either stream.

The bug these cover: ``ash --version`` exited 1 with *completely empty* stdout
and stderr. Observed on the MSIX packaging leg (job 105400271151, run
35279579798), both through the Windows app-execution alias and by running the
venv's own ``ash.exe`` directly. An operator got an exit code and no text.

Nothing was catching the exception -- the sink was gone. ``sys.stderr`` is
``None`` on a Windows process with no console attached (the CPython ``sys`` docs
say so explicitly for GUI apps and ``pythonw``, and note that ``sys.__stderr__``
may be ``None`` as well). Every reporting path ASH has ends at ``sys.stdout`` or
``sys.stderr``: ``ASH_LOGGER``'s ``RichHandler``, Typer's Rich traceback hook,
``typer.echo``, Click's usage-error printer, CPython's default ``excepthook``.
With no sink, all of them write nowhere at once, and CPython discards an
unhandled traceback without so much as a warning.

Why these run in subprocesses: the failure only exists when ``sys.stderr`` is
``None`` at interpreter level, which cannot be faked in-process without breaking
pytest's own capture machinery. And why they resolve the entry point out of
``pyproject.toml`` instead of importing a module directly -- the guarantee being
asserted belongs to *whatever the console scripts point at*. A test that imported
``cli.entrypoint`` by name would pass by construction on any tree where that file
exists, and would say nothing about the tree where ``[project.scripts]`` still
points at the bare Typer app. Reading the target is what makes these fail on the
unfixed tree.

``test_a_healthy_run_still_reports`` is the positive control. Without it, a
harness that could never observe a message would let every other test in this
file pass green.
"""

import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from automated_security_helper.utils.version_management import (
    _load_toml,
    get_project_root,
)

REPO_ROOT = get_project_root()

#: Injected into the child, then looked for in its output. Distinctive so a
#: match cannot come from unrelated text on the stream.
SENTINEL = "ASH_STARTUP_SENTINEL_9f3a1c"

#: The real trigger's shape. A Python release ASH has not been tested against
#: breaks the CLI import chain -- pydantic models, plugin discovery, config --
#: rather than failing in the command body. Seeding sys.modules reproduces that
#: without needing the incompatible interpreter: the module object is already
#: present, so no finder runs, and the attribute lookup the entry point performs
#: raises instead.
_BREAK_CLI_IMPORT = f'''
import sys


class _BrokenCLI:
    """Stands in for automated_security_helper.cli.main failing to import."""

    __name__ = "automated_security_helper.cli.main"

    def __getattr__(self, name):
        raise ImportError("{SENTINEL}")


sys.modules["automated_security_helper.cli.main"] = _BrokenCLI()
'''


def _console_script_target() -> tuple[str, str]:
    """Return the (module, attribute) the ``ash`` console script points at.

    pip's generated stub imports that attribute and calls it, so this is the
    first ASH code any invocation reaches.
    """
    scripts = _load_toml(REPO_ROOT / "pyproject.toml")["project"]["scripts"]
    module, _, attr = scripts["ash"].partition(":")
    assert module and attr, f"unparseable console script target: {scripts['ash']!r}"
    return module, attr


def _run_child(body: str, tmp_path: Path) -> subprocess.CompletedProcess:
    """Run *body* in a fresh interpreter with both streams on pipes.

    Pipes matter: the fix reattaches a ``None`` stream from its file descriptor,
    so descriptors 1 and 2 have to be open and observable. ``capture_output``
    gives exactly that.
    """
    script = tmp_path / "child.py"
    script.write_text(body)
    env = dict(os.environ)
    env.pop("PYTHONIOENCODING", None)
    # The child must import the tree under test, not a differently-versioned
    # ASH that happens to be installed in the environment.
    env["PYTHONPATH"] = (
        str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    ).rstrip(os.pathsep)
    return subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_path),
        timeout=300,
    )


def _stub(preamble: str) -> str:
    """Replicate pip's console-script stub around the real entry point."""
    module, attr = _console_script_target()
    return textwrap.dedent(preamble) + textwrap.dedent(
        f"""
        import sys
        from {module} import {attr}
        sys.exit({attr}())
        """
    )


def test_a_healthy_run_still_reports(tmp_path):
    """Positive control: with streams intact the sentinel is observable.

    This is the test that keeps the rest of the file honest. If the child could
    not surface a failure message under the best possible conditions, every
    assertion below would be vacuous.
    """
    result = _run_child(_stub(_BREAK_CLI_IMPORT), tmp_path)

    assert result.returncode != 0, "a broken CLI import must not exit 0"
    combined = result.stdout + result.stderr
    assert SENTINEL in combined, (
        "control failed -- the harness cannot observe a startup failure even "
        f"with healthy streams. stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_startup_failure_is_reported_when_stderr_is_none(tmp_path):
    """The regression. A failure with no console attached must still say why.

    Fails on the unfixed tree: ``[project.scripts]`` pointed at the bare Typer
    app, so the CLI import ran before any ASH code could notice the missing
    sink, and the ImportError was discarded -- exit 1, both streams empty.
    """
    result = _run_child(
        _stub(_BREAK_CLI_IMPORT + "\nsys.stderr = None\n"),
        tmp_path,
    )

    assert result.returncode != 0, "a broken CLI import must not exit 0"
    combined = result.stdout + result.stderr
    assert combined.strip(), (
        f"ASH exited {result.returncode} with both streams empty -- the operator "
        "has an exit code and nothing to act on. This is the reported defect."
    )
    assert SENTINEL in combined, (
        "startup failure was reported but did not identify the cause. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_report_names_the_missing_console_as_the_cause(tmp_path):
    """The report must say the process had no console, not just print a traceback.

    That sentence is the root cause. Without it an operator sees an ImportError
    and starts debugging the import, when the reason they never saw it before is
    that the process had nowhere to write. It is emitted ahead of the traceback
    because the delegated ``sys.excepthook`` path returns without reaching the
    fallback formatting, so anything attached to the fallback would rarely print.
    """
    result = _run_child(
        _stub(_BREAK_CLI_IMPORT + "\nsys.stdout = sys.stderr = None\n"),
        tmp_path,
    )

    combined = result.stdout + result.stderr
    assert "no usable" in combined and "reattached" in combined, (
        "the report did not name the missing console as the cause. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_startup_failure_is_reported_when_both_streams_are_none(tmp_path):
    """Same guarantee when stdout is gone too.

    The console-less Windows case loses both, not just stderr, so covering only
    stderr would leave the reported configuration untested.
    """
    result = _run_child(
        _stub(_BREAK_CLI_IMPORT + "\nsys.stdout = None\nsys.stderr = None\n"),
        tmp_path,
    )

    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert SENTINEL in combined, (
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_startup_failure_is_reported_when_saved_originals_are_none(tmp_path):
    """``sys.__stderr__`` can be ``None`` as well, per the CPython docs.

    So the repair cannot work by restoring from the saved original. This pins
    that it reattaches from a file descriptor instead -- delete this and a
    ``sys.stderr = sys.__stderr__`` implementation would pass everything else.
    """
    result = _run_child(
        _stub(
            _BREAK_CLI_IMPORT
            + "\nsys.stdout = sys.stderr = None"
            + "\nsys.__stdout__ = sys.__stderr__ = None\n"
        ),
        tmp_path,
    )

    assert result.returncode != 0
    combined = result.stdout + result.stderr
    assert SENTINEL in combined, (
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_version_prints_when_stdout_is_none(tmp_path):
    """The originally reported symptom, as the CI check ran it.

    ``ash --version`` on a console-less host produced nothing and exited 1. Once
    the streams are reattached it prints and exits 0, which is what the packaging
    leg's smoke check asserts.
    """
    result = _run_child(
        _stub(
            """
            import sys

            sys.argv = ["ash", "--version"]
            sys.stdout = None
            sys.stderr = None
            """
        ),
        tmp_path,
    )

    assert result.returncode == 0, (
        f"ash --version exited {result.returncode}. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "automated-security-helper v" in result.stdout, (
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_scan_exit_codes_are_not_rewritten(tmp_path):
    """The floor must not touch ``SystemExit``.

    ASH's verdict travels as ``sys.exit(<code>)`` from ``run_ash_scan``, and
    ``--version`` ends in ``raise typer.Exit()``. An entry point that caught
    those to report them would flatten every exit code ASH has.
    """
    module, attr = _console_script_target()
    result = _run_child(
        textwrap.dedent(
            f"""
            import sys


            class _ExitingCLI:
                __name__ = "automated_security_helper.cli.main"

                def __getattr__(self, name):
                    def _run_app():
                        sys.exit(3)

                    return _run_app


            sys.modules["automated_security_helper.cli.main"] = _ExitingCLI()

            from {module} import {attr}

            sys.exit({attr}())
            """
        ),
        tmp_path,
    )

    assert result.returncode == 3, (
        f"exit code was rewritten to {result.returncode}. "
        f"stderr={result.stderr!r}"
    )


@pytest.mark.parametrize(
    "payload",
    [
        # The exact two shapes from #589. The first reads as a closing tag and
        # makes rich.markup.render raise; the second reads as an opening tag and
        # is consumed silently as a style name.
        "[/bin/bash -c]",
        "[node_modules]",
    ],
)
def test_bracketed_failure_messages_survive_the_report(tmp_path, payload):
    """Rich markup in a failure message must not destroy the report.

    #589 fixed Rich parsing ``[...]`` in *log messages* -- ``RichHandler`` with
    ``markup=True`` either raised ``MarkupError`` or swallowed the span. The floor
    added here has its own first rung that renders through Rich, via
    ``sys.excepthook``, so the same family has to be ruled out on that path
    rather than assumed absent: a startup failure explaining itself with a
    subprocess argv or a Windows path is exactly when brackets show up.

    ``rich.traceback.install()`` stands in for the hook Typer installs inside
    ``Typer.__call__``. Using it rather than reaching into Typer keeps the test
    about the floor's contract -- text in, same text out -- instead of about
    Typer's internals.

    The trailing marker matters as much as the payload. The swallowing shape
    truncates rather than erroring, so asserting only that the payload is absent
    would not distinguish "dropped the span" from "dropped everything after it".
    """
    module, attr = _console_script_target()
    result = _run_child(
        textwrap.dedent(
            f"""
            import sys
            import rich.traceback

            rich.traceback.install()


            class _BrokenCLI:
                __name__ = "automated_security_helper.cli.main"

                def __getattr__(self, name):
                    def _run_app():
                        raise RuntimeError(
                            "{payload} {SENTINEL} trailing_marker"
                        )

                    return _run_app


            sys.modules["automated_security_helper.cli.main"] = _BrokenCLI()
            sys.stdout = sys.stderr = None
            sys.__stdout__ = sys.__stderr__ = None

            from {module} import {attr}

            sys.exit({attr}())
            """
        ),
        tmp_path,
    )

    assert result.returncode != 0
    # Rich wraps and colorizes, so compare with ANSI and whitespace removed.
    flat = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    flat = re.sub(r"\s+", "", flat)

    assert payload.replace(" ", "") in flat, (
        f"Rich markup destroyed the failure message. {payload!r} did not survive "
        f"the report. stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "trailing_marker" in flat, (
        "the message was truncated after the bracketed span. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


class TestStreamRepair:
    """Unit-level checks on the repair itself."""

    def test_healthy_streams_are_left_alone(self):
        """Repair acts only on ``None``.

        A stream replaced by pytest's capture, a redirect or a pipe belongs to
        its caller. Rebinding one would corrupt output capture across the suite
        and would make this very test file unable to observe anything.
        """
        entrypoint = pytest.importorskip(
            "automated_security_helper.cli.entrypoint",
            reason="entry-point module absent on this tree",
        )
        before_out, before_err = sys.stdout, sys.stderr

        repaired = entrypoint.ensure_std_streams()

        assert repaired == ()
        assert sys.stdout is before_out
        assert sys.stderr is before_err

    def test_raw_write_reaches_a_descriptor(self, capfd):
        """The last resort writes even with no stream object to hand.

        ``capfd`` captures at the descriptor level, which is the only place this
        path is observable -- it deliberately bypasses ``sys.stderr``.
        """
        entrypoint = pytest.importorskip(
            "automated_security_helper.cli.entrypoint",
            reason="entry-point module absent on this tree",
        )

        assert entrypoint._write_raw(f"{SENTINEL}\n") is True

        assert SENTINEL in capfd.readouterr().err
