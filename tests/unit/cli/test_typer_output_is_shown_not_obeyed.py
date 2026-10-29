# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What typer itself would print for ASH (usage errors, an escaping exception) is
shown, not obeyed.

typer prints a usage error in a panel and an exception that escapes a command as a
traceback, both through its own Rich console, which is not one of ASH's: left to
it, the text goes out as given. A usage error quotes the operator's arguments,
often CI-supplied (a branch name, a PR title), and click prints an unknown
option's name raw, so "##vso[" in it, which Azure Pipelines reads anywhere in a
line, would reach the log. An exception's text quotes repository paths and tool
output.

AshTyperGroup renders a usage error itself, through ash_console, and the entry
point renders an escaping exception's traceback through ash_console with the
console log's traceback rule (utils/log.py's _show_trace). Both run here through
the real entry point, in a child, with stdout and stderr as pipes.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.utils.helpers import checkout_env

REPO_ROOT = Path(__file__).resolve().parents[3]

_BIDI = "".join(chr(c) for c in (0x061C, 0x200E, 0x200F))
_BIDI += f"{chr(0x202A)}-{chr(0x202E)}{chr(0x2066)}-{chr(0x2069)}"
#: A raw control a terminal acts on (tab and newline lay text out and are kept).
_RAW = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f" + _BIDI + "]")
#: A line a CI runner reads as a command.
_COMMAND_LINE = re.compile(r"^\s*::|##[A-Za-z]*\[", re.MULTILINE)

#: Built in the child with chr(), so neither file holds the override itself. No
#: "=": click splits an option at its first "=", which would cut the name short.
_HOSTILE_EXPR = (
    "'x\\x1b]52;c;ZXZpbA\\x07\\x9b2K' + chr(0x202E) + "
    "'\\n::error title:t::injected ##vso[task.complete]x'"
)


def _run_child(
    body: str,
    tmp_path: Path,
    extra: dict[str, str] | None = None,
    unset: tuple[str, ...] = (),
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    for name in unset:
        env.pop(name, None)
    for name in (
        "CI",
        "FORCE_COLOR",
        "PY_COLORS",
        "TTY_COMPATIBLE",
        "GITHUB_ACTIONS",
        "TERMINAL_WIDTH",
        "COLUMNS",
        "ASH_LOG_TO_STDERR",
        "TYPER_STANDARD_TRACEBACK",
        "_TYPER_STANDARD_TRACEBACK",
    ):
        env.pop(name, None)
    env.update(extra or {})
    try:
        return subprocess.run(
            [sys.executable, "-c", body],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=tmp_path,
            env=checkout_env(env),
            timeout=120,
        )
    except subprocess.TimeoutExpired as expired:
        pytest.fail(f"still running after {expired.timeout} s")


def _assert_shown(text: str) -> None:
    assert not _RAW.search(text), repr(text)
    assert not _COMMAND_LINE.search(text), (_COMMAND_LINE.search(text), text)


#: A command whose run raises an exception quoting hostile text.
_RAISING_COMMAND = (
    "import sys\n"
    "import automated_security_helper.cli.report as report\n"
    "def boom(**kwargs):\n"
    f"    raise RuntimeError({_HOSTILE_EXPR})\n"
    "report.get_logger = boom\n"
    "sys.argv = ['ash', 'report', '--output-dir', 'out']\n"
)


@pytest.mark.parametrize(
    "case",
    [
        pytest.param("usage-error", id="unknown-option-name"),
        pytest.param("exception", id="exception-from-a-command"),
        # typer's switch for a plain traceback, which ASH's hook honors.
        pytest.param("standard-traceback", id="exception-standard-traceback"),
        # The floor: the hook itself failed, so the entry point prints the error.
        pytest.param("hook-raises", id="exception-when-the-hook-fails"),
    ],
)
@pytest.mark.integration
def test_typer_never_prints_argv_or_repository_text_as_given(tmp_path, case):
    extra = {}
    if case == "usage-error":
        body = (
            "import sys\n"
            f"sys.argv = ['ash', 'scan', '--bad' + {_HOSTILE_EXPR}]\n"
            "from automated_security_helper.cli.entrypoint import main\n"
            "main()\n"
        )
        expected_code, expected_text = 5, "No such option"
    elif case == "hook-raises":
        body = _RAISING_COMMAND + (
            "import automated_security_helper.cli.entrypoint as entrypoint\n"
            "def broken_hook(*args):\n"
            "    raise OSError('the hook could not print')\n"
            "entrypoint._ash_traceback = broken_hook\n"
            "entrypoint.main()\n"
        )
        expected_code, expected_text = 1, "RuntimeError"
    else:
        body = _RAISING_COMMAND + (
            "from automated_security_helper.cli.entrypoint import main\nmain()\n"
        )
        expected_code, expected_text = 1, "RuntimeError"
        if case == "standard-traceback":
            extra = {"TYPER_STANDARD_TRACEBACK": "1"}

    done = _run_child(body, tmp_path, extra)

    written = done.stdout + done.stderr
    assert done.returncode == expected_code, (done.returncode, written[-3000:])
    assert expected_text in written, written[-3000:]
    # The panel and the traceback wrap at the console width: compare without the
    # whitespace and the box's borders.
    squeezed = "".join(c for c in written if not c.isspace() and c != "│")
    assert "injected" in squeezed, written[-3000:]
    _assert_shown(written)


@pytest.mark.integration
def test_a_command_module_run_with_python_m_shows_an_escaping_exception(tmp_path):
    """`python -m automated_security_helper.cli.config` runs config_app through
    the entry point, so an exception that escapes it is shown, not obeyed."""
    body = (
        "import runpy, sys\n"
        "import automated_security_helper.config.resolve_config as resolve\n"
        "def boom(*args, **kwargs):\n"
        f"    raise RuntimeError({_HOSTILE_EXPR})\n"
        "resolve.resolve_config = boom\n"
        "sys.argv = ['config', 'get']\n"
        "runpy.run_module(\n"
        "    'automated_security_helper.cli.config', run_name='__main__',\n"
        "    alter_sys=True,\n"
        ")\n"
    )

    done = _run_child(body, tmp_path)

    written = done.stdout + done.stderr
    assert done.returncode == 1, written[-3000:]
    assert "RuntimeError" in written, written[-3000:]
    _assert_shown(written)


@pytest.mark.unit
def test_every_cli_module_runs_through_the_entry_point_when_run_as_main():
    """A module of the CLI run as a script goes through cli/entrypoint.py, whose
    failure path prints an escaping exception shown, not obeyed."""
    import ast

    package = REPO_ROOT / "automated_security_helper" / "cli"
    blocks = 0
    offenders = []
    for source in sorted(package.rglob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in tree.body:
            if not (
                isinstance(node, ast.If)
                and "__main__" in ast.unparse(node.test)
                and "__name__" in ast.unparse(node.test)
            ):
                continue
            blocks += 1
            called = {
                call.func.id if isinstance(call.func, ast.Name) else call.func.attr
                for call in ast.walk(node)
                if isinstance(call, ast.Call)
                and isinstance(call.func, (ast.Name, ast.Attribute))
            }
            if not called & {"main", "run_module_app", "run_mcp_server"}:
                offenders.append(f"{source.relative_to(package)}: {sorted(called)}")

    assert blocks >= 4, blocks
    assert offenders == [], offenders


@pytest.mark.parametrize("method", ["make_context", "invoke"])
@pytest.mark.unit
def test_typers_no_args_help_passes_through_as_it_came(method):
    """typer prints nothing for its NoArgsIsHelpError, so it is re-raised as is,
    not made its own cause."""
    from unittest.mock import MagicMock, patch

    from typer._click.exceptions import NoArgsIsHelpError
    from typer.core import TyperGroup

    from automated_security_helper.cli.main import AshTyperGroup

    error = NoArgsIsHelpError(MagicMock())
    group = AshTyperGroup(name="ash")
    ctx = MagicMock(_protected_args=[], resilient_parsing=True)
    call = (
        (lambda: group.make_context("ash", []))
        if method == "make_context"
        else (lambda: group.invoke(ctx))
    )

    with patch.object(TyperGroup, method, side_effect=error):
        with pytest.raises(NoArgsIsHelpError) as raised:
            call()

    assert raised.value is error
    assert raised.value.__cause__ is None, raised.value.__cause__


#: A color code, as the console writes them when it is forced to.
_SGR = re.compile(r"\x1b\[[0-9;]*m")


@pytest.mark.integration
def test_a_usage_error_keeps_typers_color_and_highlighting_under_github_actions(
    tmp_path,
):
    """typer forces color under GITHUB_ACTIONS, whose log shows it, and colors an
    option's name; ASH's console prints the error the same way.

    The child gets the variables GitHub documents for every job, GITHUB_ACTIONS
    and CI, both "true", and no TERM, which that list does not hold. The caller's
    TERM is not passed on: under TERM=dumb Rich writes no color even when forced.
    """
    body = (
        "import sys\n"
        "sys.argv = ['ash', 'scan', '--nope']\n"
        "from automated_security_helper.cli.entrypoint import main\n"
        "main()\n"
    )

    done = _run_child(
        body, tmp_path, {"GITHUB_ACTIONS": "true", "CI": "true"}, unset=("TERM",)
    )

    assert done.returncode == 5, done.stderr
    # The option's name in typer's option style, bold cyan: the highlighter
    # colors "-" and "-nope" as two spans.
    assert re.search(r"\x1b\[1;36m-(\x1b\[0m\x1b\[1;36m)?-nope", done.stderr), repr(
        done.stderr
    )
    _assert_shown(_SGR.sub("", done.stdout + done.stderr))


@pytest.mark.integration
def test_a_traceback_is_as_wide_as_the_console(tmp_path):
    """typer lets the traceback take the console's width; Rich's default is 100."""
    body = (
        "import sys\n"
        "import automated_security_helper.cli.report as report\n"
        "def boom(**kwargs):\n"
        "    raise RuntimeError('w ' * 70)\n"
        "report.get_logger = boom\n"
        "sys.argv = ['ash', 'report', '--output-dir', 'out']\n"
        "from automated_security_helper.cli.entrypoint import main\n"
        "main()\n"
    )

    done = _run_child(body, tmp_path, {"COLUMNS": "160"})

    assert done.returncode == 1, done.stderr
    # The frames' panel, whose top border carries the title, spans the width.
    top = [line for line in done.stderr.splitlines() if "most recent call last" in line]
    assert top, done.stderr[-2000:]
    assert len(top[0]) > 120, (len(top[0]), top[0])
