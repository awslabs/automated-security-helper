# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan's refusal of its config file is shown, not obeyed.

A workspace scan reads its execution settings (how many projects run at once)
from the workspace root's config before anything else, and refuses the run with
exit 3 when it cannot find or read that file, as the same file refuses a
single-directory scan. The refusal quotes the file's path and the error, and
the scan prints it through its config refusal printer
(``_printed_config_refusal``), which shows each of the refusal's lines on one
line, a control character and a newline in the path as their escapes. A
config path with an escape sequence and a "::add-mask::" line reaches the
terminal or the CI log shown, on the refusal's own line, each escape once.
"""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404 - the code under test runs in a child process
import sys

import pytest

from tests.utils.helpers import importing_this_checkout

#: A config path a workspace scan is given: a BEL and an OSC 52 clipboard
#: write with no terminator (a complete sequence is removed from an error's
#: text in every print), and a newline that starts a GitHub Actions command.
_HOSTILE = "cfg\x07\x1b]52;c;ZXZpbA==\n::add-mask::hidden.yaml"

#: A control character other than a tab and the line feed that ends each line
#: the printer prints; the path's own newline is written as an escape.
_RAW_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_COMMAND_LINE = re.compile(r"^\s*::|##[A-Za-z]*\[", re.MULTILINE)

#: A fresh process, as `ash scan --mode workspace` starts one, refusing as the
#: scan's own handlers refuse (run_ash_scan: ``except ASHConfigValidationError``,
#: which calls ``_printed_config_refusal``).
_CHILD = """
import sys
from pathlib import Path

from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from automated_security_helper.interactions import run_ash_scan

root = Path(sys.argv[1])
hostile = sys.argv[3]
if sys.argv[2] == "unreadable":
    config = hostile
else:
    config = None

    def discovered(source_dir):
        raise ASHConfigSourceError(f"two config files named {hostile}")

    run_ash_scan._discovered_config_path = discovered
try:
    run_ash_scan._resolve_workspace_execution_config(
        run_ash_scan.ScanOptions(source_dir=root, output_dir=root / "out", config=config)
    )
except ASHConfigValidationError as error:
    run_ash_scan._printed_config_refusal(3, error)
"""


@pytest.mark.parametrize(
    "case, says",
    [
        ("unreadable", "could not read"),
        ("undiscoverable", "two config files named"),
    ],
)
@pytest.mark.integration
def test_the_workspace_config_refusal_is_shown(tmp_path, case, says):
    env = {key: value for key, value in os.environ.items() if key != "ASH_CONFIG"}
    child = subprocess.run(  # nosec B603 - this interpreter, fixed code
        [
            sys.executable,
            "-c",
            importing_this_checkout(_CHILD),
            str(tmp_path),
            case,
            _HOSTILE,
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        timeout=120,
    )
    # Its bytes: text mode would turn a bare carriage return into "\n".
    shown = child.stdout.decode("utf-8") + child.stderr.decode("utf-8")

    assert child.returncode == 3, shown
    assert says in shown, repr(shown)
    assert "add-mask" in shown, repr(shown)
    # The path's newline is written as its escape, so "::add-mask::" stays on
    # the refusal's line rather than starting one.
    assert "\\x0a::add-mask::" in shown, repr(shown)
    assert not _RAW_CONTROL.search(shown), repr(shown)
    assert not _COMMAND_LINE.search(shown), repr(shown)
    # Each escape shown once: its backslash is not doubled.
    assert "\\x07\\x1b]52;c;ZXZpbA==" in shown, repr(shown)
    assert "\\\\x1b" not in shown, repr(shown)


_SECRET_HEAD = "canary-Zq7Kx9Lm"
_SECRET_TAIL = "Pw4Nv2Rt-canary"


@pytest.mark.parametrize("carried", [True, False], ids=["value-carried", "control"])
@pytest.mark.unit
def test_the_refusal_hides_a_value_a_complete_code_splits(capsys, carried):
    """The refusal's lines hold a carried environment value neither whole nor in pieces.

    The path in the message spells the value with a complete color code in the
    middle, which no contiguous match finds until the code is gone. The control
    carries no value, so the same line prints its pieces: the absence in the
    first case is the redaction's.
    """
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.interactions import run_ash_scan
    from automated_security_helper.utils.error_text import carry_environment_values

    error = ASHConfigValidationError(
        f"could not read cfg-{_SECRET_HEAD}\x1b[1m{_SECRET_TAIL}.yaml"
    )
    if carried:
        carry_environment_values(error, [_SECRET_HEAD + _SECRET_TAIL])

    with pytest.raises(SystemExit) as refused:
        run_ash_scan._printed_config_refusal(3, error)

    captured = capsys.readouterr()
    shown = captured.out + captured.err
    assert refused.value.code == 3
    assert "could not read" in shown, repr(shown)
    if carried:
        assert _SECRET_HEAD not in shown, repr(shown)
        assert _SECRET_TAIL not in shown, repr(shown)
    else:
        assert _SECRET_HEAD in shown, repr(shown)
