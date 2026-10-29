# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The confinement warnings quote the repository's own paths and keys, shown once.

A config file inside the scanned tree is the repository's, and the warnings that
say what ASH ignored from it name the file, its ``extends`` bases and, for the
operator-only options, the section key. The log sinks show each terminal control
in a message and break each CI command (utils/log.py, utils/terminal_text.py),
but they keep a newline, a carriage return before one, and a tab, which lay a
message out. So each warning shows its whole message, values included, with
utils/terminal_text.py's shown_on_one_line, which writes those three out too, and
logs the result with no arguments, which the sinks leave as it is.

Were the warnings to write every character that is not printable in a value as
an escape themselves, the sinks would show that escape's backslash again: an
ESC in a key would reach the console and ash.log as ``\\\\x1b``.

Control characters are built with chr() here, so this file holds none itself.
"""

import contextlib
import logging
import re
import subprocess
import sys
from pathlib import Path

from tests.utils.helpers import importing_this_checkout, mark_git_checkout

ESC, BEL = chr(0x1B), chr(0x07)

#: A raw control left in the text: C0 and C1, other than tab and newline.
_RAW_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

#: A line a CI runner reads as a command.
_COMMAND_LINE = re.compile(r"^\s*::|##[A-Za-z]*\[", re.MULTILINE)

#: ash.log's format, as get_logger sets it.
_ASH_LOG_FORMAT = "%(asctime)s\t%(levelname)s\t%(filename)s:%(lineno)d\t%(message)s "


@contextlib.contextmanager
def _ash_log(path: Path):
    """ASH's logger writing to *path* as get_logger's ash.log handler does."""
    from automated_security_helper.utils.log import (
        ASH_LOGGER,
        LogFileHandler,
        TextFileFormatter,
    )

    handler = LogFileHandler(path.as_posix())
    handler.setLevel(logging.WARNING)
    handler.setFormatter(TextFileFormatter(fmt=_ASH_LOG_FORMAT))
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)
        handler.close()


def _written(path: Path) -> str:
    # Its bytes: reading it as text would turn a bare carriage return into "\n".
    return path.read_bytes().decode("utf-8")


def _checkout(tmp_path: Path, config: str, base_name: str, base: str) -> Path:
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    (checkout / ".ash").mkdir()
    (checkout / ".ash" / ".ash.yaml").write_text(config, encoding="utf-8")
    (checkout / ".ash" / base_name).write_text(base, encoding="utf-8")
    return checkout


_ARCHIVING = (
    "reporters:\n"
    "  aws-security-hub:\n"
    "    options:\n"
    "      archive_resolved_findings: true\n"
)


def test_a_forged_record_in_a_base_name_stays_on_the_warnings_line(tmp_path):
    """ash.log keeps a message's newlines, so a base named
    "b<newline><timestamp><tab>INFO<tab>scan_phase.py:1<tab>FORGED.yaml" is shown
    on the warning's own line and starts no record of its own."""
    from automated_security_helper.config.resolve_config import resolve_config

    forged = "\n2026-10-12 13:00:00,000\tINFO\tscan_phase.py:1\tFORGED"
    checkout = _checkout(
        tmp_path,
        'extends: "b\\n2026-10-12 13:00:00,000\\tINFO\\tscan_phase.py:1\\tFORGED.yaml"\n',
        f"b{forged}.yaml",
        _ARCHIVING,
    )
    log = tmp_path / "ash.log"

    with _ash_log(log):
        resolve_config(source_dir=checkout)

    written = _written(log)
    [line] = [line for line in written.splitlines() if "FORGED" in line]
    assert "Ignoring reporters.aws-security-hub.options" in line, repr(written)
    assert (
        "b\\x0a2026-10-12 13:00:00,000\\x09INFO\\x09scan_phase.py:1\\x09FORGED" in line
    )
    assert len(written.splitlines()) == 1, repr(written)


def test_a_section_keys_controls_are_shown_once_in_ash_log(tmp_path):
    """The key "aws-security-hub<CR><ESC>]<BEL>" is read as aws-security-hub's
    section. The warning shows its carriage return, ESC and BEL at the call site,
    and ash.log's formatter writes them as they are: each shown once."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = tmp_path / "checkout"
    (checkout / ".ash").mkdir(parents=True)
    (checkout / ".ash" / ".ash.yaml").write_text(
        "reporters:\n"
        '  "aws-security-hub\\r\\e]\\a":\n'
        "    options:\n"
        "      archive_resolved_findings: true\n",
        encoding="utf-8",
    )
    log = tmp_path / "ash.log"

    with _ash_log(log):
        resolve_config(source_dir=checkout)

    written = _written(log)
    assert "reporters.aws-security-hub\\x0d\\x1b]\\x07.options" in written, repr(
        written
    )
    assert "\\\\" not in written, repr(written)
    assert not _RAW_CONTROL.search(written), repr(written)


def test_a_sandbox_grants_file_name_is_shown_once_in_ash_log(tmp_path):
    """The sandbox-grant warning names the extends base that set
    network_scanners: "b<ESC>]<BEL><newline>x.yaml", each control shown once and
    the newline kept off a line of its own."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = _checkout(
        tmp_path,
        'extends: "b\\e]\\a\\nx.yaml"\n',
        f"b{ESC}]{BEL}\nx.yaml",
        "sandbox:\n  network_scanners:\n    - bandit\n",
    )
    log = tmp_path / "ash.log"

    with _ash_log(log):
        resolve_config(source_dir=checkout)

    written = _written(log)
    assert "Ignoring sandbox.network_scanners from" in written, repr(written)
    assert "b\\x1b]\\x07\\x0ax.yaml" in written, repr(written)
    assert "\\\\" not in written, repr(written)
    assert not _RAW_CONTROL.search(written), repr(written)
    assert len(written.splitlines()) == 1, repr(written)


def test_a_plugin_module_name_is_shown_once_in_ash_log(tmp_path):
    """The plugin-module warning names the module the repository's file asked
    for: "m<ESC>]<BEL><newline>x", each control shown once and the newline kept
    off a line of its own. It was a repr, whose escapes ash.log showed again."""
    from automated_security_helper.config.resolve_config import resolve_config

    checkout = tmp_path / "checkout"
    (checkout / ".ash").mkdir(parents=True)
    (checkout / ".ash" / ".ash.yaml").write_text(
        'ash_plugin_modules:\n  - "m\\e]\\a\\nx"\n', encoding="utf-8"
    )
    log = tmp_path / "ash.log"

    with _ash_log(log):
        resolve_config(source_dir=checkout)

    written = _written(log)
    assert "Ignoring ash_plugin_modules entries 'm\\x1b]\\x07\\x0ax'" in written, repr(
        written
    )
    assert "\\\\" not in written, repr(written)
    assert not _RAW_CONTROL.search(written), repr(written)
    assert len(written.splitlines()) == 1, repr(written)


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@contextlib.contextmanager
def _warnings():
    """The records ASH's logger emits at WARNING and above."""
    from automated_security_helper.utils.log import ASH_LOGGER

    handler = _Records()
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield handler.records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


def _the_one_warning(records, start: str) -> logging.LogRecord:
    [record] = [r for r in records if r.getMessage().startswith(start)]
    return record


def test_the_sandbox_grant_warning_is_logged_as_text_not_markup(tmp_path):
    """A base named "b[red]<ESC>.yaml": "[red]" is a Rich style tag, which would
    restyle the rest of the line and drop from it. The record carries markup
    False, so the console prints the name rather than parse it, and the message
    is the shown text, with no arguments left to fill in."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.utils.terminal_text import ShownText

    checkout = _checkout(
        tmp_path,
        'extends: "b[red]\\e.yaml"\n',
        f"b[red]{ESC}.yaml",
        "sandbox:\n  network_scanners:\n    - bandit\n",
    )

    with _warnings() as records:
        resolve_config(source_dir=checkout)

    record = _the_one_warning(records, "Ignoring sandbox.network_scanners from")
    assert getattr(record, "markup", None) is False
    assert isinstance(record.msg, ShownText) and not record.args
    assert "b[red]\\x1b.yaml" in record.getMessage()


def test_the_plugin_module_warning_is_logged_as_text_not_markup(tmp_path):
    """A module named "m[/x]<ESC>", which the repository's file asks for."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.utils.terminal_text import ShownText

    checkout = tmp_path / "checkout"
    (checkout / ".ash").mkdir(parents=True)
    (checkout / ".ash" / ".ash.yaml").write_text(
        'ash_plugin_modules:\n  - "m[/x]\\e"\n', encoding="utf-8"
    )

    with _warnings() as records:
        resolve_config(source_dir=checkout)

    record = _the_one_warning(records, "Ignoring ash_plugin_modules entries")
    assert getattr(record, "markup", None) is False
    assert isinstance(record.msg, ShownText) and not record.args
    assert "'m[/x]\\x1b'" in record.getMessage()


#: A fresh process: the MCP server's get_config resolves a configuration before
#: any logging is set up, so ASH's logger has only its stand-in for logging's
#: last resort.
_FRESH_GET_CONFIG = """
import sys
from automated_security_helper.cli.mcp_tools import mcp_get_config
mcp_get_config(search_dir=sys.argv[1])
"""


def test_get_config_in_a_fresh_process_writes_no_control_from_a_base_name(tmp_path):
    """A base named "b<ESC>]52;c;ZXZpbA==<BEL><newline>::add-mask::hidden.yaml": an
    OSC 52 clipboard write, and a line GitHub Actions reads as a command. MCP
    get_config's warning names it on stderr before get_logger has run."""
    name = f"b{ESC}]52;c;ZXZpbA=={BEL}\n::add-mask::hidden.yaml"
    checkout = _checkout(
        tmp_path,
        'extends: "b\\e]52;c;ZXZpbA==\\a\\n::add-mask::hidden.yaml"\n',
        name,
        _ARCHIVING,
    )

    proc = subprocess.run(  # nosec B603 - this interpreter, fixed code
        [
            sys.executable,
            "-c",
            importing_this_checkout(_FRESH_GET_CONFIG),
            str(checkout),
        ],
        capture_output=True,
        timeout=120,
    )

    stderr = proc.stderr.decode("utf-8")
    assert proc.returncode == 0, stderr
    assert "add-mask::hidden.yaml" in stderr, repr(stderr)
    assert not _RAW_CONTROL.search(stderr), repr(stderr)
    assert not _COMMAND_LINE.search(stderr), repr(stderr)
    assert "b\\x1b]52;c;ZXZpbA==\\x07\\x0a::add-mask" in stderr, repr(stderr)
    assert "\\\\" not in stderr, repr(stderr)
