# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""When a scanner fails, the reported error must name the cause.

The failure this pins
---------------------
Two opengrep runs failed in CI with exit code 7 and the reported error was
``[Errno 2] No such file or directory``. The stderr existed the whole time --
on disk, in ``<results_dir>/OpengrepScanner.stderr.log`` -- and the error
message simply never looked there. Nothing was destroyed; the diagnostic was
just not where anyone reading the error would find it.

Why the stderr is on disk rather than in ``self.errors``
-------------------------------------------------------
``_run_subprocess`` defaults to ``stderr_preference="write"``
(``plugin_base.py``), so stderr is written to a log file and NOT returned in the
response. ``_process_command_response`` only extends ``self.errors`` from
``response.get("stderr")``, which is absent under that default. Only 3 of the 8
production call sites pass a preference that returns stderr, so the empty
``self.errors`` case is the common one, not the exotic one -- which is why the
log-file fallback below is the test that matters most.

A non-zero exit is not an exception
-----------------------------------
``run_command_with_output_handling`` passes ``check=False``
(``subprocess_utils.py``), so a tool exiting 7 returns ``{"returncode": 7}`` and
raises nothing. The scan then proceeds to read a results file the tool never
wrote, and THAT is what raises. So the failure surfaces two steps away from its
cause, in a different function, as a different exception type.

Why the assertions include the exit code
---------------------------------------
``success_exit_codes`` is ``{0, 1}`` and bandit deliberately exits 1 when it
finds issues, so "non-zero" does not mean "failed". The reported error therefore
has to say both the code AND whether that code was acceptable for this scanner:
that pair is what distinguishes "the tool ran and signalled findings" from "the
tool died". Asserting only that stderr appears would pass a message that leaves
the reader unable to tell those apart.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from automated_security_helper.core.exceptions import ScannerError


def _make_scanner(
    tmp_path,
    *,
    exit_code: int,
    stderr_to_log: str = "",
    stderr_to_errors: str = "",
    writes_results: str | None = None,
):
    """Build a scanner over the REAL base whose subprocess behaviour is fixed.

    The fake behaviour is baked into a per-call subclass as class attributes
    rather than set on the instance, because ``ScannerPluginBase`` is a pydantic
    model and undeclared instance attributes do not survive assignment. The
    class is named ``_FakeScanner`` so the stderr log filename the production
    code derives from ``self.__class__.__name__`` is predictable.
    """
    source_dir = tmp_path / "src"
    source_dir.mkdir(parents=True, exist_ok=True)
    # scan() returns early on an empty target (scanner_plugin.py:463), so the
    # directory needs at least one file or none of the error path runs at all.
    (source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    output_dir = tmp_path / "out"
    output_dir.mkdir(parents=True, exist_ok=True)
    results_file = output_dir / "scanners" / "fake" / "results.json"

    class _FakeScanner(ScannerPluginBase):
        """Subclasses the real base so the real ``scan()`` control flow runs."""

        # ClassVar, or pydantic treats these as unannotated model fields and
        # refuses to build the class.
        fake_exit_code: ClassVar[int] = exit_code
        fake_stderr_to_log: ClassVar[str] = stderr_to_log
        fake_stderr_to_errors: ClassVar[str] = stderr_to_errors
        fake_writes_results: ClassVar[str | None] = writes_results
        fake_results_file: ClassVar[Path] = results_file

        def model_post_init(self, context) -> None:
            return None

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            return (["fake-tool", "--scan"], self.fake_results_file, None)

        def _run_subprocess(self, command, results_dir=None, **kwargs):
            """Mirror the real one on a non-zero exit: set exit_code, write
            stderr to the log file, and RETURN rather than raise -- because
            run_command_with_output_handling passes check=False."""
            self.exit_code = self.fake_exit_code
            if self.fake_stderr_to_log and results_dir is not None:
                log = Path(results_dir) / f"{self.__class__.__name__}.stderr.log"
                log.parent.mkdir(parents=True, exist_ok=True)
                log.write_text(self.fake_stderr_to_log, encoding="utf-8")
            if self.fake_stderr_to_errors:
                self.errors.extend(self.fake_stderr_to_errors.splitlines())
            if self.fake_writes_results is not None:
                self.fake_results_file.parent.mkdir(parents=True, exist_ok=True)
                self.fake_results_file.write_text(
                    self.fake_writes_results, encoding="utf-8"
                )
            return {"returncode": self.fake_exit_code}

    context = MagicMock()
    context.source_dir = source_dir
    context.output_dir = output_dir
    context.work_dir = tmp_path / "work"

    scanner = _FakeScanner.model_construct()
    scanner.context = context
    scanner.config = MagicMock()
    scanner.config.name = "fake-tool"
    scanner.errors = []
    scanner.output = []
    scanner.exit_code = 0
    # model_post_init is overridden to a no-op above, so the field it normally
    # populates has to be set here -- _post_scan calls self.results_dir.mkdir
    # (scanner_plugin.py:200) and would fail on None before reaching the error
    # path under test.
    scanner.results_dir = output_dir / "scanners" / "fake"
    return scanner


def _run(scanner, tmp_path):
    return scanner.scan(target=tmp_path / "src", target_type="source")


# ---------------------------------------------------------------------------
# 1. stderr already in self.errors reaches the reported error
# ---------------------------------------------------------------------------


def test_stderr_from_errors_list_reaches_the_reported_error(tmp_path):
    scanner = _make_scanner(
        tmp_path,
        exit_code=7,
        stderr_to_errors="opengrep: could not reach the rule registry",
    )

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "could not reach the rule registry" in message, message
    # "exit code 7", not bare "7" -- pytest tmp paths contain digits, so a bare
    # substring check would pass on the path alone and prove nothing.
    assert "exit code 7" in message, message


# ---------------------------------------------------------------------------
# 2. The exit code and its acceptability are both stated
# ---------------------------------------------------------------------------


def test_the_error_states_the_exit_code_and_that_it_was_not_acceptable(tmp_path):
    """`success_exit_codes` is {0, 1}, so 7 is a real failure and 1 is not.

    The message has to carry that judgement, or a reader cannot tell a tool that
    died from one that exited non-zero to signal findings.
    """
    scanner = _make_scanner(tmp_path, exit_code=7, stderr_to_errors="boom")

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "exit code 7" in message, message
    # The acceptability verdict, not just the number.
    assert "not an accepted exit code" in message, message
    assert "success_exit_codes=[0, 1]" in message, message


def test_an_accepted_nonzero_exit_is_reported_as_accepted(tmp_path):
    """Exit 1 is in success_exit_codes -- bandit uses it for findings.

    If the results file is still missing the scan fails anyway, but the message
    must not accuse the exit code, or it sends the reader after the wrong thing.
    """
    scanner = _make_scanner(tmp_path, exit_code=1, stderr_to_errors="just findings")

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "exit code 1" in message, message
    assert "an accepted exit code for this scanner" in message, message
    assert "not an accepted" not in message, message


# ---------------------------------------------------------------------------
# 3. The log-file fallback -- the actual opengrep shape
# ---------------------------------------------------------------------------


def test_stderr_is_recovered_from_the_log_file_when_errors_is_empty(tmp_path):
    """The case that matters: default stderr_preference="write".

    5 of 8 call sites take this default, so stderr is on disk and self.errors is
    empty. Without this recovery the reported error names a missing file and the
    reason sits unread in a log beside it.
    """
    scanner = _make_scanner(
        tmp_path,
        exit_code=7,
        stderr_to_log="opengrep: registry fetch failed after 3 attempts",
    )
    assert scanner.errors == []

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "registry fetch failed after 3 attempts" in message, message


def test_the_log_file_path_is_named_when_there_is_no_stderr_anywhere(tmp_path):
    """A tool that died silently. Say where we looked, so the next reader does
    not have to guess whether stderr was empty or merely unread."""
    scanner = _make_scanner(tmp_path, exit_code=7)

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "stderr" in message.lower(), message
    assert "_FakeScanner.stderr.log" in message, message


# ---------------------------------------------------------------------------
# 4. Positive control: a successful scan is untouched
# ---------------------------------------------------------------------------


def test_a_successful_scan_still_works(tmp_path):
    """The control that makes every assertion above meaningful.

    A change that reported everything as an error would satisfy all of them.
    This scanner exits 0 and writes a valid SARIF, and must come back normally.
    """
    scanner = _make_scanner(
        tmp_path,
        exit_code=0,
        writes_results='{"version": "2.1.0", "runs": []}',
    )

    report = _run(scanner, tmp_path)

    assert report is not None
    assert getattr(report, "version", None) == "2.1.0"


def test_an_accepted_nonzero_exit_with_results_still_succeeds(tmp_path):
    """Bandit's shape: exit 1 with real output. Must not become an error.

    This is the regression that a fix keying on `exit_code != 0` would cause,
    and it is why the change is message-only.
    """
    scanner = _make_scanner(
        tmp_path,
        exit_code=1,
        writes_results='{"version": "2.1.0", "runs": []}',
    )

    report = _run(scanner, tmp_path)

    assert report is not None
    assert scanner.exit_code == 1
