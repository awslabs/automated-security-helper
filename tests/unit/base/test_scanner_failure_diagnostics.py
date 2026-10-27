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

#: What a tool writes for a clean scan: SARIF with one run and no results. A log with
#: no run records no scan, and the template reports it as nothing to grade.
ONE_RUN_SARIF = '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fake"}}, "results": []}]}'


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
            run_command_with_output_handling passes check=False. A returned
            stderr is in the response and in self.errors, as the real one puts
            it."""
            self.exit_code = self.fake_exit_code
            response = {"returncode": self.fake_exit_code}
            if self.fake_stderr_to_log and results_dir is not None:
                log = Path(results_dir) / f"{self.__class__.__name__}.stderr.log"
                log.parent.mkdir(parents=True, exist_ok=True)
                log.write_text(self.fake_stderr_to_log, encoding="utf-8")
            if self.fake_stderr_to_errors:
                self.errors.extend(self.fake_stderr_to_errors.splitlines())
                response["stderr"] = self.fake_stderr_to_errors
            if self.fake_writes_results is not None:
                self.fake_results_file.parent.mkdir(parents=True, exist_ok=True)
                self.fake_results_file.write_text(
                    self.fake_writes_results, encoding="utf-8"
                )
            return response

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
    # Exit code 1 is in success_exit_codes and the results file is missing, so
    # the failure is not a rejected result and its log is read. A rejected
    # result's log is not read (test_scanner_refusal_message.py); every cell
    # below that checks the log read or its redaction uses this shape.
    scanner = _make_scanner(
        tmp_path,
        exit_code=1,
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
        writes_results=ONE_RUN_SARIF,
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
        writes_results=ONE_RUN_SARIF,
    )

    report = _run(scanner, tmp_path)

    assert report is not None
    assert scanner.exit_code == 1


def test_a_value_straddling_the_log_excerpts_cut_is_not_leaked(tmp_path, monkeypatch):
    """The log-file excerpt is REDACTED before it is cut. The log keeps the
    tool's text verbatim, so a quoted env-read value sits in it in clear;
    cutting the raw text first can split that value at the excerpt's edge,
    leaving a live fragment that whole-spelling redaction can no longer
    match. The value here is placed so a cut-first order keeps its first
    nine characters at the excerpt's end."""
    value = "LOGSECRET" + "440771"
    filler = "e" * (2000 - 9)
    stderr = filler + value + " and trailing resolver text"
    scanner = _make_scanner(tmp_path, exit_code=1, stderr_to_log=stderr)
    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: (value,))

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "exit code 1" in message, message
    assert "LOGSECRET" not in message, message
    assert value not in message, message


def test_a_uv_scanners_log_excerpt_hides_the_runs_glued_spec(tmp_path, monkeypatch):
    """Under the default stderr_preference="write" a uv run's response carries
    no stderr, so the stderr log is the ONLY route uv's resolver text reaches
    the failure message. That route gets the SAME hiding arms as the debug
    record and the report lines: the run's plugin-built inputs ride along, so
    a spec holding a glued env-read value ("qz4b" inside "pkgqz4b==1.0") is
    hidden here too instead of printing in clear beside paths that hide it."""
    value = "qz4b"
    spec = "pkg" + value + "==1.0"
    stderr = f"error: there is no version of {spec}, so resolution failed."
    scanner = _make_scanner(tmp_path, exit_code=1, stderr_to_log=stderr)
    scanner.use_uv_tool = True
    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: (value,))
    monkeypatch.setattr(
        type(scanner), "_uv_from_spec", lambda self: spec, raising=False
    )

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "resolution failed" in message, message
    assert spec not in message, message
    assert value not in message, message


def test_a_raising_inputs_hook_keeps_the_redacted_excerpt(tmp_path, monkeypatch):
    """A third-party override of the uv inputs hook can raise. Every record
    site applies one policy for that (through _uv_run_inputs_for_records):
    the excerpt survives with the plain value layer, so the scan's real
    error and its tool text stay visible, the env-read value stays hidden,
    and the hook's own exception never replaces the scan's failure."""
    value = "HOOKSECRET-7731"
    scanner = _make_scanner(
        tmp_path, exit_code=1, stderr_to_log=f"resolver said {value}"
    )
    scanner.use_uv_tool = True
    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: (value,))

    def _raises(self):
        raise TypeError("signature drift")

    monkeypatch.setattr(type(scanner), "_uv_run_inputs", _raises, raising=False)

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "exit code 1" in message, message
    assert value not in message, message
    assert "resolver said" in message, message
    assert "could not be shown" not in message, message
    assert "signature drift" not in message, message


def test_a_raising_values_hook_does_not_replace_the_scans_real_error(
    tmp_path, monkeypatch
):
    """_values_to_redact is the hook with no safe degradation: without the
    values the excerpt cannot be redacted at all, so a raise there drops the
    excerpt and the message names the log path -- never the raw log, which
    would print the env-read values the redaction hides, and never the
    hook's own exception in place of the scan's failure."""
    value = "HOOKSECRET-7731"
    scanner = _make_scanner(
        tmp_path, exit_code=1, stderr_to_log=f"resolver said {value}"
    )
    log_path = tmp_path / "out" / "scanners" / "fake" / "_FakeScanner.stderr.log"

    def _raises(self):
        # The hook is called at several points in the scan path; the drift
        # this cell pins is one that bites when the failure message is
        # built, after the tool ran -- so it raises only once the tool's
        # stderr log exists, which is exactly the excerpt block's call.
        if log_path.exists():
            raise TypeError("signature drift")
        return (value,)

    monkeypatch.setattr(type(scanner), "_values_to_redact", _raises)

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "exit code 1" in message, message
    assert value not in message, message
    assert "resolver said" not in message, message
    assert "could not be shown" in message, message
    assert ".stderr.log" in message, message
    assert "signature drift" not in message, message


def test_a_uv_scanners_log_excerpt_hides_a_spec_that_pins_a_short_value(
    tmp_path, monkeypatch
):
    """The excerpt must carry the run's inputs, not just the value layer: a
    short env-read pin ("1.8") sits below the value layer's whole-word band,
    so an excerpt taken as written apart from the plain value layer would
    print "bandit==1.8" in clear and reveal the pin. Only the input-origin
    structure arm hides it."""
    pin = "1.8"
    spec = f"bandit=={pin}"
    stderr = f"error: because you require {spec}, resolution failed."
    scanner = _make_scanner(tmp_path, exit_code=1, stderr_to_log=stderr)
    scanner.use_uv_tool = True
    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: (pin,))
    monkeypatch.setattr(
        type(scanner), "_uv_from_spec", lambda self: spec, raising=False
    )

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "resolution failed" in message, message
    assert spec not in message, message


def test_a_value_split_at_the_log_reads_edge_is_not_leaked(tmp_path, monkeypatch):
    """The bounded log read can cut INSIDE a value: bytes past the bound were
    never read, so no redact-first order exists at that edge, and the piece
    the read kept survives whole-spelling redaction. When the text before the
    value is mostly color codes -- which the shown layers strip -- the shown
    text falls under the excerpt bound and the piece prints at its end. The
    read takes one byte past its bound so the cut is KNOWN, and the raw tail
    is trimmed of any piece that is a prefix of a value's spelling, the same
    trim the carried log's read bound applies."""
    from automated_security_helper.base.scanner_plugin import _STDERR_EXCERPT_LIMIT

    bound = _STDERR_EXCERPT_LIMIT * 32
    value = "EDGESECRET-9407716512"
    kept = 6  # characters of the value the bounded read keeps
    codes, plain_rest = divmod(bound - kept, 5)
    filler = "\x1b[31m" * codes + "y" * plain_rest
    stderr = filler + value + " trailing resolver text past the read bound"
    scanner = _make_scanner(tmp_path, exit_code=1, stderr_to_log=stderr)
    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: (value,))

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "exit code 1" in message, message
    assert value[:kept] not in message, message


def test_a_cut_log_read_names_the_log_in_the_message(tmp_path, monkeypatch):
    """When the read stopped before the log's end, the message says so and
    names the log, whatever the excerpt's length: a code-heavy log redacts
    to under the excerpt bound, so no ``...[truncated]`` marker fired and
    the message ended at the read's cut as if that were the tool's last
    line -- the real closing lines, more than 64 KB in, were never read."""
    from automated_security_helper.base.scanner_plugin import _STDERR_EXCERPT_LIMIT

    bound = _STDERR_EXCERPT_LIMIT * 32
    value = "EDGESECRET-9407716512"
    kept = 6
    codes, plain_rest = divmod(bound - kept, 5)
    stderr = "\x1b[31m" * codes + "y" * plain_rest + value + " closing lines"
    scanner = _make_scanner(tmp_path, exit_code=1, stderr_to_log=stderr)
    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: (value,))

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "the log continues beyond this excerpt" in message, message[-200:]
    assert ".stderr.log" in message, message[-200:]
    assert value[:kept] not in message, message[-200:]


def test_a_cut_read_the_trim_emptied_is_not_called_no_stderr(tmp_path, monkeypatch):
    """A log of escape codes with a value split at the read's edge trims and
    redacts to NOTHING -- but more than 64 KB were captured, so saying
    "No stderr captured" is false. The message points at the log instead."""
    from automated_security_helper.base.scanner_plugin import _STDERR_EXCERPT_LIMIT

    bound = _STDERR_EXCERPT_LIMIT * 32
    value = "EDGESECRET-9407716512"
    # Nothing plain before the split value: after the edge trim and the
    # escape strip the shown text is empty. The kept piece of the value is
    # sized so the codes fill the bound exactly.
    kept = 6 + ((bound - 6) % 5)
    stderr = "\x1b[31m" * ((bound - kept) // 5) + value + " more"
    scanner = _make_scanner(tmp_path, exit_code=1, stderr_to_log=stderr)
    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: (value,))

    with pytest.raises(ScannerError) as excinfo:
        _run(scanner, tmp_path)

    message = str(excinfo.value)
    assert "No stderr captured" not in message, message[-200:]
    assert "the log continues beyond this excerpt" in message, message[-200:]


def test_the_log_read_takes_one_byte_past_its_excerpt_margin(tmp_path, monkeypatch):
    """Pin the read bound: 32 times the excerpt limit, plus the one byte that
    tells a cut log from one that fits exactly. Unpinned, the margin could
    grow or shrink without a test noticing, and the edge trim above assumes
    the extra byte -- without it every full-length read looks cut and the
    trim runs on logs that were never split."""
    from automated_security_helper.base.scanner_plugin import _STDERR_EXCERPT_LIMIT
    from automated_security_helper.utils.sandbox import fs_guard

    seen = {}
    real_read = fs_guard.read_bytes_at_most

    def recording(path, bound):
        seen["bound"] = bound
        return real_read(path, bound)

    monkeypatch.setattr(fs_guard, "read_bytes_at_most", recording)
    scanner = _make_scanner(tmp_path, exit_code=1, stderr_to_log="resolver said no")

    with pytest.raises(ScannerError):
        _run(scanner, tmp_path)

    assert seen["bound"] == _STDERR_EXCERPT_LIMIT * 32 + 1, seen
