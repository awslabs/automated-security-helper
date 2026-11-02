# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner subprocess must be bounded, not left to run forever.

Why this file exists
--------------------
Bandit ran for over 50 minutes under the MCP server and never finished. The same
project scanned in about 20 seconds from the CLI, so the report reads like an MCP
bug, but the cause is simpler: nothing bounded the scanner subprocess at all.

`run_command_with_output_handling` called `subprocess.run` with no `timeout`, and
that is the single call every template-based scanner goes through
(`ScannerPluginBase.scan` -> `_run_subprocess` -> here). So bandit, checkov,
semgrep, grype, syft, opengrep, cfn_nag and npm-audit were all equally unbounded.

detect-secrets was the exception, and it is the reason the report contrasts the
two: it grew its own `scan_timeout` option (default 300s) and enforces it with
`future.result(timeout=...)` in its own overridden scan. That was a per-scanner
workaround for a gap in the shared path, which is why only that one scanner
timed out cleanly in the reporter's log.

What "bounded" has to mean
--------------------------
`subprocess.run(timeout=...)` raises TimeoutExpired *and kills the child*. That
matters more than the exception: without the kill, the scanner process would keep
holding CPU after ASH stopped waiting for it. The tests below assert on elapsed
time to prove the call actually returns early, rather than only that some error
was reported.

Exit code 124 is used for a timeout, matching coreutils `timeout(1)`, so a
timed-out scanner is distinguishable from the generic returncode 1 the previous
error path returned for everything.
"""

import os
import sys
import time
from unittest.mock import patch

import pytest

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.utils.subprocess_utils import (
    run_command_with_output_handling,
)

# Long enough that a passing test cannot have waited for it.
_SLEEP_SECONDS = 60
_TIMEOUT_SECONDS = 2


def _sleep_command(seconds: int = _SLEEP_SECONDS):
    return [sys.executable, "-c", f"import time; time.sleep({seconds})"]


@pytest.mark.integration
class TestTimeoutIsEnforced:
    def test_a_hanging_command_returns_instead_of_blocking(self, tmp_path):
        """The reported failure mode, reduced to its smallest form."""
        started = time.monotonic()

        response = run_command_with_output_handling(
            command=_sleep_command(),
            results_dir=tmp_path,
            timeout=_TIMEOUT_SECONDS,
        )

        elapsed = time.monotonic() - started

        # Generous headroom over the timeout for interpreter startup on a loaded
        # runner, while still far below the 60s the command wanted.
        assert elapsed < 30, (
            f"Call took {elapsed:.1f}s for a {_TIMEOUT_SECONDS}s timeout, so the "
            "timeout is not being applied to the subprocess."
        )
        assert response["returncode"] == 124
        assert response.get("timed_out") is True

    def test_timeout_message_names_the_limit(self, tmp_path):
        """A hang is hard to diagnose, so the message has to say what happened."""
        response = run_command_with_output_handling(
            command=_sleep_command(),
            results_dir=tmp_path,
            timeout=_TIMEOUT_SECONDS,
        )

        combined = f"{response.get('error', '')} {response.get('stderr', '')}"
        assert "timed out" in combined.lower()
        assert str(_TIMEOUT_SECONDS) in combined

    def test_timeout_is_distinguishable_from_a_generic_failure(self, tmp_path):
        """124 vs 1.

        The previous error path returned returncode 1 for every exception, so a
        caller could not tell a timeout from a missing binary. Anything that keys
        off the exit code needs those to differ.
        """
        timed_out = run_command_with_output_handling(
            command=_sleep_command(), results_dir=tmp_path, timeout=_TIMEOUT_SECONDS
        )
        failed = run_command_with_output_handling(
            command=[sys.executable, "-c", "raise SystemExit(3)"],
            results_dir=tmp_path,
            timeout=_TIMEOUT_SECONDS,
        )

        assert timed_out["returncode"] == 124
        assert failed["returncode"] == 3
        assert failed.get("timed_out") is not True


@pytest.mark.integration
class TestNormalExecutionIsUnaffected:
    def test_fast_command_succeeds_within_a_timeout(self, tmp_path):
        response = run_command_with_output_handling(
            command=[sys.executable, "-c", "print('done')"],
            results_dir=tmp_path,
            stdout_preference="return",
            timeout=_TIMEOUT_SECONDS,
        )

        assert response["returncode"] == 0
        assert "done" in response.get("stdout", "")
        assert response.get("timed_out") is not True

    def test_no_timeout_argument_keeps_previous_behaviour(self, tmp_path):
        """Omitting timeout must not start bounding callers that never asked.

        The parameter defaults to None so existing callers behave exactly as
        before; only the scanner template opts in.
        """
        response = run_command_with_output_handling(
            command=[sys.executable, "-c", "print('unbounded')"],
            results_dir=tmp_path,
            stdout_preference="return",
        )

        assert response["returncode"] == 0
        assert "unbounded" in response.get("stdout", "")


@pytest.fixture
def runner_with_uv(monkeypatch):
    """The global UV tool runner, with uv available, whatever the host or the order.

    ``is_uv_available`` runs ``uv --version`` once and caches the answer on the global
    runner, so reading the real one makes a test pass or fail on whether uv is on PATH,
    and on whatever an earlier test in the same worker left in that cache: with uv
    off PATH, or the cache primed False, run_tool raises "UV is not available" before
    it reaches the call under test. Here the answer is the test's, and the runner is a
    fresh one installed for this test only.
    """
    from automated_security_helper.utils import uv_tool_runner

    runner = uv_tool_runner.UVToolRunner()
    monkeypatch.setattr(runner, "uv_availability", lambda: (True, None))
    monkeypatch.setattr(uv_tool_runner, "_uv_tool_runner", runner)
    return runner


@pytest.mark.unit
class TestTheUvToolPathIsAlsoBounded:
    """The path bandit, checkov and semgrep actually take.

    `_run_subprocess` has two execution paths. The uv-tool branch returns before
    the direct-execution call, so a timeout wired only into the latter applies
    exclusively to scanners for which uv is *unavailable*.

    bandit, checkov and semgrep set `use_uv_tool = True` unconditionally and clear
    it only when uv is missing. ASH ships via uv, so on a normal install the
    reported bandit hang went through the uv branch, unbounded, no matter what
    scan_timeout said. The original version of this file tested
    `run_command_with_output_handling` directly and never exercised that branch,
    which is exactly why the gap survived a green build.
    """

    def test_run_tool_forwards_the_timeout_on_the_results_dir_branch(
        self, tmp_path, runner_with_uv
    ):
        """This is the branch scanners take: they all pass results_dir.

        `run_tool` already accepted a `timeout`, but honoured it only on its
        fallback path -- the one used by callers that do *not* want output files,
        i.e. none of the scanners.
        """
        from automated_security_helper.utils import subprocess_utils
        from automated_security_helper.utils.uv_tool_runner import UVToolRunner

        captured = {}

        def _fake(**kwargs):
            captured.update(kwargs)
            return {"returncode": 0, "stdout": "", "stderr": ""}

        # A runner of the test's own, told that uv is there. This test is about
        # where the timeout goes, not about whether uv is installed, and the
        # process-wide runner from get_uv_tool_runner() remembers the first
        # is_uv_available() answer on the worker. A test that probed it through a
        # subprocess stand-in left that answer False, and this test then failed
        # with "UV is not available" on whichever xdist worker ran both.
        runner = UVToolRunner()
        with (
            patch.object(runner, "is_uv_available", return_value=True),
            patch.object(
                subprocess_utils, "run_command_with_output_handling", side_effect=_fake
            ),
        ):
            runner.run_tool(
                tool_name="bandit",
                args=["--version"],
                results_dir=tmp_path,
                timeout=_TIMEOUT_SECONDS,
            )

        assert captured.get("timeout") == _TIMEOUT_SECONDS, (
            "run_tool dropped the timeout on the results_dir branch, so every "
            "uv-run scanner executes unbounded."
        )

    def test_run_tool_without_uv_refuses_before_running_anything(
        self, tmp_path, monkeypatch
    ):
        """The other answer, also decided here: no uv, no subprocess."""
        from automated_security_helper.utils import subprocess_utils, uv_tool_runner

        runner = uv_tool_runner.UVToolRunner()
        monkeypatch.setattr(runner, "is_uv_available", lambda: False)
        with patch.object(subprocess_utils, "run_command_with_output_handling") as run:
            with pytest.raises(uv_tool_runner.UVToolRunnerError, match="not available"):
                runner.run_tool(
                    tool_name="bandit",
                    args=["--version"],
                    results_dir=tmp_path,
                    timeout=_TIMEOUT_SECONDS,
                )
        run.assert_not_called()

    def test_try_uv_tool_execution_forwards_the_timeout(self, tmp_path):
        """The seam between the plugin and the runner.

        Patched at `uv_tool_runner.get_uv_tool_runner`, not on the mixin module.
        The mixin imports it *inside* the method, so the name is resolved from the
        source module at call time and never becomes an attribute of
        uv_tool_mixin -- patching there with create=True silently installs a decoy
        that nothing ever reads, and the test passes for the wrong reason.
        """
        from automated_security_helper.utils import uv_tool_runner as runner_module
        from automated_security_helper.base.uv_tool_mixin import UVToolMixin

        class _Probe(UVToolMixin):
            """Minimal host: what the dispatch reads from its owner on the run path."""

            command = "bandit"
            use_uv_tool = True
            # The package that provides the command when it is named apart from
            # it; the dispatch reads this attribute at its run_tool call. A host
            # without it raised inside the dispatch's try, which answered "could
            # not start" and never reached run_tool, so no timeout was captured
            # and the test read as a dropped timeout.
            uv_tool_package_name = None

            def _plugin_log(self, *args, **kwargs):
                return None

            def _process_command_response(self, response):
                # The dispatch hands the run's response to its owner; a host
                # without the hook raised inside the handler and the run read
                # as a failure after the timeout had already been forwarded.
                return None

            def _get_tool_package_extras(self):
                return None

            def _get_tool_version_constraint(self):
                return None

        captured = {}

        class _Runner:
            def uv_availability(self):
                return True, None

            def run_tool(self, **kwargs):
                captured.update(kwargs)

                class _Result:
                    stdout = ""
                    stderr = ""
                    returncode = 0

                return _Result()

        probe = _Probe()
        with patch.object(runner_module, "get_uv_tool_runner", return_value=_Runner()):
            probe._try_uv_tool_execution(
                ["bandit", "--version"],
                tmp_path,
                results_dir=tmp_path,
                timeout=_TIMEOUT_SECONDS,
            )

        # The dispatch's own reason rides along: a run it refused before the
        # launch (a host missing an attribute it reads) leaves no timeout to
        # capture, and that reads the same as a timeout dropped at the seam.
        assert captured.get("timeout") == _TIMEOUT_SECONDS, (
            "_try_uv_tool_execution accepted a timeout but did not pass it to "
            f"run_tool: {captured!r}; the dispatch's own reason, if it refused "
            f"the uv route: {probe._uv_run_failure!r}"
        )


# A child that writes one latin-1 e-acute byte, flushes, and hangs: what it
# printed before the kill is the clue to why it hung, and it only reads right
# decoded with the encoding the caller asked for.
_LATIN1_THEN_SLEEP = (
    "import sys, time\n"
    "sys.stdout.buffer.write(bytes([99, 97, 102, 233]))\n"
    "sys.stdout.buffer.flush()\n"
    f"time.sleep({_SLEEP_SECONDS})\n"
)


class TestPartialOutputKeepsTheCallersEncoding:
    """The function takes ``encoding`` and the run decodes a finished child's
    streams with it. A timed-out or failed wait hands the partial output over
    as BYTES (TimeoutExpired carries them undecoded, text mode or not), and
    the decode on those paths was pinned to UTF-8: a latin-1 tool's partial
    output came back with replacement characters, in the returned stdout and
    in the stream log, while the same tool finishing read correctly."""

    @pytest.mark.integration
    def test_a_timed_out_runs_partial_stdout_decodes_with_the_callers_encoding(
        self, tmp_path
    ):
        response = run_command_with_output_handling(
            command=[sys.executable, "-c", _LATIN1_THEN_SLEEP],
            results_dir=tmp_path,
            stdout_preference="return",
            encoding="latin-1",
            timeout=_TIMEOUT_SECONDS,
        )

        assert response.get("timed_out") is True, response
        assert response.get("stdout") == "café", response.get("stdout")

    @pytest.mark.skipif(
        os.name != "posix",
        reason="only the POSIX communicate attaches partial bytes to "
        "TimeoutExpired; the thread-reader one raises with no output",
    )
    @pytest.mark.integration
    def test_a_failed_waits_late_read_decodes_as_the_childs_streams_would(self):
        """The reap path: a wait that fails on a still-running text-mode child
        reads what sits in the pipes, and the late communicate's TimeoutExpired
        carries it as bytes. The decode follows the child's own stream
        wrappers (what communicate itself would have used), not a pinned
        UTF-8."""
        import subprocess

        from automated_security_helper.utils.subprocess_utils import (
            _output_after_failure,
        )

        process = subprocess.Popen(  # nosec B603 - fixed interpreter argv
            [sys.executable, "-c", _LATIN1_THEN_SLEEP],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="latin-1",
        )
        try:
            stdout, _stderr = _output_after_failure(process)
        finally:
            process.kill()
            process.wait()

        assert stdout == "café", repr(stdout)

    @pytest.mark.unit
    def test_partial_bytes_with_no_named_encoding_decode_as_the_locale_would(self):
        """With no encoding named, a finished run's text-mode streams decode
        with the locale encoding, so the partial bytes a timed-out wait
        carried must follow the same read instead of a pinned UTF-8 (under
        UTF-8 mode the locale read answers utf-8, so the two stay in step)."""
        from automated_security_helper.utils import subprocess_utils

        with patch.object(
            subprocess_utils.locale,
            "getpreferredencoding",
            lambda do_setlocale=True: "latin-1",
        ):
            decoded = subprocess_utils._late_decoded(b"caf\xe9", None)

        assert decoded == "café", repr(decoded)
        # The controls: a named encoding wins, and non-bytes pass through.
        assert subprocess_utils._late_decoded(b"caf\xc3\xa9", "utf-8") == "café"
        assert subprocess_utils._late_decoded("already text", None) == "already text"


@pytest.mark.unit
def test_detect_secrets_inherits_the_shared_scan_timeout():
    """detect-secrets must not carry its own copy of the option.

    Its local field declared `int` with no `ge`, shadowing the base field and
    giving one scanner a different contract from the rest: `scan_timeout: null`,
    documented by the base field as the way to run unbounded, raised a validation
    error for detect-secrets only, and `scan_timeout: 0` was accepted here and
    rejected everywhere else -- then passed to future.result(timeout=0), timing out
    instantly on every run.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScannerConfigOptions,
    )

    field = DetectSecretsScannerConfigOptions.model_fields["scan_timeout"]

    assert DetectSecretsScannerConfigOptions(scan_timeout=None).scan_timeout is None, (
        "detect-secrets rejects scan_timeout: null, so it still shadows the base "
        f"field: {field!r}"
    )


@pytest.mark.unit
def test_scanners_that_override_scan_still_pass_the_timeout():
    """A field that appears in a schema and does nothing is worse than absent.

    scan_timeout lives on ScannerOptionsBase, so it shows up in every scanner's
    generated schema. But six scanners override `scan()` and call
    `_run_subprocess` themselves rather than going through the template, so
    setting the option on them had no effect and nothing said so.

    This is a structural check on the source rather than a behavioural one:
    driving each of the six through a real scan needs a PluginContext, a target
    tree and per-tool fixtures, which is a wider harness than the property
    warrants. It catches the regression that matters -- someone adding another
    `scan()` override without threading the timeout -- and the message says where
    to look.
    """
    import pathlib

    repo_root = pathlib.Path(__file__).resolve().parents[2]
    overriding_scanners = [
        "plugin_modules/ash_builtin/scanners/cfn_nag_scanner.py",
        "plugin_modules/ash_builtin/scanners/npm_audit_scanner.py",
        "plugin_modules/ash_builtin/scanners/syft_scanner.py",
        "plugin_modules/ash_ferret_plugins/ferret_scanner.py",
        "plugin_modules/ash_snyk_plugins/snyk_code_scanner.py",
        "plugin_modules/ash_trivy_plugins/trivy_repo_scanner.py",
    ]

    missing = []
    for rel in overriding_scanners:
        path = repo_root / "automated_security_helper" / rel
        if not path.exists():
            continue
        if "_effective_scan_timeout()" not in path.read_text(encoding="utf-8"):
            missing.append(rel)

    assert not missing, (
        "These scanners override scan() and call _run_subprocess without a "
        "timeout, so scan_timeout is silently ignored for them even though it "
        f"appears in their schema: {missing}"
    )


@pytest.mark.unit
def test_scanner_options_expose_a_scan_timeout_default():
    """Every scanner gets the knob, not just the one that grew its own.

    1800 rather than the 300 detect-secrets chose, and rather than the 300 the
    issue suggested. Two reasons: it matches the timeout ASH already declares for
    a scan operation (mcp_resource_management.scan_timeout_seconds), so there is
    one number rather than two differing by 6x; and 300 would newly fail scans
    that succeed today -- checkov on a large Terraform tree fetching external
    modules, grype's first-run DB pull, semgrep against a full ruleset all
    routinely exceed five minutes.

    A genuinely stuck scanner now burns 30 minutes before it is cut, which is the
    cost of not breaking working scans.
    """
    options = ScannerOptionsBase()

    assert options.scan_timeout == 1800
