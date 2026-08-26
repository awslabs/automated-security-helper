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

import sys
import time
from unittest.mock import patch

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.utils.subprocess_utils import (
    run_command_with_output_handling,
)

# Long enough that a passing test cannot have waited for it.
_SLEEP_SECONDS = 60
_TIMEOUT_SECONDS = 2


def _sleep_command(seconds: int = _SLEEP_SECONDS):
    return [sys.executable, "-c", f"import time; time.sleep({seconds})"]


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

    def test_run_tool_forwards_the_timeout_on_the_results_dir_branch(self, tmp_path):
        """This is the branch scanners take: they all pass results_dir.

        `run_tool` already accepted a `timeout`, but honoured it only on its
        fallback path -- the one used by callers that do *not* want output files,
        i.e. none of the scanners.
        """
        from automated_security_helper.utils import subprocess_utils
        from automated_security_helper.utils.uv_tool_runner import get_uv_tool_runner

        captured = {}

        def _fake(**kwargs):
            captured.update(kwargs)
            return {"returncode": 0, "stdout": "", "stderr": ""}

        with patch.object(
            subprocess_utils, "run_command_with_output_handling", side_effect=_fake
        ):
            get_uv_tool_runner().run_tool(
                tool_name="bandit",
                args=["--version"],
                results_dir=tmp_path,
                timeout=_TIMEOUT_SECONDS,
            )

        assert captured.get("timeout") == _TIMEOUT_SECONDS, (
            "run_tool dropped the timeout on the results_dir branch, so every "
            "uv-run scanner executes unbounded."
        )

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
            """Minimal host: the mixin only needs these three from its owner."""

            command = "bandit"
            use_uv_tool = True

            def _plugin_log(self, *args, **kwargs):
                return None

            def _get_tool_package_extras(self):
                return None

            def _get_tool_version_constraint(self):
                return None

        captured = {}

        class _Runner:
            def is_uv_available(self):
                return True

            def run_tool(self, **kwargs):
                captured.update(kwargs)

                class _Result:
                    stdout = ""
                    stderr = ""
                    returncode = 0

                return _Result()

        with patch.object(runner_module, "get_uv_tool_runner", return_value=_Runner()):
            _Probe()._try_uv_tool_execution(
                ["bandit", "--version"],
                tmp_path,
                results_dir=tmp_path,
                timeout=_TIMEOUT_SECONDS,
            )

        assert captured.get("timeout") == _TIMEOUT_SECONDS, (
            "_try_uv_tool_execution accepted a timeout but did not pass it to "
            f"run_tool: {captured!r}"
        )


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
