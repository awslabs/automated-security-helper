# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The installer's post-install sweep answers its question without installing.

The sweep's question is "can a scan run this tool now". A scanner's own
dependency check installs its tool when it is missing (bandit's runs
``uv tool install`` with retries and a 300-second timeout), so asked plainly,
the question could spend minutes installing -- and an answer that needs a
network install is not "now". The sweep asks the check the way the scanner
inventory does, in check-only mode: the install step is skipped and every
``uv tool run`` probe runs ``--offline``, so a tool that is not already present
is reported as such and nothing is downloaded.

Containment is ``tests.utils.install_containment``: scratch HOME, XDG and uv
directories, stand-ins first on an otherwise-empty PATH, the bundled uv hidden,
and the uv installer replaced by a recorder. The inventory tests' control cell
(``test_a_scans_dependency_check_reaches_the_installer``) proves the real check
reaches the install paths without it; the first cell here asks the sweep's own
resolution on a plugin shaped the way the sweep asks it -- flagged with
``resolves_tool_off_path`` -- so the check-only guarantee is shown for a plugin
the sweep would ask, not only for the helper.
"""

from __future__ import annotations

import sys
from typing import ClassVar

import pytest

from automated_security_helper.base.uv_tool_mixin import deferred_tool_version_probes
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from tests.utils.install_containment import InstallSandbox, sandbox_env

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX stand-ins")


@pytest.fixture
def sandbox(tmp_path, monkeypatch) -> InstallSandbox:
    yield from sandbox_env(tmp_path, monkeypatch)


class _FlaggedBandit(BanditScanner):
    """A plugin shaped the way the sweep asks: flagged, with a real install path.

    Bandit itself is uv-managed and undeclared, so the sweep never asks it
    (``_declares_off_path_resolution`` and the ``not outcome.uv_managed`` gate);
    its check is still the real one, whose missing-tool branch installs.
    """

    resolves_tool_off_path: ClassVar[bool] = True


def _context(tmp_path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "out").mkdir(exist_ok=True)
    return PluginContext(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", config=AshConfig()
    )


def test_the_sweeps_check_installs_nothing(sandbox, tmp_path):
    """The check the sweep asks makes no install call and still answers.

    A flagged plugin with a real install path, under stand-ins that record
    every call: the sweep's resolution answers False for the absent tool, with
    zero installs and zero downloads recorded.

    Constructed inside ``deferred_tool_version_probes``, the scan phase's shape:
    bandit probes its version while constructed, with ``uv tool run --from
    <spec> bandit --version``, and constructed bare that probe runs online and
    is the one download the recorder would see. Deferred, the check runs it
    itself (``resolve_deferred_tool_version``), in check-only mode, ``--offline``.
    """
    from automated_security_helper.cli.dependencies import (
        _declares_off_path_resolution,
        _scan_can_run,
    )

    with deferred_tool_version_probes():
        scanner = _FlaggedBandit(context=_context(tmp_path))
    # The shape the sweep's gate asks about, not just any scanner.
    assert _declares_off_path_resolution(scanner) is True

    runnable = _scan_can_run(scanner)

    assert runnable is False
    assert sandbox.installs() == [], sandbox.calls()


def test_detect_secrets_without_its_console_script_installs_successfully(
    sandbox,
    tmp_path,
    monkeypatch,
):
    """detect-secrets runs in-process; its console script is not what a scan
    starts.

    Under the containment, no ``detect-secrets`` program is on PATH or beside
    the interpreter, and the library is importable, which is what a scan needs.
    ``ash dependencies install --tool detect-secrets`` is then a success, the
    tool named as one a scan can run, with nothing installed or downloaded.
    """
    import io

    from rich.console import Console
    from typer.testing import CliRunner

    from automated_security_helper.cli import dependencies

    ran = []
    monkeypatch.setattr(
        dependencies, "run_command", lambda cmd, shell=False: ran.append(cmd) or 0
    )
    panels = io.StringIO()
    monkeypatch.setattr(
        dependencies, "console", Console(file=panels, width=240, no_color=True)
    )
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        dependencies.dependencies_app,
        [
            "--plugin-type",
            "scanner",
            "--bin-path",
            str(tmp_path / "bin"),
            "--tool",
            "detect-secrets",
        ],
    )

    printed = " ".join(panels.getvalue().split())
    assert sandbox.installs() == [], sandbox.calls()
    assert result.exit_code == 0, printed
    assert "a scan can run them: detect-secrets" in printed, printed


class TestASandboxTheHostCannotProvide:
    """The sweep and the scan agree under a sandbox for an in-process check too.

    detect-secrets' check starts no process, so ``plugin_probe_scope``'s refusing
    scope cannot stop it the way it stops a probe-starting check. The channel
    that reaches it is in-process: the scope records an unavailable backend as
    the scanner's ``dependency_unavailable_reason`` (``_record_probe_refusal``),
    and the check reads that field first. So the sweep's answer is False, the
    same verdict the scan reaches when its executor refuses the scanner, and the
    recorded reason names the sandbox.

    Linux-only: the pinned backend, ``sandbox-exec``, is the macOS one, which is
    what makes it unavailable here by construction.
    """

    pytestmark = pytest.mark.skipif(
        sys.platform != "linux", reason="pins the Linux refusal of sandbox-exec"
    )

    def _detect_secrets(self, tmp_path, mode):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import (
            AshConfig,
            SandboxConfig,
        )
        from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
            DetectSecretsScanner,
        )

        (tmp_path / "src").mkdir(exist_ok=True)
        (tmp_path / "out").mkdir(exist_ok=True)
        return DetectSecretsScanner(
            context=PluginContext(
                source_dir=tmp_path / "src",
                output_dir=tmp_path / "out",
                config=AshConfig(sandbox=SandboxConfig(mode=mode)),
            )
        )

    def test_an_unavailable_backend_fails_an_in_process_check(self, sandbox, tmp_path):
        from automated_security_helper.cli.dependencies import _scan_can_run
        from automated_security_helper.utils.sandbox import clear_backend_cache

        scanner = self._detect_secrets(tmp_path, "sandbox-exec")
        assert scanner.dependency_unavailable_reason is None

        clear_backend_cache()
        try:
            answer = _scan_can_run(scanner)
        finally:
            clear_backend_cache()

        assert answer is False
        reason = scanner.dependency_unavailable_reason
        assert reason is not None
        assert reason.startswith("scanner sandbox unavailable:"), reason
        assert "sandbox-exec" in reason, reason
        assert sandbox.installs() == [], sandbox.calls()

    def test_the_control_with_the_sandbox_off_answers_true(self, sandbox, tmp_path):
        """Without this, the cell above could pass on any False, not the scope's."""
        from automated_security_helper.cli.dependencies import _scan_can_run

        scanner = self._detect_secrets(tmp_path, "off")

        assert _scan_can_run(scanner) is True
        assert scanner.dependency_unavailable_reason is None
        assert sandbox.installs() == [], sandbox.calls()
