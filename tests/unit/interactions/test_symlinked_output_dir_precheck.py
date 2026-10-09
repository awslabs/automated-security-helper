# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pre-scan output directory check decides with the sandbox mode the scan uses.

``run_ash_scan._refuse_symlinked_output_dir`` runs before the logger opens ash.log
in the output directory, so it reads the sandbox mode before any orchestrator
exists. It used to resolve the config without the trust parameters the scan
resolves with (``untrusted_config``, ``trusted_config_path``) and without the
per-project resolution of workspace mode. A config file the scanned repository or
an MCP client wrote could then set ``sandbox.mode: off`` and skip the refusal,
while the scan, which may not lower the operator's mode, still ran sandboxed with
its output written through the symlink. Here the check is held to the scan's own
resolution: an operator source can turn it off, and nothing else can.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _refuse_symlinked_output_dir,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating a symlink needs privileges on Windows"
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _mode(mode: str) -> str:
    # Quoted: YAML reads a bare `off` as false.
    return f'sandbox:\n  mode: "{mode}"\n'


@pytest.fixture
def tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A scanned directory whose ``build`` links out of it, and room beside it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('x')\n", encoding="utf-8")
    target = tmp_path / "host-dir"
    target.mkdir()
    (source / "build").symlink_to(target, target_is_directory=True)
    return SimpleNamespace(
        root=tmp_path,
        source=source,
        target=target,
        output=source / "build" / "ash",
        operator=tmp_path / "operator" / "ash.yaml",
        upload=tmp_path / "upload" / "ash.yaml",
    )


def _refused(opts: ScanOptions, capsys: pytest.CaptureFixture) -> bool:
    try:
        _refuse_symlinked_output_dir(opts)
    except SystemExit as exc:
        assert exc.code == 1
        # rich wraps and colors the message; compare its words.
        words = " ".join(re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().out).split())
        assert "The scanner sandbox is on" in words and "is a symlink" in words
        return True
    return False


class TestTheScannedTreeCannotSkipIt:
    def test_a_repository_config_that_turns_the_sandbox_off(self, tree, capsys):
        _write(tree.source / ".ash" / ".ash.yaml", _mode("off"))
        _write(tree.operator, _mode("auto"))
        opts = ScanOptions(
            source_dir=tree.source,
            output_dir=tree.output,
            trusted_config_path=str(tree.operator),
        )
        assert _refused(opts, capsys)
        assert list(tree.target.iterdir()) == []

    def test_an_mcp_supplied_config_that_turns_it_off(self, tree, capsys):
        _write(tree.upload, _mode("off"))
        _write(tree.operator, _mode("auto"))
        opts = ScanOptions(
            source_dir=tree.source,
            output_dir=tree.output,
            config=str(tree.upload),
            untrusted_config=True,
            trusted_config_path=str(tree.operator),
        )
        assert _refused(opts, capsys)

    def test_an_mcp_supplied_config_against_the_servers_ash_config(
        self, tree, capsys, monkeypatch
    ):
        # No session config: the trusted base is the server's ASH_CONFIG.
        _write(tree.upload, _mode("off"))
        monkeypatch.setenv("ASH_CONFIG", str(_write(tree.operator, _mode("auto"))))
        opts = ScanOptions(
            source_dir=tree.source,
            output_dir=tree.output,
            config=str(tree.upload),
            untrusted_config=True,
        )
        assert _refused(opts, capsys)


class TestAnOperatorSourceStillSkipsIt:
    def test_the_cli_flag(self, tree, capsys):
        # `--sandbox off` reaches the scan as this override.
        _write(tree.source / ".ash" / ".ash.yaml", _mode("auto"))
        _write(tree.operator, _mode("auto"))
        opts = ScanOptions(
            source_dir=tree.source,
            output_dir=tree.output,
            trusted_config_path=str(tree.operator),
            config_overrides=["sandbox.mode=off"],
        )
        assert not _refused(opts, capsys)

    def test_an_operator_config_file(self, tree, capsys):
        _write(tree.operator, _mode("off"))
        opts = ScanOptions(
            source_dir=tree.source, output_dir=tree.output, config=str(tree.operator)
        )
        assert not _refused(opts, capsys)

    def test_the_trusted_config_path(self, tree, capsys):
        _write(tree.upload, _mode("off"))
        _write(tree.operator, _mode("off"))
        opts = ScanOptions(
            source_dir=tree.source,
            output_dir=tree.output,
            config=str(tree.upload),
            untrusted_config=True,
            trusted_config_path=str(tree.operator),
        )
        assert not _refused(opts, capsys)

    def test_the_default_with_no_config_at_all(self, tree, capsys):
        opts = ScanOptions(source_dir=tree.source, output_dir=tree.output)
        assert not _refused(opts, capsys)


class TestWorkspaceMode:
    """Each project resolves its own config, so each project's mode counts."""

    @staticmethod
    def _plan(root: Path, web_mode: str):
        """Two projects; ``web`` has its own config, recorded as the resolver would."""
        from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

        web_config = _write(root / "web" / ".ash" / ".ash.yaml", _mode(web_mode))
        projects = []
        for key in ("api", "web"):
            (root / key).mkdir(exist_ok=True)
            (root / key / "app.py").write_text("print('x')\n", encoding="utf-8")
            projects.append(
                ProjectPlan(
                    key=key,
                    relative_path=key,
                    path=(root / key).as_posix(),
                    label=key,
                    display_label=key,
                    config_source=web_config.as_posix() if key == "web" else None,
                )
            )
        workspace_file = _write(root / "fixture.code-workspace", '{"folders": []}')
        return WorkspacePlan(
            workspace_file=workspace_file.as_posix(),
            workspace_root=root.as_posix(),
            projects=projects,
        )

    def test_a_project_whose_scan_is_sandboxed(self, tree, capsys):
        plan = self._plan(tree.source, web_mode="auto")
        _write(tree.operator, _mode("off"))
        opts = ScanOptions(
            source_dir=tree.source,
            output_dir=tree.output,
            config=str(tree.operator),
            workspace_plan=plan,
        )
        assert _refused(opts, capsys)

    def test_the_cli_flag_turns_every_project_off(self, tree, capsys):
        plan = self._plan(tree.source, web_mode="auto")
        _write(tree.operator, _mode("auto"))
        opts = ScanOptions(
            source_dir=tree.source,
            output_dir=tree.output,
            config=str(tree.operator),
            workspace_plan=plan,
            config_overrides=["sandbox.mode=off"],
        )
        assert not _refused(opts, capsys)


def test_the_check_resolves_with_the_arguments_the_scan_resolves_with(
    tree, capsys, monkeypatch
):
    """One resolution, not two: the check and the orchestrator call the same
    function with the same arguments, so a trust parameter added to one reaches
    the other."""
    from automated_security_helper.core import orchestrator as orchestrator_module
    from automated_security_helper.interactions.run_ash_scan import _run_local_mode
    from automated_security_helper.utils.log import ASH_LOGGER

    class Stop(Exception):
        pass

    seen = []

    def record(**kwargs):
        seen.append(kwargs)
        raise Stop("recorded")

    monkeypatch.setattr(orchestrator_module, "resolve_scan_config", record)
    _write(tree.upload, _mode("off"))
    _write(tree.operator, _mode("auto"))

    def gate(path: Path) -> bool:
        return True

    opts = ScanOptions(
        source_dir=tree.source,
        output_dir=tree.output,
        config=str(tree.upload),
        config_overrides=["global_settings.severity_threshold=HIGH"],
        config_base_gate=gate,
        untrusted_config=True,
        trusted_config_path=str(tree.operator),
    )
    # A resolution that fails counts as on.
    assert _refused(opts, capsys)
    with pytest.raises(SystemExit):
        _run_local_mode(opts, ASH_LOGGER)
    check, scan = seen
    assert Path(check.pop("source_dir")) == Path(scan.pop("source_dir"))
    assert list(check.pop("config_overrides") or []) == list(
        scan.pop("config_overrides") or []
    )
    assert check == scan
    assert check["untrusted_config"] is True
    assert check["trusted_config_path"] == str(tree.operator)
    assert check["config_base_gate"] is gate
