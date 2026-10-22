"""Under a scanner sandbox, the jupyter converter installs nothing and nbconvert is confined.

nbconvert is a third-party tool that reads the scanned repository's notebooks, the same
kind of program the sandbox exists to confine for scanners. With ``sandbox.mode`` set to
anything but ``off``:

- no converter installs a tool, the rule scanners already follow
  (``utils/uv_tool_runner.py`` refuses an install inside a scanner's scope);
- every nbconvert process is planned by the sandbox backend, with a scanner's policy:
  no network unless one is granted, the environment allowlist, and nothing writable in
  the scanned tree or the home directory;
- when the backend cannot be used, the notebook is refused, the refusal is recorded on
  the converter, and nbconvert does not run.

``sandbox.mode: off`` keeps the unsandboxed behavior, including installing nbconvert
when it is missing; those cases are the controls.

The tools are stand-ins on PATH: ``uv``, ``jupyter`` and ``jupyter-nbconvert`` scripts
that log every invocation and, for a conversion, write the converted file where
nbconvert would. The sandbox backend is a stand-in registered under ``bwrap``, so
whichever route resolves the backend reaches it. It records the policy of each spawn
and runs the command unchanged, so no real sandbox is needed.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
    ArchiveConverter,
)
from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
    JupyterConverter,
    JupyterConverterConfig,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import SpawnPlan

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

NOTEBOOK = json.dumps(
    {
        "cells": [
            {
                "cell_type": "code",
                "metadata": {},
                "execution_count": None,
                "outputs": [],
                "source": ["total = 1 + 1\n", "print(total)\n"],
            }
        ],
        "metadata": {"language_info": {"name": "python", "file_extension": ".py"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
)

TOKEN_VARIABLE = "NOTEBOOK_PROBE_TOKEN"

# One script for all three names; it tells them apart by argv[0].
TOOL_TEMPLATE = """\
import json
import sys
from pathlib import Path

LOG = Path({log!r})
INSTALLED = Path({installed!r})
name = Path(sys.argv[0]).name
args = sys.argv[1:]
with LOG.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps([name, *args]) + "\\n")


def nbconvert(argv):
    if "--version" in argv:
        print("7.17.1")
        return 0
    # As nbconvert does: a notebook that is not JSON is an error, and the script
    # exporter names its file with the notebook language's extension.
    try:
        notebook = json.loads(Path(argv[argv.index("--to") + 2]).read_text())
    except ValueError:
        print("Notebook does not appear to be JSON", file=sys.stderr)
        return 1
    extension = ".py"
    if argv[argv.index("--to") + 1] == "script":
        language = notebook.get("metadata", {{}}).get("language_info", {{}})
        extension = language.get("file_extension", ".txt")
    output = argv[argv.index("--output") + 1]
    if "--output-dir" in argv:
        target = Path(argv[argv.index("--output-dir") + 1], output)
    else:
        target = Path(output)
    target.with_name(target.name + extension).write_text("x = 1\\n", encoding="utf-8")
    return 0


if name == "uv":
    if args[:1] == ["--version"]:
        print("uv 0.9.0")
        sys.exit(0)
    if args[:2] == ["tool", "list"]:
        if INSTALLED.exists():
            print("nbconvert v7.17.1")
            print("- jupyter-dejavu")
            print("- jupyter-nbconvert")
        sys.exit(0)
    if args[:2] == ["tool", "install"]:
        sys.exit(1)
    if args[:2] == ["tool", "run"]:
        rest = args[2:]
        while rest and rest[0].startswith("-"):
            option = rest.pop(0)
            if option in ("--from", "--with", "--python"):
                rest.pop(0)
        rest.pop(0)
        if not INSTALLED.exists():
            sys.exit(2)
        sys.exit(nbconvert(rest))
    sys.exit(2)
if name == "jupyter":
    sys.exit(nbconvert(args[1:]) if args[:1] == ["nbconvert"] else 2)
if name == "jupyter-nbconvert":
    sys.exit(nbconvert(args))
sys.exit(2)
"""


class _Tools:
    """The stand-in tools and what they were asked to do."""

    def __init__(self, root: Path, *, installed: bool):
        self.bin = root / "bin"
        self.bin.mkdir()
        self.log = root / "tools.log"
        self.log.touch()
        self.installed_flag = root / "nbconvert-installed"
        names = ["uv"]
        if installed:
            self.installed_flag.touch()
            names += ["jupyter", "jupyter-nbconvert"]
        source = TOOL_TEMPLATE.format(
            log=str(self.log), installed=str(self.installed_flag)
        )
        for name in names:
            script = self.bin / name
            script.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
            script.chmod(0o755)

    def calls(self) -> List[List[str]]:
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def installs(self) -> List[List[str]]:
        return [
            c for c in self.calls() if c[0] == "uv" and c[1:3] == ["tool", "install"]
        ]

    def conversions(self) -> List[List[str]]:
        return [c for c in self.calls() if "--to" in c]


class _Backend:
    """A sandbox backend that records each spawn's policy and runs it unchanged."""

    name = "recorder"
    unavailable_reason = None
    spawns: list = []

    def probe(self):
        return type(self).unavailable_reason

    def plan(self, argv, env, policy):
        type(self).spawns.append((list(argv), policy, policy.filter_env(env)))
        return SpawnPlan(argv=list(argv), env=dict(env))


def _mentions_nbconvert(argv) -> bool:
    return any("nbconvert" in str(part) for part in argv)


@pytest.fixture
def backend(monkeypatch):
    class Recorder(_Backend):
        spawns = []
        unavailable_reason = None

    scope_module.clear_backend_cache()
    monkeypatch.setitem(scope_module.BACKENDS, "bwrap", Recorder)
    yield Recorder
    scope_module.clear_backend_cache()


def _isolate_tool_lookup(monkeypatch, tools: _Tools, home: Path, *, online: bool):
    monkeypatch.setenv("PATH", str(tools.bin))
    monkeypatch.setenv("ASH_BIN_PATH", str(tools.bin))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv(TOKEN_VARIABLE, "token-value")
    if online:
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        monkeypatch.delenv("UV_OFFLINE", raising=False)
    else:
        monkeypatch.setenv("ASH_OFFLINE", "YES")
    subprocess_utils.clear_find_executable_cache()
    uv_tool_runner.reset_uv_tool_runner()
    uv_tool_runner._reset_uv_tool_runner_caches()


@pytest.fixture
def tree(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "analysis.ipynb").write_text(NOTEBOOK, encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    (output / ASH_WORK_DIR_NAME).mkdir()
    home = tmp_path / "home"
    home.mkdir()
    return source, output, home


def _context(tree, mode: str) -> PluginContext:
    source, output, _home = tree
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="notebooks", sandbox=SandboxConfig(mode=mode)),
    )


def _converter(context) -> JupyterConverter:
    return JupyterConverter(context=context, config=JupyterConverterConfig())


def _run_convert_phase(context) -> AshAggregatedResults:
    results = AshAggregatedResults()
    ConvertPhase(
        plugin_context=context,
        plugins=[JupyterConverter, ArchiveConverter],
        progress_display=MagicMock(),
    )._execute_phase(aggregated_results=results)
    return results


def _failed(results: AshAggregatedResults) -> list:
    """``(path, reason)`` of each input the jupyter converter's row lists as failed."""
    return [
        (record.path, record.reason)
        for record in results.converter_results["jupyter"].failed_inputs
    ]


def _where(mode: str) -> str:
    """The suffix a failed conversion's reason has under a sandbox."""
    return "" if mode == "off" else " under the scanner sandbox"


def _inside(path, roots) -> bool:
    real = Path(os.path.realpath(path))
    return any(
        real == Path(os.path.realpath(root))
        or Path(os.path.realpath(root)) in real.parents
        for root in roots
    )


class TestNoInstallUnderASandbox:
    def test_the_dependency_check_does_not_install_nbconvert(
        self, tmp_path, tree, backend, monkeypatch
    ):
        tools = _Tools(tmp_path, installed=False)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        _converter(_context(tree, "bwrap")).validate_plugin_dependencies()

        assert tools.installs() == [], (
            f"a sandboxed scan installed a converter's tool: {tools.installs()}"
        )

    def test_the_convert_phase_installs_nothing(
        self, tmp_path, tree, backend, monkeypatch
    ):
        tools = _Tools(tmp_path, installed=False)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        _run_convert_phase(_context(tree, "bwrap"))

        assert tools.installs() == [], (
            f"the convert phase installed a tool under the sandbox: {tools.installs()}"
        )
        # `uv tool run --from nbconvert` fetches a package it does not have when it
        # can reach the index, so each one must have run without a network.
        offline_runs = {
            tuple(argv[1:])
            for argv, policy, _env in backend.spawns
            if Path(argv[0]).name == "uv" and policy.network is False
        }
        unconfined = [
            c
            for c in tools.calls()
            if c[0] == "uv"
            and c[1:3] == ["tool", "run"]
            and tuple(c[1:]) not in offline_runs
        ]
        assert unconfined == [], (
            f"uv tool run ran outside the sandbox with a network: {unconfined}"
        )

    def test_without_a_sandbox_a_missing_nbconvert_is_installed(
        self, tmp_path, tree, backend, monkeypatch
    ):
        """Control: the same lookup with sandbox mode off installs, as it always has.

        It also shows the stand-in uv is the one consulted, so an empty install list
        in the tests above is the converter's doing and not a harness that never
        reached the lookup.
        """
        tools = _Tools(tmp_path, installed=False)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        _converter(_context(tree, "off")).validate_plugin_dependencies()

        assert tools.installs(), (
            "with the sandbox off the converter installs a missing nbconvert; "
            f"calls: {tools.calls()}"
        )

    def test_without_a_sandbox_the_convert_phase_installs_a_missing_nbconvert(
        self, tmp_path, tree, backend, monkeypatch
    ):
        """Control for the convert-phase test above: same phase, sandbox mode off."""
        tools = _Tools(tmp_path, installed=False)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        _run_convert_phase(_context(tree, "off"))

        assert tools.installs(), f"calls: {tools.calls()}"


class TestNbconvertRunsUnderTheSandbox:
    @pytest.mark.parametrize("use_uv_tool", [True, False], ids=["uv", "direct"])
    def test_the_conversion_is_planned_by_the_backend_with_a_scanner_policy(
        self, tmp_path, tree, backend, monkeypatch, use_uv_tool
    ):
        source, output, home = tree
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, home, online=True)
        converter = _converter(_context(tree, "bwrap"))
        converter.use_uv_tool = use_uv_tool

        converted = converter.convert()

        assert tools.conversions(), (
            f"nbconvert never ran, so nothing was observed; calls: {tools.calls()}"
        )
        planned = [
            (argv, policy, env)
            for argv, policy, env in backend.spawns
            if _mentions_nbconvert(argv) and "--to" in argv
        ]
        assert planned, (
            "nbconvert converted the notebook without the sandbox backend planning "
            f"the process; it ran: {tools.conversions()}"
        )
        for argv, policy, env in planned:
            assert policy.network is False, f"nbconvert was given a network: {argv}"
            assert TOKEN_VARIABLE not in env, (
                "nbconvert received a credential-shaped variable the scanner "
                "environment allowlist drops"
            )
            assert policy.writable, "the policy names no writable directory"
            for writable in policy.writable:
                for protected in (source, home):
                    assert not _inside(writable, [protected]), (
                        f"nbconvert may write inside {protected}: {writable}"
                    )
                    assert not _inside(protected, [writable]), (
                        f"nbconvert may write {writable}, which holds {protected}"
                    )
        assert len(converted) == 1, "the confined conversion still produces its file"

    def test_every_nbconvert_process_of_the_convert_phase_is_planned(
        self, tmp_path, tree, backend, monkeypatch
    ):
        """Version probes and dependency checks run nbconvert too, as scanner probes do."""
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        _run_convert_phase(_context(tree, "bwrap"))

        ran = [c for c in tools.calls() if _mentions_nbconvert(c)]
        assert ran, f"no nbconvert process ran; calls: {tools.calls()}"
        planned = [argv for argv, _policy, _env in backend.spawns]
        unplanned = [
            c
            for c in ran
            if not any(
                Path(argv[0]).name == c[0] and argv[1:] == c[1:] for argv in planned
            )
        ]
        assert unplanned == [], (
            f"nbconvert processes ran without the sandbox backend: {unplanned}"
        )

    def test_without_a_sandbox_nbconvert_runs_as_before(
        self, tmp_path, tree, backend, monkeypatch
    ):
        """Control: sandbox mode off converts the notebook with no backend involved."""
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)
        converter = _converter(_context(tree, "off"))

        converted = converter.convert()

        assert tools.conversions(), f"calls: {tools.calls()}"
        assert backend.spawns == []
        assert len(converted) == 1


class TestAnUnconfinableNotebookIsRefused:
    def test_the_notebook_is_refused_and_nbconvert_does_not_run(
        self, tmp_path, tree, backend, monkeypatch
    ):
        source, _output, home = tree
        backend.unavailable_reason = "bwrap: cannot create a user namespace"
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, home, online=True)
        converter = _converter(_context(tree, "bwrap"))

        converted = converter.convert()

        assert tools.conversions() == [], (
            "nbconvert ran although the sandbox backend is unavailable: "
            f"{tools.conversions()}"
        )
        assert converted == []
        records = [
            str(record)
            for record in (
                list(getattr(converter, "refused_inputs", None) or [])
                + list(getattr(converter, "failed_inputs", None) or [])
            )
        ]
        assert any("analysis.ipynb" in record for record in records), (
            "the notebook that could not be confined is recorded on the converter; "
            f"records: {records}"
        )

    def test_the_refusal_reaches_the_converter_row(
        self, tmp_path, tree, backend, monkeypatch
    ):
        backend.unavailable_reason = "bwrap: cannot create a user namespace"
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        results = _run_convert_phase(_context(tree, "bwrap"))

        assert tools.conversions() == []
        row = results.converter_results.get("jupyter")
        assert row is not None, (
            f"no jupyter row; rows: {sorted(results.converter_results)}"
        )
        dumped = json.dumps(row.model_dump(mode="json"), default=str)
        assert "analysis.ipynb" in dumped, (
            f"the jupyter row does not record the refused notebook: {dumped}"
        )


class TestAnUnconfinableNotebookFailsTheScan:
    """The refused notebook is lost coverage, which the completeness gate reports."""

    def test_the_converter_is_listed_as_incomplete(
        self, tmp_path, tree, backend, monkeypatch
    ):
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_converters,
        )

        backend.unavailable_reason = "bwrap: cannot create a user namespace"
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        results = _run_convert_phase(_context(tree, "bwrap"))

        assert [row.name for row in incomplete_converters(results)] == ["jupyter"]

    def test_without_notebooks_nothing_is_refused(
        self, tmp_path, tree, backend, monkeypatch
    ):
        """Control: an unavailable sandbox costs nothing where there is nothing to convert."""
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_converters,
        )

        source, _output, home = tree
        (source / "analysis.ipynb").unlink()
        backend.unavailable_reason = "bwrap: cannot create a user namespace"
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, home, online=True)

        results = _run_convert_phase(_context(tree, "bwrap"))

        assert incomplete_converters(results) == []


class TestASandboxedConversionRunsNbconvertItself:
    """Under a sandbox nbconvert's own entry point runs, not uv or the jupyter launcher.

    Measured with uv 0.12 under bwrap: ``uv tool run`` exits 2 ("Could not create
    temporary file ... Read-only file system" in uv's tools directory, which the sandbox
    mounts read-only), and the fallback ran ``jupyter nbconvert``, whose launcher is not
    installed alongside nbconvert by ``uv tool install nbconvert``. Both failed, so no
    notebook was converted. ``jupyter-nbconvert`` is the executable the dependency check
    finds, and it ran under the same sandbox.

    The stand-ins here are the same as above, except that ``jupyter`` is absent and
    ``uv tool run`` fails the way it does in the sandbox.
    """

    def test_the_notebook_is_converted_without_uv_or_the_launcher(
        self, tmp_path, tree, backend, monkeypatch
    ):
        tools = _Tools(tmp_path, installed=True)
        (tools.bin / "jupyter").unlink()
        failing_uv = tools.bin / "uv"
        source = failing_uv.read_text(encoding="utf-8").replace(
            '    if args[:2] == ["tool", "run"]:\n',
            '    if args[:2] == ["tool", "run"]:\n        sys.exit(2)\n',
        )
        assert source != failing_uv.read_text(encoding="utf-8")
        failing_uv.write_text(source, encoding="utf-8")
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)
        converter = _converter(_context(tree, "bwrap"))

        converted = converter.convert()

        assert len(converted) == 1, (
            f"no notebook was converted under the sandbox; calls: {tools.calls()}"
        )
        planned = [argv for argv, _policy, _env in backend.spawns if "--to" in argv]
        assert planned and all(
            Path(argv[0]).name == "jupyter-nbconvert" for argv in planned
        ), f"nbconvert ran as {planned}"
        # nbconvert's own arguments follow the executable unchanged.
        assert all(
            argv[1:5] == ["--log-level", "WARN", "--to", "python"] for argv in planned
        ), f"nbconvert ran as {planned}"

    def test_without_a_sandbox_uv_still_runs_it(
        self, tmp_path, tree, backend, monkeypatch
    ):
        """Control: sandbox mode off keeps running nbconvert through uv."""
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)
        converter = _converter(_context(tree, "off"))

        converted = converter.convert()

        assert len(converted) == 1
        assert [c[:3] for c in tools.conversions()] == [["uv", "tool", "run"]]


class TestAFailedSandboxedConversionIsLostCoverage:
    """A notebook that was not converted under the sandbox makes the scan incomplete.

    Two ways it happens after the scope was built: the backend refuses the one spawn
    (a path sandbox-exec cannot express, a link found at spawn time), or nbconvert
    itself exits non-zero inside the sandbox (as ``uv tool run`` did, exit 2, before
    the converter ran nbconvert's own entry point there). Either way the notebook is
    recorded on the converter and the completeness gate lists the converter.
    """

    @staticmethod
    def _incomplete(results):
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_converters,
        )

        return incomplete_converters(results)

    def test_a_spawn_the_backend_refuses_records_the_notebook(
        self, tmp_path, tree, backend, monkeypatch
    ):
        from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        def refuse(self, argv, env, policy):
            if "--to" in argv:
                raise SandboxUnavailable("cannot mount the staged notebook")
            return SpawnPlan(argv=list(argv), env=dict(env))

        monkeypatch.setattr(backend, "plan", refuse)

        results = _run_convert_phase(_context(tree, "bwrap"))

        assert tools.conversions() == []
        listed = self._incomplete(results)
        assert [name for name, _ in listed] == ["jupyter"], listed
        dumped = json.dumps(
            results.converter_results["jupyter"].model_dump(mode="json")
        )
        assert "analysis.ipynb" in dumped and "cannot mount" in dumped

    def test_nbconvert_failing_inside_the_sandbox_records_the_notebook(
        self, tmp_path, tree, backend, monkeypatch
    ):
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        def failing(self, argv, env, policy):
            if "--to" in argv:
                return SpawnPlan(
                    argv=[sys.executable, "-c", "raise SystemExit(2)"], env=dict(env)
                )
            return SpawnPlan(argv=list(argv), env=dict(env))

        monkeypatch.setattr(backend, "plan", failing)

        results = _run_convert_phase(_context(tree, "bwrap"))

        listed = self._incomplete(results)
        assert [name for name, _ in listed] == ["jupyter"], listed
        assert "analysis.ipynb" in listed[0][1], listed
        # The reason is kept on the row's failed input, and says the sandbox was on.
        assert _failed(results) == [
            ("analysis.ipynb", "nbconvert exited with code 2 under the scanner sandbox")
        ]

    def test_nbconvert_timing_out_inside_the_sandbox_records_the_notebook(
        self, tmp_path, tree, backend, monkeypatch
    ):
        import subprocess

        from automated_security_helper.plugin_modules.ash_builtin.converters import (
            jupyter_converter,
        )

        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)
        real_spawn_run = jupyter_converter.spawn_run

        def spawn_run(cmd, *args, **kwargs):
            if "--to" in cmd:
                raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 60))
            return real_spawn_run(cmd, *args, **kwargs)

        monkeypatch.setattr(jupyter_converter, "spawn_run", spawn_run)

        results = _run_convert_phase(_context(tree, "bwrap"))

        listed = self._incomplete(results)
        assert [name for name, _ in listed] == ["jupyter"], listed
        assert _failed(results) == [
            (
                "analysis.ipynb",
                "nbconvert did not finish within 60s under the scanner sandbox",
            )
        ]

    def test_a_sandboxed_conversion_that_succeeds_is_complete(
        self, tmp_path, tree, backend, monkeypatch
    ):
        """Control: the same phase with every spawn planned and successful."""
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        results = _run_convert_phase(_context(tree, "bwrap"))

        assert tools.conversions()
        assert self._incomplete(results) == []


@pytest.mark.parametrize("mode", ["off", "bwrap"])
class TestAFailedConversionIsLostCoverageInEitherMode:
    """A notebook that is not converted makes the scan incomplete, sandbox or not.

    The same input and the same lost coverage give the same verdict: a malformed
    notebook, a conversion that exits 0 and writes nothing, and one that raises.
    A notebook in another language, which nbconvert's script exporter writes with
    that language's extension, is converted, not lost.
    """

    @staticmethod
    def _incomplete(results):
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_converters,
        )

        return incomplete_converters(results)

    def test_a_malformed_notebook_is_listed(
        self, tmp_path, tree, backend, monkeypatch, mode
    ):
        (tree[0] / "broken.ipynb").write_text('{"cells": [', encoding="utf-8")
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        results = _run_convert_phase(_context(tree, mode))

        listed = self._incomplete(results)
        assert [name for name, _ in listed] == ["jupyter"], listed
        assert "broken.ipynb" in listed[0][1], listed
        assert "analysis.ipynb" not in listed[0][1], "the good notebook converted"

    def test_a_conversion_that_writes_nothing_is_listed(
        self, tmp_path, tree, backend, monkeypatch, mode
    ):
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)
        monkeypatch.setattr(JupyterConverter, "_run_nbconvert", lambda *a, **k: None)

        results = _run_convert_phase(_context(tree, mode))

        listed = self._incomplete(results)
        assert [name for name, _ in listed] == ["jupyter"], listed
        assert _failed(results) == [
            ("analysis.ipynb", f"nbconvert exited 0 but wrote no output{_where(mode)}")
        ]

    def test_a_conversion_that_raises_is_listed(
        self, tmp_path, tree, backend, monkeypatch, mode
    ):
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        def raising(*args, **kwargs):
            raise FileNotFoundError("jupyter")

        monkeypatch.setattr(JupyterConverter, "_run_nbconvert", raising)

        results = _run_convert_phase(_context(tree, mode))

        listed = self._incomplete(results)
        assert [name for name, _ in listed] == ["jupyter"], listed
        # The type only: an error's message can quote the notebook.
        assert _failed(results) == [
            ("analysis.ipynb", f"conversion raised FileNotFoundError{_where(mode)}")
        ]

    def test_a_notebook_in_another_language_is_converted(
        self, tmp_path, tree, backend, monkeypatch, mode
    ):
        (tree[0] / "analysis.ipynb").write_text(
            json.dumps(
                {
                    "cells": [],
                    "metadata": {
                        "language_info": {"name": "R", "file_extension": ".r"}
                    },
                    "nbformat": 4,
                    "nbformat_minor": 5,
                }
            ),
            encoding="utf-8",
        )
        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)
        converter = _converter(_context(tree, mode))

        converted = converter.convert()

        assert [path.suffix for path in converted] == [".r"], converted
        assert converter.failed_inputs == []


class TestTheConverterConfinesItselfOutsideThePhase:
    """The converter's own guards, used where no convert phase sets a scope.

    A library caller can build a JupyterConverter and call it directly. Its
    construction probe, its dependency check and its refusal to install must hold
    without the phase's scopes, and each is tested on its own here: the install
    guard with the probe scope removed, so the runner's in-scope refusal cannot
    stand in for it.
    """

    def test_construction_and_the_dependency_check_are_planned(
        self, tmp_path, tree, backend, monkeypatch
    ):
        """Every process each step runs was planned by the backend, counted.

        Construction and the dependency check are counted apart, so the check's own
        scope is what plans its calls, and by count rather than by argv alone: a
        second, unplanned run of a planned command shows up too.
        """
        from collections import Counter

        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        def ran_since(calls_before):
            return Counter(tuple(c) for c in tools.calls()[calls_before:])

        def planned_since(spawns_before):
            return Counter(
                (Path(argv[0]).name, *argv[1:])
                for argv, _policy, _env in backend.spawns[spawns_before:]
            )

        converter = _converter(_context(tree, "bwrap"))
        construction_ran = ran_since(0)
        calls_after_construction = len(tools.calls())
        spawns_after_construction = len(backend.spawns)

        converter.validate_plugin_dependencies()
        check_ran = ran_since(calls_after_construction)

        assert construction_ran, "construction ran nothing to check"
        assert check_ran, f"the dependency check ran nothing; calls: {tools.calls()}"
        assert construction_ran - planned_since(0) == Counter(), (
            "construction ran a process the sandbox backend did not plan"
        )
        assert check_ran - planned_since(spawns_after_construction) == Counter(), (
            "the dependency check ran a process the sandbox backend did not plan: "
            f"{check_ran - planned_since(spawns_after_construction)}"
        )

    def test_a_fallback_check_the_sandbox_refuses_reports_unavailable(
        self, tmp_path, tree, backend, monkeypatch
    ):
        """The direct ``jupyter nbconvert --version`` check: a refusal is False."""
        from automated_security_helper.plugin_modules.ash_builtin.converters import (
            jupyter_converter,
        )
        from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

        tools = _Tools(tmp_path, installed=False)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)
        converter = _converter(_context(tree, "bwrap"))

        def refused(*args, **kwargs):
            raise SandboxUnavailable("the backend cannot plan this spawn")

        monkeypatch.setattr(jupyter_converter, "spawn_run", refused)

        assert converter.validate_plugin_dependencies() is False

    def test_the_install_guard_holds_without_a_scope(
        self, tmp_path, tree, backend, monkeypatch
    ):
        from contextlib import nullcontext

        tools = _Tools(tmp_path, installed=False)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)
        converter = _converter(_context(tree, "bwrap"))
        monkeypatch.setattr(converter, "_probe_scope", lambda: nullcontext())

        converter.validate_plugin_dependencies()

        assert tools.installs() == [], (
            f"the converter installed a tool under a sandbox: {tools.installs()}"
        )


class TestNbconvertReadsOnlyItsStagedCopy:
    """nbconvert is handed a staged copy, so it may not read the scanned tree.

    Every nbconvert process the convert phase starts, the version probe and the
    dependency check included, is planned without the source or the output
    directory among the paths it may read. A conversion still reads the staged copy
    and writes the converter's results directory.
    """

    @staticmethod
    def _reaches(paths, target) -> bool:
        real = Path(os.path.realpath(target))
        resolved = [Path(os.path.realpath(p)) for p in paths]
        return any(
            p == real or p in real.parents or real in p.parents for p in resolved
        )

    @staticmethod
    def _tools_beside_the_tree(tmp_path) -> _Tools:
        # A tool's install prefix is readable (the parent of its bin directory), so
        # the stand-ins live in a directory of their own rather than in the one that
        # holds the tree.
        root = tmp_path / "tools"
        root.mkdir()
        return _Tools(root, installed=True)

    def test_no_nbconvert_process_may_read_the_source_or_output_directory(
        self, tmp_path, tree, backend, monkeypatch
    ):
        source, output, home = tree
        tools = self._tools_beside_the_tree(tmp_path)
        _isolate_tool_lookup(monkeypatch, tools, home, online=True)

        _run_convert_phase(_context(tree, "bwrap"))

        planned = [
            (argv, policy)
            for argv, policy, _env in backend.spawns
            if _mentions_nbconvert(argv)
        ]
        assert any("--to" in argv for argv, _policy in planned), (
            f"no conversion was planned, so nothing was observed: {tools.calls()}"
        )
        for argv, policy in planned:
            readable = [*policy.read_only, *policy.cache]
            for withheld in (source, output):
                assert not self._reaches(readable, withheld), (
                    f"{argv} may read {withheld}: {sorted(map(str, readable))}"
                )

    def test_the_conversion_reads_the_staged_copy_and_writes_its_results(
        self, tmp_path, tree, backend, monkeypatch
    ):
        source, output, home = tree
        tools = self._tools_beside_the_tree(tmp_path)
        _isolate_tool_lookup(monkeypatch, tools, home, online=True)
        converter = _converter(_context(tree, "bwrap"))

        converted = converter.convert()

        conversions = [
            (argv, policy)
            for argv, policy, _env in backend.spawns
            if _mentions_nbconvert(argv) and "--to" in argv
        ]
        assert conversions, f"no conversion was planned: {tools.calls()}"
        for argv, policy in conversions:
            staged = Path(argv[argv.index("--to") + 2])
            assert not _inside(staged, [source]), f"nbconvert was given {staged}"
            assert _inside(staged, policy.read_only), (
                f"the staged copy {staged} is not readable: {policy.read_only}"
            )
            assert _inside(converter.results_dir, policy.writable)
            # nbconvert writes into the directory --output-dir names, so the sandbox
            # has to leave it writable; a directory beside the staged copy is not.
            written = Path(argv[argv.index("--output-dir") + 1])
            assert _inside(written, policy.writable), (
                f"nbconvert writes into {written}, which is not writable: "
                f"{policy.writable}"
            )
        assert len(converted) == 1
