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
import subprocess  # nosec B404 - the tests start their own stand-in scripts
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
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS
from tests.utils.stand_ins import on_windows, write_stand_in

# Marked per class, not per module: the stand-in backend runs every planned command
# unchanged, so the classes that reach the dependency check, the convert phase or
# nbconvert start the stand-in uv, jupyter and jupyter-nbconvert as child processes
# and are integration; only the tests of TestTheStandInsCanBeStartedOnWindows that
# read the stand-ins' files without starting them are unit.

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

#: The version the stand-ins print for ``--version`` and ``uv tool list``.
STAND_IN_NBCONVERT_VERSION = "7.17.1"

# One script for all three names; it tells them apart by argv[0], without the
# extension a Windows stand-in's script carries.
TOOL_TEMPLATE = """\
import json
import sys
from pathlib import Path

LOG = Path({log!r})
INSTALLED = Path({installed!r})
name = Path(sys.argv[0]).stem
args = sys.argv[1:]
with LOG.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps([name, *args]) + "\\n")


def nbconvert(argv):
    if "--version" in argv:
        print({version!r})
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
            print("nbconvert v" + {version!r})
            print("- jupyter-dejavu")
            print("- jupyter-nbconvert")
        sys.exit(0)
    if args[:2] == ["tool", "install"]:
        sys.exit(1)
    if args[:2] == ["pip", "install"] and "--dry-run" in args:
        # verify_pre_installed_tool asks whether the environment that provides
        # jupyter-nbconvert already satisfies the requirement; uv answers this
        # line and exits 0 when it does.
        if INSTALLED.exists():
            print("Would make no changes")
            sys.exit(0)
        print("error: No solution found when resolving dependencies", file=sys.stderr)
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


def _tool_name(program) -> str:
    """The tool a started program stands for: ``uv`` for ``uv`` and for ``uv.bat``."""
    return Path(program).stem


class _Tools:
    """The stand-in tools and what they were asked to do.

    Each stand-in is a file the host's operating system can start, made by
    ``tests/utils/stand_ins.py``: on POSIX the script itself, with this interpreter in
    its shebang line; on Windows (``windows=True``, the default there) a
    ``<name>.py`` script and a ``<name>.bat`` launcher for it, the form a package
    manager leaves on PATH, because ``CreateProcess`` never starts a shebang file.
    """

    def __init__(self, root: Path, *, installed: bool, windows: bool | None = None):
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
            log=str(self.log),
            installed=str(self.installed_flag),
            version=STAND_IN_NBCONVERT_VERSION,
        )
        self._programs: dict[str, Path] = {}
        self._made: dict[str, list[Path]] = {}
        for name in names:
            stand_in = write_stand_in(self.bin, name, source, windows=windows)
            self._programs[name] = stand_in.program
            self._made[name] = list(stand_in.files)

    def remove(self, name: str) -> None:
        """Take the stand-in for ``name`` away: every file it is made of."""
        for path in self._made.pop(name):
            path.unlink()
        del self._programs[name]

    def replace(self, name: str, old: str, new: str) -> None:
        """Change ``old`` to ``new`` in the program the stand-in for ``name`` runs."""
        program = self._programs[name]
        text = program.read_text(encoding="utf-8")
        assert old in text, f"{old!r} is not in the {name} stand-in"
        program.write_text(text.replace(old, new), encoding="utf-8")

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
    # The uv beside this interpreter is preferred over PATH's; the stand-in is
    # the uv every check here must reach.
    monkeypatch.setattr(uv_tool_runner, "bundled_uv_executable", lambda: None)
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


def _tool_version(*, windows: bool | None = None) -> str | None:
    """The ``tool_version`` the converter is configured with, or None for ASH's default.

    ASH asks uv for ``nbconvert>=7.16.0,<8.0.0`` by default. A ``.bat`` launcher is
    started through cmd.exe, which reads ``>`` and ``<`` in an argument as
    redirections, and ``subprocess.list2cmdline`` quotes only an argument that holds a
    space: the stand-in uv would be handed a cut-off command line, or none. So where
    the stand-ins are launchers they are asked for the one version they print, which
    has no such character. Everywhere else the default stands.
    """
    if windows is None:
        windows = on_windows()
    return f"=={STAND_IN_NBCONVERT_VERSION}" if windows else None


def _pinned_version(
    *, windows: bool | None = None, tool_version: str | None = None
) -> str | None:
    """The ``tool_version`` the helpers configure, or None for ASH's default.

    ``tool_version`` names it outright. Otherwise it is what ``_tool_version`` says
    for the host, or for ``windows`` when that is given, so the Windows branch can
    be built on any host.
    """
    if tool_version is not None:
        return tool_version
    return _tool_version(windows=windows)


def _context(
    tree,
    mode: str,
    *,
    windows: bool | None = None,
    tool_version: str | None = None,
) -> PluginContext:
    source, output, _home = tree
    pinned = _pinned_version(windows=windows, tool_version=tool_version)
    settings = {}
    if pinned is not None:
        settings["converters"] = {"jupyter": {"options": {"tool_version": pinned}}}
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(
            project_name="notebooks", sandbox=SandboxConfig(mode=mode), **settings
        ),
    )


def _converter(
    context, *, windows: bool | None = None, tool_version: str | None = None
) -> JupyterConverter:
    pinned = _pinned_version(windows=windows, tool_version=tool_version)
    if pinned is None:
        config = JupyterConverterConfig()
    else:
        config = JupyterConverterConfig(options={"tool_version": pinned})
    return JupyterConverter(context=context, config=config)


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


@pytest.mark.integration
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
            if _tool_name(argv[0]) == "uv" and policy.network is False
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


@pytest.mark.integration
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
                _tool_name(argv[0]) == c[0] and argv[1:] == c[1:] for argv in planned
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


@pytest.mark.integration
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
        # The sandbox refuses the dependency check itself (plugin_probe_scope
        # gives a refusing scope), so the converter is unavailable before
        # convert() runs: the row says so, with the notebook counted as a
        # candidate, and the completeness gate lists the converter.
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_converters,
        )

        assert row.dependencies_satisfied is False, row
        assert row.candidate_inputs == 1, row
        assert [r.name for r in incomplete_converters(results)] == ["jupyter"]


@pytest.mark.integration
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


@pytest.mark.integration
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
        tools.remove("jupyter")
        tools.replace(
            "uv",
            '    if args[:2] == ["tool", "run"]:\n',
            '    if args[:2] == ["tool", "run"]:\n        sys.exit(2)\n',
        )
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)
        converter = _converter(_context(tree, "bwrap"))

        converted = converter.convert()

        assert len(converted) == 1, (
            f"no notebook was converted under the sandbox; calls: {tools.calls()}"
        )
        planned = [argv for argv, _policy, _env in backend.spawns if "--to" in argv]
        assert planned and all(
            _tool_name(argv[0]) == "jupyter-nbconvert" for argv in planned
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


@pytest.mark.integration
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
        assert [row.name for row in listed] == ["jupyter"], listed
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
        assert [row.name for row in listed] == ["jupyter"], listed
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
        assert [row.name for row in listed] == ["jupyter"], listed
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


@pytest.mark.integration
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
        assert [row.name for row in listed] == ["jupyter"], listed
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
        assert [row.name for row in listed] == ["jupyter"], listed
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
        assert [row.name for row in listed] == ["jupyter"], listed
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


@pytest.mark.integration
class TestTheConverterConfinesItselfOutsideThePhase:
    """The converter's own guards, used where no convert phase sets a scope.

    A library caller can build a JupyterConverter and call it directly. Its
    construction (which records the nbconvert version probe and starts nothing),
    its dependency check (which runs that probe, sandboxed) and its refusal to
    install must hold without the phase's scopes, and each is tested on its own
    here: the install guard with the probe scope removed, so the runner's in-scope
    refusal cannot stand in for it.
    """

    def test_construction_and_the_dependency_check_are_planned(
        self, tmp_path, tree, backend, monkeypatch
    ):
        """Construction starts nothing; what the dependency check runs was planned.

        Construction only records the version probe (the converter builds itself
        inside ``deferred_tool_version_probes``), so a process started there is a
        probe that escaped the deferral and ran outside any scope. The check runs
        the recorded probe inside its own scope, so the check's scope is what
        plans its calls, counted rather than matched by argv alone: a second,
        unplanned run of a planned command shows up too.
        """
        from collections import Counter

        tools = _Tools(tmp_path, installed=True)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)

        def ran_since(calls_before):
            return Counter(tuple(c) for c in tools.calls()[calls_before:])

        def planned_since(spawns_before):
            return Counter(
                (_tool_name(argv[0]), *argv[1:])
                for argv, _policy, _env in backend.spawns[spawns_before:]
            )

        converter = _converter(_context(tree, "bwrap"))
        construction_ran = ran_since(0)
        calls_after_construction = len(tools.calls())
        spawns_after_construction = len(backend.spawns)

        converter.validate_plugin_dependencies()
        check_ran = ran_since(calls_after_construction)

        assert construction_ran == Counter(), (
            f"construction started a process: {sorted(construction_ran)}"
        )
        assert spawns_after_construction == 0, (
            "construction asked the sandbox backend to plan "
            f"{spawns_after_construction} process(es)"
        )
        assert check_ran, f"the dependency check ran nothing; calls: {tools.calls()}"
        assert any("--version" in call for call in check_ran), (
            f"the dependency check did not run the version probe: {sorted(check_ran)}"
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


@pytest.mark.integration
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


class TestTheStandInsCanBeStartedOnWindows:
    """The stand-in tools are files the host's operating system can start.

    ``CreateProcess`` runs executable images and nothing else, so a file that begins
    with a shebang line is never started on Windows, and every test above that
    asserts on what a stand-in was asked sees "nbconvert never ran". ``_Tools``
    writes the Windows form, a ``<name>.bat`` launcher for a ``<name>.py`` script,
    when ``windows=True``, which is its default on Windows. The form itself is
    checked in ``tests/unit/utils/test_stand_ins.py``, which also starts a launcher on
    a Windows host; the tests here check what ``_Tools`` does with it on any host.
    ``.bat`` and not ``.cmd``: the unit tool guard narrows a guarded name's
    candidates to ``<name>.bat`` on Windows (tests/utils/tool_guard.py).
    """

    NAMES = ["uv", "jupyter", "jupyter-nbconvert"]

    # Marked per test: three of these read the stand-ins' files and start nothing.
    @pytest.mark.integration
    def test_a_script_logs_under_the_name_of_the_tool_it_stands_for(self, tmp_path):
        tools = _Tools(tmp_path, installed=True, windows=True)

        for name in self.NAMES:
            subprocess.run(  # nosec B603 - this interpreter, on the test's own script
                [sys.executable, str(tools.bin / f"{name}.py"), "--version"],
                capture_output=True,
                check=False,
                timeout=CHILD_TIMEOUT_SECONDS,
            )

        assert [call[0] for call in tools.calls()] == self.NAMES

    @pytest.mark.unit
    @pytest.mark.parametrize("windows", [False, True], ids=["posix", "windows"])
    def test_removing_a_stand_in_removes_every_file_it_is_made_of(
        self, tmp_path, windows
    ):
        tools = _Tools(tmp_path, installed=True, windows=windows)

        tools.remove("jupyter")

        left = sorted(path.stem for path in tools.bin.iterdir())
        assert "jupyter" not in left, left
        assert "jupyter-nbconvert" in left and "uv" in left, left

    @pytest.mark.unit
    @pytest.mark.parametrize("windows", [False, True], ids=["posix", "windows"])
    def test_a_stand_in_is_rewritten_in_the_file_that_holds_its_program(
        self, tmp_path, windows
    ):
        tools = _Tools(tmp_path, installed=True, windows=windows)
        old = 'if name == "uv":\n'

        tools.replace("uv", old, old + "    sys.exit(7)\n")

        holder = tools.bin / ("uv.py" if windows else "uv")
        assert "    sys.exit(7)\n" in holder.read_text(encoding="utf-8")
        with pytest.raises(AssertionError, match="not in the uv stand-in"):
            tools.replace("uv", "text that is not there", "x")

    @pytest.mark.unit
    def test_a_launcher_is_asked_for_a_version_with_no_character_cmd_reads(self):
        """cmd.exe reads ``< > | & ^ %`` in an argument, and the default range has two."""
        pinned = _tool_version(windows=True)

        assert pinned == f"=={STAND_IN_NBCONVERT_VERSION}"
        assert not set(pinned) & set('<>|&^%"')
        assert _tool_version(windows=False) is None

    @pytest.mark.integration
    @pytest.mark.parametrize(
        "given, expected",
        [
            ({"windows": True}, f"=={STAND_IN_NBCONVERT_VERSION}"),
            ({"windows": False}, JupyterConverterConfig().options.tool_version),
            ({"tool_version": ">=7.17.0"}, ">=7.17.0"),
        ],
        ids=["a-launcher-host", "a-posix-host", "a-version-given"],
    )
    def test_the_converter_the_convert_phase_builds_is_asked_for_the_configured_version(
        self, tmp_path, tree, monkeypatch, given, expected
    ):
        """The pin reaches the converter through the run's configuration.

        The test above reads the helper's string. On Windows a configuration that
        dropped the pin would hand ``nbconvert>=7.16.0,<8.0.0`` to a ``.bat``
        launcher, and cmd.exe reads ``>`` and ``<`` in it as redirections. So read it
        where it matters, on the converter the convert phase builds from the
        configuration, on any host.
        """
        tools = _Tools(tmp_path, installed=False)
        _isolate_tool_lookup(monkeypatch, tools, tree[2], online=True)
        built = []
        post_init = JupyterConverter.model_post_init

        def remember(converter, context):
            try:
                return post_init(converter, context)
            finally:
                built.append(converter.config.options.tool_version)

        monkeypatch.setattr(JupyterConverter, "model_post_init", remember)

        _run_convert_phase(_context(tree, "off", **given))

        assert built, "the convert phase built no jupyter converter"
        assert set(built) == {expected}
