# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The config files ASH writes for a scanner's tool are outside the scanned tree.

bandit, grype, syft, trivy, trivy-repo, ferret-scan and actionlint each get a config
file ASH writes when the operator names none, one that sets nothing, so the tool does not read one
from the tree on its own (``config/tool_config_trust.empty_tool_config``), and
trivy-repo an empty modules directory (``empty_tool_directory``). The
output directory defaults to ``<source>/.ash/ash_output``, so the scanner's results
directory, where these files used to be written, is inside the tree.

Each test runs a real scanner through the scanner executor, in that default layout,
with the tool replaced by a recorder that reads the file it was handed. They check
where the file is and what it holds, that the directory holding it is private while
the tool runs and gone afterwards, that a link at the old path is not written
through, and what a sandboxed scanner may do with the directory.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import (
    in_scanned_tree,
    reset_path_refusal_warnings,
)
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.sandbox.backends import SpawnPlan
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.sandbox.scope import SandboxScope
from automated_security_helper.utils.uv_tool_runner import UVToolRunner

PluginContext.model_rebuild()
AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

_EMPTY_SARIF = json.dumps({"version": "2.1.0", "runs": []})

#: A workflow for actionlint to find.
_WORKFLOW = (
    "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    "    steps:\n      - run: echo hello\n"
)


@dataclass(frozen=True)
class Case:
    """One file, or empty directory, ASH writes for one scanner's tool."""

    scanner: str
    flag: str
    #: Its path under the scanner's results directory, where it used to be written.
    old_name: str
    content: str
    #: The tool's results file, relative to the results directory; None for a
    #: tool whose results ASH reads from its standard output.
    results_file: Optional[str]
    options: Dict[str, Any] = field(default_factory=dict)
    #: An empty directory the tool reads files from, rather than a file.
    directory: bool = False
    #: Files the scanned tree holds for this scanner to find something to scan.
    files: Dict[str, str] = field(default_factory=dict)
    #: What the tool prints when it succeeds.
    stdout: str = ""

    def __str__(self) -> str:
        return f"{self.scanner}{self.flag}"

    @property
    def expected(self) -> Any:
        """What the tool finds: the file's text, or the directory's (no) entries."""
        return () if self.directory else self.content


def _read(path: Path) -> Any:
    """``path``'s text, or the names in it when it is a directory."""
    if path.is_dir():
        return tuple(sorted(os.listdir(path)))
    return path.read_text(encoding="utf-8")


CASES = [
    Case("bandit", "--ini", "bandit-empty.ini", "[bandit]\n", "source/bandit.sarif"),
    Case("grype", "--config", "grype-empty.yaml", "{}\n", "source/results_sarif.sarif"),
    Case("syft", "--config", "syft-empty.yaml", "{}\n", "source/syft.cdx.json"),
    Case(
        "trivy-repo",
        "--ignorefile",
        "trivyignore-empty",
        "",
        "source/results_sarif.sarif",
    ),
    Case(
        "trivy-repo",
        "--secret-config",
        "trivy-secret-empty.yaml",
        "{}\n",
        "source/results_sarif.sarif",
    ),
    Case(
        "trivy-repo",
        "--config",
        "source/trivy-config.yaml",
        "",
        "source/results_sarif.sarif",
    ),
    Case(
        "trivy-repo",
        "--module-dir",
        "source/trivy-modules",
        "",
        "source/results_sarif.sarif",
        directory=True,
    ),
    Case(
        "trivy", "--ignorefile", "trivyignore-empty", "", "source/results_sarif.sarif"
    ),
    Case(
        "trivy",
        "--secret-config",
        "trivy-secret-empty.yaml",
        "{}\n",
        "source/results_sarif.sarif",
    ),
    Case("trivy", "--config", "trivy-config.yaml", "", "source/results_sarif.sarif"),
    Case(
        "actionlint",
        "-config-file",
        "source/ash-default-actionlint.yaml",
        "# Written by ASH so actionlint reads no config from the scanned tree.\n",
        None,
        files={".github/workflows/ci.yml": _WORKFLOW},
        stdout='{"version":"1.7.12","errors":[]}',
    ),
    Case(
        "ferret-scan",
        "--config",
        "ferret-empty-config.yaml",
        "{}\n",
        "source/ferret-scan.sarif",
        {"use_default_config": False},
    ),
]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch):
    for name in ("TRIVY_IGNOREFILE", "TRIVY_SECRET_CONFIG", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    reset_path_refusal_warnings()
    with patch.object(UVToolRunner, "is_uv_available", return_value=False):
        yield
    reset_path_refusal_warnings()


def _context(tmp_path: Path, case: Optional[Case] = None) -> PluginContext:
    """A checkout scanned with the default output directory, inside it."""
    source = tmp_path / "repo"
    source.mkdir()
    (source / ".git").mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    (source / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8")
    for name, text in (case.files if case is not None else {}).items():
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        (source / name).write_text(text, encoding="utf-8")
    output = source / ".ash" / "ash_output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(),
    )


def _scanner_class(name: str):
    if name == "bandit":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner as cls,
            BanditScannerConfig as config,
        )
    elif name == "grype":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (  # type: ignore[assignment]
            GrypeScanner as cls,
            GrypeScannerConfig as config,
        )
    elif name == "syft":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (  # type: ignore[assignment]
            SyftScanner as cls,
            SyftScannerConfig as config,
        )
    elif name == "trivy-repo":
        from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (  # type: ignore[assignment]
            TrivyRepoScanner as cls,
            TrivyRepoScannerConfig as config,
        )
    elif name == "trivy":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (  # type: ignore[assignment]
            TrivyScanner as cls,
            TrivyScannerConfig as config,
        )
    elif name == "actionlint":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (  # type: ignore[assignment]
            ActionlintScanner as cls,
            ActionlintScannerConfig as config,
        )
    else:
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (  # type: ignore[assignment]
            FerretScanScanner as cls,
            FerretScannerConfig as config,
        )
    return cls, config


def _scanner(case: Case, context: PluginContext, monkeypatch: pytest.MonkeyPatch):
    cls, config = _scanner_class(case.scanner)
    monkeypatch.setattr(cls, "validate_plugin_dependencies", lambda self: True)
    scanner = cls(context=context, config=config(options=dict(case.options)))
    scanner.use_uv_tool = False
    return scanner


def _config_arg(argv: List[str], flag: str) -> Optional[Path]:
    """The path ``argv`` passes with ``flag``, as ``flag path`` or ``flag=path``."""
    for index, arg in enumerate(argv):
        if arg == flag and index + 1 < len(argv):
            return Path(argv[index + 1])
        if arg.startswith(flag + "="):
            return Path(arg.split("=", 1)[1])
    return None


class _Tool:
    """Stands in for the scanner's tool and records the config it was handed.

    ``outcome`` is what the tool does after reading it: ``"writes results"``
    (exits 0 with an empty results file), ``"fails"`` (exits 2, no results) or
    ``"raises"`` (the spawn itself raises).
    """

    def __init__(self, case: Case, scanner: Any, outcome: str = "writes results"):
        self.case = case
        self.scanner = scanner
        self.outcome = outcome
        self.runs: List[SimpleNamespace] = []

    def __call__(self, command: List[str], *args: Any, **kwargs: Any) -> Dict:
        argv = [str(a) for a in command]
        path = _config_arg(argv, self.case.flag)
        assert path is not None, f"no {self.case.flag} in {argv}"
        self.runs.append(
            SimpleNamespace(
                argv=argv,
                path=path,
                text=_read(path),
                directory_mode=stat.S_IMODE(os.lstat(path.parent).st_mode),
                directory_is_link=path.parent.is_symlink(),
            )
        )
        if self.outcome == "raises":
            raise OSError("the tool could not start")
        if self.outcome == "fails":
            self.scanner.exit_code = 2
            return {"returncode": 2, "stdout": "", "stderr": "failed"}
        if self.case.results_file is not None:
            results = Path(self.scanner.results_dir) / self.case.results_file
            results.parent.mkdir(parents=True, exist_ok=True)
            results.write_text(_EMPTY_SARIF, encoding="utf-8")
        self.scanner.exit_code = 0
        return {"returncode": 0, "stdout": self.case.stdout, "stderr": ""}


def _run_through_the_executor(context: PluginContext, case: Case, scanner: Any):
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    return executor._execute_scanner(
        case.scanner, scanner, [{"path": context.source_dir, "type": "source"}]
    )


@pytest.mark.parametrize("case", CASES, ids=str)
def test_the_config_is_outside_the_scanned_tree_and_holds_what_ash_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: Case
) -> None:
    context = _context(tmp_path, case)
    scanner = _scanner(case, context, monkeypatch)
    tool = _Tool(case, scanner)
    with patch.object(scanner, "_run_subprocess", side_effect=tool):
        _run_through_the_executor(context, case, scanner)

    (run,) = tool.runs
    assert not in_scanned_tree(run.path, context.source_dir), run.path
    assert not run.path.is_relative_to(Path(context.output_dir).resolve())
    assert run.text == case.expected
    assert not (Path(scanner.results_dir) / case.old_name).exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
@pytest.mark.parametrize("outcome", ["writes results", "fails", "raises"])
@pytest.mark.parametrize("case", CASES, ids=str)
def test_the_directory_is_private_while_the_tool_runs_and_gone_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: Case, outcome: str
) -> None:
    context = _context(tmp_path, case)
    scanner = _scanner(case, context, monkeypatch)
    tool = _Tool(case, scanner, outcome)
    with patch.object(scanner, "_run_subprocess", side_effect=tool):
        _run_through_the_executor(context, case, scanner)

    (run,) = tool.runs
    assert run.directory_mode == 0o700
    assert not run.directory_is_link
    assert not run.path.exists()
    assert not run.path.parent.exists()


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
@pytest.mark.parametrize("case", CASES, ids=str)
def test_a_link_at_the_old_path_is_not_written_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: Case
) -> None:
    context = _context(tmp_path, case)
    kept = tmp_path / "elsewhere" / "kept.txt"
    kept.parent.mkdir()
    kept.write_text("not ASH's\n", encoding="utf-8")
    # Committed with the repository, at the name ASH used to write, so it is
    # there before the scanner is even constructed. A directory ASH used to
    # make there is planted as a link to a directory holding a file.
    planted = Path(context.output_dir) / "scanners" / case.scanner / case.old_name
    planted.parent.mkdir(parents=True)
    planted.symlink_to(kept.parent if case.directory else kept)

    scanner = _scanner(case, context, monkeypatch)
    assert planted == Path(scanner.results_dir) / case.old_name
    tool = _Tool(case, scanner)
    with patch.object(scanner, "_run_subprocess", side_effect=tool):
        _run_through_the_executor(context, case, scanner)

    assert kept.read_text(encoding="utf-8") == "not ASH's\n"
    assert sorted(os.listdir(kept.parent)) == ["kept.txt"]
    (run,) = tool.runs
    assert run.text == case.expected
    assert run.path.parent != planted.parent


class _RecordingBackend:
    """A sandbox backend that records each spawn's policy and runs nothing of it."""

    name = "recording"

    def __init__(self, flag: str):
        self.flag = flag
        self.spawns: List[SimpleNamespace] = []

    def plan(self, argv, env, policy) -> SpawnPlan:
        argv = [str(a) for a in argv]
        # trivy's database probe (`trivy version --config <its own empty file>`)
        # runs in the same scope after the scan; it is not the scan's spawn.
        is_probe = argv[1:2] == ["version"]
        self.spawns.append(
            SimpleNamespace(
                argv=argv,
                policy=policy,
                path=None if is_probe else _config_arg(argv, self.flag),
            )
        )
        return SpawnPlan(argv=[sys.executable, "-c", "pass"], env=dict(env))


def _real(path: Path) -> Path:
    return Path(os.path.realpath(path))


def _inside(path: Path, parents) -> bool:
    return any(
        _real(path) == _real(p) or _real(p) in _real(path).parents for p in parents
    )


@pytest.mark.skipif(os.name == "nt", reason="no sandbox backend on Windows")
@pytest.mark.parametrize("case", CASES, ids=str)
def test_a_sandboxed_scanner_may_read_the_directory_and_not_write_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: Case
) -> None:
    # Offline, so grype and trivy do not first update their databases outside
    # the sandbox, which would run the real tools.
    monkeypatch.setenv("ASH_OFFLINE", "true")
    context = _context(tmp_path, case)
    scanner = _scanner(case, context, monkeypatch)
    backend = _RecordingBackend(case.flag)

    def scope(plugin, plugin_context, target):
        return SandboxScope(
            backend=backend,  # type: ignore[arg-type]
            scanner_name=case.scanner,
            requirements=getattr(plugin, "sandbox_requirements", SandboxRequirements()),
            source_dir=Path(plugin_context.source_dir),
            output_dir=Path(plugin_context.output_dir),
            results_dir=Path(plugin.results_dir),
            scan_target=Path(target),
            offline=True,
        )

    monkeypatch.setattr(scanner_executor, "scanner_sandbox_scope", scope)
    _run_through_the_executor(context, case, scanner)

    runs = [spawn for spawn in backend.spawns if spawn.path is not None]
    assert len(runs) == 1, [spawn.argv for spawn in backend.spawns]
    (run,) = runs
    # The run's directory, which a repeated file name puts the file one level
    # below.
    directory = next(
        p for p in run.path.parents if p.name.startswith("ash-tool-config-")
    )
    policy = run.policy
    assert _real(directory) in {_real(p) for p in policy.read_only}
    assert not _inside(directory, policy.writable)
    assert not _inside(directory, policy.cache)
    # Data, never a place programs run from (sandbox-exec restricts exec).
    assert _real(directory) not in {_real(p) for p in policy.executable}
    assert not in_scanned_tree(run.path, context.source_dir)
    # And no other scanner run's directory.
    granted = [
        p for p in policy.read_only if Path(p).name.startswith("ash-tool-config-")
    ]
    assert [_real(p) for p in granted] == [_real(directory)]
    assert not directory.exists()


@pytest.mark.parametrize("scanner_name", ["trivy", "trivy-repo"])
def test_trivy_s_database_probe_names_no_config_its_run_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner_name: str
) -> None:
    """The next probe of trivy's database must not name the removed empty config.

    The probe (``trivy version --config``) reads the database through the config
    the last scan passed, and the scanner's dependency check runs it again before
    each later target, offline. trivy 0.75.0 exits with "config file ... loading
    error: ... no such file or directory" when that file is gone, which would
    read as "no usable database".
    """
    (case,) = [c for c in CASES if c.scanner == scanner_name and c.flag == "--config"]
    context = _context(tmp_path, case)
    scanner = _scanner(case, context, monkeypatch)
    tool = _Tool(case, scanner)
    with patch.object(scanner, "_run_subprocess", side_effect=tool):
        _run_through_the_executor(context, case, scanner)

    (run,) = tool.runs
    assert not run.path.exists()
    probed = scanner.content_database_probe_context().config_file
    assert probed is None or Path(probed).is_file(), probed


def test_constructing_ferret_scan_writes_no_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The empty config is written when a scan resolves its arguments, not before.

    Looked for where ASH writes it now, a new ash-tool-config-* directory in the
    temporary directory, which construction outside any run would leave there
    until the process exits.
    """
    import tempfile

    from automated_security_helper.utils.tool_config_dir import TOOL_CONFIG_DIR_PREFIX

    (case,) = [c for c in CASES if c.scanner == "ferret-scan"]
    temp = tmp_path / "temp"
    temp.mkdir(mode=0o700)
    os.chmod(temp, 0o700)
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    context = _context(tmp_path, case)
    scanner = _scanner(case, context, monkeypatch)
    assert all(arg.key != "--config" for arg in scanner.args.extra_args)
    assert [
        p for p in temp.iterdir() if p.name.startswith(TOOL_CONFIG_DIR_PREFIX)
    ] == []
    assert not (Path(scanner.results_dir) / case.old_name).exists()
