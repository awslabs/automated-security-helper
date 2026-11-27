"""Each scanner's own failures name a short reason, and the reason holds no path.

A scanner raises ``ScannerError`` for the failures only it can tell apart: a config
file that does not exist, a tool that exited with a code it never uses for a
finished run, an exclusion its tool cannot express, a scan that read no file. The
scan phase records the reason of the error on the scanner's row and the reports
show it (``ReportContentEmitter.get_scanners_not_run``), so the reason has to say
which failure it was and has to be safe to print: a count or an option name, never
a path, a value the operator set, or text the scanned tree supplied.

Each case drives one failure through the entry point that scanner's own tests use,
with the tool replaced by a stand-in that runs nothing, and checks the reason
``reason_of`` finds on what was raised. Through ``scan()`` the error raised is the
scan wrapper's, and the scanner's own is its context, which ``reason_of`` follows.

The control for each case runs it again with the scanner's module raising an error
that keeps no reason, which is what a raise site written without one does, and
expects the check to fail: a case that passed with the reason removed would check
nothing. Presence at every raise site is checked in
``tests/unit/core/test_every_scanner_error_names_a_reason.py``; here the values
are: the code, and a sentence that names a count or an option and holds none of
what the failure's own message quotes.

The one raise site left to that test alone is the guard in the cdk-nag scanner's
template loop for a wrapper that failed to import: its per-file handler records the
target as failed, so no reason reaches a report from it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Optional
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config import client_scanner_exclusions as exclusions
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import (
    FailureReason,
    ReasonCode,
    ScannerError,
    reason_of,
)
from automated_security_helper.plugin_modules.ash_betterleaks_plugins import (
    betterleaks_scanner as betterleaks_module,
)
from automated_security_helper.plugin_modules.ash_betterleaks_plugins.betterleaks_scanner import (
    BetterleaksScanner,
    BetterleaksScannerConfig,
    BetterleaksScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _grep_scanner_base as grep_base,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _trivy_scanner_base as trivy_base,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    bandit_scanner as bandit_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    opengrep_scanner as opengrep_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    trivy_scanner as trivy_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    zizmor_scanner as zizmor_module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
    UNPARSED_SKIP_REASONS,
    UNREAD_SKIP_REASONS,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners._trivy_scanner_base import (
    OUTPUT_RESTRICTING_TRIVY_ENV,
    _existing_file,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    ZizmorScanner,
    ZizmorScannerConfig,
    ZizmorScannerConfigOptions,
)
from automated_security_helper.utils import content_db_refresh as refresh
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.short_reason import is_short_reason
from tests.utils.content_db_opt_out_env import TOOL_UPDATE_OPT_OUT_ENV

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.unit,
    pytest.mark.usefixtures("no_tool_probes"),
    pytest.mark.skipif(sys.platform == "win32", reason="the fixtures use POSIX paths"),
]


# --------------------------------------------------------------------------- #
# The check, and what a case is
# --------------------------------------------------------------------------- #


def _reason(
    error: BaseException,
    code: str,
    *,
    holds: tuple[str, ...] = (),
    never: tuple[str, ...] = (),
) -> FailureReason:
    """The reason ``error`` carries, checked: its code, a fit sentence, what it says."""
    reason = reason_of(error)
    assert reason is not None, f"{type(error).__name__} carries no reason"
    assert reason.code == code, (reason.code, reason.sentence)
    assert is_short_reason(reason.sentence), reason.sentence
    for text in holds:
        assert text in reason.sentence, (text, reason.sentence)
    for text in never:
        assert text not in reason.sentence, (text, reason.sentence)
    return reason


class _DidNotFail(Exception):
    """The action a case expects to fail returned."""


def _raised(action: Callable[[], object]) -> BaseException:
    """What ``action`` raised; a skip or a failed assertion passes through."""
    try:
        action()
    except Exception as error:  # noqa: BLE001 - the case reads whatever was raised
        return error
    raise _DidNotFail("the action a case expects to fail returned")


class _DropsTheReason(ScannerError):
    """A ``ScannerError`` that keeps no reason: a raise site written without one."""

    def __init__(self, *args: object, reason: Optional[FailureReason] = None) -> None:
        super().__init__(*args)


def _drop_in(module: Any) -> Callable[[pytest.MonkeyPatch], None]:
    """Make ``module`` raise errors that keep no reason."""

    def drop(monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(module, "ScannerError", _DropsTheReason)

    return drop


@dataclass(frozen=True)
class Case:
    """One failure: how to cause it, how to remove its reason, and what it must say."""

    name: str
    scenario: Callable[[Path, pytest.MonkeyPatch], BaseException]
    drop: Callable[[pytest.MonkeyPatch], None]
    code: str
    holds: tuple[str, ...] = ()
    never: tuple[str, ...] = ()


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


# --------------------------------------------------------------------------- #
# Betterleaks
# --------------------------------------------------------------------------- #

_BETTERLEAKS_ENV = (
    "BETTERLEAKS_CONFIG",
    "BETTERLEAKS_CONFIG_TOML",
    "GITLEAKS_CONFIG",
    "GITLEAKS_CONFIG_TOML",
)


def _betterleaks_tree(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n", encoding="utf-8")
    return source


def _betterleaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **options: Any
) -> BetterleaksScanner:
    """A scanner over ``tmp_path/src``, its tool found on PATH and its options the
    operator's own."""
    for name in _BETTERLEAKS_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        betterleaks_module, "find_executable", lambda cmd: f"/fake/bin/{cmd}"
    )
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    output = tmp_path / "out"
    return BetterleaksScanner(
        context=PluginContext(
            source_dir=tmp_path / "src",
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=BetterleaksScannerConfig(
            enabled=True, options=BetterleaksScannerConfigOptions(**options)
        ),
    )


def _betterleaks_scan(
    scanner: BetterleaksScanner, monkeypatch: pytest.MonkeyPatch, exit_code: int = 0
):
    """``scan()`` with a tool that writes an empty report and exits ``exit_code``."""

    def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
        report = next(arg for arg in command if arg.startswith("--report-path="))
        path = Path(report.split("=", 1)[1])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"version": "2.1.0", "runs": []}', encoding="utf-8")
        scanner.exit_code = exit_code
        return {"returncode": exit_code, "stdout": "", "stderr": ""}

    monkeypatch.setattr(scanner, "_run_subprocess", run)
    return scanner.scan(target=Path(scanner.context.source_dir), target_type="source")


def _betterleaks_exit_code(tmp_path, monkeypatch):
    _betterleaks_tree(tmp_path)
    scanner = _betterleaks(tmp_path, monkeypatch)
    return _raised(lambda: _betterleaks_scan(scanner, monkeypatch, exit_code=1))


def _betterleaks_config_missing(tmp_path, monkeypatch):
    _betterleaks_tree(tmp_path)
    scanner = _betterleaks(
        tmp_path, monkeypatch, config_file=str(tmp_path / "shared" / "absent.toml")
    )
    return _raised(lambda: _betterleaks_scan(scanner, monkeypatch))


def _betterleaks_config_linked_out(tmp_path, monkeypatch):
    source = _betterleaks_tree(tmp_path)
    outside = tmp_path / "shared" / "betterleaks.toml"
    outside.parent.mkdir()
    outside.write_text("title = 'elsewhere'\n", encoding="utf-8")
    (source / "lint").mkdir()
    _symlink_or_skip(source / "lint" / "betterleaks.toml", outside)
    scanner = _betterleaks(tmp_path, monkeypatch, config_file="lint/betterleaks.toml")
    return _raised(lambda: _betterleaks_scan(scanner, monkeypatch))


def _betterleaks_ignore_file(tmp_path, monkeypatch):
    source = _betterleaks_tree(tmp_path)
    (source / ".betterleaksignore").write_text(
        "app.py:github-pat:4\n", encoding="utf-8"
    )
    scanner = _betterleaks(tmp_path, monkeypatch)
    return _raised(lambda: _betterleaks_scan(scanner, monkeypatch))


# --------------------------------------------------------------------------- #
# zizmor
# --------------------------------------------------------------------------- #


def _zizmor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **options: Any
) -> ZizmorScanner:
    """A scanner over ``tmp_path/src``, with the uv version probe answered."""
    monkeypatch.setattr(
        ZizmorScanner, "_get_uv_tool_version", lambda self, *_: "1.30.1"
    )
    source = tmp_path / "src"
    workflows = source / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("on: push\njobs: {}\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return ZizmorScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=ZizmorScannerConfig(
            enabled=True, options=ZizmorScannerConfigOptions(**options)
        ),
    )


def _zizmor_argv(scanner: ZizmorScanner):
    source = Path(scanner.context.source_dir)
    scanner._inputs = scanner._collect_inputs(source, "source", [])
    scanner.results_dir.mkdir(parents=True, exist_ok=True)
    return scanner._execute_scan(source, "source", [])


def _zizmor_config_missing(tmp_path, monkeypatch):
    scanner = _zizmor(tmp_path, monkeypatch, config_file="absent-zizmor.yml")
    return _raised(lambda: _zizmor_argv(scanner))


def _zizmor_config_linked_out(tmp_path, monkeypatch):
    scanner = _zizmor(tmp_path, monkeypatch, config_file="zizmor-ci.yml")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "creds").write_text("first-line-of-a-file-outside-the-tree\n")
    _symlink_or_skip(tmp_path / "src" / "zizmor-ci.yml", outside / "creds")
    return _raised(lambda: _zizmor_argv(scanner))


# --------------------------------------------------------------------------- #
# trivy
# --------------------------------------------------------------------------- #

_TRIVY_ENV = (
    "TRIVY_CONFIG",
    "TRIVY_IGNOREFILE",
    "TRIVY_SECRET_CONFIG",
    "TRIVY_SCANNERS",
    "TRIVY_CACHE_DIR",
    "TRIVY_SKIP_DIRS",
    "TRIVY_SKIP_FILES",
    "TRIVY_MISCONFIG_SCANNERS",
    *OUTPUT_RESTRICTING_TRIVY_ENV,
    "ASH_OFFLINE",
)


def _trivy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    operator: bool = False,
    **options: Any,
) -> TrivyScanner:
    """A builtin trivy scanner; ``operator`` records its options as the operator's."""
    for name in _TRIVY_ENV:
        monkeypatch.delenv(name, raising=False)
    options.setdefault("offline", False)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    (context.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    if operator:
        record_provenance(context.config, in_tree=[])
    return TrivyScanner(
        context=context,
        config=TrivyScannerConfig(options=TrivyScannerConfigOptions(**options)),
    )


def _trivy_config_key_missing(tmp_path, monkeypatch):
    return _raised(
        lambda: _existing_file(
            "scanners.trivy.options.config_file",
            "private-value/trivy.yaml",
            tmp_path / "absent.yaml",
        )
    )


def _trivy_config_variable_missing(tmp_path, monkeypatch):
    return _raised(
        lambda: _existing_file(
            "TRIVY_CONFIG",
            "private-value/trivy.yaml",
            tmp_path / "absent.yaml",
            show_value=True,
        )
    )


def _trivy_secret_config_missing(tmp_path, monkeypatch):
    # The operator's config, and a scan that runs the secret scanner: a missing
    # file the scan never reads only warns.
    scanner = _trivy(
        tmp_path,
        monkeypatch,
        operator=True,
        secret_config_file=str(tmp_path / "operator" / "trivy-secret.yaml"),
        scanners=["vuln", "secret"],
    )
    return _raised(
        lambda: scanner._execute_scan(Path(scanner.context.source_dir), "source", [])
    )


def _trivy_exit_code(tmp_path, monkeypatch):
    scanner = _trivy(tmp_path, monkeypatch)
    scanner.exit_code = 2
    return _raised(lambda: scanner._read_results_file(tmp_path / "results.sarif"))


# --------------------------------------------------------------------------- #
# bandit
# --------------------------------------------------------------------------- #


def _bandit_context(source: Path, base: Path) -> PluginContext:
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _bandit_source(base: Path, files: dict[str, str]) -> Path:
    source = base / "source"
    for rel, text in files.items():
        (source / rel).parent.mkdir(parents=True, exist_ok=True)
        (source / rel).write_text(text, encoding="utf-8")
    source.mkdir(exist_ok=True)
    return source


def _bandit(source: Path, base: Path) -> BanditScanner:
    return BanditScanner(
        context=_bandit_context(source, base),
        config=BanditScannerConfig(options=BanditScannerConfigOptions()),
    )


def _bandit_scan_reading(scanner: BanditScanner, source: Path, scanned: list[str]):
    """``scan()`` with a tool run that writes a SARIF whose metrics list ``scanned``."""
    metrics: dict[str, Any] = {"_totals": {"loc": 0}}
    metrics.update({path: {"loc": 1} for path in scanned})
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Bandit"}},
                "results": [],
                "properties": {"metrics": metrics},
            }
        ],
    }

    def fake_run(*args, **kwargs):
        argv = list(kwargs.get("command") or args[0])
        Path(argv[argv.index("--output") + 1]).write_text(json.dumps(sarif))
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=fake_run),
    ):
        return scanner.scan(target=source, target_type="source")


def _bandit_scanned_nothing(tmp_path, monkeypatch):
    source = _bandit_source(tmp_path, {"a.py": "x = 1\n"})
    scanner = _bandit(source, tmp_path)
    scanner.dependencies_satisfied = True
    scanner.results_dir = tmp_path / "ash-output" / "scanners" / "bandit"
    return _raised(lambda: _bandit_scan_reading(scanner, source, []))


def _bandit_link_with_a_line_break(tmp_path, monkeypatch):
    source = _bandit_source(tmp_path, {"app.py": "x = 1\n"})
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")
    (source / "secret-link\nname.py").symlink_to(outside)
    scanner = _bandit(source, tmp_path)
    return _raised(lambda: scanner._execute_scan(source, "source", []))


def _bandit_target_with_a_line_break(tmp_path, monkeypatch):
    source = _bandit_source(tmp_path, {"app.py": "x = 1\n"})
    scanner = _bandit(source, tmp_path)
    return _raised(
        lambda: scanner._execute_scan(tmp_path / "hidden\ntarget", "converted", [])
    )


def _bandit_configuration_refused(tmp_path, monkeypatch):
    source = _bandit_source(tmp_path, {"app.py": "x = 1\n"})
    scanner = _bandit(source, tmp_path)
    return _raised(
        lambda: scanner.configure(SimpleNamespace(options=SimpleNamespace()))
    )


# --------------------------------------------------------------------------- #
# semgrep, opengrep and their shared base
# --------------------------------------------------------------------------- #

_EMPTY_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "tool"}}, "results": []}],
}


def _plain_context(base: Path) -> PluginContext:
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    source = base / "source"
    source.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _opengrep_patterns_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    context = _plain_context(tmp_path)
    return _raised(
        lambda: OpengrepScanner(
            context=context,
            config=OpengrepScannerConfig(
                options=OpengrepScannerConfigOptions(
                    offline=True, patterns=["eval($X)"]
                )
            ),
        )
    )


def _grep_scanner(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    if name == "semgrep":
        scanner_class, config_class = SemgrepScanner, SemgrepScannerConfig
    else:
        scanner_class, config_class = OpengrepScanner, OpengrepScannerConfig
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    for file_name in ("a.py", "b.py"):
        (source / file_name).write_text("x = 1\n", encoding="utf-8")
    scanner = scanner_class(context=_plain_context(tmp_path), config=config_class())
    scanner.dependencies_satisfied = True
    scanner.results_dir = tmp_path / "ash-output" / "scanners" / name
    return scanner, source


def _grep_scan_with_paths(scanner, source: Path, paths: dict):
    """``scan()`` with a tool run that writes an empty SARIF and ``paths``."""

    def fake_run(*args, **kwargs):
        argv = list(kwargs.get("command") or args[0])
        Path(argv[argv.index("--sarif-output") + 1]).write_text(
            json.dumps(_EMPTY_SARIF)
        )
        for arg in argv:
            if str(arg).startswith("--json-output="):
                Path(str(arg).split("=", 1)[1]).write_text(
                    json.dumps({"results": [], "paths": paths})
                )
        return {"stdout": "", "stderr": "", "returncode": 0}

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=fake_run),
    ):
        return scanner.scan(target=source, target_type="source")


def _grep_every_file_excluded(tmp_path, monkeypatch, name="opengrep"):
    scanner, source = _grep_scanner(name, tmp_path, monkeypatch)
    skipped = [
        {"path": str(source / file_name), "reason": "cli_exclude_flags_match"}
        for file_name in ("a.py", "b.py")
    ]
    return _raised(
        lambda: _grep_scan_with_paths(
            scanner, source, {"scanned": [], "skipped": skipped}
        )
    )


def _grep_skipped_for(reason: str, name: str = "opengrep"):
    def scenario(tmp_path, monkeypatch):
        scanner, source = _grep_scanner(name, tmp_path, monkeypatch)
        skipped = [
            {"path": str(source / file_name), "reason": reason}
            for file_name in ("a.py", "b.py")
        ]
        return _raised(
            lambda: _grep_scan_with_paths(
                scanner, source, {"scanned": [], "skipped": skipped}
            )
        )

    return scenario


# --------------------------------------------------------------------------- #
# The database update and the exclusion patterns
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _a_fresh_database_update_memo(monkeypatch):
    for name in TOOL_UPDATE_OPT_OUT_ENV:
        monkeypatch.delenv(name, raising=False)
    refresh.forget_prepared()
    yield
    refresh.forget_prepared()


def _where(tmp_path: Path) -> dict:
    return {
        "source_dir": tmp_path / "src",
        "results_dir": tmp_path / "out" / "scanners" / "grype",
    }


class _FailingTool:
    """Stands in for ``spawn_run``: the tool exits ``returncode`` with ``stderr``."""

    def __init__(self, returncode: int, stderr: str) -> None:
        self.returncode, self.stderr = returncode, stderr

    def __call__(self, argv, **kwargs):
        return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)


def _database_tool_not_installed(tmp_path, monkeypatch):
    monkeypatch.setattr(refresh, "find_executable", lambda tool: None)
    return _raised(
        lambda: refresh.prepare_content_db(
            "grype", tmp_path, offline=False, **_where(tmp_path)
        )
    )


def _database_update_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        refresh, "spawn_run", _FailingTool(1, "unable to download the database")
    )
    return _raised(
        lambda: refresh.prepare_content_db(
            "grype",
            tmp_path,
            offline=False,
            scan_id="s",
            executable="grype",
            **_where(tmp_path),
        )
    )


def _pattern_already_ran_past(tmp_path, monkeypatch):
    def evaluate():
        with exclusions.EvaluationBudget() as budget:
            budget._timed_out["(a+)+$"] = "an exclusion option"
            budget.evaluate(1.0, "an exclusion option", "(a+)+$", len, "x")

    return _raised(evaluate)


def _pattern_time_spent(tmp_path, monkeypatch):
    def evaluate():
        with exclusions.EvaluationBudget() as budget:
            budget._spent[1.0] = 1.0
            budget.evaluate(1.0, "an exclusion option", "(b+)+$", len, "x")

    return _raised(evaluate)


# --------------------------------------------------------------------------- #
# The cases
# --------------------------------------------------------------------------- #

CASES = [
    Case(
        "betterleaks exit code",
        _betterleaks_exit_code,
        _drop_in(betterleaks_module),
        ReasonCode.EXIT_CODE_REJECTED,
        holds=("exited 1",),
    ),
    Case(
        "betterleaks config file missing",
        _betterleaks_config_missing,
        _drop_in(betterleaks_module),
        ReasonCode.CONFIG_FILE_MISSING,
        holds=("config_file",),
        never=("absent.toml", "shared"),
    ),
    Case(
        "betterleaks config file linked out of the tree",
        _betterleaks_config_linked_out,
        _drop_in(betterleaks_module),
        ReasonCode.CONFIG_FILE_OUTSIDE_TREE,
        holds=("config_file",),
        never=("lint", "elsewhere"),
    ),
    Case(
        "betterleaks ignore file in the tree",
        _betterleaks_ignore_file,
        _drop_in(betterleaks_module),
        ReasonCode.IGNORE_FILE_IN_TREE,
        holds=(".betterleaksignore",),
    ),
    Case(
        "zizmor config file missing",
        _zizmor_config_missing,
        lambda monkeypatch: monkeypatch.setattr(
            zizmor_module._ConfigFileMissing, "reason", None
        ),
        ReasonCode.CONFIG_FILE_MISSING,
        holds=("config_file",),
        never=("absent-zizmor.yml",),
    ),
    Case(
        "zizmor config file linked out of the tree",
        _zizmor_config_linked_out,
        _drop_in(zizmor_module),
        ReasonCode.CONFIG_FILE_OUTSIDE_TREE,
        holds=("config_file",),
        never=("zizmor-ci.yml", "creds"),
    ),
    Case(
        "trivy config option names no file",
        _trivy_config_key_missing,
        _drop_in(trivy_base),
        ReasonCode.CONFIG_FILE_MISSING,
        holds=("scanners.trivy.options.config_file",),
        never=("private-value", "absent.yaml"),
    ),
    Case(
        "trivy config variable names no file",
        _trivy_config_variable_missing,
        _drop_in(trivy_base),
        ReasonCode.CONFIG_FILE_MISSING,
        holds=("TRIVY_CONFIG",),
        never=("private-value", "absent.yaml"),
    ),
    Case(
        "trivy secret config names no file",
        _trivy_secret_config_missing,
        _drop_in(trivy_base),
        ReasonCode.CONFIG_FILE_MISSING,
        holds=("secret_config_file",),
        never=("trivy-secret.yaml",),
    ),
    Case(
        "trivy exit code",
        _trivy_exit_code,
        _drop_in(trivy_module),
        ReasonCode.EXIT_CODE_REJECTED,
        holds=("exited 2",),
    ),
    Case(
        "bandit scanned none of the files it was given",
        _bandit_scanned_nothing,
        _drop_in(bandit_module),
        ReasonCode.NOTHING_SCANNED,
        holds=("none of the 1 Python file(s)",),
        never=("a.py",),
    ),
    Case(
        "bandit link whose name holds a line break",
        _bandit_link_with_a_line_break,
        _drop_in(bandit_module),
        ReasonCode.EXCLUDE_CANNOT_EXPRESS,
        holds=("--exclude",),
        never=("secret-link",),
    ),
    Case(
        "bandit target whose path holds a line break",
        _bandit_target_with_a_line_break,
        _drop_in(bandit_module),
        ReasonCode.TARGET_PATH_REFUSED,
        holds=("line break",),
        never=("hidden",),
    ),
    Case(
        "bandit configuration it cannot apply",
        _bandit_configuration_refused,
        _drop_in(bandit_module),
        ReasonCode.CONSTRUCTION_FAILED,
        holds=("its configuration could not be applied",),
    ),
    Case(
        "opengrep patterns option",
        _opengrep_patterns_refused,
        _drop_in(opengrep_module),
        ReasonCode.OPTION_REFUSED,
        holds=("patterns option",),
        never=("eval($X)",),
    ),
    Case(
        "grep scanner left no file by its exclusions",
        _grep_every_file_excluded,
        _drop_in(grep_base),
        ReasonCode.NOTHING_SCANNED,
        holds=("left out all 2 files",),
        never=("a.py", "b.py"),
    ),
    Case(
        "grep scanner could not parse the files it found",
        _grep_skipped_for(min(UNPARSED_SKIP_REASONS)),
        _drop_in(grep_base),
        ReasonCode.FILES_NOT_READ,
        holds=("could not parse them",),
        never=(min(UNPARSED_SKIP_REASONS), "a.py"),
    ),
    Case(
        "grep scanner did not read the files it found",
        _grep_skipped_for(min(UNREAD_SKIP_REASONS)),
        _drop_in(grep_base),
        ReasonCode.FILES_NOT_READ,
        holds=("did not read 2 file(s)",),
        never=(min(UNREAD_SKIP_REASONS), "a.py"),
    ),
    Case(
        "grep scanner skipped files for a reason ASH does not know",
        _grep_skipped_for("a_reason_no_version_of_the_tool_wrote"),
        _drop_in(grep_base),
        ReasonCode.FILES_NOT_READ,
        holds=("does not know",),
        never=("a_reason_no_version_of_the_tool_wrote", "a.py"),
    ),
    Case(
        "database update with no tool installed",
        _database_tool_not_installed,
        _drop_in(refresh),
        ReasonCode.DATABASE_UPDATE_FAILED,
        holds=("not installed",),
    ),
    Case(
        "database update that failed",
        _database_update_failed,
        _drop_in(refresh),
        ReasonCode.DATABASE_UPDATE_FAILED,
        holds=("exited with code 1",),
        never=("unable to download the database",),
    ),
    Case(
        "pattern that already ran past the time limit",
        _pattern_already_ran_past,
        _drop_in(exclusions),
        ReasonCode.PATTERN_TIME_LIMIT,
        holds=("already ran past",),
        never=("(a+)+$",),
    ),
    Case(
        "pattern time limit spent on earlier patterns",
        _pattern_time_spent,
        _drop_in(exclusions),
        ReasonCode.PATTERN_TIME_LIMIT,
        holds=("was spent",),
        never=("(b+)+$",),
    ),
]


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_the_failure_names_its_reason(case, tmp_path, monkeypatch):
    error = case.scenario(tmp_path, monkeypatch)

    _reason(error, case.code, holds=case.holds, never=case.never)


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_control_a_site_with_its_reason_removed_fails_its_case(
    case, tmp_path, monkeypatch
):
    case.drop(monkeypatch)

    error = case.scenario(tmp_path, monkeypatch)

    assert reason_of(error) is None, "the control left a reason in place"
    with pytest.raises(AssertionError):
        _reason(error, case.code, holds=case.holds, never=case.never)


@pytest.mark.parametrize("name", ["semgrep", "opengrep"])
def test_both_grep_scanners_share_the_reason_the_base_class_records(
    name, tmp_path, monkeypatch
):
    error = _grep_every_file_excluded(tmp_path, monkeypatch, name)

    _reason(
        error,
        ReasonCode.NOTHING_SCANNED,
        holds=("left out all 2 files",),
        never=("a.py", "b.py"),
    )


# --------------------------------------------------------------------------- #
# The check itself
# --------------------------------------------------------------------------- #


class TestTheCheckCanFail:
    def test_an_error_with_no_reason_fails_it(self):
        with pytest.raises(AssertionError, match="carries no reason"):
            _reason(ScannerError("plain"), ReasonCode.RUN_FAILED)

    def test_another_code_fails_it(self):
        error = ScannerError("x", reason=FailureReason(ReasonCode.TIMED_OUT))
        with pytest.raises(AssertionError):
            _reason(error, ReasonCode.NO_PLUGIN_CONTEXT)

    def test_a_sentence_without_what_it_must_say_fails_it(self):
        error = ScannerError(
            "x", reason=FailureReason(ReasonCode.TIMED_OUT, "it timed out")
        )
        with pytest.raises(AssertionError):
            _reason(error, ReasonCode.TIMED_OUT, holds=("killed after",))

    def test_a_sentence_with_what_it_must_not_say_fails_it(self):
        error = ScannerError(
            "x", reason=FailureReason(ReasonCode.TIMED_OUT, "it timed out after 5 s")
        )
        with pytest.raises(AssertionError):
            _reason(error, ReasonCode.TIMED_OUT, never=("5 s",))

    def test_a_reason_found_on_the_context_passes_it(self):
        inner = ScannerError(
            "inner", reason=FailureReason(ReasonCode.TIMED_OUT, "it timed out")
        )
        try:
            try:
                raise inner
            except ScannerError:
                raise ScannerError("wrapper")
        except ScannerError as outer:
            error = outer

        _reason(error, ReasonCode.TIMED_OUT, holds=("timed out",))

    def test_the_dropped_error_keeps_no_reason_whatever_it_is_given(self):
        error = _DropsTheReason(
            "x", reason=FailureReason(ReasonCode.TIMED_OUT, "it timed out")
        )

        assert reason_of(error) is None
