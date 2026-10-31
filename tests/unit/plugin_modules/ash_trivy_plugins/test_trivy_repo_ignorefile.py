# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""trivy-repo gets an explicit --ignorefile, never the scanned tree's .trivyignore.

Without --ignorefile, trivy reads .trivyignore from its working directory, which is
the source directory. These tests record the argv trivy-repo would run and check
which ignore file it names. tests/integration/scanners/test_trivy_repo_real_ignorefile.py
runs the real trivy.
"""

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
)
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()


@pytest.fixture(autouse=True)
def _fresh_warnings(monkeypatch):
    monkeypatch.delenv("TRIVY_IGNOREFILE", raising=False)
    monkeypatch.delenv("TRIVY_SECRET_CONFIG", raising=False)
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


def _tree(tmp_path: Path) -> Path:
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    (source / ".trivyignore").write_text("github-pat\n")
    return source


def _argv(tmp_path: Path, source: Path, options=None) -> list:
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    # Built from no config file in the tree: the options here are the operator's.
    # tests/unit/plugin_modules/ash_builtin/test_trivy_input_provenance.py covers
    # options the scanned tree or an MCP client set.
    config = AshConfig()
    record_provenance(config, in_tree=[])
    scanner = TrivyRepoScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=config),
        config=TrivyRepoScannerConfig(options=options or {}),
    )
    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_run_subprocess", return_value={"returncode": 0}) as run,
    ):
        scanner.scan(target=source, target_type="source")
    return [str(a) for a in run.call_args.kwargs["command"]]


def _ignorefile(argv: list) -> Path:
    values = [a.split("=", 1)[1] for a in argv if a.startswith("--ignorefile=")]
    assert len(values) == 1, argv
    return Path(values[0])


def test_the_trees_trivyignore_is_not_used(tmp_path):
    source = _tree(tmp_path)
    passed = _ignorefile(_argv(tmp_path, source))
    assert not passed.resolve().is_relative_to(source.resolve())
    assert passed.read_text() == ""


def test_an_operator_ignore_file_outside_the_tree_is_passed(tmp_path):
    source = _tree(tmp_path)
    operator = tmp_path / "operator" / "trivyignore"
    operator.parent.mkdir()
    operator.write_text("github-pat\n")
    passed = _ignorefile(_argv(tmp_path, source, {"ignore_file": str(operator)}))
    assert passed == operator.resolve()


def test_trivy_ignorefile_from_the_environment_is_passed(tmp_path, monkeypatch):
    source = _tree(tmp_path)
    operator = tmp_path / "operator" / "trivyignore"
    operator.parent.mkdir()
    operator.write_text("github-pat\n")
    monkeypatch.setenv("TRIVY_IGNOREFILE", str(operator))
    assert _ignorefile(_argv(tmp_path, source)) == operator.resolve()


@pytest.mark.parametrize(
    ("env", "flag"),
    [
        ("TRIVY_IGNOREFILE", "--ignorefile="),
        ("TRIVY_SECRET_CONFIG", "--secret-config="),
    ],
)
def test_a_relative_path_in_the_environment_is_taken_from_the_working_directory(
    tmp_path, monkeypatch, env, flag
):
    """The variable is the operator's, set where ASH runs, not in the scanned tree."""
    source = _tree(tmp_path)
    (source / "operator-file").write_text("github-pat\n")
    workdir = tmp_path / "ci"
    workdir.mkdir()
    (workdir / "operator-file").write_text("github-pat\n")
    monkeypatch.chdir(workdir)
    monkeypatch.setenv(env, "operator-file")
    values = [a.split("=", 1)[1] for a in _argv(tmp_path, source) if a.startswith(flag)]
    assert [Path(v) for v in values] == [(workdir / "operator-file").resolve()]


@pytest.mark.parametrize("value", [".trivyignore", "sub/ignore"])
def test_an_ignore_file_inside_the_tree_is_not_passed(tmp_path, value):
    source = _tree(tmp_path)
    (source / "sub").mkdir()
    (source / "sub" / "ignore").write_text("github-pat\n")
    passed = _ignorefile(_argv(tmp_path, source, {"ignore_file": value}))
    assert not passed.resolve().is_relative_to(source.resolve())
    assert passed.read_text() == ""


def _flag(argv: list, name: str) -> Path:
    values = [a.split("=", 1)[1] for a in argv if a.startswith(f"{name}=")]
    assert len(values) == 1, argv
    return Path(values[0])


def test_the_trees_trivy_secret_yaml_is_not_used(tmp_path):
    source = _tree(tmp_path)
    (source / "trivy-secret.yaml").write_text("disable-rules:\n  - github-pat\n")
    passed = _flag(_argv(tmp_path, source), "--secret-config")
    assert not passed.resolve().is_relative_to(source.resolve())
    assert passed.read_text().strip() == "{}"


def test_an_operator_secret_config_outside_the_tree_is_passed(tmp_path):
    source = _tree(tmp_path)
    operator = tmp_path / "operator" / "trivy-secret.yaml"
    operator.parent.mkdir()
    operator.write_text("{}\n")
    argv = _argv(tmp_path, source, {"secret_config_file": str(operator)})
    assert _flag(argv, "--secret-config") == operator.resolve()


def test_an_environment_secret_config_inside_the_tree_is_refused_without_its_path(
    tmp_path, monkeypatch
):
    """A value an environment variable chose is never printed: the warning
    names the variable and shows the path as the environment-value marker."""
    source = _tree(tmp_path)
    inside = source / "secret-rules.yaml"
    inside.write_text("{}\n")
    monkeypatch.setenv("TRIVY_SECRET_CONFIG", str(inside))

    messages: list = []

    class _Records(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    handler = _Records(level=logging.WARNING)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        argv = _argv(tmp_path, source)
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)

    named = [m for m in messages if "TRIVY_SECRET_CONFIG" in m]
    assert named, messages
    assert all(str(inside) not in m and inside.name not in m for m in named), named
    assert any("<value>" in m for m in named), named
    assert not _flag(argv, "--secret-config").resolve().is_relative_to(source.resolve())


def test_an_environment_ignore_file_inside_the_tree_is_refused_without_its_path(
    tmp_path, monkeypatch
):
    """The same holds for the ignore file: the warning names the variable and
    shows the path as the environment-value marker."""
    source = _tree(tmp_path)
    inside = source / "ignore-rules"
    inside.write_text("github-pat\n")
    monkeypatch.setenv("TRIVY_IGNOREFILE", str(inside))

    messages: list = []

    class _Records(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    handler = _Records(level=logging.WARNING)
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        argv = _argv(tmp_path, source)
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)

    named = [m for m in messages if "TRIVY_IGNOREFILE" in m]
    assert named, messages
    assert all(str(inside) not in m and inside.name not in m for m in named), named
    assert any("<value>" in m for m in named), named
    assert not _ignorefile(argv).resolve().is_relative_to(source.resolve())


def _scanner(tmp_path: Path, source: Path, options=None) -> TrivyRepoScanner:
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    # Built from no config file in the tree, as _argv does: the options are the
    # operator's, so an option naming no file is refused rather than ignored
    # (utils/config_trust.set_by_operator refuses a config with no provenance).
    config = AshConfig()
    record_provenance(config, in_tree=[])
    return TrivyRepoScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=config),
        config=TrivyRepoScannerConfig(options=options or {}),
    )


def _not_a_file(tmp_path: Path, kind: str) -> Path:
    """A path outside the scanned tree that names no file: missing, or a directory."""
    operator = tmp_path / "operator"
    operator.mkdir(exist_ok=True)
    path = operator / f"marker-input-{kind}"
    if kind == "directory":
        path.mkdir()
    return path


@pytest.mark.parametrize("kind", ["missing", "directory"])
@pytest.mark.parametrize(
    ("variable", "method"),
    [
        ("TRIVY_SECRET_CONFIG", "_secret_config_file"),
        ("TRIVY_IGNOREFILE", "_ignore_file"),
    ],
)
def test_an_environment_input_that_names_no_file_is_refused_without_its_value(
    tmp_path, monkeypatch, variable, method, kind
):
    """The refusal names the variable only: the value an environment variable
    chose, in any spelling of the path, is not in the message."""
    source = _tree(tmp_path)
    chosen = _not_a_file(tmp_path, kind)
    monkeypatch.setenv(variable, str(chosen))
    scanner = _scanner(tmp_path, source)

    with pytest.raises(ScannerError) as raised:
        getattr(scanner, method)()

    message = str(raised.value)
    assert variable in message, message
    assert str(chosen) not in message, message
    assert chosen.name not in message, message
    assert chosen.resolve().as_posix() not in message, message
    assert "does not name a file" in message, message


@pytest.mark.parametrize(
    ("option", "method"),
    [
        ("secret_config_file", "_secret_config_file"),
        ("ignore_file", "_ignore_file"),
    ],
)
def test_an_option_that_names_no_file_is_refused_by_its_key(tmp_path, option, method):
    """Control: the refusal for a configured option names the option's key, so
    the message stays actionable."""
    source = _tree(tmp_path)
    chosen = _not_a_file(tmp_path, "missing")
    scanner = _scanner(tmp_path, source, {option: str(chosen)})

    with pytest.raises(ScannerError) as raised:
        getattr(scanner, method)()

    message = str(raised.value)
    assert f"scanners.trivy-repo.options.{option}" in message, message
    assert "does not name a file" in message, message


def test_a_refused_option_does_not_hide_the_operators_environment_file(
    tmp_path, monkeypatch
):
    source = _tree(tmp_path)
    operator = tmp_path / "operator" / "trivyignore"
    operator.parent.mkdir()
    operator.write_text("github-pat\n")
    monkeypatch.setenv("TRIVY_IGNOREFILE", str(operator))
    argv = _argv(tmp_path, source, {"ignore_file": ".trivyignore"})
    assert _ignorefile(argv) == operator.resolve()


def test_the_flags_follow_the_subcommand_however_the_target_is_spelled(tmp_path):
    """On Windows the argv can carry the target with backslashes."""
    source = _tree(tmp_path)
    output = tmp_path / "out"
    output.mkdir()
    scanner = TrivyRepoScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=AshConfig()),
        config=TrivyRepoScannerConfig(),
    )
    scanner.dependencies_satisfied = True
    resolved = ["trivy", "repository", "--format", "sarif", r"C:\work\repo"]
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_resolve_arguments", return_value=list(resolved)),
        patch.object(scanner, "_run_subprocess", return_value={"returncode": 0}) as run,
    ):
        scanner.scan(target=source, target_type="source")
    argv = run.call_args.kwargs["command"]
    assert argv[:2] == ["trivy", "repository"]
    assert argv[2].startswith("--ignorefile=")
    assert argv[3].startswith("--secret-config=")
    # The config and modules directory trivy-repo also pins, and the deadline it
    # matches to ASH's scan timeout, are the only additions.
    assert [
        a
        for a in argv[4:]
        if not a.startswith(("--config=", "--module-dir=", "--timeout="))
    ] == resolved[2:]


def test_the_trees_trivyignore_stays_unused_while_the_sandbox_skips_the_db_update(
    tmp_path, monkeypatch
):
    """Both changes to trivy-repo's argv at once: an online scan in a sandbox.

    The database is prepared outside the sandbox and trivy is told not to update
    it, and the ignore file is still ASH's own, not the scanned tree's .trivyignore.
    The update and its flags come from TrivyScannerBase._run_subprocess, which
    trivy fs and trivy-repo share, so it is the base spawn that is replaced here.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        _trivy_scanner_base as trivy_base,
    )

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    source = _tree(tmp_path)
    output = tmp_path / "out"
    output.mkdir()
    config = AshConfig()
    record_provenance(config, in_tree=[])
    scanner = TrivyRepoScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=config),
        config=TrivyRepoScannerConfig(options={"ignore_file": ".trivyignore"}),
    )
    scanner.dependencies_satisfied = True
    prepared = []
    commands = []
    monkeypatch.setattr(
        trivy_base,
        "prepare_content_db",
        lambda tool, *a, **k: prepared.append((tool, k)),
    )
    # A completed run carries its exit code; a response without one is a tool
    # that never ran, which the scanner refuses before grading.
    monkeypatch.setattr(
        trivy_base.ScannerPluginBase,
        "_run_subprocess",
        lambda self, command, *a, **k: (
            commands.append(list(command)) or {"returncode": 0}
        ),
    )
    with patch.object(scanner, "_pre_scan", return_value=True):
        scanner.scan(target=source, target_type="source")
    assert [tool for tool, _ in prepared] == ["trivy"]
    assert prepared[0][1]["offline"] is False
    (argv,) = commands
    passed = _ignorefile(argv)
    assert not passed.resolve().is_relative_to(source.resolve())
    assert passed.read_text() == ""
    flags = ["--skip-db-update", "--skip-java-db-update", "--cache-backend=memory"]
    for flag in flags:
        assert flag in argv, argv
    # Every inserted flag sits between the subcommand and the target. The ignore
    # file is found by its prefix: trivy-repo spells its value with as_posix(), so
    # rebuilding the argument from a Path would use backslashes on Windows.
    subcommand_at = argv.index("repository")
    target_at = max(i for i, a in enumerate(argv) if Path(a) == source)
    ignore_at = next(i for i, a in enumerate(argv) if a.startswith("--ignorefile="))
    cache_at = next(i for i, a in enumerate(argv) if a.startswith("--cache-dir="))
    for at in [*(argv.index(flag) for flag in flags), ignore_at, cache_at]:
        assert subcommand_at < at < target_at, argv


EMPTY_SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {"driver": {"name": "Trivy", "version": "0.99.0", "rules": []}},
            "results": [],
        }
    ],
}


class _CapturedRecords(logging.Handler):
    def __init__(self):
        super().__init__(level=1)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def _scan_recording_command_lines(tmp_path):
    """Scan with a fake trivy that writes an empty SARIF file where it is told to.

    Returns the report, the "Running command" log records and the argv.
    """
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "out"
    output.mkdir()
    scanner = TrivyRepoScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=AshConfig()),
        config=TrivyRepoScannerConfig(options={}),
    )
    scanner.dependencies_satisfied = True
    argv = []

    def fake_run(*, command, **kwargs):
        argv[:] = [str(a) for a in command]
        results = Path(command[command.index("--output") + 1])
        results.parent.mkdir(parents=True, exist_ok=True)
        results.write_text(json.dumps(EMPTY_SARIF))
        return {"returncode": 0}

    capture = _CapturedRecords()
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(capture)
    ASH_LOGGER.setLevel(1)
    try:
        with (
            patch.object(scanner, "_pre_scan", return_value=True),
            patch.object(scanner, "_run_subprocess", side_effect=fake_run),
        ):
            report = scanner.scan(target=source, target_type="source")
    finally:
        ASH_LOGGER.removeHandler(capture)
        ASH_LOGGER.setLevel(previous_level)
    running = [m for m in capture.messages if "Running command" in m]
    return report, running, argv


def test_env_read_input_paths_masked_in_command_records(tmp_path, monkeypatch):
    """The ignore file and secret config paths trivy-repo reads from the
    environment are hidden in the logged command line and in the SARIF
    invocation fields."""
    ignore = tmp_path / "marker-ignore-path-value" / ".trivyignore"
    secret = tmp_path / "marker-secret-config-value" / "trivy-secret.yaml"
    ignore.parent.mkdir()
    secret.parent.mkdir()
    ignore.write_text("")
    secret.write_text("disable-rules: []\n")
    monkeypatch.setenv("TRIVY_IGNOREFILE", str(ignore))
    monkeypatch.setenv("TRIVY_SECRET_CONFIG", str(secret))

    report, running, argv = _scan_recording_command_lines(tmp_path)

    assert running, "the scan did not reach the Running command log call"
    assert any(str(ignore.resolve()) in a for a in argv), argv
    report_text = report.model_dump_json()
    for marker in ("marker-ignore-path-value", "marker-secret-config-value"):
        assert not any(marker in m for m in running), (marker, running)
        assert marker not in report_text, marker


def test_command_records_keep_the_whole_command_without_env_read_paths(tmp_path):
    report, running, argv = _scan_recording_command_lines(tmp_path)

    assert running, "the scan did not reach the Running command log call"
    results_path = argv[argv.index("--output") + 1]
    assert "--output" in running[0]
    assert results_path in running[0]
    invocation = report.runs[0].invocations[0]
    assert results_path in invocation.commandLine
    assert results_path in invocation.arguments
