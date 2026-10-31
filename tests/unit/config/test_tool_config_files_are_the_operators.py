# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""bandit's, grype's and syft's own config files come from the operator.

A config file inside the scanned tree does not choose ``config_file`` for these
scanners, the scanners no longer find one by name in the source directory, and
each scan hands the tool an explicit config so it does not read one from the tree
on its own. An operator names a file, even one inside the tree, with
``--config-overrides`` or in a config file outside the tree.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.path_trust import in_scanned_tree
from automated_security_helper.config.resolve_config import resolve_config
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

SCANNERS = ["bandit", "grype", "syft"]


def _repo(tmp_path: Path, scanners: Dict[str, Any]) -> Path:
    """A checkout whose own .ash/.ash.yaml sets ``scanners``."""
    repo = tmp_path / "repo"
    (repo / ".ash").mkdir(parents=True)
    mark_git_checkout(repo)
    (repo / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump({"scanners": scanners}), encoding="utf-8"
    )
    return repo


def _config_file(config: Any, scanner: str) -> Any:
    return config.get_plugin_config("scanner", scanner)["options"].get("config_file")


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_a_repositorys_config_does_not_choose_the_tool_config(
    tmp_path: Path, scanner: str
) -> None:
    repo = _repo(tmp_path, {scanner: {"options": {"config_file": ".ash/tool.yaml"}}})
    config = resolve_config(source_dir=repo)
    assert _config_file(config, scanner) is None


@pytest.mark.parametrize("scanner", SCANNERS)
def test_an_override_names_the_tool_config_even_inside_the_tree(
    tmp_path: Path, scanner: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative override is taken from the working directory, here the tree."""
    repo = _repo(tmp_path, {scanner: {"options": {"config_file": ".ash/other.yaml"}}})
    monkeypatch.chdir(repo)
    config = resolve_config(
        source_dir=repo,
        config_overrides=[f"scanners.{scanner}.options.config_file=.ash/tool.yaml"],
    )
    assert Path(_config_file(config, scanner)) == repo / ".ash" / "tool.yaml"


@pytest.mark.parametrize("scanner", SCANNERS)
def test_an_operator_config_outside_the_tree_names_the_tool_config(
    tmp_path: Path, scanner: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        yaml.safe_dump(
            {"scanners": {scanner: {"options": {"config_file": "/etc/tool.yaml"}}}}
        ),
        encoding="utf-8",
    )
    config = resolve_config(config_path=operator, source_dir=repo)
    assert _config_file(config, scanner) == "/etc/tool.yaml"


@pytest.mark.parametrize(
    "override,read",
    [
        (
            "scanners.bandit.options.config_file=.ash/tool.ini",
            lambda config: _config_file(config, "bandit"),
        ),
        (
            "reporters.s3.options.bucket_name=other-bucket",
            lambda config: (
                (config.get_plugin_config("reporter", "s3") or {}).get("options") or {}
            ).get("bucket_name"),
        ),
    ],
    ids=["scanner-config-file", "reporter-destination"],
)
def test_an_mcp_clients_overrides_are_not_replayed_as_the_operators(
    tmp_path: Path, override: str, read: Any
) -> None:
    """Under the MCP server, ``config_overrides`` are the client's, not the operator's.

    The workspace tools pass a client's overrides, already held to the session's
    allowlist, with the session's rules (``client_config_policy``). An allowlist
    that lets a client change a field does not make its value the operator's, so
    it is not replayed onto the trusted base the way ``--config-overrides`` is.
    """
    from automated_security_helper.config.ash_config import (
        AshConfig,
        RuntimeOverridesConfig,
    )
    from automated_security_helper.config.client_config_policy import (
        ClientConfigRules,
    )

    repo = _repo(tmp_path, {"bandit": {"options": {"config_file": ".ash/other.ini"}}})
    rules = ClientConfigRules(policy=RuntimeOverridesConfig(), base=AshConfig())

    from_the_client = resolve_config(
        source_dir=repo, config_overrides=[override], client_config_policy=rules
    )
    from_the_operator = resolve_config(source_dir=repo, config_overrides=[override])

    assert read(from_the_client) is None
    # The operator's relative path is taken from the working directory.
    written = override.partition("=")[2]
    expected = str(Path.cwd() / written) if written.startswith(".ash/") else written
    assert read(from_the_operator) == expected


#: opengrep's and semgrep's rules and metrics setting, each with a value other
#: than its default.
RULE_CHOICES = [
    ("opengrep", "config", "p/default"),
    ("semgrep", "config", "https://rules.example.invalid/rules.yaml"),
    ("opengrep", "metrics", "on"),
    ("semgrep", "metrics", "on"),
]
_RULE_IDS = [f"{scanner}.{option}" for scanner, option, _ in RULE_CHOICES]


def _option(config: Any, scanner: str, option: str) -> Any:
    return config.get_plugin_config("scanner", scanner)["options"].get(option)


@pytest.mark.parametrize(("scanner", "option", "value"), RULE_CHOICES, ids=_RULE_IDS)
def test_a_repositorys_config_does_not_choose_the_rules_or_metrics(
    tmp_path: Path, scanner: str, option: str, value: str
) -> None:
    repo = _repo(tmp_path, {scanner: {"options": {option: value}}})
    default = _option(resolve_config(source_dir=tmp_path / "empty"), scanner, option)
    config = resolve_config(source_dir=repo)
    assert _option(config, scanner, option) == default != value


@pytest.mark.parametrize(("scanner", "option", "value"), RULE_CHOICES, ids=_RULE_IDS)
def test_an_override_chooses_the_rules_or_metrics(
    tmp_path: Path, scanner: str, option: str, value: str
) -> None:
    repo = _repo(tmp_path, {scanner: {"options": {"severity": []}}})
    config = resolve_config(
        source_dir=repo,
        config_overrides=[f"scanners.{scanner}.options.{option}={value}"],
    )
    assert _option(config, scanner, option) == value


@pytest.mark.parametrize(("scanner", "option", "value"), RULE_CHOICES, ids=_RULE_IDS)
def test_an_operator_config_outside_the_tree_chooses_the_rules_or_metrics(
    tmp_path: Path, scanner: str, option: str, value: str
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        yaml.safe_dump({"scanners": {scanner: {"options": {option: value}}}}),
        encoding="utf-8",
    )
    config = resolve_config(config_path=operator, source_dir=repo)
    assert _option(config, scanner, option) == value


def _context(tmp_path: Path) -> PluginContext:
    from automated_security_helper.config.default_config import get_default_config

    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source, output_dir=output, config=get_default_config()
    )


def _values_after(argv: List[str], flag: str) -> List[str]:
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == flag]


@pytest.mark.parametrize(
    "name", [".grype.yaml", ".grype/config.yaml", ".ash/.grype.yaml", ".ash/grype.yaml"]
)
def test_grype_gets_an_empty_config_not_the_trees(tmp_path: Path, name: str) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
    )

    context = _context(tmp_path)
    in_tree = Path(context.source_dir) / name
    in_tree.parent.mkdir(parents=True, exist_ok=True)
    in_tree.write_text("only-fixed: true\n", encoding="utf-8")
    scanner = GrypeScanner(context=context, config=GrypeScannerConfig())
    argv, _, _ = scanner._execute_scan(Path(context.source_dir), "source", [])
    (passed,) = _values_after([str(a) for a in argv], "--config")
    # Written outside the scanned tree, not in the results directory under it.
    assert not in_scanned_tree(passed, context.source_dir)
    assert Path(passed).parent != Path(scanner.results_dir)
    assert yaml.safe_load(Path(passed).read_text(encoding="utf-8")) == {}
    assert all(arg.key != "--config" for arg in scanner.args.extra_args), (
        "the empty config is added for the scan only"
    )


def test_grype_gets_the_operators_config(tmp_path: Path) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
        GrypeScannerConfigOptions,
    )

    context = _context(tmp_path)
    operator = tmp_path / "grype.yaml"
    operator.write_text("output: sarif\n", encoding="utf-8")
    scanner = GrypeScanner(
        context=context,
        config=GrypeScannerConfig(
            options=GrypeScannerConfigOptions(config_file=str(operator))
        ),
    )
    argv, _, _ = scanner._execute_scan(Path(context.source_dir), "source", [])
    assert _values_after([str(a) for a in argv], "--config") == [
        operator.resolve().as_posix()
    ]


@pytest.mark.parametrize("name", [".syft.yaml", ".syft.yml"])
def test_syft_gets_an_empty_config_not_the_trees(
    tmp_path: Path, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        syft_scanner,
    )

    context = _context(tmp_path)
    (Path(context.source_dir) / name).write_text(
        "exclude: ['./requirements.txt']\n", encoding="utf-8"
    )
    scanner = syft_scanner.SyftScanner(
        context=context, config=syft_scanner.SyftScannerConfig()
    )
    scanner.dependencies_satisfied = True
    calls: List[List[str]] = []
    contents: List[Any] = []

    def fake_run(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        argv = [str(a) for a in kwargs.get("command") or args[0]]
        calls.append(argv)
        (passed,) = _values_after(argv, "--config")
        contents.append(yaml.safe_load(Path(passed).read_text(encoding="utf-8")))
        raise RuntimeError("stop after the command is built")

    monkeypatch.setattr(scanner, "_pre_scan", lambda *a, **k: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    with pytest.raises(Exception):
        scanner.scan(target=Path(context.source_dir), target_type="source")
    (argv,) = calls
    (passed,) = _values_after(argv, "--config")
    # Written outside the scanned tree, not in the results directory under it.
    assert not in_scanned_tree(passed, context.source_dir)
    assert Path(passed).parent != Path(scanner.results_dir)
    assert contents == [{}]


@pytest.mark.parametrize("tool", ["semgrep", "opengrep"])
def test_a_semgrepignore_is_not_honored_and_the_defaults_are_kept(
    tmp_path: Path, tool: str
) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners._grep_scanner_base import (
        SEMGREP_DEFAULT_IGNORES,
    )

    if tool == "semgrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner as cls,
            SemgrepScannerConfig as cfg,
        )
    else:
        from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
            OpengrepScanner as cls,  # type: ignore[assignment]
            OpengrepScannerConfig as cfg,  # type: ignore[assignment]
        )
    context = _context(tmp_path)
    scanner = cls(context=context, config=cfg())
    argv = [
        str(a)
        for a in scanner._resolve_arguments(
            target=Path(context.source_dir), results_file=tmp_path / "r.sarif"
        )
    ]
    assert "--x-ignore-semgrepignore-files" in argv
    excluded = _values_after(argv, "--exclude")
    assert set(SEMGREP_DEFAULT_IGNORES) <= set(excluded)


def _semgrepignore_notes(tmp_path: Path, *, enabled: bool) -> List[str]:
    """The ``.semgrepignore`` notes a semgrep scanner records while its command is built.

    The scanner is enabled or disabled explicitly: ``SemgrepScannerConfig``'s
    default is False on Windows, where semgrep publishes no build, and the note
    is recorded only for an enabled scanner (a disabled one runs neither tool,
    so it leaves nothing unhonored), so a test of the note cannot rest on the
    default.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScanner,
        SemgrepScannerConfig,
    )

    context = _context(tmp_path)
    (Path(context.source_dir) / ".semgrepignore").write_text("hidden/\n", "utf-8")
    scanner = SemgrepScanner(
        context=context, config=SemgrepScannerConfig(enabled=enabled)
    )
    scanner._resolve_arguments(
        target=Path(context.source_dir), results_file=tmp_path / "r.sarif"
    )
    return [w for w in context.config._resolution_warnings if ".semgrepignore" in w]


def test_an_unhonored_semgrepignore_is_noted_in_the_results(tmp_path: Path) -> None:
    (note,) = _semgrepignore_notes(tmp_path, enabled=True)
    assert "was not honored" in note
    assert "global_settings.ignore_paths" in note


def test_a_disabled_scanner_records_no_semgrepignore_note(tmp_path: Path) -> None:
    assert _semgrepignore_notes(tmp_path, enabled=False) == []


#: Options naming a file a tool reads, which config/path_trust.py refuses inside
#: the tree; one outside it is the operator's to name.
PATH_CHOICES = [
    ("checkov", "config_file"),
    ("ferret-scan", "config_file"),
    ("detect-secrets", "baseline_file"),
    ("trivy-repo", "ignore_file"),
    ("trivy-repo", "secret_config_file"),
]
_PATH_IDS = [f"{scanner}.{option}" for scanner, option in PATH_CHOICES]


def _outside(tmp_path: Path) -> str:
    elsewhere = tmp_path / "elsewhere" / "tool-file"
    elsewhere.parent.mkdir(exist_ok=True)
    elsewhere.write_text("x\n", encoding="utf-8")
    return elsewhere.as_posix()


@pytest.mark.parametrize(("scanner", "option"), PATH_CHOICES, ids=_PATH_IDS)
def test_a_repositorys_config_does_not_name_a_tool_file_outside_the_tree(
    tmp_path: Path, scanner: str, option: str
) -> None:
    repo = _repo(tmp_path, {scanner: {"options": {option: _outside(tmp_path)}}})
    config = resolve_config(source_dir=repo)
    assert not _option(config, scanner, option)


@pytest.mark.parametrize(("scanner", "option"), PATH_CHOICES, ids=_PATH_IDS)
def test_an_override_names_a_tool_file_outside_the_tree(
    tmp_path: Path, scanner: str, option: str
) -> None:
    outside = _outside(tmp_path)
    repo = _repo(tmp_path, {scanner: {"options": {option: "in-tree-name"}}})
    config = resolve_config(
        source_dir=repo,
        config_overrides=[f"scanners.{scanner}.options.{option}={outside}"],
    )
    assert str(_option(config, scanner, option)) == outside


def _plugin_entry(path: str) -> dict:
    return {"name": "LocalPlugin", "path": f"file://{path}"}


def _settings_paths(config: Any) -> List[str]:
    settings = config.scanners.detect_secrets.options.scan_settings
    return [entry.path for entry in settings.plugins_used if entry.path]


def test_a_repositorys_config_does_not_load_a_detect_secrets_plugin_file(
    tmp_path: Path,
) -> None:
    outside = _outside(tmp_path)
    repo = _repo(
        tmp_path,
        {
            "detect-secrets": {
                "options": {
                    "scan_settings": {
                        "plugins_used": [
                            {"name": "AWSKeyDetector"},
                            _plugin_entry(outside),
                        ]
                    }
                }
            }
        },
    )
    config = resolve_config(source_dir=repo)
    settings = config.scanners.detect_secrets.options.scan_settings
    assert [entry.name for entry in settings.plugins_used] == ["AWSKeyDetector"]


def test_an_operator_config_outside_the_tree_loads_its_plugin_file(
    tmp_path: Path,
) -> None:
    outside = _outside(tmp_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        yaml.safe_dump(
            {
                "scanners": {
                    "detect-secrets": {
                        "options": {
                            "scan_settings": {"plugins_used": [_plugin_entry(outside)]}
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    config = resolve_config(config_path=operator, source_dir=repo)
    assert _settings_paths(config) == [f"file://{outside}"]


def test_a_repositorys_config_does_not_choose_opengreps_patterns(
    tmp_path: Path,
) -> None:
    """Patterns mode runs the patterns in place of every rule config."""
    repo = _repo(tmp_path, {"opengrep": {"options": {"patterns": ["X_9q"]}}})
    assert _option(resolve_config(source_dir=repo), "opengrep", "patterns") == []
    chosen = resolve_config(
        source_dir=repo,
        config_overrides=['scanners.opengrep.options.patterns=["Y_9q"]'],
    )
    assert _option(chosen, "opengrep", "patterns") == ["Y_9q"]


def test_patterns_mode_is_refused_whatever_else_the_section_sets(
    tmp_path: Path,
) -> None:
    """A section that sets ``patterns`` is refused while the scanner is built.

    opengrep runs a ``--pattern`` search only with a language, which no option of
    this scanner supplies, so no command is built for it: the refusal names the
    missing language option. The other settings of the section, an operator's
    ``exclude`` here, do not change that.
    """
    from automated_security_helper.core.exceptions import ScannerError
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
        OpengrepScannerConfig,
    )

    context = _context(tmp_path)
    with pytest.raises(ScannerError) as refused:
        OpengrepScanner(
            context=context,
            config=OpengrepScannerConfig.model_validate(
                {"options": {"patterns": ["X_9q"], "exclude": ["operator-dir"]}}
            ),
        )
    assert "--lang" in str(refused.value)
    assert "scanners.opengrep.options.patterns" in str(refused.value)


@pytest.mark.parametrize("scanner", ["opengrep", "semgrep"])
def test_a_repositorys_metrics_off_is_kept(tmp_path: Path, scanner: str) -> None:
    """``off`` only stops the tool sending usage data, so any config may set it."""
    repo = _repo(tmp_path, {scanner: {"options": {"metrics": "off"}}})
    assert _option(resolve_config(source_dir=repo), scanner, "metrics") == "off"


@pytest.mark.parametrize(
    ("scanner", "option"),
    [
        ("trivy-repo", "ignore_file"),
        ("trivy-repo", "secret_config_file"),
        ("ferret-scan", "config_file"),
    ],
)
def test_a_dash_spelled_override_names_a_plugins_tool_file(
    tmp_path: Path, scanner: str, option: str
) -> None:
    outside = _outside(tmp_path)
    repo = _repo(tmp_path, {scanner: {"options": {option: "in-tree-name"}}})
    config = resolve_config(
        source_dir=repo,
        config_overrides=[
            f"scanners.{scanner}.options.{option.replace('_', '-')}={outside}"
        ],
    )
    options = config.get_plugin_config("scanner", scanner)["options"]
    assert outside in {
        str(options.get(option)),
        str(options.get(option.replace("_", "-"))),
    }


def test_an_in_tree_config_repeating_the_operators_tool_config_is_no_change(
    tmp_path: Path,
) -> None:
    """The same value as the trusted base's is kept, with no warning."""
    import logging

    from automated_security_helper.utils.log import ASH_LOGGER

    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        yaml.safe_dump(
            {"scanners": {"bandit": {"options": {"config_file": "/etc/bandit.ini"}}}}
        ),
        encoding="utf-8",
    )
    repo = _repo(tmp_path, {"bandit": {"options": {"config_file": "/etc/bandit.ini"}}})
    records: List[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Keep(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        config = resolve_config(source_dir=repo, trusted_config_path=operator)
    finally:
        ASH_LOGGER.removeHandler(handler)
    assert _config_file(config, "bandit") == "/etc/bandit.ini"
    assert not [r for r in records if "Ignoring" in r.getMessage()], records


def _warnings_while(call: Any) -> List[str]:
    import logging

    from automated_security_helper.utils.log import ASH_LOGGER

    records: List[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Keep(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        call()
    finally:
        ASH_LOGGER.removeHandler(handler)
    return [r.getMessage() for r in records]


@pytest.mark.parametrize("value", [True, None])
def test_a_repositorys_ferret_default_config_choice_at_the_default_is_no_change(
    tmp_path: Path, value: Any
) -> None:
    """``use_default_config: true`` is the default, so nothing is ignored or warned.

    An explicit null is given the default too, rather than handed to the plugin.
    """
    repo = _repo(tmp_path, {"ferret-scan": {"options": {"use_default_config": value}}})
    seen: Dict[str, Any] = {}
    warnings = _warnings_while(
        lambda: seen.setdefault("config", resolve_config(source_dir=repo))
    )
    options = seen["config"].get_plugin_config("scanner", "ferret-scan")["options"]
    assert options.get("use_default_config", True) is True
    assert not [w for w in warnings if "Ignoring" in w], warnings


def test_a_confined_choice_on_a_model_section_falls_back_to_its_default() -> None:
    """A section held as a model is set to the default when the trusted base has none."""
    from types import SimpleNamespace

    from automated_security_helper.config.tool_config_trust import _MISSING, _set

    options = SimpleNamespace(use_default_config=False)
    _set(options, "use_default_config", _MISSING, True)
    assert options.use_default_config is True
    _set(options, "use_default_config", None, True)
    assert options.use_default_config is True


def test_a_repositorys_default_value_under_an_operators_choice_is_not_warned_about(
    tmp_path: Path,
) -> None:
    """The operator's value applies; the repository only wrote the default."""
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        yaml.safe_dump(
            {"scanners": {"ferret-scan": {"options": {"use_default_config": False}}}}
        ),
        encoding="utf-8",
    )
    repo = _repo(tmp_path, {"ferret-scan": {"options": {"use_default_config": True}}})
    seen: Dict[str, Any] = {}
    warnings = _warnings_while(
        lambda: seen.setdefault(
            "config", resolve_config(source_dir=repo, trusted_config_path=operator)
        )
    )
    options = seen["config"].get_plugin_config("scanner", "ferret-scan")["options"]
    assert options["use_default_config"] is False
    assert not [w for w in warnings if "Ignoring" in w], warnings
