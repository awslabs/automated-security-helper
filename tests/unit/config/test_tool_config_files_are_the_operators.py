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
from automated_security_helper.config.resolve_config import resolve_config

SCANNERS = ["bandit", "grype", "syft"]


def _repo(tmp_path: Path, scanners: Dict[str, Any]) -> Path:
    """A checkout whose own .ash/.ash.yaml sets ``scanners``."""
    repo = tmp_path / "repo"
    (repo / ".ash").mkdir(parents=True)
    (repo / ".git").mkdir()
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
    tmp_path: Path, scanner: str
) -> None:
    repo = _repo(tmp_path, {scanner: {"options": {"config_file": ".ash/other.yaml"}}})
    config = resolve_config(
        source_dir=repo,
        config_overrides=[f"scanners.{scanner}.options.config_file=.ash/tool.yaml"],
    )
    assert _config_file(config, scanner) == ".ash/tool.yaml"


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
    assert read(from_the_operator) == override.partition("=")[2]


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
    assert Path(passed).parent == Path(scanner.results_dir)
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

    def fake_run(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        calls.append([str(a) for a in kwargs.get("command") or args[0]])
        raise RuntimeError("stop after the command is built")

    monkeypatch.setattr(scanner, "_pre_scan", lambda *a, **k: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    with pytest.raises(Exception):
        scanner.scan(target=Path(context.source_dir), target_type="source")
    (argv,) = calls
    (passed,) = _values_after(argv, "--config")
    assert Path(passed).parent == Path(scanner.results_dir)
    assert yaml.safe_load(Path(passed).read_text(encoding="utf-8")) == {}


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


def test_an_unhonored_semgrepignore_is_noted_in_the_results(tmp_path: Path) -> None:
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScanner,
        SemgrepScannerConfig,
    )

    context = _context(tmp_path)
    (Path(context.source_dir) / ".semgrepignore").write_text("hidden/\n", "utf-8")
    scanner = SemgrepScanner(context=context, config=SemgrepScannerConfig())
    scanner._resolve_arguments(
        target=Path(context.source_dir), results_file=tmp_path / "r.sarif"
    )
    (note,) = [w for w in context.config._resolution_warnings if ".semgrepignore" in w]
    assert "was not honored" in note
    assert "global_settings.ignore_paths" in note


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
