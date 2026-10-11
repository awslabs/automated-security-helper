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
