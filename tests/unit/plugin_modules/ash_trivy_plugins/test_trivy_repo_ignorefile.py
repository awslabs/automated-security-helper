# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""trivy-repo gets an explicit --ignorefile, never the scanned tree's .trivyignore.

Without --ignorefile, trivy reads .trivyignore from its working directory, which is
the source directory. These tests record the argv trivy-repo would run and check
which ignore file it names. tests/integration/scanners/test_trivy_repo_real_ignorefile.py
runs the real trivy.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
)

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
    scanner = TrivyRepoScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=AshConfig()),
        config=TrivyRepoScannerConfig(options=options or {}),
    )
    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_run_subprocess", return_value={}) as run,
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
