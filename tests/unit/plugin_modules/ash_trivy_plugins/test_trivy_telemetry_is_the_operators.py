# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only the operator turns trivy's and trivy-repo's telemetry on.

``disable_telemetry`` decides whether trivy sends anonymous usage data to its
vendor on an online scan. A config file inside a git checkout or the scanned
directory may set it to true, which only narrows what trivy sends, but not to
false: that value is ignored with a warning, and trivy gets
``--disable-telemetry`` (``tool_config_trust.TIGHTENING_VALUES``). The operator's
false, from ``--config-overrides`` or a config file outside every checkout and the
scanned directory, applies, also when such a file leaves the option out. An MCP
client's config is refused for setting it at all (``client_config_policy``).
The builtin trivy scanner and trivy-repo share the option (``_trivy_scanner_base``),
so each test runs for both.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)

#: Each scanner's class, config class and options class.
SCANNERS = {
    "trivy-repo": (
        TrivyRepoScanner,
        TrivyRepoScannerConfig,
        TrivyRepoScannerConfigOptions,
    ),
    "trivy": (TrivyScanner, TrivyScannerConfig, TrivyScannerConfigOptions),
}

pytestmark = [pytest.mark.unit, pytest.mark.parametrize("name", sorted(SCANNERS))]


def _key(name: str) -> str:
    return f"scanners.{name}.options.disable_telemetry"


def _config(name: str, value: bool) -> str:
    return (
        "project_name: telemetry\n"
        f"scanners:\n  {name}:\n    options:\n"
        f"      disable_telemetry: {str(value).lower()}\n"
    )


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch):
    for variable in ("ASH_CONFIG", "ASH_OFFLINE", "TRIVY_DISABLE_TELEMETRY"):
        monkeypatch.delenv(variable, raising=False)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _repo(tmp_path: Path, text: str) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    _write(repo / ".ash" / ".ash.yaml", text)
    return repo


def _options(config, name: str):
    section = config.get_plugin_config("scanner", name) or {}
    options = section.get("options") if isinstance(section, dict) else None
    if options is None:
        options = getattr(section, "options", None)
    return options


def _disable_telemetry(config, name: str) -> bool:
    options = _options(config, name)
    value = (
        options.get("disable_telemetry")
        if isinstance(options, dict)
        else getattr(options, "disable_telemetry", None)
    )
    return True if value is None else value


def _trivy_args(config, name: str, source: Path, tmp_path: Path) -> list:
    """The arguments the scanner builds from the resolved config's options."""
    scanner_class, config_class, options_class = SCANNERS[name]
    options = _options(config, name)
    scanner = scanner_class(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=config_class(
            options=options_class(**(options if isinstance(options, dict) else {}))
        ),
    )
    scanner._process_config_options()
    return [arg.key for arg in scanner.args.extra_args]


def test_a_repository_config_cannot_turn_telemetry_on(tmp_path, caplog, name):
    repo = _repo(tmp_path, _config(name, False))
    caplog.set_level(logging.WARNING)

    config = resolve_config(source_dir=repo)

    assert _disable_telemetry(config, name) is True
    assert any(_key(name) in r.getMessage() for r in caplog.records), [
        r.getMessage() for r in caplog.records
    ]
    assert "--disable-telemetry" in _trivy_args(config, name, repo, tmp_path)


def test_a_repository_config_may_turn_telemetry_off_over_the_operators_choice(
    tmp_path, monkeypatch, caplog, name
):
    """Stricter than the operator's choice, so it applies from any config."""
    repo = _repo(tmp_path, _config(name, True))
    monkeypatch.setenv(
        "ASH_CONFIG", str(_write(tmp_path / "operator.yaml", _config(name, False)))
    )
    caplog.set_level(logging.WARNING)

    assert _disable_telemetry(resolve_config(source_dir=repo), name) is True
    assert not any(_key(name) in r.getMessage() for r in caplog.records)


def test_the_operators_choice_survives_an_in_tree_section_that_leaves_it_out(
    tmp_path, monkeypatch, name
):
    """The default of an option the file does not write is not the file's choice."""
    repo = _repo(
        tmp_path,
        "project_name: telemetry\n"
        f"scanners:\n  {name}:\n    options:\n      severity_threshold: HIGH\n",
    )
    monkeypatch.setenv(
        "ASH_CONFIG", str(_write(tmp_path / "operator.yaml", _config(name, False)))
    )

    assert _disable_telemetry(resolve_config(source_dir=repo), name) is False


def test_control_the_operators_config_turns_telemetry_on(tmp_path, name):
    plain = tmp_path / "plain"
    plain.mkdir()
    operator = _write(tmp_path / "operator" / "ash.yaml", _config(name, False))

    config = resolve_config(config_path=operator, source_dir=plain)

    assert _disable_telemetry(config, name) is False
    assert "--disable-telemetry" not in _trivy_args(config, name, plain, tmp_path)


def test_control_an_override_turns_telemetry_on_over_a_repository_config(
    tmp_path, name
):
    repo = _repo(tmp_path, _config(name, True))

    config = resolve_config(source_dir=repo, config_overrides=[f"{_key(name)}=false"])

    assert _disable_telemetry(config, name) is False
