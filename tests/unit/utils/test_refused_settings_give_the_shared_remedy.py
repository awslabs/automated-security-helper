# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner that ignores a setting the operator did not choose says how to keep it.

actionlint, cfn-guard, cfn-lint, gitleaks, trivy and zizmor take some options only
from the operator (``utils/config_trust.set_by_operator`` and ``operator_path``).
Set by a config file inside a git checkout or the scanned directory, or by an MCP
client, such an option is ignored with a warning. The warning gives the reason
(``config_trust.NOT_THE_OPERATORS``) and ends with the remedy every confinement
warning ends with, ``confinement_remedy.KEEP_A_SETTING``, rather than one of its
own, so the advice reads the same wherever the setting was.

Each case writes the option into the scanned repository's ``.ash/.ash.yaml``,
resolves the config as a scan does, and asks the scanner for the value.
"""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

import pytest
from rich.text import Text

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.config_trust import NOT_THE_OPERATORS

pytestmark = pytest.mark.unit

_SCANNERS = "automated_security_helper.plugin_modules.ash_builtin.scanners"

#: Each scanner's module, class name and config-class prefix.
SCANNER_CLASSES: Dict[str, Tuple[str, str, str]] = {
    "actionlint": ("actionlint_scanner", "ActionlintScanner", "Actionlint"),
    "cfn-guard": ("cfn_guard_scanner", "CfnGuardScanner", "CfnGuard"),
    "cfn-lint": ("cfn_lint_scanner", "CfnLintScanner", "CfnLint"),
    "gitleaks": ("gitleaks_scanner", "GitleaksScanner", "Gitleaks"),
    "trivy": ("trivy_scanner", "TrivyScanner", "Trivy"),
    "zizmor": ("zizmor_scanner", "ZizmorScanner", "Zizmor"),
}

#: The remedy as these warnings gave it in their own words before.
RESTATED = "with --config-overrides or a config file outside"

#: An absolute path outside the scanned tree, so only provenance refuses it.
OUTSIDE = "/nonexistent-operator-dir/tool.conf"

#: (scanner, option, YAML value, the call that reads the option).
CASES: Dict[str, Tuple[str, str, str, Callable[[Any, Path], Any]]] = {
    "actionlint-shellcheck": (
        "actionlint",
        "shellcheck",
        "my-shellcheck",
        lambda scanner, source: scanner._integration_executables(),
    ),
    "actionlint-config_file": (
        "actionlint",
        "config_file",
        OUTSIDE,
        lambda scanner, source: scanner._resolve_config_file(source),
    ),
    "cfn-guard-rule_sets": (
        "cfn-guard",
        "rule_sets",
        "[cis-aws-benchmark-level-1]",
        lambda scanner, source: scanner._operator_rule_sets(),
    ),
    "cfn-guard-rules_paths": (
        "cfn-guard",
        "rules_paths",
        f"[{OUTSIDE}]",
        lambda scanner, source: scanner._operator_rules(source),
    ),
    "cfn-lint-ignore_checks": (
        "cfn-lint",
        "ignore_checks",
        "[W3]",
        lambda scanner, source: scanner._operator_option("ignore_checks"),
    ),
    "cfn-lint-honor_inline_ignores": (
        "cfn-lint",
        "honor_inline_ignores",
        "true",
        lambda scanner, source: scanner._honor_inline_ignores(),
    ),
    "cfn-lint-config_file": (
        "cfn-lint",
        "config_file",
        OUTSIDE,
        lambda scanner, source: scanner._operator_config_file(OUTSIDE),
    ),
    "gitleaks-config_file": (
        "gitleaks",
        "config_file",
        OUTSIDE,
        lambda scanner, source: scanner._operator_option_path("config_file"),
    ),
    "gitleaks-honor_inline_ignores": (
        "gitleaks",
        "honor_inline_ignores",
        "true",
        lambda scanner, source: scanner._honor_inline_ignores(),
    ),
    "gitleaks-max_target_megabytes": (
        "gitleaks",
        "max_target_megabytes",
        "5",
        lambda scanner, source: scanner._max_target_megabytes(),
    ),
    "trivy-scanners": (
        "trivy",
        "scanners",
        "[vuln, secret]",
        lambda scanner, source: scanner._honor_scanner_set(),
    ),
    "trivy-config_file": (
        "trivy",
        "config_file",
        OUTSIDE,
        lambda scanner, source: scanner._trivy_config_file(),
    ),
    "zizmor-config_file": (
        "zizmor",
        "config_file",
        OUTSIDE,
        lambda scanner, source: scanner._config_file_argument(),
    ),
    "zizmor-online_audits": (
        "zizmor",
        "online_audits",
        "true",
        lambda scanner, source: scanner._online(),
    ),
    "zizmor-honor_inline_ignores": (
        "zizmor",
        "honor_inline_ignores",
        "true",
        lambda scanner, source: scanner._honor_inline_ignores(),
    ),
}


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    for variable in ("ASH_CONFIG", "ASH_OFFLINE", "TRIVY_CONFIG"):
        monkeypatch.delenv(variable, raising=False)


def _repo(tmp_path: Path, name: str, option: str, value: str) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".ash").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(
        "project_name: remedy\n"
        f"scanners:\n  {name}:\n    options:\n      {option}: {value}\n",
        encoding="utf-8",
    )
    return repo


def _scanner(name: str, config, source: Path, tmp_path: Path):
    module_name, class_name, prefix = SCANNER_CLASSES[name]
    module = importlib.import_module(f"{_SCANNERS}.{module_name}")
    section = config.get_plugin_config("scanner", name) or {}
    options = section.get("options") if isinstance(section, dict) else None
    options_class = getattr(module, f"{prefix}ScannerConfigOptions")
    config_class = getattr(module, f"{prefix}ScannerConfig")
    return getattr(module, class_name)(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=config_class(options=options_class(**(options or {}))),
    )


def _shown(record: logging.LogRecord) -> str:
    """The record's message as every sink writes it.

    A plugin's warning is logged with markup (PluginBase._plugin_log styles its
    prefix and escapes each part for Rich), so the raw message carries tags and
    empty styles around a part that holds a colon, and the console and both log
    files render it to its text first (utils/log.py's _file_text). The remedy is
    read where the operator reads it, at the end of that text.
    """
    message = record.getMessage()
    if not getattr(record, "markup", False):
        return message
    return Text.from_markup(message).plain


def test_the_reason_holds_no_remedy_of_its_own():
    assert "--config-overrides" not in NOT_THE_OPERATORS
    assert NOT_THE_OPERATORS.startswith("it came from")


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_warning_ends_with_the_shared_remedy(tmp_path, caplog, case):
    name, option, value, read = CASES[case]
    source = _repo(tmp_path, name, option, value)
    config = resolve_config(source_dir=source)
    scanner = _scanner(name, config, source, tmp_path)
    caplog.set_level(logging.WARNING)

    read(scanner, source)

    key = f"scanners.{name}.options.{option}"
    messages = [_shown(r) for r in caplog.records if key in r.getMessage()]
    assert messages, [_shown(r) for r in caplog.records]
    for message in messages:
        assert message.endswith(KEEP_A_SETTING), message
        assert RESTATED not in message, message
