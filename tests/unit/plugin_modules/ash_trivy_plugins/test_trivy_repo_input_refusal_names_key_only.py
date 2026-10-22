# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""trivy-repo's refusal of an input file that is not a file names the key only.

TRIVY_IGNOREFILE and TRIVY_SECRET_CONFIG are read straight from the environment,
so the run's configuration never holds their values. The scanner's environment
reads join the values its text is redacted with, and the refusal names the key,
never the value or the path it resolved to.
"""

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import reset_path_refusal_warnings
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
)
from automated_security_helper.utils.error_text import error_text

PluginContext.model_rebuild()

CANARY = "zz-canary-9f3a71"


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch):
    monkeypatch.delenv("TRIVY_IGNOREFILE", raising=False)
    monkeypatch.delenv("TRIVY_SECRET_CONFIG", raising=False)
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


def _scanner(tmp_path: Path, options=None) -> TrivyRepoScanner:
    source = tmp_path / "repo"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return TrivyRepoScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=AshConfig()),
        config=TrivyRepoScannerConfig(options=options or {}),
    )


def _missing_outside_tree(tmp_path: Path) -> Path:
    return tmp_path / "operator" / CANARY / "rules.yaml"


def _assert_value_absent(text: str, missing: Path) -> None:
    for fragment in (str(missing), missing.as_posix(), CANARY, missing.name):
        assert fragment not in text, text


@pytest.mark.parametrize(
    "env,call",
    [
        ("TRIVY_SECRET_CONFIG", "_secret_config_file"),
        ("TRIVY_IGNOREFILE", "_ignore_file"),
    ],
)
def test_the_refusal_of_an_environment_input_names_the_key_not_the_value(
    tmp_path, monkeypatch, env, call
):
    missing = _missing_outside_tree(tmp_path)
    monkeypatch.setenv(env, str(missing))
    scanner = _scanner(tmp_path)

    with pytest.raises(ScannerError) as raised:
        getattr(scanner, call)()

    assert env in str(raised.value)
    _assert_value_absent(str(raised.value), missing)
    # The text a handler records: redacted with this scanner's own values.
    recorded = error_text(raised.value, scanner._values_to_redact())
    assert env in recorded
    _assert_value_absent(recorded, missing)


@pytest.mark.parametrize(
    "option,call",
    [
        ("secret_config_file", "_secret_config_file"),
        ("ignore_file", "_ignore_file"),
    ],
)
def test_the_refusal_of_a_configured_input_names_the_key_not_the_value(
    tmp_path, option, call
):
    missing = _missing_outside_tree(tmp_path)
    scanner = _scanner(tmp_path, {option: str(missing)})

    with pytest.raises(ScannerError) as raised:
        getattr(scanner, call)()

    assert f"scanners.trivy-repo.options.{option}" in str(raised.value)
    _assert_value_absent(str(raised.value), missing)


@pytest.mark.parametrize("env", ["TRIVY_SECRET_CONFIG", "TRIVY_IGNOREFILE"])
def test_the_scanners_environment_reads_join_its_redaction_values(
    tmp_path, monkeypatch, env
):
    missing = _missing_outside_tree(tmp_path)
    monkeypatch.setenv(env, str(missing))
    scanner = _scanner(tmp_path)
    assert str(missing) in scanner._environment_values()
    assert str(missing) in scanner._values_to_redact()


def test_no_environment_value_is_added_when_neither_variable_is_set(tmp_path):
    scanner = _scanner(tmp_path)
    assert scanner._environment_values() == ()
    assert scanner._values_to_redact() == ()


def test_an_existing_operator_file_is_still_honored(tmp_path, monkeypatch):
    operator = tmp_path / "operator" / "trivy-secret.yaml"
    operator.parent.mkdir()
    operator.write_text("{}\n")
    monkeypatch.setenv("TRIVY_SECRET_CONFIG", str(operator))
    scanner = _scanner(tmp_path)
    assert Path(scanner._secret_config_file()) == operator.resolve()
