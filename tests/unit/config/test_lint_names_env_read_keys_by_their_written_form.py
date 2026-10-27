# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Lint output names env-read keys and values by their written form.

The config linter reads each file unfolded, so its warnings can name the
spelling the file wrote. A section key or an option value can be read from the
environment; the warning's message and its location both say ``<value>`` (or
the written ``${VAR}`` form) instead of the value, which can be a credential.
Only ``--fix`` works on the key as the file resolves it, which never prints.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

VAR_EXT = "ASH_TEST_LINT_EXT"
EXT_VALUE = "lint-needle-9f.json"
VAR_SECT = "ASH_TEST_LINT_SECT"
SECT_VALUE = "dEtEcT-sEcReTs"
VAR_SECT2 = "ASH_TEST_LINT_SECT2"
SECT2_VALUE = "detect_secrets"

SPELLINGS = ["detect-secrets", "detect_secrets", "DETECT-SECRETS", "DetectSecrets"]


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VAR_EXT, EXT_VALUE)
    monkeypatch.setenv(VAR_SECT, SECT_VALUE)
    monkeypatch.setenv(VAR_SECT2, SECT2_VALUE)


def _lint(tmp_path, monkeypatch, scanners_body):
    path = tmp_path / "ash.yaml"
    path.write_text("project_name: t\nscanners:\n" + scanners_body, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["config", "lint", "--config", str(path)])
    return result.exit_code, result.output


@pytest.mark.parametrize("spelling", SPELLINGS)
def test_lint_names_no_value_under_a_respelled_section(tmp_path, monkeypatch, spelling):
    code, output = _lint(
        tmp_path,
        monkeypatch,
        f"  {spelling}:\n    options:\n"
        f"      baseline_file: ${{{VAR_EXT}}}\n"
        f"      bogus_option: ${{{VAR_EXT}}}\n",
    )
    assert EXT_VALUE not in "".join(output.split()), output


@pytest.mark.parametrize(
    ("variable", "value"), [(VAR_SECT, SECT_VALUE), (VAR_SECT2, SECT2_VALUE)]
)
def test_lint_names_no_env_read_section_key(tmp_path, monkeypatch, variable, value):
    code, output = _lint(
        tmp_path, monkeypatch, f"  ${{{variable}}}:\n    enabled: false\n"
    )
    assert value not in "".join(output.split()), output


def test_lint_names_an_env_read_key_by_its_reference_and_claims_no_fix(
    tmp_path, monkeypatch
):
    # One form on both surfaces: the warning names the key as the ambiguity
    # refusal does, by its written reference, and claims no auto-fix, since
    # lint --fix refuses any file that reads the environment.
    code, output = _lint(
        tmp_path, monkeypatch, f"  ${{{VAR_SECT2}}}:\n    enabled: false\n"
    )
    flat = " ".join(output.split())
    assert f"${{{VAR_SECT2}}}" in flat, flat
    assert "auto-fixable" not in flat, flat


def test_lint_conflict_names_no_env_read_section_key(tmp_path, monkeypatch):
    # Both the canonical form and an env-read legacy variant are present, so
    # the collision warning fires; it names the env-read key by its written
    # form in the message and the location alike.
    code, output = _lint(
        tmp_path,
        monkeypatch,
        f"  detect-secrets:\n    enabled: false\n"
        f"  ${{{VAR_SECT2}}}:\n    enabled: true\n",
    )
    assert SECT2_VALUE not in "".join(output.split()), output
