# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The config check reads each file under the rule its caller names for the environment.

Why this file exists
--------------------
Which files of a chain may read the environment is a rule the caller chooses
(``config_sources.env_refused_for``): by default only a file an MCP client
delivered, and for a remote MCP caller every file the operator did not set aside.
``ConfigValidator.validate_config_file`` took that rule as ``refuse_env`` and
dropped it, and ``check_config_file`` did not take it, so the check read every
file under the default rule and resolved each ``${VAR}`` in a file the caller's
rule keeps from the environment. A caller that wanted the stricter rule read the
chain a second time before the check, and the answer held only if no file
changed between the two reads.

``check_config_file`` now takes the rule and applies it in the one read it makes:
a file the rule refuses, the named file or a base of it, is refused before any of
its references is resolved, in the words every other refusal of that kind uses,
so the answer is the same whether or not the variable it reads is set.

The refusal cells use a variable the test does not set, and one it sets, and
expect the same sentence for both. The controls pass before and after where they
do not need the new argument: the default rule resolves the references of a file
outside any session's directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config.config_validator import ConfigValidator

pytestmark = pytest.mark.unit

UNSET_VAR = "ASH_CHECK_RULE_UNSET_PROBE"
SET_VAR = "ASH_CHECK_RULE_SET_PROBE"
SET_VALUE = "a-value-the-servers-environment-holds"
READS_UNSET = f"project_name: ${{{UNSET_VAR}}}\n"
READS_SET = f"project_name: ${{{SET_VAR}}}\n"
CLEAN = "project_name: plain\n"


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(UNSET_VAR, raising=False)
    monkeypatch.setenv(SET_VAR, SET_VALUE)
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _refuse_everything(path: Path) -> bool:
    return True


def _refuse_nothing(path: Path) -> bool:
    return False


@pytest.mark.parametrize("text", [READS_UNSET, READS_SET], ids=["unset", "set"])
def test_a_file_the_rule_refuses_is_refused_before_its_references_resolve(
    tmp_path, text
):
    named = _write(tmp_path / ".ash.yaml", text)

    check = ConfigValidator.check_config_file(
        named, source_dir=tmp_path, refuse_env=_refuse_everything
    )

    assert not check.scan_accepts, check.errors
    assert len(check.errors) == 1, check.errors
    assert check.errors[0].startswith(ConfigValidator.ENV_NOT_RESOLVED_ERROR_PREFIX), (
        check.errors
    )
    # The same words whether or not the variable is set, and none of its value.
    assert UNSET_VAR not in check.errors[0] and SET_VAR not in check.errors[0]
    assert SET_VALUE not in check.errors[0], check.errors


def test_the_refusal_of_a_set_and_an_unset_variable_is_one_sentence(tmp_path):
    first = ConfigValidator.check_config_file(
        _write(tmp_path / "set.yaml", READS_SET),
        source_dir=tmp_path,
        refuse_env=_refuse_everything,
    )
    second = ConfigValidator.check_config_file(
        _write(tmp_path / "unset.yaml", READS_UNSET),
        source_dir=tmp_path,
        refuse_env=_refuse_everything,
    )

    assert [e.replace("set.yaml", "F") for e in first.errors] == [
        e.replace("unset.yaml", "F") for e in second.errors
    ], (first.errors, second.errors)


def test_a_base_of_a_file_the_rule_refuses_is_refused_by_the_name_that_chose_it(
    tmp_path,
):
    _write(tmp_path / "base.yaml", READS_UNSET)
    named = _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")

    check = ConfigValidator.check_config_file(
        named, source_dir=tmp_path, refuse_env=_refuse_everything
    )

    assert not check.scan_accepts, check.errors
    assert len(check.errors) == 1, check.errors
    assert check.errors[0].startswith(ConfigValidator.ENV_NOT_RESOLVED_ERROR_PREFIX), (
        check.errors
    )
    assert "base.yaml" in check.errors[0], check.errors
    assert UNSET_VAR not in check.errors[0], check.errors


def test_a_rule_that_refuses_only_the_named_file_still_refuses_its_base(tmp_path):
    """The file that names a base is what chose it, so the base is refused with
    it (config_sources, "Environment variables")."""
    base = _write(tmp_path / "base.yaml", READS_UNSET)
    named = _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")

    def refuse_the_named_file(path: Path) -> bool:
        return Path(path).resolve() == named.resolve()

    check = ConfigValidator.check_config_file(
        named, source_dir=tmp_path, refuse_env=refuse_the_named_file
    )

    assert not check.scan_accepts, check.errors
    assert base.name in check.errors[0], check.errors
    assert check.errors[0].startswith(ConfigValidator.ENV_NOT_RESOLVED_ERROR_PREFIX), (
        check.errors
    )


def test_validate_config_file_applies_the_rule_it_is_given(tmp_path):
    named = _write(tmp_path / ".ash.yaml", READS_UNSET)

    valid, problems = ConfigValidator.validate_config_file(
        named, source_dir=tmp_path, refuse_env=_refuse_everything
    )

    assert valid is False, problems
    assert problems and problems[0].startswith(
        ConfigValidator.ENV_NOT_RESOLVED_ERROR_PREFIX
    ), problems


def test_control_a_file_outside_any_session_resolves_its_references(tmp_path):
    """The default rule refuses only a file an MCP client delivered."""
    named = _write(tmp_path / ".ash.yaml", READS_SET)

    check = ConfigValidator.check_config_file(named, source_dir=tmp_path)

    assert check.scan_accepts, check.errors
    assert check.resolved_data["project_name"] == SET_VALUE, check.resolved_data


def test_a_rule_that_refuses_nothing_resolves_the_references(tmp_path):
    named = _write(tmp_path / ".ash.yaml", READS_SET)

    check = ConfigValidator.check_config_file(
        named, source_dir=tmp_path, refuse_env=_refuse_nothing
    )

    assert check.scan_accepts, check.errors
    assert check.resolved_data["project_name"] == SET_VALUE, check.resolved_data


def test_control_a_file_that_reads_nothing_is_accepted_under_a_rule_that_refuses_it(
    tmp_path,
):
    named = _write(tmp_path / ".ash.yaml", CLEAN)

    check = ConfigValidator.check_config_file(
        named, source_dir=tmp_path, refuse_env=_refuse_everything
    )

    assert check.scan_accepts, check.errors
